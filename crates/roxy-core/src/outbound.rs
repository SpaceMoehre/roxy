//! Shared outbound HTTP(S) client helpers used by API and intruder flows.

use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    header::{CONTENT_LENGTH, HOST},
};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_boring::connect as tls_connect;
use tracing::debug;

use crate::{
    raw_http::ParsedRequestBlob,
    tls_ech::{apply_ech_client_config, ech_retry_from_handshake_error},
};

#[derive(Clone, Debug)]
/// Represents an outbound upstream response.
pub struct OutboundResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// Sends a parsed request blob directly to its target URI.
pub async fn send_parsed_request(
    parsed_request: ParsedRequestBlob,
    timeout: Duration,
    accept_invalid_certs: bool,
) -> Result<OutboundResponse> {
    tokio::time::timeout(timeout, async move {
        let uri = parsed_request
            .uri
            .parse::<Uri>()
            .with_context(|| format!("invalid request URI '{}'", parsed_request.uri))?;
        let scheme = uri.scheme_str().unwrap_or("http");
        if scheme != "http" && scheme != "https" {
            return Err(anyhow!("unsupported request URI scheme '{scheme}'"));
        }

        let authority = uri_authority_with_default_port(&uri)?;
        let stream = TcpStream::connect(&authority)
            .await
            .with_context(|| format!("failed connecting to upstream authority {authority}"))?;

        if scheme == "https" {
            let host = uri
                .host()
                .ok_or_else(|| anyhow!("request URI missing host"))?;
            let connector = tls_connector(accept_invalid_certs);
            let mut tls_config = connector
                .configure()
                .context("failed preparing outbound boring TLS connector")?;
            if accept_invalid_certs {
                tls_config.set_verify_hostname(false);
            }
            apply_ech_client_config(&mut tls_config, host, None).await;

            let tls_stream = match tls_connect(tls_config, host, stream).await {
                Ok(stream) => stream,
                Err(err) => {
                    if let Some(retry) = ech_retry_from_handshake_error(&err) {
                        debug!(
                            %host,
                            public_name_override = ?retry.public_name_override,
                            "retrying outbound TLS handshake with ECH retry configs"
                        );
                        let retry_stream = TcpStream::connect(&authority).await.with_context(|| {
                            format!(
                                "failed reconnecting to upstream authority {authority} for ECH retry"
                            )
                        })?;
                        let mut retry_tls_config = connector
                            .configure()
                            .context("failed preparing outbound TLS connector for ECH retry")?;
                        if accept_invalid_certs {
                            retry_tls_config.set_verify_hostname(false);
                        }
                        apply_ech_client_config(
                            &mut retry_tls_config,
                            host,
                            Some(retry.config_list.as_slice()),
                        )
                        .await;
                        tls_connect(retry_tls_config, host, retry_stream)
                            .await
                            .map_err(|retry_err| {
                                anyhow!(
                                    "TLS handshake to upstream host '{host}' failed after ECH retry: {retry_err}"
                                )
                            })?
                    } else {
                        return Err(anyhow!(
                            "TLS handshake to upstream host '{host}' failed: {err}"
                        ));
                    }
                }
            };
            debug!(%host, ech_accepted = tls_stream.ssl().ech_accepted(), "outbound TLS handshake completed");
            return send_http_request_over_stream(tls_stream, &parsed_request, &uri, &authority)
                .await;
        }

        send_http_request_over_stream(stream, &parsed_request, &uri, &authority).await
    })
    .await
    .with_context(|| format!("outbound request timed out after {timeout:?}"))?
}

fn tls_connector(accept_invalid_certs: bool) -> Arc<SslConnector> {
    static STRICT: OnceLock<Arc<SslConnector>> = OnceLock::new();
    static INSECURE: OnceLock<Arc<SslConnector>> = OnceLock::new();

    if accept_invalid_certs {
        INSECURE
            .get_or_init(|| Arc::new(build_tls_connector(true)))
            .clone()
    } else {
        STRICT
            .get_or_init(|| Arc::new(build_tls_connector(false)))
            .clone()
    }
}

fn build_tls_connector(accept_invalid_certs: bool) -> SslConnector {
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .expect("failed building outbound boring TLS connector");
    builder.set_verify(if accept_invalid_certs {
        SslVerifyMode::NONE
    } else {
        SslVerifyMode::PEER
    });
    builder
        .set_alpn_protos(b"\x08http/1.1")
        .expect("failed configuring outbound ALPN protocol list");
    builder.build()
}

async fn send_http_request_over_stream<S>(
    stream: S,
    parsed_request: &ParsedRequestBlob,
    uri: &Uri,
    authority: &str,
) -> Result<OutboundResponse>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let method = parsed_request
        .method
        .parse::<Method>()
        .with_context(|| format!("invalid request method '{}'", parsed_request.method))?;
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    let mut request = Request::builder()
        .method(method)
        .uri(path_and_query)
        .body(Full::new(parsed_request.body.clone()))
        .context("failed building outbound request object")?;

    let headers = request.headers_mut();
    let mut has_host = false;
    for header in &parsed_request.headers {
        let Ok(name) = HeaderName::from_bytes(header.name.as_bytes()) else {
            continue;
        };
        if name == CONTENT_LENGTH {
            continue;
        }
        if name == HOST {
            has_host = true;
        }
        let Ok(value) = HeaderValue::from_str(&header.value) else {
            continue;
        };
        headers.append(name, value);
    }

    if !has_host {
        headers.insert(
            HOST,
            HeaderValue::from_str(
                uri.authority()
                    .map(|auth| auth.as_str())
                    .unwrap_or(authority),
            )
            .context("invalid host header value")?,
        );
    }

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("failed opening outbound HTTP/1.1 client connection")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let response = sender
        .send_request(request)
        .await
        .context("failed sending outbound request")?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .context("failed reading outbound response body")?
        .to_bytes();
    Ok(OutboundResponse {
        status,
        headers,
        body,
    })
}

fn uri_authority_with_default_port(uri: &Uri) -> Result<String> {
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("request URI missing host"))?;
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("https") => 443,
        _ => 80,
    });
    Ok(format_authority(host, port))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
