//! Shared outbound HTTP(S) client helpers used by API and intruder flows.

use std::{
    io,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslMethod, SslVerifyMode,
    SslVersion,
};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    header::{CONTENT_LENGTH, HOST},
};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_boring::connect as tls_connect;
use tracing::{debug, warn};

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
            let use_h2 = tls_stream.ssl().selected_alpn_protocol() == Some(b"h2");
            debug!(
                %host,
                ech_accepted = tls_stream.ssl().ech_accepted(),
                selected_alpn = ?tls_stream.ssl().selected_alpn_protocol(),
                "outbound TLS handshake completed"
            );
            return send_http_request_over_stream(
                tls_stream,
                &parsed_request,
                &uri,
                &authority,
                use_h2,
            )
            .await;
        }

        send_http_request_over_stream(stream, &parsed_request, &uri, &authority, false).await
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
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .expect("failed setting outbound TLS minimum protocol version");
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .expect("failed setting outbound TLS maximum protocol version");
    if let Err(err) = builder.set_curves_list("X25519MLKEM768") {
        warn!(
            %err,
            "upstream does not support X25519MLKEM768 in this BoringSSL build; falling back to X25519"
        );
        builder
            .set_curves_list("X25519")
            .expect("failed setting outbound TLS fallback key exchange groups");
    }
    builder
        .set_sigalgs_list("ecdsa_secp256r1_sha256")
        .expect("failed setting outbound TLS signature algorithms");
    builder.enable_signed_cert_timestamps();
    if let Err(err) = builder.add_certificate_compression_algorithm(BrotliCertCompression) {
        warn!(
            %err,
            "failed enabling TLS certificate compression extension for outbound client"
        );
    }
    builder.set_permute_extensions(false);
    builder.set_verify(if accept_invalid_certs {
        SslVerifyMode::NONE
    } else {
        SslVerifyMode::PEER
    });
    builder
        .set_alpn_protos(b"\x02h2\x08http/1.1")
        .expect("failed configuring outbound ALPN protocol list");
    builder.build()
}

#[derive(Clone, Copy, Debug)]
struct BrotliCertCompression;

impl CertificateCompressor for BrotliCertCompression {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, _input: &[u8], _output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "certificate compression is not used on client-side sends",
        ))
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        brotli::BrotliDecompress(&mut io::Cursor::new(input), output)
    }
}

async fn send_http_request_over_stream<S>(
    stream: S,
    parsed_request: &ParsedRequestBlob,
    uri: &Uri,
    authority: &str,
    use_h2: bool,
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

    if use_h2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(stream))
                .await
                .context("failed opening outbound HTTP/2 client connection")?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let response = sender
            .send_request(request)
            .await
            .context("failed sending outbound HTTP/2 request")?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .context("failed reading outbound HTTP/2 response body")?
            .to_bytes();
        return Ok(OutboundResponse {
            status,
            headers,
            body,
        });
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
