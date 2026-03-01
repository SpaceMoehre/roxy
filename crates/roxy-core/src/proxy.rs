use std::{
    convert::Infallible,
    fmt::Write as _,
    io,
    io::Read,
    net::SocketAddr,
    sync::{Arc, Once},
    time::Instant,
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{HeaderName, HeaderValue},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use crate::{
    cert::CertManager,
    config::ProxyConfig,
    middleware::ProxyMiddleware,
    model::{
        CapturedExchange, CapturedRequest, CapturedResponse, EventEnvelope, HeaderValuePair,
        apply_mutation, apply_response_mutation, headers_to_pairs, now_unix_ms,
    },
    raw_http::{build_request_blob, parse_request_blob},
    state::{AppState, InterceptDecision, ResponseInterceptDecision},
};

#[derive(Clone)]
pub struct ProxyEngine {
    config: ProxyConfig,
    state: Arc<AppState>,
    cert_manager: Arc<CertManager>,
    event_tx: mpsc::Sender<EventEnvelope>,
    client: Client,
    middleware: Option<Arc<dyn ProxyMiddleware>>,
}

impl ProxyEngine {
    pub fn new(
        config: ProxyConfig,
        state: Arc<AppState>,
        cert_manager: Arc<CertManager>,
        event_tx: mpsc::Sender<EventEnvelope>,
    ) -> Self {
        ensure_rustls_crypto_provider();
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(config.request_timeout)
            .build()
            .expect("reqwest client should build");

        Self {
            config,
            state,
            cert_manager,
            event_tx,
            client,
            middleware: None,
        }
    }

    pub fn with_middleware(mut self, middleware: Arc<dyn ProxyMiddleware>) -> Self {
        self.middleware = Some(middleware);
        self
    }

    pub async fn run(self) -> Result<()> {
        let (_tx, rx) = watch::channel(false);
        self.run_with_shutdown(rx).await
    }

    pub async fn run_with_shutdown(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        self.run_with_shutdown_and_ready(&mut shutdown, None).await
    }

    pub async fn run_with_shutdown_and_ready(
        self,
        shutdown: &mut watch::Receiver<bool>,
        ready: Option<oneshot::Sender<SocketAddr>>,
    ) -> Result<()> {
        let listener_addr = find_available_bind(self.config.bind)
            .await
            .with_context(|| {
                format!(
                    "failed to find available proxy bind starting from {}",
                    self.config.bind
                )
            })?;
        let listener = TcpListener::bind(listener_addr)
            .await
            .with_context(|| format!("failed to bind proxy listener on {listener_addr}"))?;
        info!(requested_bind = %self.config.bind, actual_bind = %listener_addr, "proxy listener started");
        if let Some(tx) = ready {
            let _ = tx.send(listener_addr);
        }

        let shared = Arc::new(self);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        info!("proxy listener shutdown requested");
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.context("proxy accept failed")?;
                    let engine = shared.clone();
                    tokio::spawn(async move {
                        if let Err(err) = engine.serve_stream(stream, peer).await {
                            warn!(%err, "proxy stream failed");
                        }
                    });
                }
            }
        }

        Ok(())
    }

    pub async fn serve_stream(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) -> Result<()> {
        let io = TokioIo::new(stream);
        let svc_engine = self.clone();
        let service = service_fn(move |req| {
            let request_engine = svc_engine.clone();
            async move { request_engine.handle_request(req).await }
        });

        hyper::server::conn::http1::Builder::new()
            .keep_alive(true)
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, service)
            .with_upgrades()
            .await
            .with_context(|| format!("failed serving client connection {peer}"))?;

        Ok(())
    }

    async fn handle_request(
        self: Arc<Self>,
        request: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        if request.method() == Method::CONNECT {
            return Ok(self.handle_connect(request));
        }

        match self.forward_http_request(request, "http", None).await {
            Ok(response) => Ok(response),
            Err(err) => {
                error!(%err, "proxy forwarding failed");
                Ok(build_text_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream forwarding failed",
                ))
            }
        }
    }

    fn handle_connect(self: Arc<Self>, request: Request<Incoming>) -> Response<Full<Bytes>> {
        let authority = match request.uri().authority().map(|a| a.to_string()) {
            Some(auth) => auth,
            None => {
                return build_text_response(StatusCode::BAD_REQUEST, "CONNECT missing authority");
            }
        };

        let mitm_enabled = self.state.mitm_enabled() && self.config.mitm_enabled;
        let engine = self.clone();

        tokio::spawn(async move {
            match hyper::upgrade::on(request).await {
                Ok(upgraded) => {
                    if mitm_enabled {
                        if let Err(err) = engine
                            .serve_https_mitm(TokioIo::new(upgraded), authority.clone())
                            .await
                        {
                            warn!(%err, %authority, "https mitm failed");
                        };
                    } else if let Err(err) = engine
                        .tunnel_connect(TokioIo::new(upgraded), authority)
                        .await
                    {
                        warn!(%err, "connect tunnel failed");
                    }
                }
                Err(err) => {
                    warn!(%err, "failed to upgrade CONNECT request");
                }
            }
        });

        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .expect("valid CONNECT response")
    }

    async fn tunnel_connect<T>(&self, mut upgraded: T, authority: String) -> Result<()>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut upstream = TcpStream::connect(&authority)
            .await
            .with_context(|| format!("failed connecting to upstream authority {authority}"))?;
        let _ = copy_bidirectional(&mut upgraded, &mut upstream)
            .await
            .context("CONNECT bidirectional copy failed")?;
        Ok(())
    }

    async fn serve_https_mitm<T>(&self, upgraded: T, authority: String) -> Result<()>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let domain = authority
            .split(':')
            .next()
            .ok_or_else(|| anyhow!("invalid CONNECT authority"))?;

        let leaf = self
            .cert_manager
            .get_or_create_domain_cert(domain)
            .await
            .with_context(|| format!("failed creating domain certificate for {domain}"))?;

        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf.key_der),
        );
        let certs = vec![rustls::pki_types::CertificateDer::from(leaf.cert_der)];

        let mut tls_server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("failed building downstream TLS server config")?;
        tls_server.alpn_protocols = vec![b"http/1.1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(tls_server));
        let tls_stream = acceptor
            .accept(upgraded)
            .await
            .context("TLS handshake with downstream client failed")?;

        let authority = Arc::new(authority);
        let engine = Arc::new(self.clone());
        let service = service_fn(move |req| {
            let engine = engine.clone();
            let authority = authority.clone();
            async move {
                match engine
                    .forward_http_request(req, "https", Some(authority.as_str()))
                    .await
                {
                    Ok(response) => Ok::<_, Infallible>(response),
                    Err(err) => {
                        error!(%err, "mitm https forwarding failed");
                        Ok(build_text_response(
                            StatusCode::BAD_GATEWAY,
                            "mitm upstream forwarding failed",
                        ))
                    }
                }
            }
        });

        hyper::server::conn::http1::Builder::new()
            .keep_alive(true)
            .serve_connection(TokioIo::new(tls_stream), service)
            .await
            .context("failed serving mitm TLS http connection")?;

        Ok(())
    }

    async fn forward_http_request(
        &self,
        request: Request<Incoming>,
        default_scheme: &str,
        authority_hint: Option<&str>,
    ) -> Result<Response<Full<Bytes>>> {
        let started = Instant::now();
        let request_id = Uuid::new_v4();

        let (parts, body) = request.into_parts();
        let raw_body = body
            .collect()
            .await
            .context("failed reading request body")?
            .to_bytes();
        let request_target = request_target_for_blob(&parts);
        let effective_uri = build_effective_uri(&parts, default_scheme, authority_hint)?;
        let host = extract_host(&parts, authority_hint);
        let request_headers = headers_to_pairs(&parts.headers);
        let request_blob = build_request_blob(
            parts.method.as_str(),
            &request_target,
            &request_headers,
            raw_body.as_ref(),
        );

        let mut captured_request = CapturedRequest {
            id: request_id,
            created_at_unix_ms: now_unix_ms(),
            method: parts.method.to_string(),
            uri: effective_uri,
            host: host.clone(),
            headers: request_headers,
            body: raw_body.clone(),
            raw: request_blob,
        };
        self.log_request_snapshot("captured", &captured_request);

        if let Some(middleware) = &self.middleware {
            match middleware
                .on_request_pre_capture(captured_request.clone())
                .await
            {
                Ok(mut mutated) => {
                    mutated.id = request_id;
                    if mutated.created_at_unix_ms == 0 {
                        mutated.created_at_unix_ms = captured_request.created_at_unix_ms;
                    }
                    captured_request = mutated;
                    self.log_request_snapshot("middleware-mutated", &captured_request);
                }
                Err(err) => {
                    warn!(%err, %request_id, "request middleware hook failed");
                }
            }
        }

        if self.state.intercept_enabled() {
            self.log_debug(
                request_id,
                "request interception is enabled; waiting for interceptor decision",
            );
            let rx = self.state.enqueue_intercept(captured_request.clone());
            match rx.await {
                Ok(InterceptDecision::Forward) => {
                    self.log_debug(request_id, "request interceptor decision: forward");
                }
                Ok(InterceptDecision::Drop) => {
                    self.log_debug(request_id, "request interceptor decision: drop");
                    return Ok(build_text_response(
                        StatusCode::FORBIDDEN,
                        "request dropped by interceptor",
                    ));
                }
                Ok(InterceptDecision::Mutate(mutation)) => {
                    self.log_debug(request_id, "request interceptor decision: mutate");
                    captured_request = apply_mutation(captured_request, mutation);
                    self.log_request_snapshot("mutated", &captured_request);
                }
                Err(_) => {
                    self.log_debug(request_id, "request interceptor canceled pending request");
                    return Ok(build_text_response(
                        StatusCode::CONFLICT,
                        "interceptor canceled request",
                    ));
                }
            }
        }

        let parsed_request = parse_request_blob(
            captured_request.raw.as_ref(),
            default_scheme,
            authority_hint,
        )
        .context("failed parsing request blob for upstream forwarding")?;
        captured_request.method = parsed_request.method.clone();
        captured_request.uri = parsed_request.uri.clone();
        captured_request.host = parsed_request.host;
        captured_request.headers = parsed_request.headers.clone();
        captured_request.body = parsed_request.body.clone();
        self.log_request_snapshot("forwarding", &captured_request);

        let parsed_path = parsed_request
            .uri
            .parse::<http::Uri>()
            .ok()
            .map(|uri| uri.path().to_string())
            .unwrap_or_else(|| "/".to_string());
        self.state
            .register_site_path(captured_request.host.clone(), parsed_path);

        let mut outbound = self
            .client
            .request(parsed_request.method.parse()?, &parsed_request.uri);

        for header in &parsed_request.headers {
            if header.name.eq_ignore_ascii_case("host")
                || header.name.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            outbound = outbound.header(&header.name, &header.value);
        }

        let upstream_response = outbound
            .body(parsed_request.body)
            .send()
            .await
            .context("upstream request failed")?;

        let status = upstream_response.status();
        let headers = upstream_response.headers().clone();
        let encoded_response_body = upstream_response
            .bytes()
            .await
            .context("failed reading upstream response body")?;
        let content_encoding = content_encoding_from_headers(&headers);
        let mut response_decoded = false;
        let response_body = match decode_http_body_bytes(
            encoded_response_body.as_ref(),
            content_encoding.as_deref(),
        ) {
            Ok(decoded) => {
                response_decoded = true;
                Bytes::from(decoded)
            }
            Err(err) => {
                warn!(
                    %err,
                    encoding = ?content_encoding,
                    "failed decoding upstream response body; preserving original bytes"
                );
                encoded_response_body
            }
        };

        let mut captured_response = CapturedResponse {
            request_id,
            created_at_unix_ms: now_unix_ms(),
            status: status.as_u16(),
            headers: headers
                .iter()
                .filter_map(|(name, value)| {
                    if name.as_str().eq_ignore_ascii_case("content-length")
                        || name.as_str().eq_ignore_ascii_case("transfer-encoding")
                    {
                        return None;
                    }
                    if response_decoded && name.as_str().eq_ignore_ascii_case("content-encoding") {
                        return None;
                    }
                    value.to_str().ok().map(|v| HeaderValuePair {
                        name: name.to_string(),
                        value: v.to_string(),
                    })
                })
                .collect(),
            body: response_body,
        };
        self.log_response_snapshot("upstream", &captured_response);

        if let Some(middleware) = &self.middleware {
            match middleware
                .on_response_pre_capture(&captured_request, captured_response.clone())
                .await
            {
                Ok(mut mutated) => {
                    mutated.request_id = request_id;
                    if mutated.created_at_unix_ms == 0 {
                        mutated.created_at_unix_ms = captured_response.created_at_unix_ms;
                    }
                    captured_response = mutated;
                    self.log_response_snapshot("middleware-mutated", &captured_response);
                }
                Err(err) => {
                    warn!(%err, %request_id, "response middleware hook failed");
                }
            }
        }

        if self.state.intercept_response_enabled() {
            self.log_debug(
                request_id,
                "response interception is enabled; waiting for interceptor decision",
            );
            let rx = self
                .state
                .enqueue_response_intercept(captured_response.clone());
            match rx.await {
                Ok(ResponseInterceptDecision::Forward) => {
                    self.log_debug(request_id, "response interceptor decision: forward");
                }
                Ok(ResponseInterceptDecision::Drop) => {
                    self.log_debug(request_id, "response interceptor decision: drop");
                    let exchange = CapturedExchange {
                        request: captured_request,
                        response: None,
                        duration_ms: started.elapsed().as_millis(),
                        error: Some("response dropped by interceptor".to_string()),
                    };
                    let _ = self.event_tx.try_send(EventEnvelope::Exchange(exchange));
                    return Ok(build_text_response(
                        StatusCode::FORBIDDEN,
                        "response dropped by interceptor",
                    ));
                }
                Ok(ResponseInterceptDecision::Mutate(mutation)) => {
                    self.log_debug(request_id, "response interceptor decision: mutate");
                    captured_response = apply_response_mutation(captured_response, mutation);
                    self.log_response_snapshot("mutated", &captured_response);
                }
                Err(_) => {
                    self.log_debug(request_id, "response interceptor canceled pending response");
                    return Ok(build_text_response(
                        StatusCode::CONFLICT,
                        "response interceptor canceled response",
                    ));
                }
            }
        }

        let exchange = CapturedExchange {
            request: captured_request,
            response: Some(captured_response.clone()),
            duration_ms: started.elapsed().as_millis(),
            error: None,
        };

        if let Err(err) = self.event_tx.try_send(EventEnvelope::Exchange(exchange)) {
            debug!(%err, "storage event queue is full; dropping event");
        }

        let status = StatusCode::from_u16(captured_response.status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response_builder = Response::builder().status(status);

        for header in &captured_response.headers {
            if header.name.eq_ignore_ascii_case("content-length")
                || header.name.eq_ignore_ascii_case("transfer-encoding")
            {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(header.name.as_bytes()),
                HeaderValue::from_str(&header.value),
            ) {
                response_builder = response_builder.header(name, value);
            }
        }

        let response = response_builder
            .body(Full::new(captured_response.body))
            .context("failed building downstream response")?;
        self.log_debug(
            request_id,
            &format!(
                "request completed in {}ms with status {}",
                started.elapsed().as_millis(),
                captured_response.status
            ),
        );
        Ok(response)
    }

    fn log_debug(&self, request_id: Uuid, message: &str) {
        if !self.config.debug_logging.enabled {
            return;
        }
        debug!(%request_id, "{message}");
    }

    fn log_request_snapshot(&self, phase: &str, request: &CapturedRequest) {
        if !self.config.debug_logging.enabled {
            return;
        }

        debug!(
            request_id = %request.id,
            phase,
            method = %request.method,
            uri = %request.uri,
            host = %request.host,
            headers = request.headers.len(),
            body_bytes = request.body.len(),
            raw_bytes = request.raw.len(),
            "proxy request snapshot"
        );
        trace!(request_id = %request.id, phase, headers = ?request.headers, "proxy request headers");

        if self.config.debug_logging.log_bodies {
            let limit = self.config.debug_logging.body_preview_bytes;
            debug!(
                request_id = %request.id,
                phase,
                body_preview = %format_body_preview(request.body.as_ref(), limit),
                raw_preview = %format_body_preview(request.raw.as_ref(), limit),
                "proxy request body preview"
            );
        }
    }

    fn log_response_snapshot(&self, phase: &str, response: &CapturedResponse) {
        if !self.config.debug_logging.enabled {
            return;
        }

        debug!(
            request_id = %response.request_id,
            phase,
            status = response.status,
            headers = response.headers.len(),
            body_bytes = response.body.len(),
            "proxy response snapshot"
        );
        trace!(request_id = %response.request_id, phase, headers = ?response.headers, "proxy response headers");

        if self.config.debug_logging.log_bodies {
            let limit = self.config.debug_logging.body_preview_bytes;
            debug!(
                request_id = %response.request_id,
                phase,
                body_preview = %format_body_preview(response.body.as_ref(), limit),
                "proxy response body preview"
            );
        }
    }
}

fn extract_host(parts: &http::request::Parts, authority_hint: Option<&str>) -> String {
    parts
        .uri
        .host()
        .map(ToOwned::to_owned)
        .or_else(|| {
            parts
                .headers
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
        })
        .or_else(|| authority_hint.map(|a| a.split(':').next().unwrap_or(a).to_string()))
        .unwrap_or_else(|| "unknown-host".to_string())
}

fn build_effective_uri(
    parts: &http::request::Parts,
    default_scheme: &str,
    authority_hint: Option<&str>,
) -> Result<String> {
    if parts.uri.scheme().is_some() {
        return Ok(parts.uri.to_string());
    }

    let authority = parts
        .uri
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            parts
                .headers
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(ToOwned::to_owned)
        })
        .or_else(|| authority_hint.map(ToOwned::to_owned))
        .ok_or_else(|| anyhow!("request missing host header"))?;

    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    Ok(format!("{default_scheme}://{authority}{path}"))
}

fn build_text_response(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain")
        .header(http::header::CONTENT_LENGTH, msg.len().to_string())
        .body(Full::new(Bytes::from(msg.to_owned())))
        .expect("valid static response")
}

fn request_target_for_blob(parts: &http::request::Parts) -> String {
    if parts.uri.scheme().is_some() {
        return parts.uri.to_string();
    }
    parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string())
}

fn content_encoding_from_headers(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn decode_http_body_bytes(body: &[u8], content_encoding: Option<&str>) -> Result<Vec<u8>> {
    let Some(content_encoding) = content_encoding else {
        return Ok(match maybe_decode_http_body_by_magic(body)? {
            Some(decoded) => decoded,
            None => body.to_vec(),
        });
    };

    let mut decoded = body.to_vec();
    let encodings: Vec<String> = content_encoding
        .split(',')
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty() && v != "identity")
        .collect();

    for encoding in encodings.iter().rev() {
        decoded = match encoding.as_str() {
            "gzip" | "x-gzip" => {
                let mut decoder = flate2::read::GzDecoder::new(decoded.as_slice());
                let mut out = Vec::new();
                decoder
                    .read_to_end(&mut out)
                    .context("failed decoding gzip body")?;
                out
            }
            "deflate" => {
                let mut out = Vec::new();
                let zlib_attempt = {
                    let mut decoder = flate2::read::ZlibDecoder::new(decoded.as_slice());
                    decoder.read_to_end(&mut out)
                };
                if zlib_attempt.is_ok() {
                    out
                } else {
                    let mut raw_out = Vec::new();
                    let mut decoder = flate2::read::DeflateDecoder::new(decoded.as_slice());
                    decoder
                        .read_to_end(&mut raw_out)
                        .context("failed decoding deflate body")?;
                    raw_out
                }
            }
            "br" => {
                let mut decoder = brotli::Decompressor::new(decoded.as_slice(), 4096);
                let mut out = Vec::new();
                decoder
                    .read_to_end(&mut out)
                    .context("failed decoding brotli body")?;
                out
            }
            "zstd" | "x-zstd" => {
                zstd::stream::decode_all(decoded.as_slice()).context("failed decoding zstd body")?
            }
            unknown => {
                return Err(anyhow!(
                    "unsupported content-encoding '{unknown}' while decoding upstream response"
                ));
            }
        };
    }

    Ok(decoded)
}

fn maybe_decode_http_body_by_magic(body: &[u8]) -> Result<Option<Vec<u8>>> {
    if body.starts_with(&[0x1f, 0x8b]) {
        let mut decoder = flate2::read::GzDecoder::new(body);
        let mut out = Vec::new();
        decoder
            .read_to_end(&mut out)
            .context("failed decoding gzip body by magic header")?;
        return Ok(Some(out));
    }

    if body.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let out =
            zstd::stream::decode_all(body).context("failed decoding zstd body by magic header")?;
        return Ok(Some(out));
    }

    Ok(None)
}

fn format_body_preview(bytes: &[u8], max_bytes: usize) -> String {
    let shown = bytes.len().min(max_bytes);
    let mut out = String::new();
    for byte in &bytes[..shown] {
        match *byte {
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(*byte as char),
            _ => {
                let _ = write!(&mut out, "\\x{byte:02x}");
            }
        }
    }

    if bytes.len() > shown {
        let remaining = bytes.len() - shown;
        let _ = write!(&mut out, "...<truncated {remaining} bytes>");
    }

    out
}

async fn find_available_bind(start: SocketAddr) -> io::Result<SocketAddr> {
    let mut addr = start;
    loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                drop(listener);
                return Ok(addr);
            }
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                addr = increment_port(addr)?;
            }
            Err(err) => return Err(err),
        }
    }
}

fn increment_port(mut addr: SocketAddr) -> io::Result<SocketAddr> {
    let port = addr.port();
    if port == u16::MAX {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "port range exhausted while searching for available bind",
        ));
    }
    addr.set_port(port + 1);
    Ok(addr)
}

fn ensure_rustls_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{decode_http_body_bytes, format_body_preview};

    #[test]
    fn body_preview_escapes_binary_and_control_chars() {
        let bytes = b"line1\nline2\t\x00\xff";
        let preview = format_body_preview(bytes, 128);
        assert_eq!(preview, "line1\\nline2\\t\\x00\\xff");
    }

    #[test]
    fn body_preview_truncates_when_limit_is_hit() {
        let preview = format_body_preview(b"abcdef", 3);
        assert_eq!(preview, "abc...<truncated 3 bytes>");
    }

    #[test]
    fn decodes_gzip_response() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"decoded").expect("write payload");
        let compressed = encoder.finish().expect("finish gzip");

        let decoded = decode_http_body_bytes(&compressed, Some("gzip")).expect("decode");
        assert_eq!(decoded, b"decoded");
    }

    #[test]
    fn decodes_zstd_response() {
        let compressed = zstd::stream::encode_all("decoded-zstd".as_bytes(), 1).expect("encode");
        let decoded = decode_http_body_bytes(&compressed, Some("zstd")).expect("decode");
        assert_eq!(decoded, b"decoded-zstd");
    }

    #[test]
    fn decodes_zstd_response_without_encoding_header_by_magic() {
        let compressed = zstd::stream::encode_all("decoded-zstd".as_bytes(), 1).expect("encode");
        let decoded = decode_http_body_bytes(&compressed, None).expect("decode");
        assert_eq!(decoded, b"decoded-zstd");
    }
}
