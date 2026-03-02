//! roxy_core `proxy` module.
//!
//! Exposes public types and functions used by the `roxy` runtime and API surface.

use std::{
    convert::Infallible,
    fmt::Write as _,
    io,
    io::Read,
    net::SocketAddr,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, OnceLock},
    time::Instant,
};

use anyhow::{Context, Result, anyhow};
use boring::{
    pkey::PKey,
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{HOST, HeaderName, HeaderValue},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch},
};
use tokio_boring::{accept as tls_accept, connect as tls_connect};
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
    state::{
        AppState, InterceptDecision, ResponseInterceptDecision, UpstreamChainMode,
        UpstreamProxyEntry, UpstreamProxyProtocol, UpstreamProxySettings,
    },
    tls_ech::{apply_ech_client_config, ech_retry_from_handshake_error},
};

#[derive(Clone)]
/// Represents `ProxyEngine`.
///
/// See also: [`ProxyEngine`].
pub struct ProxyEngine {
    config: ProxyConfig,
    state: Arc<AppState>,
    cert_manager: Arc<CertManager>,
    event_tx: mpsc::Sender<EventEnvelope>,
    middleware: Option<Arc<dyn ProxyMiddleware>>,
}

impl ProxyEngine {
    /// Constructs a new instance.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    pub fn new(
        config: ProxyConfig,
        state: Arc<AppState>,
        cert_manager: Arc<CertManager>,
        event_tx: mpsc::Sender<EventEnvelope>,
    ) -> Self {
        Self {
            config,
            state,
            cert_manager,
            event_tx,
            middleware: None,
        }
    }

    /// Executes `with middleware`.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    pub fn with_middleware(mut self, middleware: Arc<dyn ProxyMiddleware>) -> Self {
        self.middleware = Some(middleware);
        self
    }

    /// Executes `run`.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
    pub async fn run(self) -> Result<()> {
        let (_tx, rx) = watch::channel(false);
        self.run_with_shutdown(rx).await
    }

    /// Runs `with shutdown`.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
    pub async fn run_with_shutdown(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        self.run_with_shutdown_and_ready(&mut shutdown, None).await
    }

    /// Runs `with shutdown and ready`.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
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

    /// Executes `serve stream`.
    ///
    /// # Examples
    /// ```
    /// use roxy_core as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
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
                error!(
                    error = %err,
                    error_chain = %format_error_chain(&err),
                    "proxy forwarding failed"
                );
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
                            warn!(
                                %authority,
                                error = %err,
                                error_chain = %format_error_chain(&err),
                                "https mitm failed"
                            );
                        };
                    } else if let Err(err) = engine
                        .tunnel_connect(TokioIo::new(upgraded), authority)
                        .await
                    {
                        warn!(error = %err, error_chain = %format_error_chain(&err), "connect tunnel failed");
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
        let mut upstream = self
            .connect_for_connect_tunnel(&authority)
            .await
            .with_context(|| {
                format!("failed connecting tunnel target via upstream chain: {authority}")
            })?;
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

        let cert = X509::from_der(&leaf.cert_der)
            .context("failed parsing generated leaf certificate for boring TLS")?;
        let key = PKey::private_key_from_der(&leaf.key_der)
            .context("failed parsing generated leaf private key for boring TLS")?;
        let mut tls_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .context("failed building downstream TLS acceptor")?;
        tls_builder
            .set_certificate(&cert)
            .context("failed assigning downstream certificate")?;
        tls_builder
            .set_private_key(&key)
            .context("failed assigning downstream private key")?;
        tls_builder
            .check_private_key()
            .context("downstream certificate/private key mismatch")?;
        tls_builder
            .set_alpn_protos(b"\x08http/1.1")
            .context("failed configuring downstream ALPN protocol list")?;

        let acceptor = tls_builder.build();
        let tls_stream = tls_accept(&acceptor, upgraded)
            .await
            .map_err(|err| anyhow!("TLS handshake with downstream client failed: {err}"))?;

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
                        error!(
                            authority = %authority.as_str(),
                            error = %err,
                            error_chain = %format_error_chain(&err),
                            "mitm https forwarding failed"
                        );
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

    fn select_upstream_chain(&self, seed: u64) -> Vec<UpstreamProxyEntry> {
        let settings = self.state.upstream_proxy_settings();
        select_upstream_chain_from_settings(&settings, seed)
    }

    async fn connect_for_connect_tunnel(&self, authority: &str) -> Result<TcpStream> {
        let settings = self.state.upstream_proxy_settings();
        let chain = self.select_upstream_chain(hash_seed(authority.as_bytes()));
        dial_via_upstream_chain(authority, &chain, settings.proxy_dns).await
    }

    async fn forward_upstream_request(
        &self,
        request_id: Uuid,
        parsed_request: &crate::raw_http::ParsedRequestBlob,
    ) -> Result<(StatusCode, http::HeaderMap, Bytes)> {
        let timeout = self.config.request_timeout;
        tokio::time::timeout(timeout, async {
            let uri = parsed_request
                .uri
                .parse::<http::Uri>()
                .with_context(|| format!("invalid request URI '{}'", parsed_request.uri))?;
            let scheme = uri.scheme_str().unwrap_or("http");
            if scheme != "http" && scheme != "https" {
                return Err(anyhow!("unsupported request URI scheme '{scheme}'"));
            }
            let authority = uri_authority_with_default_port(&uri)?;

            let settings = self.state.upstream_proxy_settings();
            let chain = self.select_upstream_chain(
                hash_seed(parsed_request.uri.as_bytes()) ^ request_id.as_u128() as u64,
            );
            if self.config.debug_logging.enabled {
                if chain.is_empty() {
                    debug!(
                        request_id = %request_id,
                        configured_proxies = settings.proxies.len(),
                        "no upstream proxy chain configured; using direct upstream connection"
                    );
                } else {
                    let chain_desc = chain
                        .iter()
                        .map(|entry| {
                            format!(
                                "{}://{}:{}",
                                upstream_protocol_label(&entry.protocol),
                                entry.address,
                                entry.port
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" -> ");
                    debug!(
                        request_id = %request_id,
                        chain_mode = ?settings.chain_mode,
                        selected_chain_len = chain.len(),
                        configured_proxies = settings.proxies.len(),
                        chain = %chain_desc,
                        "using upstream proxy chain",
                    );
                }
            }

            let stream = dial_via_upstream_chain(&authority, &chain, settings.proxy_dns).await?;
            if scheme == "https" {
                let host = uri
                    .host()
                    .ok_or_else(|| anyhow!("request URI missing host"))?;
                let connector = upstream_tls_connector();
                let mut tls_config = connector
                    .configure()
                    .context("failed preparing upstream boring TLS connector")?;
                apply_ech_client_config(&mut tls_config, host, None).await;

                let tls_stream = match tls_connect(tls_config, host, stream).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        if let Some(retry) = ech_retry_from_handshake_error(&err) {
                            debug!(
                                request_id = %request_id,
                                %host,
                                public_name_override = ?retry.public_name_override,
                                "retrying upstream TLS handshake with ECH retry configs"
                            );
                            let retry_stream =
                                dial_via_upstream_chain(&authority, &chain, settings.proxy_dns)
                                    .await
                                    .with_context(|| {
                                        format!(
                                            "failed reconnecting upstream chain for ECH retry authority={authority}"
                                        )
                                    })?;
                            let mut retry_tls_config = connector.configure().context(
                                "failed preparing upstream boring TLS connector for ECH retry",
                            )?;
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
                debug!(
                    request_id = %request_id,
                    %host,
                    ech_accepted = tls_stream.ssl().ech_accepted(),
                    "upstream TLS handshake completed"
                );
                return send_http_request_over_stream(tls_stream, parsed_request, &uri, &authority)
                    .await;
            }

            send_http_request_over_stream(stream, parsed_request, &uri, &authority).await
        })
        .await
        .with_context(|| {
            format!(
                "upstream request timed out after {:?} method={} uri={}",
                timeout, parsed_request.method, parsed_request.uri
            )
        })?
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
        captured_request.host = parsed_request.host.clone();
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

        let (status, headers, encoded_response_body) = self
            .forward_upstream_request(request_id, &parsed_request)
            .await
            .with_context(|| {
                format!(
                    "upstream request failed request_id={request_id} method={} uri={}",
                    parsed_request.method, parsed_request.uri
                )
            })?;
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

fn select_upstream_chain_from_settings(
    settings: &UpstreamProxySettings,
    seed: u64,
) -> Vec<UpstreamProxyEntry> {
    if settings.proxies.is_empty() {
        return Vec::new();
    }

    let len = settings.proxies.len();
    let min_len = settings.min_chain_length.max(1).min(len);
    let max_len = settings.max_chain_length.max(min_len).min(len);

    match settings.chain_mode {
        UpstreamChainMode::StrictChain => settings.proxies.clone(),
        UpstreamChainMode::RandomChain => {
            let mut indices: Vec<usize> = (0..len).collect();
            let mut state = if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            };
            let chain_len = if min_len == max_len {
                min_len
            } else {
                state = xorshift64(state);
                min_len + ((state as usize) % (max_len - min_len + 1))
            };
            for i in (1..indices.len()).rev() {
                state = xorshift64(state);
                let j = (state as usize) % (i + 1);
                indices.swap(i, j);
            }
            indices
                .into_iter()
                .take(chain_len)
                .map(|idx| settings.proxies[idx].clone())
                .collect()
        }
    }
}

fn upstream_protocol_label(protocol: &UpstreamProxyProtocol) -> &'static str {
    match protocol {
        UpstreamProxyProtocol::Http => "http",
        UpstreamProxyProtocol::Https => "https",
        UpstreamProxyProtocol::Socks4 => "socks4",
        UpstreamProxyProtocol::Socks5 => "socks5",
    }
}

async fn dial_via_upstream_chain(
    authority: &str,
    chain: &[UpstreamProxyEntry],
    proxy_dns: bool,
) -> Result<TcpStream> {
    if chain.is_empty() {
        return TcpStream::connect(authority)
            .await
            .with_context(|| format!("failed connecting to upstream authority {authority}"));
    }

    let final_targets = if proxy_dns {
        vec![authority.to_string()]
    } else {
        resolve_authority_candidates(authority).await?
    };

    let mut last_err: Option<anyhow::Error> = None;
    for final_target in final_targets {
        match dial_chain_once(chain, &final_target).await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last_err = Some(err.context(format!(
                    "failed dialing upstream chain to resolved target {final_target}"
                )));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("failed dialing upstream chain")))
}

async fn dial_chain_once(chain: &[UpstreamProxyEntry], final_target: &str) -> Result<TcpStream> {
    let first = &chain[0];
    if matches!(first.protocol, UpstreamProxyProtocol::Https) {
        return Err(anyhow!(
            "https upstream proxies are not supported for chained dialing yet"
        ));
    }
    let mut stream = TcpStream::connect((first.address.as_str(), first.port))
        .await
        .with_context(|| {
            format!(
                "failed connecting to first upstream proxy {}:{}",
                first.address, first.port
            )
        })?;

    for (index, proxy) in chain.iter().enumerate() {
        let target = if index + 1 < chain.len() {
            let next = &chain[index + 1];
            format_authority(&next.address, next.port)
        } else {
            final_target.to_string()
        };
        send_proxy_connect(&mut stream, &proxy.protocol, &target)
            .await
            .with_context(|| {
                format!(
                    "failed proxy CONNECT at hop={} protocol={} target={}",
                    index,
                    upstream_protocol_label(&proxy.protocol),
                    target
                )
            })?;
    }

    Ok(stream)
}

async fn send_proxy_connect<T>(
    stream: &mut T,
    protocol: &UpstreamProxyProtocol,
    target: &str,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match protocol {
        UpstreamProxyProtocol::Http => send_http_connect(stream, target).await,
        UpstreamProxyProtocol::Socks4 => send_socks4_connect(stream, target).await,
        UpstreamProxyProtocol::Socks5 => send_socks5_connect(stream, target).await,
        UpstreamProxyProtocol::Https => Err(anyhow!(
            "https upstream proxy protocol is not supported in chained mode"
        )),
    }
}

async fn send_http_request_over_stream<S>(
    stream: S,
    parsed_request: &crate::raw_http::ParsedRequestBlob,
    uri: &http::Uri,
    authority: &str,
) -> Result<(StatusCode, http::HeaderMap, Bytes)>
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
        .context("failed building upstream request object")?;

    let headers = request.headers_mut();
    let mut has_host = false;
    for header in &parsed_request.headers {
        if header.name.eq_ignore_ascii_case("content-length")
            || header.name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }

        let Ok(name) = HeaderName::from_bytes(header.name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(&header.value) else {
            continue;
        };
        if name == HOST {
            has_host = true;
        }
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
            .context("invalid host header")?,
        );
    }

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("failed opening upstream HTTP/1.1 client connection")?;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            trace!(%err, "upstream client connection closed with error");
        }
    });

    let response = sender
        .send_request(request)
        .await
        .context("failed sending request to upstream")?;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .context("failed reading upstream response body")?
        .to_bytes();
    Ok((status, headers, body))
}

fn uri_authority_with_default_port(uri: &http::Uri) -> Result<String> {
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("request URI missing host"))?;
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("https") => 443,
        _ => 80,
    });
    Ok(format_authority(host, port))
}

fn upstream_tls_connector() -> Arc<SslConnector> {
    static CONNECTOR: OnceLock<Arc<SslConnector>> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let mut builder = SslConnector::builder(SslMethod::tls_client())
                .expect("failed building upstream boring TLS connector");
            builder.set_verify(SslVerifyMode::PEER);
            builder
                .set_alpn_protos(b"\x08http/1.1")
                .expect("failed configuring upstream boring ALPN protocol list");
            Arc::new(builder.build())
        })
        .clone()
}

fn hash_seed(input: &[u8]) -> u64 {
    let mut out: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input {
        out ^= u64::from(*byte);
        out = out.wrapping_mul(0x1000_0000_01b3);
    }
    out
}

fn xorshift64(mut x: u64) -> u64 {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

async fn resolve_authority_candidates(authority: &str) -> Result<Vec<String>> {
    let authority = authority
        .parse::<http::uri::Authority>()
        .with_context(|| format!("invalid authority '{authority}'"))?;
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(443);
    let resolved = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("dns lookup failed for {host}:{port}"))?;
    let mut addrs: Vec<SocketAddr> = resolved.collect();
    if addrs.is_empty() {
        return Err(anyhow!("dns lookup returned no records for {host}:{port}"));
    }
    sort_socket_addrs_prefer_ipv4(&mut addrs);
    Ok(addrs
        .into_iter()
        .map(|addr| format_authority(&addr.ip().to_string(), port))
        .collect())
}

fn sort_socket_addrs_prefer_ipv4(addrs: &mut [SocketAddr]) {
    addrs.sort_by_key(|addr| if addr.is_ipv4() { 0_u8 } else { 1_u8 });
}

async fn send_http_connect<T>(stream: &mut T, target: &str) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed writing CONNECT request")?;
    stream
        .flush()
        .await
        .context("failed flushing CONNECT request")?;

    let mut response = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while response.len() < 64 * 1024 {
        let read = stream
            .read(&mut byte)
            .await
            .context("failed reading CONNECT response")?;
        if read == 0 {
            break;
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if response.len() >= 64 * 1024 {
        return Err(anyhow!("CONNECT response header exceeds limit"));
    }

    let text = String::from_utf8_lossy(&response);
    let status_line = text.lines().next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("invalid CONNECT response status line: {status_line}"))?;
    if status_code / 100 != 2 {
        return Err(anyhow!(
            "upstream proxy CONNECT failed with status {status_code}"
        ));
    }

    Ok(())
}

async fn send_socks5_connect<T>(stream: &mut T, target: &str) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .context("failed writing SOCKS5 greeting")?;
    stream
        .flush()
        .await
        .context("failed flushing SOCKS5 greeting")?;

    let mut greeting_response = [0_u8; 2];
    stream
        .read_exact(&mut greeting_response)
        .await
        .context("failed reading SOCKS5 greeting response")?;
    if greeting_response[0] != 0x05 {
        return Err(anyhow!(
            "invalid SOCKS5 greeting version {}",
            greeting_response[0]
        ));
    }
    if greeting_response[1] == 0xFF {
        return Err(anyhow!(
            "SOCKS5 proxy has no acceptable authentication method"
        ));
    }
    if greeting_response[1] != 0x00 {
        return Err(anyhow!(
            "SOCKS5 proxy requires unsupported auth method {}",
            greeting_response[1]
        ));
    }

    let (host, port) = parse_target_host_port(target)?;
    let mut request = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        request.push(0x01);
        request.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
        request.push(0x04);
        request.extend_from_slice(&ip.octets());
    } else {
        if host.len() > 255 {
            return Err(anyhow!(
                "SOCKS5 target host is too long ({} bytes)",
                host.len()
            ));
        }
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
    }
    request.extend_from_slice(&port.to_be_bytes());

    stream
        .write_all(&request)
        .await
        .context("failed writing SOCKS5 CONNECT request")?;
    stream
        .flush()
        .await
        .context("failed flushing SOCKS5 CONNECT request")?;

    let mut response_head = [0_u8; 4];
    stream
        .read_exact(&mut response_head)
        .await
        .context("failed reading SOCKS5 CONNECT response header")?;
    if response_head[0] != 0x05 {
        return Err(anyhow!(
            "invalid SOCKS5 response version {}",
            response_head[0]
        ));
    }
    if response_head[1] != 0x00 {
        return Err(anyhow!(
            "SOCKS5 proxy CONNECT failed with status {}",
            response_head[1]
        ));
    }

    let atyp = response_head[3];
    match atyp {
        0x01 => {
            let mut addr = [0_u8; 4];
            stream
                .read_exact(&mut addr)
                .await
                .context("failed reading SOCKS5 IPv4 bind address")?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .context("failed reading SOCKS5 domain length")?;
            let mut domain = vec![0_u8; usize::from(len[0])];
            stream
                .read_exact(&mut domain)
                .await
                .context("failed reading SOCKS5 domain bind address")?;
        }
        0x04 => {
            let mut addr = [0_u8; 16];
            stream
                .read_exact(&mut addr)
                .await
                .context("failed reading SOCKS5 IPv6 bind address")?;
        }
        _ => return Err(anyhow!("SOCKS5 response has unknown address type {atyp}")),
    }

    let mut bind_port = [0_u8; 2];
    stream
        .read_exact(&mut bind_port)
        .await
        .context("failed reading SOCKS5 bind port")?;

    Ok(())
}

async fn send_socks4_connect<T>(stream: &mut T, target: &str) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (host, port) = parse_target_host_port(target)?;
    let mut request = vec![0x04, 0x01];
    request.extend_from_slice(&port.to_be_bytes());
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        request.extend_from_slice(&ip.octets());
        request.push(0x00);
    } else {
        request.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        request.push(0x00);
        request.extend_from_slice(host.as_bytes());
        request.push(0x00);
    }

    stream
        .write_all(&request)
        .await
        .context("failed writing SOCKS4 CONNECT request")?;
    stream
        .flush()
        .await
        .context("failed flushing SOCKS4 CONNECT request")?;

    let mut response = [0_u8; 8];
    stream
        .read_exact(&mut response)
        .await
        .context("failed reading SOCKS4 CONNECT response")?;
    if response[1] != 0x5A {
        return Err(anyhow!(
            "SOCKS4 proxy CONNECT failed with status {}",
            response[1]
        ));
    }
    Ok(())
}

fn parse_target_host_port(target: &str) -> Result<(String, u16)> {
    let authority = target
        .parse::<http::uri::Authority>()
        .with_context(|| format!("invalid target authority '{target}'"))?;
    let host = authority.host().to_string();
    let port = authority
        .port_u16()
        .ok_or_else(|| anyhow!("target authority '{target}' missing explicit port"))?;
    Ok((host, port))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
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

fn content_encoding_from_headers(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(http::header::CONTENT_ENCODING)
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

fn format_error_chain(err: &anyhow::Error) -> String {
    let mut parts = Vec::new();
    for (idx, cause) in err.chain().enumerate() {
        if idx == 0 {
            parts.push(cause.to_string());
        } else {
            parts.push(format!("caused by[{idx}]: {cause}"));
        }
    }
    parts.join(" | ")
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

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        decode_http_body_bytes, format_body_preview, select_upstream_chain_from_settings,
        send_socks5_connect, sort_socket_addrs_prefer_ipv4,
    };
    use crate::{
        UpstreamChainMode, UpstreamProxyEntry, UpstreamProxyProtocol, UpstreamProxySettings,
    };

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

    #[test]
    fn strict_chain_selects_all_entries() {
        let settings = UpstreamProxySettings {
            proxies: vec![
                UpstreamProxyEntry {
                    protocol: UpstreamProxyProtocol::Http,
                    address: "1.1.1.1".to_string(),
                    port: 8080,
                },
                UpstreamProxyEntry {
                    protocol: UpstreamProxyProtocol::Http,
                    address: "2.2.2.2".to_string(),
                    port: 8080,
                },
                UpstreamProxyEntry {
                    protocol: UpstreamProxyProtocol::Http,
                    address: "3.3.3.3".to_string(),
                    port: 8080,
                },
            ],
            proxy_dns: false,
            chain_mode: UpstreamChainMode::StrictChain,
            min_chain_length: 2,
            max_chain_length: 3,
        };
        let selected = select_upstream_chain_from_settings(&settings, 42);
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].address, "1.1.1.1");
        assert_eq!(selected[1].address, "2.2.2.2");
        assert_eq!(selected[2].address, "3.3.3.3");
    }

    #[test]
    fn random_chain_selects_requested_length() {
        let settings = UpstreamProxySettings {
            proxies: vec![
                UpstreamProxyEntry {
                    protocol: UpstreamProxyProtocol::Http,
                    address: "1.1.1.1".to_string(),
                    port: 8080,
                },
                UpstreamProxyEntry {
                    protocol: UpstreamProxyProtocol::Http,
                    address: "2.2.2.2".to_string(),
                    port: 8080,
                },
                UpstreamProxyEntry {
                    protocol: UpstreamProxyProtocol::Http,
                    address: "3.3.3.3".to_string(),
                    port: 8080,
                },
            ],
            proxy_dns: false,
            chain_mode: UpstreamChainMode::RandomChain,
            min_chain_length: 2,
            max_chain_length: 3,
        };
        let selected = select_upstream_chain_from_settings(&settings, 7);
        assert!(selected.len() >= 2);
        assert!(selected.len() <= 3);
        assert!(
            selected.iter().all(|entry| {
                matches!(entry.address.as_str(), "1.1.1.1" | "2.2.2.2" | "3.3.3.3")
            })
        );
    }

    #[test]
    fn sort_socket_addrs_prefers_ipv4() {
        let mut addrs = vec![
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8080, 0, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
        ];
        sort_socket_addrs_prefer_ipv4(&mut addrs);
        assert!(addrs[0].is_ipv4());
        assert!(addrs[1].is_ipv6());
    }

    #[tokio::test]
    async fn socks5_connect_handshake_success() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind socks mock");
        let addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut greeting = [0_u8; 3];
            socket
                .read_exact(&mut greeting)
                .await
                .expect("read greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            socket
                .write_all(&[0x05, 0x00])
                .await
                .expect("write greeting response");

            let mut head = [0_u8; 4];
            socket
                .read_exact(&mut head)
                .await
                .expect("read request head");
            assert_eq!(head[0], 0x05);
            assert_eq!(head[1], 0x01);
            assert_eq!(head[2], 0x00);
            match head[3] {
                0x03 => {
                    let mut len = [0_u8; 1];
                    socket.read_exact(&mut len).await.expect("read domain len");
                    let mut domain = vec![0_u8; usize::from(len[0])];
                    socket.read_exact(&mut domain).await.expect("read domain");
                    assert_eq!(
                        String::from_utf8(domain).expect("domain utf8"),
                        "example.com"
                    );
                }
                other => panic!("unexpected ATYP {other}"),
            }
            let mut port = [0_u8; 2];
            socket.read_exact(&mut port).await.expect("read port");
            assert_eq!(u16::from_be_bytes(port), 443);

            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90])
                .await
                .expect("write connect response");
        });

        let mut client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect socks mock");
        send_socks5_connect(&mut client, "example.com:443")
            .await
            .expect("socks5 connect succeeds");
        server.await.expect("server join");
    }
}
