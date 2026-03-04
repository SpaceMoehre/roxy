//! roxy application entry-point.
//!
//! Wires together the proxy engine ([`roxy_core`]), REST API
//! ([`roxy_api`]), WebSocket hub, plugin manager ([`roxy_plugin`]),
//! and persistent storage ([`roxy_storage`]) into a single
//! multi-listener server.
//!
//! ## Architecture
//!
//! An **ingress TCP listener** accepts all traffic on the configured
//! `ROXY_BIND` address and routes each connection to one of:
//!
//! * **HTTP CONNECT / proxy traffic** → forwarded to the
//!   [`ProxyEngine`] over a local loopback
//!   socket.
//! * **REST API requests** (`/api/*`, static assets) → forwarded to the
//!   `ntex` HTTP server over a Unix domain socket.
//! * **WebSocket upgrades** (`/ws`) → forwarded to the
//!   tokio-tungstenite listener over a Unix domain socket.
//!
//! ## Configuration
//!
//! All configuration is via environment variables:
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `ROXY_BIND` | `127.0.0.1:8080` | Ingress listen address |
//! | `ROXY_DATA_DIR` | `.roxy-data` | Persistent data directory |
//! | `ROXY_DEBUG_LOGGING` | `false` | Enable verbose proxy tracing |
//! | `ROXY_DEBUG_LOG_BODIES` | `false` | Include body previews in traces |
//! | `ROXY_DEBUG_LOG_BODY_LIMIT` | `2048` | Max bytes per body preview |
//! | `ROXY_API_WORKERS` | `4` | API ntex workers (`max` = let ntex choose) |

use std::{
    env, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxy_api::{
    ApiState, run_api_with_shutdown_and_ready_uds_with_workers,
    web_modules::{UiModule, UiModuleRegistry},
    ws::{WsHub, run_ws_server_with_shutdown_and_ready_uds},
};
use roxy_core::{
    AppState, AppStateEvent, CapturedRequest, CapturedResponse, CertManager, DebugLoggingConfig,
    EventEnvelope, HeaderValuePair, IntruderManager, ProxyConfig, ProxyEngine, ProxyMiddleware,
};
use roxy_plugin::{
    PluginAlteration, PluginInvocation, PluginManager, PluginManagerEvent, PluginRegistration,
};
use roxy_storage::StorageManager;
use serde_json::Value;
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{mpsc, watch},
    time::timeout,
};
use tracing::{debug, error, info, warn};

const DEFAULT_API_WORKERS: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CliOptions {
    debug: bool,
    api_workers: Option<ApiWorkerSelection>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApiWorkerSelection {
    Max,
    Fixed(usize),
}

impl ApiWorkerSelection {
    fn as_ntex_workers(self) -> Option<usize> {
        match self {
            Self::Max => None,
            Self::Fixed(workers) => Some(workers),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PluginOpsApplied {
    state_ops_applied: usize,
    ui_modules_registered: usize,
}

#[derive(Clone)]
struct PluginBridgeMiddleware {
    plugins: PluginManager,
    app_state: Arc<AppState>,
    ui_modules: Arc<UiModuleRegistry>,
}

impl PluginBridgeMiddleware {
    fn new(
        plugins: PluginManager,
        app_state: Arc<AppState>,
        ui_modules: Arc<UiModuleRegistry>,
    ) -> Self {
        Self {
            plugins,
            app_state,
            ui_modules,
        }
    }
}

#[async_trait]
impl ProxyMiddleware for PluginBridgeMiddleware {
    async fn on_request_pre_capture(&self, request: CapturedRequest) -> Result<CapturedRequest> {
        let payload = serde_json::json!({
            "request": {
                "id": request.id.to_string(),
                "method": request.method.clone(),
                "uri": request.uri.clone(),
                "host": request.host.clone(),
                "headers": request.headers.clone(),
                "raw_base64": STANDARD.encode(request.raw.as_ref()),
                "raw_text": String::from_utf8_lossy(request.raw.as_ref()).to_string(),
                "body_base64": STANDARD.encode(request.body.as_ref()),
            }
        });
        let plugin_results = self
            .plugins
            .invoke_all(
                "on_request_pre_capture",
                payload,
                Duration::from_millis(350),
            )
            .await;

        let mut out = request;
        for result in plugin_results {
            match result {
                Ok(response) => {
                    apply_plugin_output_ops(&self.app_state, &self.ui_modules, &response.output, Some(&response.plugin));
                    let before = out.raw.clone();
                    out = apply_request_middleware_output(out, &response.output)?;
                    if out.raw != before {
                        let summary = format!(
                            "request blob mutated: '{}' -> '{}'",
                            http_start_line(before.as_ref()),
                            http_start_line(out.raw.as_ref())
                        );
                        let alteration = PluginAlteration {
                            plugin: response.plugin.clone(),
                            hook: "on_request_pre_capture".to_string(),
                            request_id: Some(out.id.to_string()),
                            unix_ms: now_unix_ms_local(),
                            summary,
                        };
                        if let Err(err) = self.plugins.record_alteration(alteration).await {
                            warn!(%err, "failed recording request alteration");
                        }
                    }
                }
                Err(err) => warn!(%err, "request middleware plugin failed"),
            }
        }

        Ok(out)
    }

    async fn on_response_pre_capture(
        &self,
        request: &CapturedRequest,
        response: CapturedResponse,
    ) -> Result<CapturedResponse> {
        let payload = serde_json::json!({
            "request": {
                "id": request.id.to_string(),
                "method": request.method.clone(),
                "uri": request.uri.clone(),
                "host": request.host.clone(),
                "headers": request.headers.clone(),
                "raw_base64": STANDARD.encode(request.raw.as_ref()),
                "raw_text": String::from_utf8_lossy(request.raw.as_ref()).to_string(),
                "body_base64": STANDARD.encode(request.body.as_ref()),
            },
            "response": {
                "request_id": response.request_id.to_string(),
                "status": response.status,
                "headers": response.headers.clone(),
                "body_base64": STANDARD.encode(response.body.as_ref()),
                "body_text": String::from_utf8_lossy(response.body.as_ref()).to_string(),
            }
        });
        let plugin_results = self
            .plugins
            .invoke_all(
                "on_response_pre_capture",
                payload,
                Duration::from_millis(350),
            )
            .await;

        let mut out = response;
        for result in plugin_results {
            match result {
                Ok(response) => {
                    apply_plugin_output_ops(&self.app_state, &self.ui_modules, &response.output, Some(&response.plugin));
                    let before_status = out.status;
                    let before_headers = out.headers.clone();
                    let before_body = out.body.clone();
                    out = apply_response_middleware_output(out, &response.output)?;
                    if before_status != out.status
                        || before_headers != out.headers
                        || before_body != out.body
                    {
                        let summary = format!(
                            "response mutated: status {} -> {}, body {} -> {} bytes",
                            before_status,
                            out.status,
                            before_body.len(),
                            out.body.len()
                        );
                        let alteration = PluginAlteration {
                            plugin: response.plugin.clone(),
                            hook: "on_response_pre_capture".to_string(),
                            request_id: Some(request.id.to_string()),
                            unix_ms: now_unix_ms_local(),
                            summary,
                        };
                        if let Err(err) = self.plugins.record_alteration(alteration).await {
                            warn!(%err, "failed recording response alteration");
                        }
                    }
                }
                Err(err) => warn!(%err, "response middleware plugin failed"),
            }
        }

        Ok(out)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_cli_options_from_args(env::args().skip(1))?;
    let debug_logging_enabled = cli.debug || read_bool_env("ROXY_DEBUG_LOGGING", false)?;
    let debug_log_bodies = read_bool_env("ROXY_DEBUG_LOG_BODIES", false)?;
    let debug_log_body_limit = read_usize_env("ROXY_DEBUG_LOG_BODY_LIMIT", 2048)?;
    let api_workers = resolve_api_workers(cli.api_workers)?;
    let api_workers_log = api_workers
        .map(|workers| workers.to_string())
        .unwrap_or_else(|| "max".to_string());
    init_tracing(debug_logging_enabled);

    let bind = read_addr_env("ROXY_BIND", "127.0.0.1:8080")?;
    let data_dir =
        PathBuf::from(env::var("ROXY_DATA_DIR").unwrap_or_else(|_| ".roxy-data".to_string()));
    let runtime_dir = data_dir.join("run");
    let api_uds_path = runtime_dir.join("api.sock");
    let ws_uds_path = runtime_dir.join("ws.sock");

    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed creating data dir {data_dir:?}"))?;
    std::fs::create_dir_all(&runtime_dir)
        .with_context(|| format!("failed creating runtime dir {runtime_dir:?}"))?;

    let app_state = Arc::new(AppState::new());
    let cert_manager = Arc::new(CertManager::load_or_create(data_dir.join("certs"))?);

    // Install the Roxy root CA into the system trust store so tools that
    // proxy through Roxy (e.g. Photon, Sublist3r) accept MITM-signed certs.
    install_ca_to_system_trust(&data_dir.join("certs").join("ca-cert.pem"), &data_dir, bind);

    let storage = StorageManager::open(data_dir.join("storage"))?;
    let plugins = PluginManager::default();
    if let Some(venv_python) = ensure_plugin_venv(&data_dir) {
        plugins.set_python_path(venv_python).await;
    }
    let intruder = IntruderManager::default();
    let ws_hub = WsHub::new(4096);
    let ui_modules = Arc::new(UiModuleRegistry::with_builtin_modules());

    auto_register_plugins(&plugins, &app_state, &ui_modules).await;

    let (event_tx, mut event_rx) = mpsc::channel::<EventEnvelope>(4096);
    let (storage_tx, storage_rx) = mpsc::channel(4096);
    let storage_task = storage.spawn_ingestor(storage_rx);

    let plugins_for_loop = plugins.clone();
    let ws_hub_for_loop = ws_hub.clone();
    let app_state_for_plugins = app_state.clone();
    let ui_modules_for_plugins = ui_modules.clone();
    let event_dispatch = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let EventEnvelope::Exchange(exchange) = &event;
            if let Err(err) = storage_tx.send(exchange.clone()).await {
                error!(%err, "storage ingestion channel closed");
            }

            let payload = serde_json::to_value(exchange).unwrap_or(serde_json::Value::Null);
            let plugin_results = plugins_for_loop
                .invoke_all("on_exchange", payload, Duration::from_millis(200))
                .await;
            for result in plugin_results {
                if let Ok(response) = result {
                    let _ = apply_plugin_output_ops(
                        &app_state_for_plugins,
                        &ui_modules_for_plugins,
                        &response.output,
                        Some(&response.plugin),
                    );
                }
            }

            ws_hub_for_loop.publish(&event);
        }
    });

    let mut intruder_events = intruder.subscribe_events();
    let ws_hub_intruder = ws_hub.clone();
    let intruder_event_dispatch = tokio::spawn(async move {
        while let Ok(event) = intruder_events.recv().await {
            ws_hub_intruder.publish(&event);
        }
    });

    let mut plugin_events = plugins.subscribe_events();
    let ws_hub_plugins = ws_hub.clone();
    let plugin_event_dispatch = tokio::spawn(async move {
        while let Ok(event) = plugin_events.recv().await {
            match event {
                PluginManagerEvent::PluginRegistered(_)
                | PluginManagerEvent::PluginUnregistered { .. }
                | PluginManagerEvent::PluginSettingsUpdated { .. }
                | PluginManagerEvent::PluginAlterationRecorded(_) => {
                    ws_hub_plugins.publish(&event);
                }
            }
        }
    });

    let mut app_state_events = app_state.subscribe_events();
    let ws_hub_state = ws_hub.clone();
    let app_state_event_dispatch = tokio::spawn(async move {
        while let Ok(event) = app_state_events.recv().await {
            match event {
                AppStateEvent::ProxyToggles(_)
                | AppStateEvent::PendingIntercepts(_)
                | AppStateEvent::SiteMapUpdated(_)
                | AppStateEvent::ScopeUpdated(_)
                | AppStateEvent::UpstreamProxySettingsUpdated(_) => {
                    ws_hub_state.publish(&event);
                }
            }
        }
    });

    let plugin_bridge = Arc::new(PluginBridgeMiddleware::new(
        plugins.clone(),
        app_state.clone(),
        ui_modules.clone(),
    ));

    let proxy = Arc::new(
        ProxyEngine::new(
            ProxyConfig {
                bind: loopback_with_port(0),
                debug_logging: DebugLoggingConfig {
                    enabled: debug_logging_enabled,
                    log_bodies: debug_log_bodies,
                    body_preview_bytes: debug_log_body_limit,
                },
                ..ProxyConfig::default()
            },
            app_state.clone(),
            cert_manager.clone(),
            event_tx,
        )
        .with_middleware(plugin_bridge),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let ws_shutdown = shutdown_rx.clone();
    let api_shutdown = shutdown_rx.clone();
    let mut ingress_shutdown = shutdown_rx.clone();

    let ws_hub_for_server = ws_hub.clone();
    let ws_uds_for_server = ws_uds_path.clone();
    let mut ws_task = tokio::spawn(async move {
        run_ws_server_with_shutdown_and_ready_uds(
            ws_uds_for_server,
            ws_hub_for_server,
            ws_shutdown,
            None,
        )
        .await
    });

    let api_state = ApiState::new(
        app_state,
        cert_manager,
        storage,
        plugins,
        intruder,
        ws_hub.clone(),
        ui_modules,
    );
    let api_uds_for_server = api_uds_path.clone();
    let mut api_task = tokio::task::spawn_blocking(move || {
        let runner = ntex::rt::System::new("roxy-api");
        runner.block_on(async move {
            run_api_with_shutdown_and_ready_uds_with_workers(
                api_uds_for_server,
                api_state,
                api_shutdown,
                None,
                api_workers,
            )
            .await
        })
    });

    let (ingress_listener, ingress_actual) = bind_available_tcp_listener(bind)
        .await
        .with_context(|| format!("failed to bind ingress listener from {bind}"))?;
    let targets = IngressTargets {
        proxy,
        api_uds: api_uds_path,
        ws_uds: ws_uds_path,
    };
    let mut ingress_task = tokio::spawn(async move {
        run_ingress_with_shutdown(
            bind,
            ingress_actual,
            ingress_listener,
            targets,
            &mut ingress_shutdown,
        )
        .await
    });
    ws_hub.set_listen_port(ingress_actual.port());

    info!(
        requested_bind = %bind,
        actual_bind = %ingress_actual,
        debug_cli = cli.debug,
        debug_logging_enabled,
        debug_log_bodies,
        debug_log_body_limit,
        api_workers = %api_workers_log,
        "roxy started"
    );

    let mut ctrl_c_triggered = false;
    tokio::select! {
        result = &mut api_task => {
            let result = result.context("api task join failure")?;
            result.context("api server stopped unexpectedly")?;
        }
        result = &mut ws_task => {
            let result = result.context("websocket task join failure")?;
            result.context("websocket server stopped unexpectedly")?;
        }
        result = &mut ingress_task => {
            let result = result.context("ingress task join failure")?;
            result.context("ingress server stopped unexpectedly")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown requested");
            ctrl_c_triggered = true;
        }
    }

    if ctrl_c_triggered {
        let _ = shutdown_tx.send(true);

        // Wait for the three listener tasks to finish (they stop their
        // accept loops when the shutdown watch fires).
        let graceful = timeout(Duration::from_secs(5), async {
            let _ = (&mut ingress_task).await;
            let _ = (&mut ws_task).await;
            let _ = (&mut api_task).await;
        })
        .await;

        if graceful.is_err() {
            warn!("graceful shutdown timed out, aborting remaining tasks");
            ingress_task.abort();
            ws_task.abort();
            api_task.abort();
        }

        // Abort background dispatch tasks.  Once these stop, the
        // channels they hold (storage_tx, broadcast subscribers) are
        // dropped, which cascades cleanup to the storage ingestor.
        event_dispatch.abort();
        intruder_event_dispatch.abort();
        plugin_event_dispatch.abort();
        app_state_event_dispatch.abort();
        storage_task.abort();

        // Safety-net: if something still blocks the runtime from
        // shutting down (e.g. a spawn_blocking thread), force exit
        // after a short grace period so the user never has to pkill.
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            warn!("forcing process exit after shutdown timeout");
            std::process::exit(0);
        });
    }

    Ok(())
}

#[derive(Clone)]
struct IngressTargets {
    proxy: Arc<ProxyEngine>,
    api_uds: PathBuf,
    ws_uds: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IngressRoute {
    Proxy,
    Api,
    WebSocket,
}

async fn run_ingress_with_shutdown(
    requested_bind: SocketAddr,
    actual_bind: SocketAddr,
    listener: TcpListener,
    targets: IngressTargets,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<()> {
    info!(
        requested_bind = %requested_bind,
        actual_bind = %actual_bind,
        api_uds = %targets.api_uds.display(),
        ws_uds = %targets.ws_uds.display(),
        "ingress listener started"
    );

    let mut connection_tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!("ingress listener shutdown requested");
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let targets = targets.clone();
                        connection_tasks.spawn(async move {
                            if let Err(err) = route_ingress_stream(stream, peer, targets).await {
                                warn!(%err, %peer, "ingress stream routing failed");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(%err, "ingress accept failed; continuing");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            }
            // Reap completed connection tasks so the JoinSet doesn't
            // grow unboundedly during long-running sessions.
            Some(_) = connection_tasks.join_next(), if !connection_tasks.is_empty() => {}
        }
    }

    // Abort all still-running connection handlers (keep-alive, CONNECT
    // tunnels, etc.) so the process can exit cleanly.
    let active = connection_tasks.len();
    if active > 0 {
        info!(active_connections = active, "aborting active connection handlers");
        connection_tasks.shutdown().await;
    }

    Ok(())
}

async fn route_ingress_stream(
    stream: TcpStream,
    peer: SocketAddr,
    targets: IngressTargets,
) -> Result<()> {
    let route = detect_ingress_route(&stream).await;
    debug!(%peer, ?route, "ingress route selected");
    match route {
        IngressRoute::Proxy => targets.proxy.serve_stream(stream, peer).await,
        IngressRoute::Api => tunnel_to_uds(stream, &targets.api_uds).await,
        IngressRoute::WebSocket => tunnel_to_uds(stream, &targets.ws_uds).await,
    }
}

async fn tunnel_to_uds(mut stream: TcpStream, path: &Path) -> Result<()> {
    let mut upstream = tokio::net::UnixStream::connect(path)
        .await
        .with_context(|| format!("failed connecting ingress uds target {}", path.display()))?;
    let _ = copy_bidirectional(&mut stream, &mut upstream)
        .await
        .context("ingress bidirectional copy failed")?;
    Ok(())
}

async fn detect_ingress_route(stream: &TcpStream) -> IngressRoute {
    let mut buf = [0_u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            debug!("ingress route detect timed out waiting for request bytes; defaulting to Api");
            return IngressRoute::Api;
        }

        let remaining = deadline.saturating_duration_since(now);
        match timeout(remaining, stream.peek(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let data = &buf[..n];
                if data.contains(&b'\n') || n == buf.len() {
                    let route = classify_ingress_route(data);
                    debug!(
                        ?route,
                        preview = %ingress_request_line_preview(data),
                        bytes_peeked = n,
                        "ingress route classified from request bytes"
                    );
                    return route;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(Ok(_)) => tokio::time::sleep(Duration::from_millis(10)).await,
            Ok(Err(err)) => {
                debug!(%err, "ingress route detect peek failed; defaulting to Api");
                return IngressRoute::Api;
            }
            Err(_) => {
                debug!("ingress route detect wait timed out; defaulting to Api");
                return IngressRoute::Api;
            }
        }
    }
}

fn ingress_request_line_preview(buffer: &[u8]) -> String {
    let line = String::from_utf8_lossy(buffer)
        .lines()
        .next()
        .unwrap_or_default()
        .trim_end_matches('\r')
        .chars()
        .take(160)
        .collect::<String>();
    if line.is_empty() {
        "<empty>".to_string()
    } else {
        line
    }
}

fn classify_ingress_route(buffer: &[u8]) -> IngressRoute {
    let text = String::from_utf8_lossy(buffer);
    let mut lines = text.lines();
    let first = match lines.next() {
        Some(line) => line.trim_end_matches('\r'),
        None => return IngressRoute::Proxy,
    };
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or_default();

    if method == "CONNECT" || target.starts_with("http://") || target.starts_with("https://") {
        return IngressRoute::Proxy;
    }

    if target.starts_with("/ws") && is_websocket_upgrade(buffer) {
        return IngressRoute::WebSocket;
    }

    if target.starts_with('/') {
        return IngressRoute::Api;
    }

    IngressRoute::Proxy
}

fn is_websocket_upgrade(buffer: &[u8]) -> bool {
    let text = String::from_utf8_lossy(buffer).to_ascii_lowercase();
    let mut has_upgrade_websocket = false;
    let mut has_connection_upgrade = false;

    for line in text.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name == "upgrade" && value.contains("websocket") {
                has_upgrade_websocket = true;
            }
            if name == "connection" && value.contains("upgrade") {
                has_connection_upgrade = true;
            }
        }
    }

    has_upgrade_websocket && has_connection_upgrade
}

async fn bind_available_tcp_listener(start: SocketAddr) -> io::Result<(TcpListener, SocketAddr)> {
    const INGRESS_LISTEN_BACKLOG: u32 = 2048;
    let mut addr = start;
    loop {
        match bind_tcp_listener_with_backlog(addr, INGRESS_LISTEN_BACKLOG) {
            Ok(listener) => return Ok((listener, addr)),
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                addr = increment_port(addr)?;
            }
            Err(err) => return Err(err),
        }
    }
}

fn bind_tcp_listener_with_backlog(addr: SocketAddr, backlog: u32) -> io::Result<TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(backlog)
}

fn init_tracing(debug_logging_enabled: bool) {
    let default_filter = if debug_logging_enabled {
        "debug,roxy_core::proxy=trace,roxy_api=debug"
    } else {
        "info"
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_filter.into()),
        )
        .try_init();
}

fn parse_cli_options_from_args<I>(args: I) -> Result<CliOptions>
where
    I: IntoIterator<Item = String>,
{
    let mut options = CliOptions::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--debug" => {
                options.debug = true;
            }
            "--workers" | "--api-workers" => {
                let value = args.next().ok_or_else(|| {
                    anyhow!(
                        "missing value for {}. expected a positive integer or 'max'",
                        arg
                    )
                })?;
                options.api_workers = Some(parse_api_worker_value(&arg, &value)?);
            }
            _ if arg.starts_with("--workers=") => {
                let (_, value) = arg.split_once('=').expect("starts_with ensures '='");
                options.api_workers = Some(parse_api_worker_value("--workers", value)?);
            }
            _ if arg.starts_with("--api-workers=") => {
                let (_, value) = arg.split_once('=').expect("starts_with ensures '='");
                options.api_workers = Some(parse_api_worker_value("--api-workers", value)?);
            }
            unknown => {
                return Err(anyhow!(
                    "unknown argument '{unknown}'. supported flags: --debug, --workers <N|max>, --workers=<N|max>, --api-workers <N|max>, --api-workers=<N|max>"
                ));
            }
        }
    }
    Ok(options)
}

fn parse_api_worker_value(source: &str, value: &str) -> Result<ApiWorkerSelection> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized == "max" {
        return Ok(ApiWorkerSelection::Max);
    }

    let workers = normalized.parse::<usize>().with_context(|| {
        format!("invalid worker count in {source}: '{value}' (expected positive integer or 'max')")
    })?;
    if workers == 0 {
        return Err(anyhow!(
            "invalid worker count in {source}: '{value}' (must be >= 1 or 'max')"
        ));
    }
    Ok(ApiWorkerSelection::Fixed(workers))
}

fn resolve_api_workers(cli_override: Option<ApiWorkerSelection>) -> Result<Option<usize>> {
    if let Some(selection) = cli_override {
        return Ok(selection.as_ntex_workers());
    }

    match env::var("ROXY_API_WORKERS") {
        Ok(value) => Ok(parse_api_worker_value("ROXY_API_WORKERS", &value)?.as_ntex_workers()),
        Err(env::VarError::NotPresent) => Ok(Some(DEFAULT_API_WORKERS)),
        Err(err) => Err(anyhow!("failed reading ROXY_API_WORKERS: {err}")),
    }
}

fn read_addr_env(key: &str, default: &str) -> Result<SocketAddr> {
    let value = env::var(key).unwrap_or_else(|_| default.to_string());
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid socket address in {key}: {value}"))
}

fn loopback_with_port(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
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

fn read_bool_env(key: &str, default: bool) -> Result<bool> {
    match env::var(key) {
        Ok(value) => parse_bool_env_value(key, &value),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(anyhow!("failed reading {key}: {err}")),
    }
}

fn parse_bool_env_value(key: &str, value: &str) -> Result<bool> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(anyhow!(
            "invalid boolean in {key}: '{value}' (accepted: true/false/1/0/yes/no/on/off)"
        )),
    }
}

fn read_usize_env(key: &str, default: usize) -> Result<usize> {
    match env::var(key) {
        Ok(value) => value
            .trim()
            .parse::<usize>()
            .with_context(|| format!("invalid usize in {key}: {value}")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(anyhow!("failed reading {key}: {err}")),
    }
}

async fn auto_register_plugins(
    plugins: &PluginManager,
    app_state: &AppState,
    ui_modules: &UiModuleRegistry,
) {
    let Some(plugin_dir) = resolve_plugin_dir() else {
        info!("plugin autoload skipped: no plugin directory found");
        return;
    };

    let mut scripts = match discover_plugin_scripts(&plugin_dir) {
        Ok(scripts) => scripts,
        Err(err) => {
            warn!(%err, path = %plugin_dir.display(), "plugin autoload failed to read plugin directory");
            return;
        }
    };
    scripts.sort();

    for script in scripts {
        let Some(stem) = script.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let plugin_name = stem.replace('_', "-");
        let registration = PluginRegistration {
            name: plugin_name.clone(),
            script_path: script.clone(),
            hooks: infer_plugin_hooks(&script),
        };

        if let Err(err) = plugins.register(registration).await {
            warn!(%err, %plugin_name, path = %script.display(), "failed autoload plugin registration");
            continue;
        }

        match plugins
            .invoke(
                &plugin_name,
                PluginInvocation {
                    hook: "on_load".to_string(),
                    payload: serde_json::json!({
                        "api_base": "/api/v1",
                        "ui_module_schema_version": 1,
                        "autoload": true
                    }),
                },
            )
            .await
        {
            Ok(result) => {
                let applied = apply_plugin_output_ops(app_state, ui_modules, &result.output, Some(&plugin_name));
                info!(
                    %plugin_name,
                    state_ops_applied = applied.state_ops_applied,
                    ui_modules_registered = applied.ui_modules_registered,
                    "autoloaded plugin"
                );
            }
            Err(err) => {
                warn!(%err, %plugin_name, "plugin autoload on_load invocation failed");
            }
        }
    }
}

fn infer_plugin_hooks(script: &Path) -> Vec<String> {
    const KNOWN_HOOKS: &[&str] = &[
        "on_load",
        "on_exchange",
        "on_request_pre_capture",
        "on_response_pre_capture",
        "decoder",
        "enumerate",
        "crawl",
        "update",
        "status",
    ];

    let source = match fs::read_to_string(script) {
        Ok(source) => source,
        Err(_) => return vec!["on_load".to_string()],
    };

    let mut hooks = Vec::new();
    for hook in KNOWN_HOOKS {
        let single = format!("'{hook}'");
        let double = format!("\"{hook}\"");
        if source.contains(&single) || source.contains(&double) {
            hooks.push((*hook).to_string());
        }
    }

    if !hooks.iter().any(|hook| hook == "on_load") {
        hooks.push("on_load".to_string());
    }
    hooks
}

fn discover_plugin_scripts(plugin_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut scripts = Vec::new();
    let mut stack = vec![plugin_dir.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir)
            .with_context(|| format!("failed reading directory {}", dir.display()))?;

        for entry in entries {
            let entry =
                entry.with_context(|| format!("failed reading entry in {}", dir.display()))?;
            let path = entry.path();
            let file_type = entry.file_type().with_context(|| {
                format!("failed reading file type for {}", entry.path().display())
            })?;

            if file_type.is_dir() {
                if path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|name| name == "__pycache__")
                {
                    continue;
                }
                stack.push(path);
                continue;
            }

            if file_type.is_file() && path.extension().is_some_and(|ext| ext == "py") {
                scripts.push(path);
            }
        }
    }

    scripts.sort();
    Ok(scripts)
}

fn resolve_plugin_dir() -> Option<PathBuf> {
    if let Ok(configured) = env::var("ROXY_PLUGIN_DIR") {
        let path = PathBuf::from(configured);
        if path.is_dir() {
            return Some(path);
        }
    }

    if let Ok(cwd) = env::current_dir() {
        let path = cwd.join("plugins");
        if path.is_dir() {
            return Some(path);
        }
    }

    let workspace_plugins = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../plugins")
        .canonicalize()
        .ok()?;
    if workspace_plugins.is_dir() {
        return Some(workspace_plugins);
    }

    None
}

/// Creates a Python virtual environment at `<data_dir>/venv` (if it doesn't
/// already exist) and returns the path to its `python` interpreter.  Returns
/// `None` when venv creation fails so the app can fall back to the system
/// `python3`.
fn ensure_plugin_venv(data_dir: &Path) -> Option<PathBuf> {
    let venv_dir = data_dir.join("venv");
    let python = venv_dir.join("bin").join("python");

    if python.is_file() {
        info!(python = %python.display(), "plugin venv already exists");
        return Some(python);
    }

    info!(venv = %venv_dir.display(), "creating plugin virtual environment");

    let result = std::process::Command::new("python3")
        .args(["-m", "venv", "--clear"])
        .arg(&venv_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status();

    match result {
        Ok(status) if status.success() && python.is_file() => {
            info!(python = %python.display(), "plugin venv created");
            Some(python)
        }
        Ok(status) => {
            warn!(%status, "python3 -m venv exited unsuccessfully");
            None
        }
        Err(err) => {
            warn!(%err, "failed to create plugin venv");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// System CA trust installation
// ---------------------------------------------------------------------------

/// Install the Roxy root CA into the OS trust store so that subprocess tools
/// (Python plugins proxying through Roxy) accept MITM-signed certificates
/// without any manual configuration.
///
/// **Strategy:**
///
/// 1.  Copy the PEM to `/usr/local/share/ca-certificates/roxy-ca.crt` and
///     run `update-ca-certificates` (Debian / Ubuntu).  This is the cleanest
///     approach and makes *every* library that uses the system trust store
///     just work.
///
/// 2.  If that fails (e.g. the process is not running as root), build a
///     combined CA bundle (`<data_dir>/certs/ca-bundle-combined.pem`) that
///     contains the default system certificates plus the Roxy CA, then
///     export `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` into the process
///     environment so child processes inherit them.
fn install_ca_to_system_trust(ca_pem_path: &Path, data_dir: &Path, bind: SocketAddr) {
    let pem = match fs::read_to_string(ca_pem_path) {
        Ok(p) => p,
        Err(err) => {
            warn!(%err, path = %ca_pem_path.display(),
                  "could not read CA cert – skipping system trust installation");
            return;
        }
    };

    // ── Attempt 1: system-wide install via update-ca-certificates ────────
    let system_wide_ok = try_system_wide_install(&pem);
    if system_wide_ok {
        info!("Roxy CA installed into system trust store");
    } else {
        info!("system-wide CA install not possible – falling back to combined CA bundle");
        let api_url = format!("http://{bind}/api/v1/ca/cert.pem");
        warn!(
            "\n\n\
             ╔══════════════════════════════════════════════════════════════════════╗\n\
             ║  Roxy could not install its CA certificate system-wide.             ║\n\
             ║  To trust HTTPS traffic through Roxy, install it manually:          ║\n\
             ║                                                                     ║\n\
             ║  Linux (Debian/Ubuntu):                                             ║\n\
             ║    sudo wget -qO /usr/local/share/ca-certificates/roxy-ca.crt \\     \n\
             ║      {api_url}                                                      \n\
             ║    sudo update-ca-certificates                                      ║\n\
             ║                                                                     ║\n\
             ║  macOS:                                                             ║\n\
             ║    wget -qO /tmp/roxy-ca.pem {api_url}                              \n\
             ║    sudo security add-trusted-cert -d -r trustRoot \\                  \n\
             ║      -k /Library/Keychains/System.keychain /tmp/roxy-ca.pem         ║\n\
             ╚══════════════════════════════════════════════════════════════════════╝\n",
        );
    }

    // Always create bundle + set env vars – Python's `requests` library uses
    // its own `certifi` CA bundle and ignores the system trust store, so
    // `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` must be set for child processes.
    if let Err(err) = install_ca_via_env_bundle(ca_pem_path, data_dir, &pem) {
        warn!(%err, "failed to create combined CA bundle");
    }
}

/// Try to copy the cert into the system CA directory and run
/// `update-ca-certificates`.  Returns `true` on success.
fn try_system_wide_install(pem: &str) -> bool {
    let dest = Path::new("/usr/local/share/ca-certificates/roxy-ca.crt");

    // Skip the write + update if the cert is already installed and identical.
    if dest.exists() {
        if let Ok(existing) = fs::read_to_string(dest) {
            if existing == pem {
                return update_ca_certificates_runs_ok();
            }
        }
    }

    if let Some(parent) = dest.parent() {
        if fs::create_dir_all(parent).is_err() {
            return false;
        }
    }
    if fs::write(dest, pem).is_err() {
        return false;
    }

    update_ca_certificates_runs_ok()
}

fn update_ca_certificates_runs_ok() -> bool {
    Command::new("update-ca-certificates")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build a PEM bundle that combines all system CA certificates with the Roxy
/// CA and export `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` so child processes
/// (Python plugins) pick it up automatically.
fn install_ca_via_env_bundle(_ca_pem_path: &Path, data_dir: &Path, roxy_pem: &str) -> Result<()> {
    // Locate the system CA bundle – common paths on Debian, RHEL, Alpine.
    let system_bundle = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
    ]
    .iter()
    .map(Path::new)
    .find(|p| p.exists());

    let mut combined = String::new();
    if let Some(bundle) = system_bundle {
        combined = fs::read_to_string(bundle)
            .with_context(|| format!("failed reading system CA bundle {:?}", bundle))?;
        if !combined.ends_with('\n') {
            combined.push('\n');
        }
    }
    combined.push_str(roxy_pem);
    if !combined.ends_with('\n') {
        combined.push('\n');
    }

    let combined_path = data_dir.join("certs").join("ca-bundle-combined.pem");
    fs::write(&combined_path, &combined)
        .with_context(|| format!("failed writing combined CA bundle {:?}", combined_path))?;

    let abs = combined_path
        .canonicalize()
        .unwrap_or_else(|_| combined_path.clone());
    let abs_str = abs.to_string_lossy().to_string();

    // SAFETY: called once during single-threaded startup, before any
    // multi-threaded work that reads these variables.
    unsafe {
        env::set_var("SSL_CERT_FILE", &abs_str);
        env::set_var("REQUESTS_CA_BUNDLE", &abs_str);
    }
    info!(
        path = %abs_str,
        "exported SSL_CERT_FILE and REQUESTS_CA_BUNDLE for child processes"
    );
    Ok(())
}

fn apply_plugin_output_ops(
    app_state: &AppState,
    ui_modules: &UiModuleRegistry,
    output: &Value,
    plugin_name: Option<&str>,
) -> PluginOpsApplied {
    PluginOpsApplied {
        state_ops_applied: apply_plugin_state_ops(app_state, output),
        ui_modules_registered: apply_plugin_ui_modules(ui_modules, output, plugin_name),
    }
}

fn apply_plugin_state_ops(app_state: &AppState, output: &Value) -> usize {
    let mut applied = 0usize;
    let Some(ops) = output.get("state_ops").and_then(|v| v.as_array()) else {
        return 0;
    };

    for op in ops {
        let Some(name) = op.get("op").and_then(|v| v.as_str()) else {
            continue;
        };

        match name {
            "set_intercept_enabled" => {
                if let Some(enabled) = op.get("enabled").and_then(|v| v.as_bool()) {
                    app_state.set_intercept_enabled(enabled);
                    applied += 1;
                }
            }
            "set_intercept_response_enabled" => {
                if let Some(enabled) = op.get("enabled").and_then(|v| v.as_bool()) {
                    app_state.set_intercept_response_enabled(enabled);
                    applied += 1;
                }
            }
            "set_mitm_enabled" => {
                if let Some(enabled) = op.get("enabled").and_then(|v| v.as_bool()) {
                    app_state.set_mitm_enabled(enabled);
                    applied += 1;
                }
            }
            "set_scope_hosts" => {
                if let Some(hosts) = op.get("hosts").and_then(|v| v.as_array()) {
                    let hosts = hosts
                        .iter()
                        .filter_map(|h| h.as_str().map(ToOwned::to_owned))
                        .collect::<Vec<_>>();
                    app_state.set_scope_hosts(hosts);
                    applied += 1;
                }
            }
            _ => {}
        }
    }

    applied
}

fn apply_plugin_ui_modules(ui_modules: &UiModuleRegistry, output: &Value, plugin_name: Option<&str>) -> usize {
    let Some(modules) = output.get("register_ui_modules").and_then(Value::as_array) else {
        return 0;
    };

    let mut registered = 0usize;
    for module in modules {
        let Some(id) = module.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(title) = module.get("title").and_then(Value::as_str) else {
            continue;
        };
        let Some(panel_html) = module.get("panel_html").and_then(Value::as_str) else {
            continue;
        };
        let Some(settings_html) = module.get("settings_html").and_then(Value::as_str) else {
            continue;
        };
        let Some(script_js) = module.get("script_js").and_then(Value::as_str) else {
            continue;
        };

        let id = id.trim();
        let title = title.trim();
        if id.is_empty() || title.is_empty() {
            continue;
        }

        ui_modules.register(UiModule {
            id: id.to_string(),
            title: title.to_string(),
            nav_hidden: module
                .get("nav_hidden")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            accepts_request: module
                .get("accepts_request")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            plugin_name: plugin_name.map(str::to_string),
            panel_html: panel_html.to_string(),
            settings_html: settings_html.to_string(),
            script_js: script_js.to_string(),
        });
        registered += 1;
    }

    registered
}

fn apply_request_middleware_output(
    mut request: CapturedRequest,
    output: &Value,
) -> Result<CapturedRequest> {
    if let Some(raw_base64) = output.get("request_raw_base64").and_then(Value::as_str) {
        let raw = STANDARD
            .decode(raw_base64)
            .context("invalid request_raw_base64 from middleware plugin")?;
        request.raw = raw.into();
    } else if let Some(raw_text) = output
        .get("request_raw_text")
        .or_else(|| output.get("request_raw"))
        .and_then(Value::as_str)
    {
        request.raw = raw_text.as_bytes().to_vec().into();
    }

    Ok(request)
}

fn apply_response_middleware_output(
    mut response: CapturedResponse,
    output: &Value,
) -> Result<CapturedResponse> {
    if let Some(status) = output.get("response_status").and_then(Value::as_u64) {
        response.status = u16::try_from(status).context("invalid response_status range")?;
    }

    if let Some(headers) = output.get("response_headers") {
        if let Ok(parsed) = serde_json::from_value::<Vec<HeaderValuePair>>(headers.clone()) {
            response.headers = parsed;
        }
    }

    if let Some(body_base64) = output.get("response_body_base64").and_then(Value::as_str) {
        let body = STANDARD
            .decode(body_base64)
            .context("invalid response_body_base64 from middleware plugin")?;
        response.body = body.into();
    } else if let Some(body_text) = output.get("response_body_text").and_then(Value::as_str) {
        response.body = body_text.as_bytes().to_vec().into();
    }

    Ok(response)
}

fn http_start_line(raw: &[u8]) -> String {
    let line = raw
        .split(|b| *b == b'\n')
        .next()
        .unwrap_or_default()
        .iter()
        .copied()
        .filter(|b| *b != b'\r')
        .take(180)
        .collect::<Vec<u8>>();
    String::from_utf8_lossy(&line).to_string()
}

fn now_unix_ms_local() -> u128 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use roxy_core::model::now_unix_ms;
    use std::{fs, path::PathBuf, time::Duration};
    use tempfile::tempdir;
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };
    use uuid::Uuid;

    use super::{
        ApiWorkerSelection, AppState, CapturedRequest, CapturedResponse, IngressRoute,
        UiModuleRegistry, apply_plugin_output_ops, apply_request_middleware_output,
        apply_response_middleware_output, classify_ingress_route, detect_ingress_route,
        discover_plugin_scripts, parse_api_worker_value, parse_bool_env_value,
        parse_cli_options_from_args,
    };

    #[test]
    fn parse_bool_env_accepts_common_truthy_values() {
        for value in ["1", "true", "yes", "on", "TRUE", " On "] {
            assert!(parse_bool_env_value("TEST", value).expect("valid bool"));
        }
    }

    #[test]
    fn parse_bool_env_accepts_common_falsy_values() {
        for value in ["0", "false", "no", "off", "FALSE", " Off "] {
            assert!(!parse_bool_env_value("TEST", value).expect("valid bool"));
        }
    }

    #[test]
    fn parse_bool_env_rejects_invalid_values() {
        let err = parse_bool_env_value("TEST", "maybe").expect_err("invalid bool");
        assert!(err.to_string().contains("invalid boolean"));
    }

    #[test]
    fn parse_cli_options_accepts_debug() {
        let opts =
            parse_cli_options_from_args(vec!["--debug".to_string()]).expect("parse should work");
        assert!(opts.debug);
    }

    #[test]
    fn parse_cli_options_accepts_workers_equals_syntax() {
        let opts = parse_cli_options_from_args(vec!["--workers=9".to_string()])
            .expect("parse should work");
        assert_eq!(opts.api_workers, Some(ApiWorkerSelection::Fixed(9)));
    }

    #[test]
    fn parse_cli_options_accepts_api_workers_space_syntax() {
        let opts =
            parse_cli_options_from_args(vec!["--api-workers".to_string(), "max".to_string()])
                .expect("parse should work");
        assert_eq!(opts.api_workers, Some(ApiWorkerSelection::Max));
    }

    #[test]
    fn parse_cli_options_rejects_unknown_flag() {
        let err = parse_cli_options_from_args(vec!["--wat".to_string()]).expect_err("should fail");
        assert!(err.to_string().contains("unknown argument"));
    }

    #[test]
    fn parse_api_worker_value_accepts_max_case_insensitive() {
        assert_eq!(
            parse_api_worker_value("TEST", " Max ").expect("valid worker value"),
            ApiWorkerSelection::Max
        );
    }

    #[test]
    fn parse_api_worker_value_rejects_zero() {
        let err = parse_api_worker_value("TEST", "0").expect_err("zero should fail");
        assert!(err.to_string().contains("must be >= 1"));
    }

    #[test]
    fn classify_ingress_connect_routes_to_proxy() {
        let data = b"CONNECT ifconfig.co:443 HTTP/1.1\r\nhost: ifconfig.co:443\r\n\r\n";
        assert_eq!(classify_ingress_route(data), IngressRoute::Proxy);
    }

    #[test]
    fn classify_ingress_absolute_uri_routes_to_proxy() {
        let data = b"GET http://example.com/a HTTP/1.1\r\nhost: example.com\r\n\r\n";
        assert_eq!(classify_ingress_route(data), IngressRoute::Proxy);
    }

    #[test]
    fn classify_ingress_ws_upgrade_routes_to_websocket() {
        let data = b"GET /ws HTTP/1.1\r\nhost: 127.0.0.1\r\nupgrade: websocket\r\nconnection: keep-alive, Upgrade\r\n\r\n";
        assert_eq!(classify_ingress_route(data), IngressRoute::WebSocket);
    }

    #[test]
    fn classify_ingress_relative_path_routes_to_api() {
        let data = b"GET /api/v1/health HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n";
        assert_eq!(classify_ingress_route(data), IngressRoute::Api);
    }

    #[tokio::test]
    async fn detect_ingress_route_waits_for_slow_request_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            tokio::time::sleep(Duration::from_millis(3200)).await;
            stream
                .write_all(b"GET /app.js HTTP/1.1\r\nhost: 127.0.0.1\r\n\r\n")
                .await
                .expect("write request");
        });

        let (server_stream, _) = listener.accept().await.expect("accept stream");
        let route = detect_ingress_route(&server_stream).await;
        assert_eq!(route, IngressRoute::Api);

        client.await.expect("client join");
    }

    #[test]
    fn discover_plugin_scripts_finds_nested_python_files() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        let nested = root.join("string_substitute");
        fs::create_dir_all(&nested).expect("create nested dir");
        fs::create_dir_all(root.join("__pycache__")).expect("create pycache");

        let plugin = nested.join("string_substitute.py");
        fs::write(&plugin, b"print('ok')").expect("write plugin");
        fs::write(root.join("__pycache__/ignored.py"), b"print('ignored')").expect("write cached");
        fs::write(root.join("README.txt"), b"not-a-plugin").expect("write txt");

        let scripts = discover_plugin_scripts(root).expect("discover scripts");
        let scripts = scripts
            .into_iter()
            .map(|path| path.canonicalize().expect("canonicalize"))
            .collect::<Vec<PathBuf>>();
        assert_eq!(
            scripts,
            vec![plugin.canonicalize().expect("canonicalize plugin")]
        );
    }

    #[test]
    fn middleware_request_output_replaces_raw_blob() {
        let request = CapturedRequest {
            id: Uuid::new_v4(),
            created_at_unix_ms: now_unix_ms(),
            method: "GET".to_string(),
            uri: "http://example.com/path".to_string(),
            host: "example.com".to_string(),
            headers: vec![],
            body: Bytes::new(),
            raw: Bytes::from_static(b"GET /path HTTP/1.1\r\nhost: example.com\r\n\r\n"),
        };

        let output = serde_json::json!({
            "request_raw_text": "GET /mutated HTTP/1.1\r\nhost: example.com\r\n\r\n"
        });
        let mutated = apply_request_middleware_output(request, &output).expect("apply middleware");
        assert!(String::from_utf8_lossy(mutated.raw.as_ref()).contains("/mutated"));
    }

    #[test]
    fn middleware_response_output_replaces_body() {
        let response = CapturedResponse {
            request_id: Uuid::new_v4(),
            created_at_unix_ms: now_unix_ms(),
            status: 200,
            headers: vec![],
            body: Bytes::from_static(b"original"),
        };

        let output = serde_json::json!({
            "response_status": 201,
            "response_body_text": "replaced"
        });
        let mutated =
            apply_response_middleware_output(response, &output).expect("apply middleware");
        assert_eq!(mutated.status, 201);
        assert_eq!(mutated.body, Bytes::from_static(b"replaced"));
    }

    #[test]
    fn plugin_output_ops_registers_ui_module() {
        let app_state = AppState::new();
        let modules = UiModuleRegistry::with_builtin_modules();
        let output = serde_json::json!({
            "state_ops": [
                {"op": "set_intercept_enabled", "enabled": true}
            ],
            "register_ui_modules": [
                {
                    "id": "demo",
                    "title": "Demo",
                    "panel_html": "<div>panel</div>",
                    "settings_html": "<div>settings</div>",
                    "script_js": "window.__demo=true;"
                }
            ]
        });

        let applied = apply_plugin_output_ops(&app_state, &modules, &output, None);
        assert_eq!(applied.state_ops_applied, 1);
        assert_eq!(applied.ui_modules_registered, 1);
        assert!(app_state.intercept_enabled());
        assert!(modules.modules().iter().any(|m| m.id == "demo"));
    }
}
