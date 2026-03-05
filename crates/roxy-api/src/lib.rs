//! HTTP API and web UI layer for the **roxy** intercepting proxy.
//!
//! This crate provides the [`ntex`]-based HTTP server that serves both the
//! single-page web dashboard and the `/api/v1/*` JSON REST endpoints consumed
//! by the dashboard as well as external tooling and plugins.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────┐   unix socket / tcp   ┌─────────────────────────┐
//! │  browser /  │ ────────────────────► │  ntex web server        │
//! │  curl       │                       │  (static assets + API)  │
//! └────────────┘                       └──────────┬──────────────┘
//!                                                 │
//!             ┌───────────┬───────────────────────┤──────────┐
//!             ▼           ▼                       ▼          ▼
//!        [AppState]  [StorageManager]     [PluginManager]  [WsHub]
//! ```
//!
//! # Quick Start
//!
//! The primary entry points are:
//!
//! * [`run_api`] — bind to a TCP address with no shutdown control.
//! * [`run_api_with_shutdown`] — bind to a TCP address with a [`watch`]
//!   shutdown channel.
//! * [`run_api_with_shutdown_and_ready`] — same as above but also signals the
//!   actual bound address via a [`oneshot`] channel.
//! * [`run_api_with_shutdown_and_ready_uds`] — bind to a Unix domain socket
//!   instead of TCP.
//!
//! All variants accept an [`ApiState`] bundle that carries shared application
//! state, certificate management, storage, plugin management, and the WebSocket
//! hub.
//!
//! # Modules
//!
//! * [`web_modules`] — UI module registry for dynamically loaded dashboard panels.
//! * [`ws`] — WebSocket hub for real-time event broadcast to connected clients.

pub mod web_modules;
pub mod ws;

use std::{
    io,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use ntex::web::{self, HttpRequest, HttpResponse};
use roxy_core::{
    AppState, CertManager, InterceptDecision, IntruderJobSpec, IntruderManager, ParsedRequestBlob,
    RequestMutation, ResponseInterceptDecision, ResponseMutation, UpstreamProxySettings,
    model::{HeaderValuePair, now_unix_ms},
    parse_request_blob, send_parsed_request,
};
use roxy_plugin::{PluginInvocation, PluginManager, PluginRegistration};
use roxy_storage::StorageManager;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tera::{Context as TeraContext, Tera};
use tokio::sync::{oneshot, watch};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::ws::WsHub;

const INDEX_TEMPLATE: &str = include_str!("../web/templates/index.html.tera");
const APP_TEMPLATE: &str = include_str!("../web/templates/app.js.tera");
const STYLES_CSS: &str = include_str!("../web/styles.css");
const FAVICON_SVG: &str = include_str!("../web/icons/favicon.svg");
const SAFARI_PINNED_TAB_SVG: &str = include_str!("../web/icons/safari-pinned-tab.svg");
const SITE_WEBMANIFEST: &str = include_str!("../web/icons/site.webmanifest");
const BROWSERCONFIG_XML: &str = include_str!("../web/icons/browserconfig.xml");
const FAVICON_ICO: &[u8] = include_bytes!("../web/icons/favicon.ico");
const FAVICON_16_PNG: &[u8] = include_bytes!("../web/icons/favicon-16x16.png");
const FAVICON_32_PNG: &[u8] = include_bytes!("../web/icons/favicon-32x32.png");
const APPLE_TOUCH_ICON_PNG: &[u8] = include_bytes!("../web/icons/apple-touch-icon.png");
const ANDROID_CHROME_192_PNG: &[u8] = include_bytes!("../web/icons/android-chrome-192x192.png");
const ANDROID_CHROME_512_PNG: &[u8] = include_bytes!("../web/icons/android-chrome-512x512.png");
const MSTILE_150_PNG: &[u8] = include_bytes!("../web/icons/mstile-150x150.png");
const DEFAULT_API_WORKERS: usize = 4;

#[derive(Clone)]
/// Shared application state threaded through every API handler.
///
/// Wraps the core proxy state, certificate authority, persistent storage,
/// plugin system, intruder engine, WebSocket hub, and dynamic UI module
/// registry.  Each field is cheaply cloneable (typically behind an [`Arc`] or
/// interior-mutable wrapper) so the struct can be cloned into every `ntex`
/// worker thread.
///
/// # Examples
///
/// ```
/// use roxy_api::web_modules::UiModuleRegistry;
/// use std::sync::Arc;
///
/// // Fields require live runtime instances; verify the type exists.
/// let _: fn() -> UiModuleRegistry = UiModuleRegistry::new;
/// ```
pub struct ApiState {
    /// Core proxy state (intercept toggles, scope, site map, pending requests).
    pub app_state: Arc<AppState>,
    /// TLS certificate authority used for MITM certificate generation.
    pub cert_manager: Arc<CertManager>,
    /// Full-text search and persistence layer for HTTP history.
    pub storage: StorageManager,
    /// Plugin lifecycle manager (register / invoke / unregister).
    pub plugins: PluginManager,
    /// Background intruder (fuzzer) job scheduler.
    pub intruder: IntruderManager,
    /// Broadcast hub for WebSocket event delivery.
    pub ws_hub: WsHub,
    /// Dynamic registry of plugin-contributed UI panels.
    pub ui_modules: Arc<web_modules::UiModuleRegistry>,
}

impl ApiState {
    /// Creates a new [`ApiState`] from its constituent parts.
    ///
    /// All arguments are stored as-is — no cloning or additional allocation is
    /// performed beyond the struct construction itself.
    ///
    /// # Examples
    ///
    /// ```
    /// use roxy_api::ApiState;
    /// // `ApiState::new` is a simple constructor; verifying it compiles is
    /// // sufficient for a doc-test since the real dependencies require a
    /// // running async runtime and file system.
    /// assert_eq!(std::mem::size_of::<ApiState>() > 0, true);
    /// ```
    pub fn new(
        app_state: Arc<AppState>,
        cert_manager: Arc<CertManager>,
        storage: StorageManager,
        plugins: PluginManager,
        intruder: IntruderManager,
        ws_hub: WsHub,
        ui_modules: Arc<web_modules::UiModuleRegistry>,
    ) -> Self {
        Self {
            app_state,
            cert_manager,
            storage,
            plugins,
            intruder,
            ws_hub,
            ui_modules,
        }
    }
}

/// JSON envelope returned by every error response.
#[derive(Serialize)]
struct ApiErrorBody {
    error: String,
}

/// Response payload for `GET /api/v1/health`.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    unix_ms: u128,
}

/// Response for endpoints that read or mutate a boolean toggle.
#[derive(Serialize)]
struct ToggleResponse {
    enabled: bool,
}

/// Request body for endpoints that set a boolean toggle.
#[derive(Deserialize)]
struct ToggleRequest {
    enabled: bool,
}

/// Body for `POST /proxy/intercepts/{id}/continue`.
///
/// `decision` is one of `"forward"`, `"drop"`, or `"mutate"`.
#[derive(Deserialize)]
struct ContinueRequest {
    decision: String,
    mutation: Option<MutationPayload>,
}

/// Body for `POST /proxy/response-intercepts/{id}/continue`.
#[derive(Deserialize)]
struct ContinueResponseRequest {
    decision: String,
    mutation: Option<ResponseMutationPayload>,
}

/// Optional mutation data attached to a `"mutate"` request decision.
///
/// `raw_base64` carries the full raw HTTP request blob as Base64.
#[derive(Deserialize)]
struct MutationPayload {
    raw_base64: Option<String>,
}

/// Optional mutation data attached to a `"mutate"` response decision.
///
/// Each field is independently replaceable; `None` fields are left unchanged.
#[derive(Deserialize)]
struct ResponseMutationPayload {
    status: Option<u16>,
    headers: Option<Vec<HeaderValuePair>>,
    body_base64: Option<String>,
}

/// URL path parameter for intercept continuation endpoints.
#[derive(Deserialize)]
struct ContinuePath {
    id: String,
}

/// Single host and its observed request paths for the site-map endpoint.
#[derive(Serialize)]
struct SiteMapRow {
    host: String,
    paths: Vec<String>,
}

/// Query string parameters for `GET /history/search`.
#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    limit: Option<usize>,
}

/// Query string parameters for `GET /history/recent`.
#[derive(Deserialize)]
struct RecentHistoryQuery {
    limit: Option<usize>,
}

/// Body for `PUT /target/scope` — replaces the entire scope list.
#[derive(Deserialize)]
struct ScopeSetRequest {
    hosts: Vec<String>,
}

/// Body for `POST /target/scope` — appends a single host.
#[derive(Deserialize)]
struct ScopeAddRequest {
    host: String,
}

/// Response for scope-related endpoints, echoing the current scope list.
#[derive(Serialize)]
struct ScopeResponse {
    hosts: Vec<String>,
}

/// Body for `POST /plugins` — registers a new plugin.
#[derive(Deserialize)]
struct RegisterPluginRequest {
    name: String,
    path: PathBuf,
    hooks: Vec<String>,
}

/// Body for `POST /ui/modules` — registers a dynamically loaded UI panel.
#[derive(Deserialize)]
struct RegisterUiModuleRequest {
    id: String,
    title: String,
    nav_hidden: Option<bool>,
    accepts_request: Option<bool>,
    plugin_name: Option<String>,
    panel_html: String,
    settings_html: String,
    script_js: String,
}

/// Body for `POST /plugins/{id}/invoke`.
#[derive(Deserialize)]
struct InvokePluginRequest {
    hook: String,
    payload: Value,
}

/// Query string for `GET /plugins/{id}/alterations`.
#[derive(Deserialize)]
struct PluginAlterationsQuery {
    limit: Option<usize>,
}

/// Body for `POST /repeater/send` — replays an HTTP request from a raw blob.
#[derive(Deserialize)]
struct RepeaterRequest {
    /// Full raw HTTP request (request-line + headers + body) encoded as Base64.
    request_blob_base64: String,
    /// Scheme to use when the blob does not specify one (default: `"http"`).
    default_scheme: Option<String>,
}

/// Response from `POST /repeater/send` containing the upstream reply.
#[derive(Serialize)]
struct RepeaterResponse {
    status: u16,
    headers: Vec<HeaderValuePair>,
    body_base64: String,
}

/// Body for `POST /decoder/transform`.
///
/// `mode` is one of the built-in transforms (`"base64_encode"`,
/// `"base64_decode"`) or a `"plugin:<name>[:<op>]"` reference.
#[derive(Deserialize)]
struct DecodeRequest {
    mode: String,
    payload: String,
}

/// Result of a decoder/transform operation.
#[derive(Serialize)]
struct DecodeResponse {
    result: String,
}

/// Response for `GET /ws/stats`, reporting connected WebSocket clients.
#[derive(Serialize)]
struct WsStatsResponse {
    clients: usize,
    ws_port: Option<u16>,
}

/// Pagination query for `GET /intruder/jobs/{id}/results`.
#[derive(Deserialize)]
struct IntruderResultsQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

/// Body for `POST /intruder/payload-source/fetch`.
#[derive(Deserialize)]
struct IntruderPayloadSourceFetchRequest {
    url: String,
}

/// Response containing the downloaded payload list text.
#[derive(Serialize)]
struct IntruderPayloadSourceFetchResponse {
    text: String,
}

/// URL path parameter for intruder job endpoints.
#[derive(Deserialize)]
struct IntruderPath {
    id: String,
}

/// URL path parameter for `DELETE /target/scope/{host}`.
#[derive(Deserialize)]
struct ScopePath {
    host: String,
}

/// Summary returned after processing plugin output operations.
#[derive(Serialize)]
struct PluginOpsApplied {
    /// Number of `state_ops` entries that were successfully applied.
    state_ops_applied: usize,
    /// Number of UI modules registered by the plugin output.
    ui_modules_registered: usize,
}

/// Starts the HTTP API server bound to `bind` and blocks until the server
/// terminates.
///
/// This is a convenience wrapper around [`run_api_with_shutdown`] that creates
/// a no-op shutdown channel internally.  Use it for simple one-shot runs where
/// graceful shutdown signalling is not needed.
///
/// # Errors
///
/// Returns [`std::io::Error`] if binding to the requested address fails (e.g.
/// permission denied, address in use with no fallback ports remaining).
pub async fn run_api(bind: SocketAddr, state: ApiState) -> std::io::Result<()> {
    let (_tx, rx) = watch::channel(false);
    run_api_with_shutdown(bind, state, rx).await
}

/// Starts the HTTP API server with graceful shutdown support.
///
/// The server runs until `shutdown` receives `true` (or the sender is
/// dropped).  Delegates to [`run_api_with_shutdown_and_ready`] with
/// `ready = None`.
///
/// # Errors
///
/// Returns [`std::io::Error`] on bind failure.
pub async fn run_api_with_shutdown(
    bind: SocketAddr,
    state: ApiState,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    run_api_with_shutdown_and_ready(bind, state, shutdown, None).await
}

/// Starts the HTTP API server on a TCP socket with shutdown and readiness
/// notification.
///
/// If the requested port is already in use the function automatically
/// increments the port number and retries until a free port is found (up to
/// `u16::MAX`).  Once the server is listening, the actual [`SocketAddr`] is
/// sent through `ready` (when [`Some`]).
///
/// The server shuts down gracefully when `shutdown` yields `true`.
///
/// # Errors
///
/// * [`std::io::ErrorKind::AddrNotAvailable`] — returned if all ports from
///   `bind.port()` through `u16::MAX` are exhausted.
/// * Any other [`std::io::Error`] propagated from `ntex` bind/run.
pub async fn run_api_with_shutdown_and_ready(
    bind: SocketAddr,
    state: ApiState,
    shutdown: watch::Receiver<bool>,
    ready: Option<oneshot::Sender<SocketAddr>>,
) -> std::io::Result<()> {
    run_api_with_shutdown_and_ready_with_workers(
        bind,
        state,
        shutdown,
        ready,
        Some(DEFAULT_API_WORKERS),
    )
    .await
}

/// Starts the HTTP API server on a TCP socket with shutdown/readiness support
/// and an optional explicit worker count.
///
/// Passing `workers = None` keeps ntex defaults (equivalent to not calling
/// `HttpServer::workers`).
pub async fn run_api_with_shutdown_and_ready_with_workers(
    bind: SocketAddr,
    state: ApiState,
    mut shutdown: watch::Receiver<bool>,
    ready: Option<oneshot::Sender<SocketAddr>>,
    workers: Option<usize>,
) -> std::io::Result<()> {
    let mut bind_addr = bind;
    let mut ready = ready;
    loop {
        let mut server = web::HttpServer::new({
            let state = state.clone();
            move || {
                web::App::new()
                    .state(state.clone())
                    .route("/", web::get().to(index))
                    .route("/app.js", web::get().to(app_js))
                    .route("/styles.css", web::get().to(styles_css))
                    .route("/favicon.ico", web::get().to(favicon_ico))
                    .route("/favicon.svg", web::get().to(favicon_svg))
                    .route("/favicon-16x16.png", web::get().to(favicon_16_png))
                    .route("/favicon-32x32.png", web::get().to(favicon_32_png))
                    .route("/apple-touch-icon.png", web::get().to(apple_touch_icon_png))
                    .route(
                        "/android-chrome-192x192.png",
                        web::get().to(android_chrome_192_png),
                    )
                    .route(
                        "/android-chrome-512x512.png",
                        web::get().to(android_chrome_512_png),
                    )
                    .route(
                        "/safari-pinned-tab.svg",
                        web::get().to(safari_pinned_tab_svg),
                    )
                    .route("/site.webmanifest", web::get().to(site_webmanifest))
                    .route("/browserconfig.xml", web::get().to(browserconfig_xml))
                    .route("/mstile-150x150.png", web::get().to(mstile_150_png))
                    .service(
                        web::scope("/api/v1")
                            .route("/health", web::get().to(health))
                            .route("/proxy/intercept", web::get().to(get_intercept))
                            .route("/proxy/intercept", web::put().to(set_intercept))
                            .route(
                                "/proxy/intercept-response",
                                web::get().to(get_response_intercept),
                            )
                            .route(
                                "/proxy/intercept-response",
                                web::put().to(set_response_intercept),
                            )
                            .route("/proxy/mitm", web::get().to(get_mitm))
                            .route("/proxy/mitm", web::put().to(set_mitm))
                            .route("/proxy/intercepts", web::get().to(list_pending_intercepts))
                            .route(
                                "/proxy/intercepts/{id}/continue",
                                web::post().to(continue_intercept),
                            )
                            .route(
                                "/proxy/response-intercepts",
                                web::get().to(list_pending_response_intercepts),
                            )
                            .route(
                                "/proxy/response-intercepts/{id}/continue",
                                web::post().to(continue_response_intercept),
                            )
                            .route("/proxy/settings/ca.der", web::get().to(download_ca_der))
                            .route(
                                "/proxy/settings/upstream",
                                web::get().to(get_upstream_proxy_settings),
                            )
                            .route(
                                "/proxy/settings/upstream",
                                web::put().to(set_upstream_proxy_settings),
                            )
                            .route(
                                "/proxy/settings/ca/regenerate",
                                web::post().to(regenerate_ca),
                            )
                            .route("/target/site-map", web::get().to(site_map))
                            .route("/target/scope", web::get().to(get_scope))
                            .route("/target/scope", web::put().to(set_scope))
                            .route("/target/scope", web::post().to(add_scope))
                            .route("/target/scope/{host}", web::delete().to(remove_scope))
                            .route("/history/search", web::get().to(history_search))
                            .route("/history/recent", web::get().to(history_recent))
                            .route("/ui/modules", web::get().to(list_ui_modules))
                            .route("/ui/modules", web::post().to(register_ui_module))
                            .route("/plugins", web::get().to(list_plugins))
                            .route("/plugins", web::post().to(register_plugin))
                            .route("/plugins/{id}", web::delete().to(unregister_plugin))
                            .route("/plugins/{id}/settings", web::get().to(get_plugin_settings))
                            .route("/plugins/{id}/settings", web::put().to(set_plugin_settings))
                            .route(
                                "/plugins/{id}/alterations",
                                web::get().to(list_plugin_alterations),
                            )
                            .route("/plugins/{id}/invoke", web::post().to(invoke_plugin))
                            .route(
                                "/plugins/{id}/invoke-stream",
                                web::post().to(invoke_plugin_stream),
                            )
                            .route(
                                "/plugins/{id}/template/{file}",
                                web::get().to(get_plugin_template),
                            )
                            .route("/repeater/send", web::post().to(repeater_send))
                            .route("/decoder/transform", web::post().to(decode_transform))
                            .route("/intruder/jobs", web::post().to(intruder_create_job))
                            .route("/intruder/jobs", web::get().to(intruder_list_jobs))
                            .route(
                                "/intruder/payload-source/fetch",
                                web::post().to(intruder_fetch_payload_source),
                            )
                            .route("/intruder/jobs/{id}", web::get().to(intruder_get_job))
                            .route(
                                "/intruder/jobs/{id}/results",
                                web::get().to(intruder_get_job_results),
                            )
                            .route("/intruder/jobs/{id}", web::delete().to(intruder_delete_job))
                            .route("/ws/stats", web::get().to(ws_stats)),
                    )
            }
        })
        .disable_signals();
        if let Some(worker_count) = workers {
            server = server.workers(worker_count);
        }

        match server.bind(bind_addr) {
            Ok(server) => {
                info!(requested_bind = %bind, actual_bind = %bind_addr, "api listener started");
                if let Some(tx) = ready.take() {
                    let _ = tx.send(bind_addr);
                }
                let srv = server.run();
                let stopper = srv.clone();
                ntex::rt::spawn(async move {
                    loop {
                        if shutdown.changed().await.is_err() || *shutdown.borrow() {
                            let _ = stopper.stop(true).await;
                            break;
                        }
                    }
                });
                return srv.await;
            }
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                bind_addr = increment_port(bind_addr)?;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Starts the HTTP API server on a **Unix domain socket** with shutdown and
/// readiness notification.
///
/// Any pre-existing socket file at `path` is removed before binding.  After
/// the server stops the socket file is cleaned up automatically.
///
/// # Errors
///
/// * [`std::io::Error`] if the stale socket file cannot be removed, the new
///   socket cannot be created, or the `ntex` server fails to run.
pub async fn run_api_with_shutdown_and_ready_uds(
    path: impl AsRef<Path>,
    state: ApiState,
    shutdown: watch::Receiver<bool>,
    ready: Option<oneshot::Sender<PathBuf>>,
) -> std::io::Result<()> {
    run_api_with_shutdown_and_ready_uds_with_workers(
        path,
        state,
        shutdown,
        ready,
        Some(DEFAULT_API_WORKERS),
    )
    .await
}

/// Starts the HTTP API server on a Unix domain socket with shutdown/readiness
/// support and an optional explicit worker count.
///
/// Passing `workers = None` keeps ntex defaults (equivalent to not calling
/// `HttpServer::workers`).
pub async fn run_api_with_shutdown_and_ready_uds_with_workers(
    path: impl AsRef<Path>,
    state: ApiState,
    mut shutdown: watch::Receiver<bool>,
    ready: Option<oneshot::Sender<PathBuf>>,
    workers: Option<usize>,
) -> std::io::Result<()> {
    let path = path.as_ref().to_path_buf();
    cleanup_uds_socket_path(&path)?;

    let mut server = web::HttpServer::new({
        let state = state.clone();
        move || {
            web::App::new()
                .state(state.clone())
                .route("/", web::get().to(index))
                .route("/app.js", web::get().to(app_js))
                .route("/styles.css", web::get().to(styles_css))
                .route("/favicon.ico", web::get().to(favicon_ico))
                .route("/favicon.svg", web::get().to(favicon_svg))
                .route("/favicon-16x16.png", web::get().to(favicon_16_png))
                .route("/favicon-32x32.png", web::get().to(favicon_32_png))
                .route("/apple-touch-icon.png", web::get().to(apple_touch_icon_png))
                .route(
                    "/android-chrome-192x192.png",
                    web::get().to(android_chrome_192_png),
                )
                .route(
                    "/android-chrome-512x512.png",
                    web::get().to(android_chrome_512_png),
                )
                .route(
                    "/safari-pinned-tab.svg",
                    web::get().to(safari_pinned_tab_svg),
                )
                .route("/site.webmanifest", web::get().to(site_webmanifest))
                .route("/browserconfig.xml", web::get().to(browserconfig_xml))
                .route("/mstile-150x150.png", web::get().to(mstile_150_png))
                .service(
                    web::scope("/api/v1")
                        .route("/health", web::get().to(health))
                        .route("/proxy/intercept", web::get().to(get_intercept))
                        .route("/proxy/intercept", web::put().to(set_intercept))
                        .route(
                            "/proxy/intercept-response",
                            web::get().to(get_response_intercept),
                        )
                        .route(
                            "/proxy/intercept-response",
                            web::put().to(set_response_intercept),
                        )
                        .route("/proxy/mitm", web::get().to(get_mitm))
                        .route("/proxy/mitm", web::put().to(set_mitm))
                        .route("/proxy/intercepts", web::get().to(list_pending_intercepts))
                        .route(
                            "/proxy/intercepts/{id}/continue",
                            web::post().to(continue_intercept),
                        )
                        .route(
                            "/proxy/response-intercepts",
                            web::get().to(list_pending_response_intercepts),
                        )
                        .route(
                            "/proxy/response-intercepts/{id}/continue",
                            web::post().to(continue_response_intercept),
                        )
                        .route("/proxy/settings/ca.der", web::get().to(download_ca_der))
                        .route(
                            "/proxy/settings/upstream",
                            web::get().to(get_upstream_proxy_settings),
                        )
                        .route(
                            "/proxy/settings/upstream",
                            web::put().to(set_upstream_proxy_settings),
                        )
                        .route(
                            "/proxy/settings/ca/regenerate",
                            web::post().to(regenerate_ca),
                        )
                        .route("/target/site-map", web::get().to(site_map))
                        .route("/target/scope", web::get().to(get_scope))
                        .route("/target/scope", web::put().to(set_scope))
                        .route("/target/scope", web::post().to(add_scope))
                        .route("/target/scope/{host}", web::delete().to(remove_scope))
                        .route("/history/search", web::get().to(history_search))
                        .route("/history/recent", web::get().to(history_recent))
                        .route("/ui/modules", web::get().to(list_ui_modules))
                        .route("/ui/modules", web::post().to(register_ui_module))
                        .route("/plugins", web::get().to(list_plugins))
                        .route("/plugins", web::post().to(register_plugin))
                        .route("/plugins/{id}", web::delete().to(unregister_plugin))
                        .route("/plugins/{id}/settings", web::get().to(get_plugin_settings))
                        .route("/plugins/{id}/settings", web::put().to(set_plugin_settings))
                        .route(
                            "/plugins/{id}/alterations",
                            web::get().to(list_plugin_alterations),
                        )
                        .route("/plugins/{id}/invoke", web::post().to(invoke_plugin))
                        .route(
                            "/plugins/{id}/invoke-stream",
                            web::post().to(invoke_plugin_stream),
                        )
                        .route(
                            "/plugins/{id}/template/{file}",
                            web::get().to(get_plugin_template),
                        )
                        .route("/repeater/send", web::post().to(repeater_send))
                        .route("/decoder/transform", web::post().to(decode_transform))
                        .route("/intruder/jobs", web::post().to(intruder_create_job))
                        .route("/intruder/jobs", web::get().to(intruder_list_jobs))
                        .route(
                            "/intruder/payload-source/fetch",
                            web::post().to(intruder_fetch_payload_source),
                        )
                        .route("/intruder/jobs/{id}", web::get().to(intruder_get_job))
                        .route(
                            "/intruder/jobs/{id}/results",
                            web::get().to(intruder_get_job_results),
                        )
                        .route("/intruder/jobs/{id}", web::delete().to(intruder_delete_job))
                        .route("/ws/stats", web::get().to(ws_stats)),
                )
        }
    })
    .disable_signals();
    if let Some(worker_count) = workers {
        server = server.workers(worker_count);
    }

    let server = server.bind_uds(&path)?;
    if let Some(tx) = ready {
        let _ = tx.send(path.clone());
    }
    info!(path = %path.display(), "api uds listener started");

    let srv = server.run();
    let stopper = srv.clone();
    ntex::rt::spawn(async move {
        loop {
            if shutdown.changed().await.is_err() || *shutdown.borrow() {
                let _ = stopper.stop(true).await;
                break;
            }
        }
    });
    let result = srv.await;
    let _ = std::fs::remove_file(&path);
    result
}

/// Renders the main `index.html` template, injecting the current set of
/// registered [`UiModule`](web_modules::UiModule) entries so the SPA can
/// build navigation and panel containers at load time.
fn render_index_html(state: &ApiState) -> Result<String> {
    let mut context = TeraContext::new();
    let modules = state.ui_modules.modules();
    context.insert("modules", &modules);
    Tera::one_off(INDEX_TEMPLATE, &context, false).context("failed rendering index template")
}

/// Renders the `app.js` template, splicing in the concatenated JavaScript
/// bundles from all registered UI modules.
fn render_app_js(state: &ApiState) -> Result<String> {
    let mut context = TeraContext::new();
    context.insert("module_scripts", &state.ui_modules.module_scripts_bundle());
    Tera::one_off(APP_TEMPLATE, &context, false).context("failed rendering app template")
}

/// Emits a `debug!` trace for every web-UI asset request.
fn log_web_ui_request(req: &HttpRequest, asset: &str) {
    debug!(
        asset,
        method = %req.method(),
        path = %req.path(),
        peer = ?req.peer_addr(),
        "ntex web ui request received"
    );
}

async fn index(req: HttpRequest, state: web::types::State<ApiState>) -> HttpResponse {
    log_web_ui_request(&req, "index");
    match render_index_html(&state) {
        Ok(html) => HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .set_header("cache-control", "no-store")
            .body(html),
        Err(err) => {
            error!(%err, "web ui html rendering failed");
            json_error(
                HttpResponse::InternalServerError(),
                "failed rendering web ui",
            )
        }
    }
}

async fn app_js(req: HttpRequest, state: web::types::State<ApiState>) -> HttpResponse {
    log_web_ui_request(&req, "app.js");
    match render_app_js(&state) {
        Ok(js) => HttpResponse::Ok()
            .content_type("application/javascript; charset=utf-8")
            .set_header("cache-control", "no-store")
            .body(js),
        Err(err) => {
            error!(%err, "web ui script rendering failed");
            json_error(
                HttpResponse::InternalServerError(),
                "failed rendering web ui script",
            )
        }
    }
}

async fn styles_css(req: HttpRequest) -> HttpResponse {
    log_web_ui_request(&req, "styles.css");
    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .set_header("cache-control", "no-store")
        .body(STYLES_CSS)
}

/// Builds a cacheable text response with a 24-hour `Cache-Control` header.
fn static_text_response(content_type: &'static str, body: &'static str) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(content_type)
        .set_header("cache-control", "public, max-age=86400")
        .body(body)
}

/// Builds a cacheable binary response with a 24-hour `Cache-Control` header.
fn static_bytes_response(content_type: &'static str, body: &'static [u8]) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(content_type)
        .set_header("cache-control", "public, max-age=86400")
        .body(body)
}

async fn favicon_ico() -> HttpResponse {
    static_bytes_response("image/x-icon", FAVICON_ICO)
}

async fn favicon_svg() -> HttpResponse {
    static_text_response("image/svg+xml; charset=utf-8", FAVICON_SVG)
}

async fn favicon_16_png() -> HttpResponse {
    static_bytes_response("image/png", FAVICON_16_PNG)
}

async fn favicon_32_png() -> HttpResponse {
    static_bytes_response("image/png", FAVICON_32_PNG)
}

async fn apple_touch_icon_png() -> HttpResponse {
    static_bytes_response("image/png", APPLE_TOUCH_ICON_PNG)
}

async fn android_chrome_192_png() -> HttpResponse {
    static_bytes_response("image/png", ANDROID_CHROME_192_PNG)
}

async fn android_chrome_512_png() -> HttpResponse {
    static_bytes_response("image/png", ANDROID_CHROME_512_PNG)
}

async fn safari_pinned_tab_svg() -> HttpResponse {
    static_text_response("image/svg+xml; charset=utf-8", SAFARI_PINNED_TAB_SVG)
}

async fn site_webmanifest() -> HttpResponse {
    static_text_response("application/manifest+json; charset=utf-8", SITE_WEBMANIFEST)
}

async fn browserconfig_xml() -> HttpResponse {
    static_text_response("application/xml; charset=utf-8", BROWSERCONFIG_XML)
}

async fn mstile_150_png() -> HttpResponse {
    static_bytes_response("image/png", MSTILE_150_PNG)
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(&HealthResponse {
        status: "ok",
        unix_ms: now_unix_ms(),
    })
}

async fn get_intercept(state: web::types::State<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(&ToggleResponse {
        enabled: state.app_state.intercept_enabled(),
    })
}

async fn set_intercept(
    state: web::types::State<ApiState>,
    req: web::types::Json<ToggleRequest>,
) -> HttpResponse {
    state.app_state.set_intercept_enabled(req.enabled);
    HttpResponse::Ok().json(&ToggleResponse {
        enabled: state.app_state.intercept_enabled(),
    })
}

async fn get_response_intercept(state: web::types::State<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(&ToggleResponse {
        enabled: state.app_state.intercept_response_enabled(),
    })
}

async fn set_response_intercept(
    state: web::types::State<ApiState>,
    req: web::types::Json<ToggleRequest>,
) -> HttpResponse {
    state.app_state.set_intercept_response_enabled(req.enabled);
    HttpResponse::Ok().json(&ToggleResponse {
        enabled: state.app_state.intercept_response_enabled(),
    })
}

async fn get_mitm(state: web::types::State<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(&ToggleResponse {
        enabled: state.app_state.mitm_enabled(),
    })
}

async fn set_mitm(
    state: web::types::State<ApiState>,
    req: web::types::Json<ToggleRequest>,
) -> HttpResponse {
    state.app_state.set_mitm_enabled(req.enabled);
    HttpResponse::Ok().json(&ToggleResponse {
        enabled: state.app_state.mitm_enabled(),
    })
}

async fn list_pending_intercepts(state: web::types::State<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(&state.app_state.pending_requests())
}

async fn continue_intercept(
    state: web::types::State<ApiState>,
    path: web::types::Path<ContinuePath>,
    req: web::types::Json<ContinueRequest>,
) -> HttpResponse {
    let id = match Uuid::parse_str(&path.id) {
        Ok(id) => id,
        Err(_) => return json_error(HttpResponse::BadRequest(), "invalid request id"),
    };

    let decision = match parse_decision(&req) {
        Ok(decision) => decision,
        Err(err) => return json_error(HttpResponse::BadRequest(), &err.to_string()),
    };

    match state.app_state.continue_intercept(id, decision) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) => json_error(HttpResponse::NotFound(), &err.to_string()),
    }
}

async fn list_pending_response_intercepts(state: web::types::State<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(&state.app_state.pending_responses())
}

async fn continue_response_intercept(
    state: web::types::State<ApiState>,
    path: web::types::Path<ContinuePath>,
    req: web::types::Json<ContinueResponseRequest>,
) -> HttpResponse {
    let id = match Uuid::parse_str(&path.id) {
        Ok(id) => id,
        Err(_) => return json_error(HttpResponse::BadRequest(), "invalid request id"),
    };

    let decision = match parse_response_decision(&req) {
        Ok(decision) => decision,
        Err(err) => return json_error(HttpResponse::BadRequest(), &err.to_string()),
    };

    match state.app_state.continue_response_intercept(id, decision) {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) => json_error(HttpResponse::NotFound(), &err.to_string()),
    }
}

async fn download_ca_der(state: web::types::State<ApiState>) -> HttpResponse {
    let der = state.cert_manager.export_ca_der().await;
    HttpResponse::Ok()
        .content_type("application/x-x509-ca-cert")
        .set_header("content-disposition", "attachment; filename=roxy-ca.der")
        .body(der)
}

async fn get_upstream_proxy_settings(state: web::types::State<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(&state.app_state.upstream_proxy_settings())
}

async fn set_upstream_proxy_settings(
    state: web::types::State<ApiState>,
    req: web::types::Json<UpstreamProxySettings>,
) -> HttpResponse {
    state
        .app_state
        .set_upstream_proxy_settings(req.into_inner());
    let saved = state.app_state.upstream_proxy_settings();
    info!(
        proxies = saved.proxies.len(),
        proxy_dns = saved.proxy_dns,
        chain_mode = ?saved.chain_mode,
        min_chain_length = saved.min_chain_length,
        max_chain_length = saved.max_chain_length,
        "updated upstream proxy settings"
    );
    HttpResponse::Ok().json(&saved)
}

async fn regenerate_ca(state: web::types::State<ApiState>) -> HttpResponse {
    match state.cert_manager.regenerate_ca().await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) => json_error(HttpResponse::InternalServerError(), &err.to_string()),
    }
}

async fn site_map(state: web::types::State<ApiState>) -> HttpResponse {
    let rows: Vec<SiteMapRow> = state
        .app_state
        .site_map()
        .into_iter()
        .map(|(host, paths)| SiteMapRow { host, paths })
        .collect();
    HttpResponse::Ok().json(&rows)
}

async fn get_scope(state: web::types::State<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(&ScopeResponse {
        hosts: state.app_state.scope_hosts(),
    })
}

async fn set_scope(
    state: web::types::State<ApiState>,
    req: web::types::Json<ScopeSetRequest>,
) -> HttpResponse {
    state.app_state.set_scope_hosts(req.hosts.clone());
    HttpResponse::Ok().json(&ScopeResponse {
        hosts: state.app_state.scope_hosts(),
    })
}

async fn add_scope(
    state: web::types::State<ApiState>,
    req: web::types::Json<ScopeAddRequest>,
) -> HttpResponse {
    state.app_state.add_scope_host(req.host.clone());
    HttpResponse::Ok().json(&ScopeResponse {
        hosts: state.app_state.scope_hosts(),
    })
}

async fn remove_scope(
    state: web::types::State<ApiState>,
    path: web::types::Path<ScopePath>,
) -> HttpResponse {
    let host = path.host.replace("%2A", "*");
    if state.app_state.remove_scope_host(&host) {
        HttpResponse::Ok().json(&ScopeResponse {
            hosts: state.app_state.scope_hosts(),
        })
    } else {
        HttpResponse::NotFound().finish()
    }
}

async fn history_search(
    state: web::types::State<ApiState>,
    query: web::types::Query<SearchQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(50).min(200);
    match state.storage.search(&query.q, limit) {
        Ok(rows) => HttpResponse::Ok().json(&rows),
        Err(err) => json_error(HttpResponse::BadRequest(), &err.to_string()),
    }
}

async fn history_recent(
    state: web::types::State<ApiState>,
    query: web::types::Query<RecentHistoryQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(200).min(1000);
    match state.storage.list_recent(limit) {
        Ok(rows) => HttpResponse::Ok().json(&rows),
        Err(err) => json_error(HttpResponse::BadRequest(), &err.to_string()),
    }
}

async fn list_ui_modules(state: web::types::State<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(&state.ui_modules.modules())
}

async fn register_ui_module(
    state: web::types::State<ApiState>,
    req: web::types::Json<RegisterUiModuleRequest>,
) -> HttpResponse {
    if req.id.trim().is_empty() || req.title.trim().is_empty() {
        return json_error(
            HttpResponse::BadRequest(),
            "module id and title must not be empty",
        );
    }

    state.ui_modules.register(web_modules::UiModule {
        id: req.id.trim().to_string(),
        title: req.title.trim().to_string(),
        nav_hidden: req.nav_hidden.unwrap_or(false),
        accepts_request: req.accepts_request.unwrap_or(false),
        plugin_name: req.plugin_name.clone(),
        panel_html: req.panel_html.clone(),
        settings_html: req.settings_html.clone(),
        script_js: req.script_js.clone(),
    });
    HttpResponse::Created().finish()
}

async fn register_plugin(
    state: web::types::State<ApiState>,
    req: web::types::Json<RegisterPluginRequest>,
) -> HttpResponse {
    let registration = PluginRegistration {
        name: req.name.clone(),
        script_path: req.path.clone(),
        hooks: req.hooks.clone(),
    };

    match state.plugins.register(registration).await {
        Ok(_) => {
            let mut ops_applied = PluginOpsApplied {
                state_ops_applied: 0,
                ui_modules_registered: 0,
            };

            if req.hooks.iter().any(|hook| hook == "on_load") {
                match state
                    .plugins
                    .invoke(
                        &req.name,
                        PluginInvocation {
                            hook: "on_load".to_string(),
                            payload: serde_json::json!({
                                "api_base": "/api/v1",
                                "ui_module_schema_version": 1
                            }),
                        },
                    )
                    .await
                {
                    Ok(result) => {
                        ops_applied = apply_plugin_output_ops(
                            &state.app_state,
                            &state.ui_modules,
                            &result.output,
                            Some(&req.name),
                        );
                    }
                    Err(err) => {
                        let _ = state.plugins.unregister(&req.name).await;
                        return json_error(
                            HttpResponse::BadRequest(),
                            &format!("plugin on_load hook failed: {err}"),
                        );
                    }
                }
            }

            HttpResponse::Created().json(&ops_applied)
        }
        Err(err) => json_error(HttpResponse::BadRequest(), &err.to_string()),
    }
}

async fn list_plugins(state: web::types::State<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(&state.plugins.list().await)
}

/// URL path parameter for single-plugin endpoints (`/plugins/{id}/…`).
#[derive(Deserialize)]
struct PluginPath {
    id: String,
}

async fn unregister_plugin(
    state: web::types::State<ApiState>,
    path: web::types::Path<PluginPath>,
) -> HttpResponse {
    if state.plugins.unregister(&path.id).await {
        HttpResponse::NoContent().finish()
    } else {
        HttpResponse::NotFound().finish()
    }
}

async fn get_plugin_settings(
    state: web::types::State<ApiState>,
    path: web::types::Path<PluginPath>,
) -> HttpResponse {
    match state.plugins.get_settings(&path.id).await {
        Ok(settings) => HttpResponse::Ok().json(&settings),
        Err(err) => json_error(HttpResponse::NotFound(), &err.to_string()),
    }
}

async fn set_plugin_settings(
    state: web::types::State<ApiState>,
    path: web::types::Path<PluginPath>,
    req: web::types::Json<Value>,
) -> HttpResponse {
    let value = match req.into_inner() {
        Value::Object(map) => Value::Object(map),
        _ => {
            return json_error(
                HttpResponse::BadRequest(),
                "plugin settings payload must be a JSON object",
            );
        }
    };
    match state.plugins.set_settings(&path.id, value).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) => json_error(HttpResponse::NotFound(), &err.to_string()),
    }
}

async fn list_plugin_alterations(
    state: web::types::State<ApiState>,
    path: web::types::Path<PluginPath>,
    query: web::types::Query<PluginAlterationsQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(200).min(1_000);
    match state.plugins.list_alterations(&path.id, limit).await {
        Ok(rows) => HttpResponse::Ok().json(&rows),
        Err(err) => json_error(HttpResponse::NotFound(), &err.to_string()),
    }
}

async fn invoke_plugin(
    state: web::types::State<ApiState>,
    path: web::types::Path<PluginPath>,
    req: web::types::Json<InvokePluginRequest>,
) -> HttpResponse {
    match state
        .plugins
        .invoke(
            &path.id,
            PluginInvocation {
                hook: req.hook.clone(),
                payload: req.payload.clone(),
            },
        )
        .await
    {
        Ok(result) => {
            let applied = apply_plugin_output_ops(
                &state.app_state,
                &state.ui_modules,
                &result.output,
                Some(&path.id),
            );
            HttpResponse::Ok().json(&serde_json::json!({
                "plugin_result": result,
                "state_ops_applied": applied.state_ops_applied,
                "ui_modules_registered": applied.ui_modules_registered
            }))
        }
        Err(err) => json_error(HttpResponse::BadRequest(), &err.to_string()),
    }
}

async fn invoke_plugin_stream(
    state: web::types::State<ApiState>,
    path: web::types::Path<PluginPath>,
    req: web::types::Json<InvokePluginRequest>,
) -> HttpResponse {
    let scan_id = Uuid::new_v4().to_string();
    let plugin_name = path.id.clone();
    let invocation = PluginInvocation {
        hook: req.hook.clone(),
        payload: req.payload.clone(),
    };

    let (mut line_rx, result_rx) = match state
        .plugins
        .invoke_streaming(&plugin_name, invocation)
        .await
    {
        Ok(pair) => pair,
        Err(err) => return json_error(HttpResponse::BadRequest(), &err.to_string()),
    };

    let ws_hub = state.ws_hub.clone();
    let app_state = state.app_state.clone();
    let ui_modules = state.ui_modules.clone();
    let scan_id_bg = scan_id.clone();
    let plugin_name_bg = plugin_name.clone();

    tokio::spawn(async move {
        // Forward each stderr line as a WS event.
        while let Some(line) = line_rx.recv().await {
            ws_hub.publish(&serde_json::json!({
                "event": "plugin_stream_output",
                "payload": {
                    "plugin": plugin_name_bg,
                    "scan_id": scan_id_bg,
                    "line": line,
                }
            }));
        }

        // Process the final result.
        let outcome = match result_rx.await {
            Ok(Ok(result)) => {
                let applied = apply_plugin_output_ops(
                    &app_state,
                    &ui_modules,
                    &result.output,
                    Some(&plugin_name_bg),
                );
                serde_json::json!({
                    "plugin_result": result,
                    "state_ops_applied": applied.state_ops_applied,
                    "ui_modules_registered": applied.ui_modules_registered,
                })
            }
            Ok(Err(err)) => serde_json::json!({ "error": err.to_string() }),
            Err(_) => serde_json::json!({ "error": "plugin task dropped" }),
        };

        ws_hub.publish(&serde_json::json!({
            "event": "plugin_stream_complete",
            "payload": {
                "plugin": plugin_name_bg,
                "scan_id": scan_id_bg,
                "result": outcome,
            }
        }));
    });

    HttpResponse::Accepted().json(&serde_json::json!({
        "scan_id": scan_id,
        "plugin": plugin_name,
        "status": "started",
    }))
}

/// URL path parameters for `GET /plugins/{id}/template/{file}`.
#[derive(Deserialize)]
struct PluginTemplatePath {
    id: String,
    file: String,
}

async fn get_plugin_template(
    state: web::types::State<ApiState>,
    path: web::types::Path<PluginTemplatePath>,
) -> HttpResponse {
    let allowed_files = ["panel.html", "script.js", "settings.html"];
    if !allowed_files.contains(&path.file.as_str()) {
        return json_error(
            HttpResponse::BadRequest(),
            "only panel.html, script.js, and settings.html are allowed",
        );
    }

    let registration = match state.plugins.get_registration(&path.id).await {
        Some(reg) => reg,
        None => return HttpResponse::NotFound().finish(),
    };

    let template_dir = registration
        .script_path
        .parent()
        .map(|p| p.join("templates"));

    let template_path = match template_dir {
        Some(dir) => dir.join(&path.file),
        None => return HttpResponse::NotFound().finish(),
    };

    match tokio::fs::read_to_string(&template_path).await {
        Ok(content) => {
            let content_type = if path.file.ends_with(".html") {
                "text/html; charset=utf-8"
            } else {
                "application/javascript; charset=utf-8"
            };
            HttpResponse::Ok()
                .header("content-type", content_type)
                .body(content)
        }
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

async fn repeater_send(
    _state: web::types::State<ApiState>,
    req: web::types::Json<RepeaterRequest>,
) -> HttpResponse {
    match execute_repeater(&req).await {
        Ok(response) => HttpResponse::Ok().json(&response),
        Err(err) => json_error(HttpResponse::BadGateway(), &err.to_string()),
    }
}

/// Executes a repeater request: decodes the Base64 blob, sends it upstream,
/// decompresses the response body when a known `Content-Encoding` is present,
/// and returns the result with the body re-encoded as Base64.
async fn execute_repeater(req: &RepeaterRequest) -> Result<RepeaterResponse> {
    let raw_blob = STANDARD
        .decode(&req.request_blob_base64)
        .context("invalid request_blob_base64")?;
    let parsed = parse_request_blob(
        &raw_blob,
        req.default_scheme.as_deref().unwrap_or("http"),
        None,
    )
    .context("invalid request blob")?;

    let response = send_parsed_request(parsed, Duration::from_secs(30), true)
        .await
        .context("repeater request failed")?;
    let status = response.status.as_u16();
    let headers_map = response.headers;
    let content_encoding = content_encoding_from_headers(&headers_map);
    let encoded_body_bytes = response.body;
    let mut response_decoded = false;
    let body_bytes =
        match decode_http_body_bytes(encoded_body_bytes.as_ref(), content_encoding.as_deref()) {
            Ok(decoded) => {
                response_decoded = true;
                decoded
            }
            Err(err) => {
                warn!(
                    %err,
                    encoding = ?content_encoding,
                    "failed decoding repeater response body; preserving original bytes"
                );
                encoded_body_bytes.clone().to_vec()
            }
        };

    let headers = headers_map
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
        .collect();
    Ok(RepeaterResponse {
        status,
        headers,
        body_base64: STANDARD.encode(body_bytes),
    })
}

/// Extracts the `Content-Encoding` header value, returning `None` when the
/// header is absent or empty.
fn content_encoding_from_headers(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Decodes an HTTP response body according to the supplied
/// `content_encoding` value.
///
/// Supports `gzip`, `deflate` (both zlib-wrapped and raw), `br` (Brotli),
/// and `zstd`.  Multiple comma-separated encodings are unwound in reverse
/// order (outermost encoding last in the list).
///
/// When `content_encoding` is `None` the function falls back to
/// [`maybe_decode_http_body_by_magic`] which inspects the first few magic
/// bytes.
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
                    "unsupported content-encoding '{unknown}' while decoding repeater response"
                ));
            }
        };
    }

    Ok(decoded)
}

/// Attempts to detect the compression format of `body` by inspecting the
/// leading magic bytes.
///
/// Returns `Ok(Some(decoded))` when gzip (`1f 8b`) or zstd (`28 b5 2f fd`)
/// magic is detected and decompression succeeds.  Returns `Ok(None)` when no
/// known magic is found.
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

async fn decode_transform(
    state: web::types::State<ApiState>,
    req: web::types::Json<DecodeRequest>,
) -> HttpResponse {
    match req.mode.as_str() {
        "base64_encode" => HttpResponse::Ok().json(&DecodeResponse {
            result: STANDARD.encode(req.payload.as_bytes()),
        }),
        "base64_decode" => match STANDARD.decode(&req.payload) {
            Ok(decoded) => HttpResponse::Ok().json(&DecodeResponse {
                result: String::from_utf8_lossy(&decoded).to_string(),
            }),
            Err(err) => json_error(HttpResponse::BadRequest(), &err.to_string()),
        },
        _ if req.mode.starts_with("plugin:") => {
            let Some((plugin, plugin_mode)) = parse_plugin_decoder_mode(&req.mode) else {
                return json_error(HttpResponse::BadRequest(), "invalid plugin decoder mode");
            };
            match state
                .plugins
                .invoke(
                    &plugin,
                    PluginInvocation {
                        hook: "decoder".to_string(),
                        payload: serde_json::json!({
                            "mode": req.mode,
                            "payload": req.payload,
                            "plugin_mode": plugin_mode
                        }),
                    },
                )
                .await
            {
                Ok(response) => {
                    let applied = apply_plugin_output_ops(
                        &state.app_state,
                        &state.ui_modules,
                        &response.output,
                        Some(&plugin),
                    );
                    let result = response
                        .output
                        .get("result")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| response.output.to_string());
                    HttpResponse::Ok().json(&serde_json::json!({
                        "result": result,
                        "state_ops_applied": applied.state_ops_applied,
                        "ui_modules_registered": applied.ui_modules_registered
                    }))
                }
                Err(err) => json_error(HttpResponse::BadRequest(), &err.to_string()),
            }
        }
        _ => json_error(HttpResponse::BadRequest(), "unsupported decoder mode"),
    }
}

/// Parses a `"plugin:<name>[:<mode>]"` decoder mode string into a
/// `(plugin_name, optional_sub_mode)` tuple.
///
/// Returns `None` when the string does not start with `"plugin:"` or the
/// plugin name portion is empty.
fn parse_plugin_decoder_mode(mode: &str) -> Option<(String, Option<String>)> {
    if !mode.starts_with("plugin:") {
        return None;
    }
    let raw = mode.trim_start_matches("plugin:").trim();
    if raw.is_empty() {
        return None;
    }
    if let Some((plugin, plugin_mode)) = raw.split_once(':') {
        let plugin = plugin.trim();
        if plugin.is_empty() {
            return None;
        }
        let plugin_mode = plugin_mode.trim();
        return Some((
            plugin.to_string(),
            if plugin_mode.is_empty() {
                None
            } else {
                Some(plugin_mode.to_string())
            },
        ));
    }
    Some((raw.to_string(), None))
}

async fn intruder_create_job(
    state: web::types::State<ApiState>,
    req: web::types::Json<IntruderJobSpec>,
) -> HttpResponse {
    match state.intruder.start_job(req.into_inner()).await {
        Ok(id) => HttpResponse::Created().json(&serde_json::json!({ "id": id })),
        Err(err) => json_error(HttpResponse::BadRequest(), &err.to_string()),
    }
}

async fn intruder_list_jobs(state: web::types::State<ApiState>) -> HttpResponse {
    let rows = state.intruder.list_jobs().await;
    HttpResponse::Ok().json(&rows)
}

async fn intruder_fetch_payload_source(
    _state: web::types::State<ApiState>,
    req: web::types::Json<IntruderPayloadSourceFetchRequest>,
) -> HttpResponse {
    let url = req.url.trim();
    let uri = match url.parse::<http::Uri>() {
        Ok(uri) => uri,
        Err(err) => return json_error(HttpResponse::BadRequest(), &format!("invalid url: {err}")),
    };
    let scheme = uri.scheme_str().unwrap_or_default();
    if scheme != "http" && scheme != "https" {
        return json_error(
            HttpResponse::BadRequest(),
            "payload source url must use http or https",
        );
    }
    let Some(host) = uri.host() else {
        return json_error(
            HttpResponse::BadRequest(),
            "payload source url is missing host",
        );
    };

    let parsed_request = ParsedRequestBlob {
        method: "GET".to_string(),
        uri: url.to_string(),
        host: host.to_string(),
        headers: Vec::new(),
        body: Bytes::new(),
    };

    let response = match send_parsed_request(parsed_request, Duration::from_secs(20), true).await {
        Ok(response) => response,
        Err(err) => return json_error(HttpResponse::BadGateway(), &format!("fetch failed: {err}")),
    };

    if !response.status.is_success() {
        return json_error(
            HttpResponse::BadGateway(),
            &format!("source returned HTTP {}", response.status),
        );
    }
    let bytes = response.body;

    const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
    if bytes.len() > MAX_SOURCE_BYTES {
        return json_error(
            HttpResponse::BadRequest(),
            "payload source too large (max 4 MiB)",
        );
    }

    HttpResponse::Ok().json(&IntruderPayloadSourceFetchResponse {
        text: String::from_utf8_lossy(&bytes).to_string(),
    })
}

async fn intruder_get_job(
    state: web::types::State<ApiState>,
    path: web::types::Path<IntruderPath>,
) -> HttpResponse {
    let id = match Uuid::parse_str(&path.id) {
        Ok(id) => id,
        Err(_) => return json_error(HttpResponse::BadRequest(), "invalid intruder job id"),
    };

    match state.intruder.get_job_details(id, 200).await {
        Some(details) => HttpResponse::Ok().json(&details),
        None => HttpResponse::NotFound().finish(),
    }
}

async fn intruder_get_job_results(
    state: web::types::State<ApiState>,
    path: web::types::Path<IntruderPath>,
    query: web::types::Query<IntruderResultsQuery>,
) -> HttpResponse {
    let id = match Uuid::parse_str(&path.id) {
        Ok(id) => id,
        Err(_) => return json_error(HttpResponse::BadRequest(), "invalid intruder job id"),
    };

    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).min(1000);

    match state.intruder.get_job_results(id, offset, limit).await {
        Some(results) => HttpResponse::Ok().json(&results),
        None => HttpResponse::NotFound().finish(),
    }
}

async fn intruder_delete_job(
    state: web::types::State<ApiState>,
    path: web::types::Path<IntruderPath>,
) -> HttpResponse {
    let id = match Uuid::parse_str(&path.id) {
        Ok(id) => id,
        Err(_) => return json_error(HttpResponse::BadRequest(), "invalid intruder job id"),
    };

    if state.intruder.remove_job(id) {
        HttpResponse::NoContent().finish()
    } else {
        HttpResponse::NotFound().finish()
    }
}

async fn ws_stats(state: web::types::State<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(&WsStatsResponse {
        clients: state.ws_hub.client_count(),
        ws_port: state.ws_hub.listen_port(),
    })
}

/// Parses a [`ContinueRequest`] into an [`InterceptDecision`].
///
/// Valid `decision` values: `"forward"`, `"drop"`, `"mutate"`.  When
/// `"mutate"` is chosen the `mutation.raw_base64` field must be present and
/// contain valid Base64.
fn parse_decision(req: &ContinueRequest) -> Result<InterceptDecision> {
    match req.decision.as_str() {
        "forward" => Ok(InterceptDecision::Forward),
        "drop" => Ok(InterceptDecision::Drop),
        "mutate" => {
            let mutation = req
                .mutation
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("mutation payload is required"))?;
            let raw = mutation
                .raw_base64
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("mutation raw_base64 is required"))
                .and_then(|encoded| {
                    STANDARD
                        .decode(encoded)
                        .context("invalid mutation raw_base64")
                })?;

            Ok(InterceptDecision::Mutate(RequestMutation {
                raw: Some(Bytes::from(raw)),
            }))
        }
        other => Err(anyhow::anyhow!(
            "unknown decision '{other}', expected forward|drop|mutate"
        )),
    }
}

/// Parses a [`ContinueResponseRequest`] into a [`ResponseInterceptDecision`].
///
/// Mirrors [`parse_decision`] but operates on response-level intercepts with
/// individually replaceable status, headers, and body.
fn parse_response_decision(req: &ContinueResponseRequest) -> Result<ResponseInterceptDecision> {
    match req.decision.as_str() {
        "forward" => Ok(ResponseInterceptDecision::Forward),
        "drop" => Ok(ResponseInterceptDecision::Drop),
        "mutate" => {
            let mutation = req
                .mutation
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("mutation payload is required"))?;
            let body = mutation
                .body_base64
                .as_ref()
                .map(|encoded| {
                    STANDARD
                        .decode(encoded)
                        .context("invalid mutation body_base64")
                })
                .transpose()?;

            Ok(ResponseInterceptDecision::Mutate(ResponseMutation {
                status: mutation.status,
                headers: mutation.headers.clone(),
                body: body.map(Bytes::from),
            }))
        }
        other => Err(anyhow::anyhow!(
            "unknown decision '{other}', expected forward|drop|mutate"
        )),
    }
}

/// Increments the port of `addr` by one, returning an error when the port
/// would overflow `u16::MAX`.
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

/// Removes a pre-existing Unix domain socket file at `path`, if present.
fn cleanup_uds_socket_path(path: &Path) -> io::Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Processes the `state_ops` and `register_ui_modules` arrays from a plugin
/// invocation result, applying side-effects to [`AppState`] and the
/// [`UiModuleRegistry`](web_modules::UiModuleRegistry).
fn apply_plugin_output_ops(
    app_state: &AppState,
    ui_modules: &web_modules::UiModuleRegistry,
    output: &Value,
    plugin_name: Option<&str>,
) -> PluginOpsApplied {
    PluginOpsApplied {
        state_ops_applied: apply_plugin_state_ops(app_state, output),
        ui_modules_registered: apply_plugin_ui_modules(ui_modules, output, plugin_name),
    }
}

/// Applies the `state_ops` array from a plugin output JSON object.
///
/// Recognised operations:
/// - `set_intercept_enabled`
/// - `set_intercept_response_enabled`
/// - `set_mitm_enabled`
/// - `set_scope_hosts`
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

/// Registers UI modules declared in the `register_ui_modules` array of a
/// plugin output payload.  Existing modules with the same `id` are replaced.
fn apply_plugin_ui_modules(
    ui_modules: &web_modules::UiModuleRegistry,
    output: &Value,
    plugin_name: Option<&str>,
) -> usize {
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

        ui_modules.register(web_modules::UiModule {
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

/// Builds a JSON error [`HttpResponse`] using the provided response builder
/// and error message string.
fn json_error(mut builder: ntex::http::ResponseBuilder, msg: &str) -> HttpResponse {
    builder.json(&ApiErrorBody {
        error: msg.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxy_core::AppState;
    use std::io::Write;

    #[test]
    fn parses_forward_decision() {
        let req = ContinueRequest {
            decision: "forward".to_string(),
            mutation: None,
        };
        let decision = parse_decision(&req).expect("decision");
        assert!(matches!(decision, InterceptDecision::Forward));
    }

    #[test]
    fn parses_response_forward_decision() {
        let req = ContinueResponseRequest {
            decision: "forward".to_string(),
            mutation: None,
        };
        let decision = parse_response_decision(&req).expect("decision");
        assert!(matches!(decision, ResponseInterceptDecision::Forward));
    }

    #[test]
    fn parse_mutation_requires_payload() {
        let req = ContinueRequest {
            decision: "mutate".to_string(),
            mutation: None,
        };
        let err = parse_decision(&req).expect_err("should fail");
        assert!(err.to_string().contains("mutation payload is required"));
    }

    #[test]
    fn parse_mutation_requires_raw_blob() {
        let req = ContinueRequest {
            decision: "mutate".to_string(),
            mutation: Some(MutationPayload { raw_base64: None }),
        };
        let err = parse_decision(&req).expect_err("should fail");
        assert!(err.to_string().contains("raw_base64"));
    }

    #[test]
    fn plugin_output_ops_registers_ui_module() {
        let app_state = AppState::new();
        let modules = web_modules::UiModuleRegistry::new();
        let output = serde_json::json!({
            "state_ops": [
                { "op": "set_mitm_enabled", "enabled": false }
            ],
            "register_ui_modules": [
                {
                    "id": "demo",
                    "title": "Demo",
                    "panel_html": "<div>demo</div>",
                    "settings_html": "<div>settings</div>",
                    "script_js": "window.__demo=true;"
                }
            ]
        });

        let applied = apply_plugin_output_ops(&app_state, &modules, &output, None);
        assert_eq!(applied.state_ops_applied, 1);
        assert_eq!(applied.ui_modules_registered, 1);
        assert!(!app_state.mitm_enabled());
        assert!(modules.modules().iter().any(|m| m.id == "demo"));
    }

    #[test]
    fn plugin_alteration_query_limit_defaults() {
        let query = PluginAlterationsQuery { limit: None };
        assert_eq!(query.limit, None);
        let sample = roxy_plugin::PluginAlteration {
            plugin: "demo".to_string(),
            hook: "on_request_pre_capture".to_string(),
            request_id: Some("abc".to_string()),
            unix_ms: 1,
            summary: "changed".to_string(),
        };
        assert_eq!(sample.plugin, "demo");
    }

    #[test]
    fn repeater_decodes_gzip_body_from_header() {
        let input = b"{\"hello\":\"world\"}";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(input).expect("write");
        let encoded = encoder.finish().expect("finish");

        let decoded = decode_http_body_bytes(&encoded, Some("gzip")).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn repeater_decodes_zstd_body_from_magic_without_header() {
        let input = b"{\"kind\":\"zstd\"}";
        let encoded = zstd::stream::encode_all(input.as_slice(), 1).expect("encode");

        let decoded = decode_http_body_bytes(&encoded, None).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn parse_plugin_decoder_mode_supports_operation_suffix() {
        let parsed =
            parse_plugin_decoder_mode("plugin:decoder-codec:base64_encode").expect("must parse");
        assert_eq!(parsed.0, "decoder-codec");
        assert_eq!(parsed.1.as_deref(), Some("base64_encode"));
    }

    #[test]
    fn parse_plugin_decoder_mode_supports_plain_plugin_name() {
        let parsed = parse_plugin_decoder_mode("plugin:custom").expect("must parse");
        assert_eq!(parsed.0, "custom");
        assert_eq!(parsed.1, None);
    }
}
