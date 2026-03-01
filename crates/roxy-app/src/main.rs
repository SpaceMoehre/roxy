use std::{
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use roxy_api::{
    ApiState, run_api_with_shutdown,
    web_modules::{UiModule, UiModuleRegistry},
    ws::{WsHub, run_ws_server_with_shutdown},
};
use roxy_core::{
    AppState, CapturedRequest, CapturedResponse, CertManager, DebugLoggingConfig, EventEnvelope,
    HeaderValuePair, IntruderManager, ProxyConfig, ProxyEngine, ProxyMiddleware,
};
use roxy_plugin::{PluginAlteration, PluginInvocation, PluginManager, PluginRegistration};
use roxy_storage::StorageManager;
use serde_json::Value;
use tokio::{
    sync::{mpsc, watch},
    time::timeout,
};
use tracing::{error, info, warn};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CliOptions {
    debug: bool,
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
                    apply_plugin_output_ops(&self.app_state, &self.ui_modules, &response.output);
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
                    apply_plugin_output_ops(&self.app_state, &self.ui_modules, &response.output);
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
    init_tracing(debug_logging_enabled);

    let proxy_bind = read_addr_env("ROXY_PROXY_BIND", "127.0.0.1:8080")?;
    let api_bind = read_addr_env("ROXY_API_BIND", "127.0.0.1:3000")?;
    let ws_bind = read_addr_env("ROXY_WS_BIND", "127.0.0.1:3001")?;
    let data_dir =
        PathBuf::from(env::var("ROXY_DATA_DIR").unwrap_or_else(|_| ".roxy-data".to_string()));

    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed creating data dir {data_dir:?}"))?;

    let app_state = Arc::new(AppState::new());
    let cert_manager = Arc::new(CertManager::load_or_create(data_dir.join("certs"))?);
    let storage = StorageManager::open(data_dir.join("storage"))?;
    let plugins = PluginManager::default();
    let intruder = IntruderManager::default();
    let ws_hub = WsHub::new(4096);
    let ui_modules = Arc::new(UiModuleRegistry::with_builtin_modules());

    auto_register_plugins(&plugins, &app_state, &ui_modules).await;

    let (event_tx, mut event_rx) = mpsc::channel::<EventEnvelope>(4096);
    let (storage_tx, storage_rx) = mpsc::channel(4096);
    let _storage_task = storage.spawn_ingestor(storage_rx);

    let plugins_for_loop = plugins.clone();
    let ws_hub_for_loop = ws_hub.clone();
    let app_state_for_plugins = app_state.clone();
    let ui_modules_for_plugins = ui_modules.clone();
    let _event_dispatch = tokio::spawn(async move {
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
                    );
                }
            }

            ws_hub_for_loop.publish(&event);
        }
    });

    let mut intruder_events = intruder.subscribe_events();
    let ws_hub_intruder = ws_hub.clone();
    let _intruder_event_dispatch = tokio::spawn(async move {
        while let Ok(event) = intruder_events.recv().await {
            ws_hub_intruder.publish(&event);
        }
    });

    let plugin_bridge = Arc::new(PluginBridgeMiddleware::new(
        plugins.clone(),
        app_state.clone(),
        ui_modules.clone(),
    ));

    let proxy = ProxyEngine::new(
        ProxyConfig {
            bind: proxy_bind,
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
    .with_middleware(plugin_bridge);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy_shutdown = shutdown_rx.clone();
    let ws_shutdown = shutdown_rx.clone();
    let api_shutdown = shutdown_rx.clone();

    let mut proxy_task = tokio::spawn(async move { proxy.run_with_shutdown(proxy_shutdown).await });

    let ws_hub_for_server = ws_hub.clone();
    let mut ws_task = tokio::spawn(async move {
        run_ws_server_with_shutdown(ws_bind, ws_hub_for_server, ws_shutdown).await
    });

    let api_state = ApiState::new(
        app_state,
        cert_manager,
        storage,
        plugins,
        intruder,
        ws_hub,
        ui_modules,
    );
    let mut api_task = tokio::task::spawn_blocking(move || {
        let runner = ntex::rt::System::new("roxy-api");
        runner
            .block_on(async move { run_api_with_shutdown(api_bind, api_state, api_shutdown).await })
    });

    info!(
        %proxy_bind,
        %api_bind,
        %ws_bind,
        debug_cli = cli.debug,
        debug_logging_enabled,
        debug_log_bodies,
        debug_log_body_limit,
        "roxy started"
    );

    let mut ctrl_c_triggered = false;
    tokio::select! {
        result = &mut api_task => {
            let result = result.context("api task join failure")?;
            result.context("api server stopped unexpectedly")?;
        }
        result = &mut proxy_task => {
            let result = result.context("proxy task join failure")?;
            result.context("proxy server stopped unexpectedly")?;
        }
        result = &mut ws_task => {
            let result = result.context("websocket task join failure")?;
            result.context("websocket server stopped unexpectedly")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown requested");
            ctrl_c_triggered = true;
        }
    }

    if ctrl_c_triggered {
        let _ = shutdown_tx.send(true);

        let graceful = timeout(Duration::from_secs(5), async {
            let _ = (&mut proxy_task).await;
            let _ = (&mut ws_task).await;
            let _ = (&mut api_task).await;
        })
        .await;

        if graceful.is_err() {
            warn!("graceful shutdown timed out, aborting remaining tasks");
            proxy_task.abort();
            ws_task.abort();
            api_task.abort();
        }
    }

    Ok(())
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
    for arg in args {
        match arg.as_str() {
            "--debug" => {
                options.debug = true;
            }
            unknown => {
                return Err(anyhow!(
                    "unknown argument '{unknown}'. supported flags: --debug"
                ));
            }
        }
    }
    Ok(options)
}

fn read_addr_env(key: &str, default: &str) -> Result<SocketAddr> {
    let value = env::var(key).unwrap_or_else(|_| default.to_string());
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid socket address in {key}: {value}"))
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

    let mut scripts = match fs::read_dir(&plugin_dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "py"))
            .collect::<Vec<_>>(),
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
            hooks: vec![
                "on_load".to_string(),
                "on_exchange".to_string(),
                "on_request_pre_capture".to_string(),
                "on_response_pre_capture".to_string(),
                "decoder".to_string(),
            ],
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
                let applied = apply_plugin_output_ops(app_state, ui_modules, &result.output);
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

fn apply_plugin_output_ops(
    app_state: &AppState,
    ui_modules: &UiModuleRegistry,
    output: &Value,
) -> PluginOpsApplied {
    PluginOpsApplied {
        state_ops_applied: apply_plugin_state_ops(app_state, output),
        ui_modules_registered: apply_plugin_ui_modules(ui_modules, output),
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

fn apply_plugin_ui_modules(ui_modules: &UiModuleRegistry, output: &Value) -> usize {
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
    use uuid::Uuid;

    use super::{
        AppState, CapturedRequest, CapturedResponse, UiModuleRegistry, apply_plugin_output_ops,
        apply_request_middleware_output, apply_response_middleware_output, parse_bool_env_value,
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
    fn parse_cli_options_rejects_unknown_flag() {
        let err = parse_cli_options_from_args(vec!["--wat".to_string()]).expect_err("should fail");
        assert!(err.to_string().contains("unknown argument"));
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

        let applied = apply_plugin_output_ops(&app_state, &modules, &output);
        assert_eq!(applied.state_ops_applied, 1);
        assert_eq!(applied.ui_modules_registered, 1);
        assert!(app_state.intercept_enabled());
        assert!(modules.modules().iter().any(|m| m.id == "demo"));
    }
}
