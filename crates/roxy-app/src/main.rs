use std::{env, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use roxy_api::{
    ApiState, run_api_with_shutdown,
    ws::{WsHub, run_ws_server_with_shutdown},
};
use roxy_core::{AppState, CertManager, EventEnvelope, IntruderManager, ProxyConfig, ProxyEngine};
use roxy_plugin::PluginManager;
use roxy_storage::StorageManager;
use serde_json::Value;
use tokio::{
    sync::{mpsc, watch},
    time::timeout,
};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

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

    let (event_tx, mut event_rx) = mpsc::channel::<EventEnvelope>(4096);
    let (storage_tx, storage_rx) = mpsc::channel(4096);
    let _storage_task = storage.spawn_ingestor(storage_rx);

    let plugins_for_loop = plugins.clone();
    let ws_hub_for_loop = ws_hub.clone();
    let app_state_for_plugins = app_state.clone();
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
                    let _ = apply_plugin_state_ops(&app_state_for_plugins, &response.output);
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

    let proxy = ProxyEngine::new(
        ProxyConfig {
            bind: proxy_bind,
            ..ProxyConfig::default()
        },
        app_state.clone(),
        cert_manager.clone(),
        event_tx,
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let proxy_shutdown = shutdown_rx.clone();
    let ws_shutdown = shutdown_rx.clone();
    let api_shutdown = shutdown_rx.clone();

    let mut proxy_task = tokio::spawn(async move { proxy.run_with_shutdown(proxy_shutdown).await });

    let ws_hub_for_server = ws_hub.clone();
    let mut ws_task = tokio::spawn(async move {
        run_ws_server_with_shutdown(ws_bind, ws_hub_for_server, ws_shutdown).await
    });

    let api_state = ApiState::new(app_state, cert_manager, storage, plugins, intruder, ws_hub);
    let mut api_task = tokio::task::spawn_blocking(move || {
        let runner = ntex::rt::System::new("roxy-api");
        runner
            .block_on(async move { run_api_with_shutdown(api_bind, api_state, api_shutdown).await })
    });

    info!(%proxy_bind, %api_bind, %ws_bind, "roxy started");

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

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

fn read_addr_env(key: &str, default: &str) -> Result<SocketAddr> {
    let value = env::var(key).unwrap_or_else(|_| default.to_string());
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid socket address in {key}: {value}"))
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
