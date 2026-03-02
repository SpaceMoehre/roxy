//! roxy_plugin `crate root` module.
//!
//! Exposes public types and functions used by the `roxy` runtime and API surface.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::{
    io::AsyncWriteExt,
    process::Command,
    sync::{RwLock, broadcast},
    time::{Duration, timeout},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Represents `PluginRegistration`.
///
/// See also: [`PluginRegistration`].
pub struct PluginRegistration {
    pub name: String,
    pub script_path: PathBuf,
    pub hooks: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Represents `PluginInvocation`.
///
/// See also: [`PluginInvocation`].
pub struct PluginInvocation {
    pub hook: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Represents `PluginResponse`.
///
/// See also: [`PluginResponse`].
pub struct PluginResponse {
    pub plugin: String,
    pub hook: String,
    pub output: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Represents `PluginAlteration`.
///
/// See also: [`PluginAlteration`].
pub struct PluginAlteration {
    pub plugin: String,
    pub hook: String,
    pub request_id: Option<String>,
    pub unix_ms: u128,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Represents `PluginEventRegistration`.
///
/// See also: [`PluginEventRegistration`].
pub struct PluginEventRegistration {
    pub name: String,
    pub hooks: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", content = "payload", rename_all = "snake_case")]
/// Enumerates `PluginManagerEvent` variants.
///
/// See also: [`PluginManagerEvent`].
pub enum PluginManagerEvent {
    PluginRegistered(PluginEventRegistration),
    PluginUnregistered { name: String },
    PluginSettingsUpdated { name: String },
    PluginAlterationRecorded(PluginAlteration),
}

#[derive(Clone)]
/// Represents `PluginManager`.
///
/// See also: [`PluginManager`].
pub struct PluginManager {
    registry: Arc<RwLock<HashMap<String, PluginRegistration>>>,
    settings: Arc<RwLock<HashMap<String, Value>>>,
    alterations: Arc<RwLock<HashMap<String, Vec<PluginAlteration>>>>,
    events_tx: Arc<broadcast::Sender<PluginManagerEvent>>,
}

impl Default for PluginManager {
    fn default() -> Self {
        let (events_tx, _) = broadcast::channel(4096);
        Self {
            registry: Arc::new(RwLock::new(HashMap::new())),
            settings: Arc::new(RwLock::new(HashMap::new())),
            alterations: Arc::new(RwLock::new(HashMap::new())),
            events_tx: Arc::new(events_tx),
        }
    }
}

impl PluginManager {
    /// Subscribes to `events`.
    ///
    /// # Examples
    /// ```
    /// use roxy_plugin as _;
    /// assert!(true);
    /// ```
    pub fn subscribe_events(&self) -> broadcast::Receiver<PluginManagerEvent> {
        self.events_tx.subscribe()
    }

    fn publish_event(&self, event: PluginManagerEvent) {
        let _ = self.events_tx.send(event);
    }

    /// Executes `register`.
    ///
    /// # Examples
    /// ```
    /// use roxy_plugin as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
    pub async fn register(&self, registration: PluginRegistration) -> Result<()> {
        if !registration.script_path.exists() {
            return Err(anyhow!(
                "plugin script does not exist: {:?}",
                registration.script_path
            ));
        }

        let event_registration = PluginEventRegistration {
            name: registration.name.clone(),
            hooks: registration.hooks.clone(),
        };
        let plugin_name = registration.name.clone();
        self.registry
            .write()
            .await
            .insert(plugin_name.clone(), registration);
        self.settings
            .write()
            .await
            .entry(plugin_name.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        self.alterations
            .write()
            .await
            .entry(plugin_name)
            .or_insert_with(Vec::new);
        self.publish_event(PluginManagerEvent::PluginRegistered(event_registration));
        Ok(())
    }

    /// Executes `unregister`.
    ///
    /// # Examples
    /// ```
    /// use roxy_plugin as _;
    /// assert!(true);
    /// ```
    pub async fn unregister(&self, name: &str) -> bool {
        let removed = self.registry.write().await.remove(name).is_some();
        if removed {
            self.settings.write().await.remove(name);
            self.alterations.write().await.remove(name);
            self.publish_event(PluginManagerEvent::PluginUnregistered {
                name: name.to_string(),
            });
        }
        removed
    }

    /// Executes `list`.
    ///
    /// # Examples
    /// ```
    /// use roxy_plugin as _;
    /// assert!(true);
    /// ```
    pub async fn list(&self) -> Vec<PluginRegistration> {
        let mut rows: Vec<PluginRegistration> =
            self.registry.read().await.values().cloned().collect();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        rows
    }

    /// Executes `invoke`.
    ///
    /// # Examples
    /// ```
    /// use roxy_plugin as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
    pub async fn invoke(
        &self,
        plugin_name: &str,
        invocation: PluginInvocation,
    ) -> Result<PluginResponse> {
        let plugin = self
            .registry
            .read()
            .await
            .get(plugin_name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown plugin: {plugin_name}"))?;

        if !plugin.hooks.iter().any(|h| h == &invocation.hook) {
            return Err(anyhow!(
                "plugin '{}' does not expose hook '{}'",
                plugin_name,
                invocation.hook
            ));
        }

        let invocation = self
            .enrich_invocation_payload(plugin_name, invocation)
            .await;
        run_python_plugin(&plugin, invocation).await
    }

    /// Executes `invoke all`.
    ///
    /// # Examples
    /// ```
    /// use roxy_plugin as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
    pub async fn invoke_all(
        &self,
        hook: &str,
        payload: Value,
        timeout_per_plugin: Duration,
    ) -> Vec<Result<PluginResponse>> {
        let plugins: Vec<PluginRegistration> = self
            .registry
            .read()
            .await
            .values()
            .filter(|plugin| plugin.hooks.iter().any(|h| h == hook))
            .cloned()
            .collect();

        let settings_snapshot = self.settings.read().await.clone();
        let mut out = Vec::with_capacity(plugins.len());
        for plugin in plugins {
            let settings = settings_snapshot
                .get(&plugin.name)
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new()));
            if !should_invoke_plugin_for_hook(&plugin.name, hook, &settings) {
                continue;
            }
            let invocation = enrich_invocation_payload_with_settings(
                &plugin.name,
                PluginInvocation {
                    hook: hook.to_string(),
                    payload: payload.clone(),
                },
                settings,
            );
            let response = timeout(timeout_per_plugin, run_python_plugin(&plugin, invocation))
                .await
                .map_err(|_| anyhow!("plugin '{}' timed out", plugin.name))
                .and_then(|r| r);
            out.push(response);
        }

        out
    }

    /// Sets `settings`.
    ///
    /// # Examples
    /// ```
    /// use roxy_plugin as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
    pub async fn set_settings(&self, plugin_name: &str, settings: Value) -> Result<()> {
        if !self.registry.read().await.contains_key(plugin_name) {
            return Err(anyhow!("unknown plugin: {plugin_name}"));
        }
        self.settings
            .write()
            .await
            .insert(plugin_name.to_string(), normalize_plugin_settings(settings));
        self.publish_event(PluginManagerEvent::PluginSettingsUpdated {
            name: plugin_name.to_string(),
        });
        Ok(())
    }

    /// Gets `settings`.
    ///
    /// # Examples
    /// ```
    /// use roxy_plugin as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
    pub async fn get_settings(&self, plugin_name: &str) -> Result<Value> {
        if !self.registry.read().await.contains_key(plugin_name) {
            return Err(anyhow!("unknown plugin: {plugin_name}"));
        }
        Ok(self
            .settings
            .read()
            .await
            .get(plugin_name)
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new())))
    }

    /// Executes `record alteration`.
    ///
    /// # Examples
    /// ```
    /// use roxy_plugin as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
    pub async fn record_alteration(&self, alteration: PluginAlteration) -> Result<()> {
        if !self.registry.read().await.contains_key(&alteration.plugin) {
            return Err(anyhow!("unknown plugin: {}", alteration.plugin));
        }

        let event_alteration = alteration.clone();
        let mut alterations = self.alterations.write().await;
        let entries = alterations.entry(alteration.plugin.clone()).or_default();
        entries.push(alteration);
        if entries.len() > 1_000 {
            let drain = entries.len() - 1_000;
            entries.drain(0..drain);
        }
        self.publish_event(PluginManagerEvent::PluginAlterationRecorded(
            event_alteration,
        ));
        Ok(())
    }

    /// Lists `alterations`.
    ///
    /// # Examples
    /// ```
    /// use roxy_plugin as _;
    /// assert!(true);
    /// ```
    ///
    /// # Errors
    /// Returns an error when the operation cannot be completed.
    pub async fn list_alterations(
        &self,
        plugin_name: &str,
        limit: usize,
    ) -> Result<Vec<PluginAlteration>> {
        if !self.registry.read().await.contains_key(plugin_name) {
            return Err(anyhow!("unknown plugin: {plugin_name}"));
        }

        let limit = limit.clamp(1, 1_000);
        let mut rows = self
            .alterations
            .read()
            .await
            .get(plugin_name)
            .cloned()
            .unwrap_or_default();
        rows.sort_by(|a, b| b.unix_ms.cmp(&a.unix_ms));
        rows.truncate(limit);
        Ok(rows)
    }

    async fn enrich_invocation_payload(
        &self,
        plugin_name: &str,
        invocation: PluginInvocation,
    ) -> PluginInvocation {
        let settings = self
            .settings
            .read()
            .await
            .get(plugin_name)
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));

        enrich_invocation_payload_with_settings(plugin_name, invocation, settings)
    }
}

fn normalize_plugin_settings(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(map),
        Value::Null => Value::Object(Map::new()),
        other => {
            let mut map = Map::new();
            map.insert("value".to_string(), other);
            Value::Object(map)
        }
    }
}

fn enrich_invocation_payload_with_settings(
    plugin_name: &str,
    invocation: PluginInvocation,
    settings: Value,
) -> PluginInvocation {
    let mut payload_obj = match invocation.payload {
        Value::Object(map) => map,
        other => {
            let mut map = Map::new();
            map.insert("payload".to_string(), other);
            map
        }
    };
    payload_obj.insert(
        "plugin_name".to_string(),
        Value::String(plugin_name.to_string()),
    );
    payload_obj.insert("plugin_settings".to_string(), settings);

    PluginInvocation {
        hook: invocation.hook,
        payload: Value::Object(payload_obj),
    }
}

fn should_invoke_plugin_for_hook(plugin_name: &str, hook: &str, settings: &Value) -> bool {
    if plugin_name != "string-substitute" {
        return true;
    }
    if hook != "on_request_pre_capture" && hook != "on_response_pre_capture" {
        return true;
    }
    string_substitute_has_rules(settings)
}

fn string_substitute_has_rules(settings: &Value) -> bool {
    let Some(obj) = settings.as_object() else {
        return false;
    };
    if let Some(rules) = obj.get("rules").and_then(Value::as_array) {
        if rules.iter().any(|rule| {
            rule.get("search")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        }) {
            return true;
        }
    }
    for key in ["request_search", "response_search"] {
        if obj
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        {
            return true;
        }
    }
    false
}

async fn run_python_plugin(
    plugin: &PluginRegistration,
    invocation: PluginInvocation,
) -> Result<PluginResponse> {
    let input = serde_json::to_vec(&invocation).context("failed serializing plugin invocation")?;

    let mut command = Command::new("python3");
    command.arg(&plugin.script_path);
    command.stdin(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = command
        .spawn()
        .with_context(|| format!("failed spawning python plugin {}", plugin.name))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&input)
            .await
            .context("failed writing plugin stdin")?;
        stdin
            .shutdown()
            .await
            .context("failed closing plugin stdin")?;
    }

    let output = child
        .wait_with_output()
        .await
        .context("failed waiting for plugin output")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "plugin '{}' exited with status {}: {}",
            plugin.name,
            output.status,
            stderr
        ));
    }

    let value: Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("plugin '{}' returned invalid JSON", plugin.name))?;

    Ok(PluginResponse {
        plugin: plugin.name.clone(),
        hook: invocation.hook,
        output: value,
    })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn invokes_python_plugin() {
        let tmp = TempDir::new().expect("tempdir");
        let script = tmp.path().join("plugin.py");
        std::fs::write(
            &script,
            r#"#!/usr/bin/env python3
import json, sys
payload = json.loads(sys.stdin.read())
print(json.dumps({"hook": payload["hook"], "echo": payload["payload"]}))
"#,
        )
        .expect("write script");

        let manager = PluginManager::default();
        manager
            .register(PluginRegistration {
                name: "echo".to_string(),
                script_path: script,
                hooks: vec!["on_request".to_string()],
            })
            .await
            .expect("register plugin");

        let response = manager
            .invoke(
                "echo",
                PluginInvocation {
                    hook: "on_request".to_string(),
                    payload: serde_json::json!({ "k": "v" }),
                },
            )
            .await
            .expect("invoke plugin");

        assert_eq!(response.output["hook"], "on_request");
        assert_eq!(response.output["echo"]["k"], "v");
        assert_eq!(response.output["echo"]["plugin_name"], "echo");
    }

    #[tokio::test]
    async fn plugin_settings_are_injected_into_payload() {
        let tmp = TempDir::new().expect("tempdir");
        let script = tmp.path().join("plugin.py");
        std::fs::write(
            &script,
            r#"#!/usr/bin/env python3
import json, sys
payload = json.loads(sys.stdin.read())
print(json.dumps({"settings": payload["payload"].get("plugin_settings", {})}))
"#,
        )
        .expect("write script");

        let manager = PluginManager::default();
        manager
            .register(PluginRegistration {
                name: "cfg".to_string(),
                script_path: script,
                hooks: vec!["hook".to_string()],
            })
            .await
            .expect("register plugin");
        manager
            .set_settings(
                "cfg",
                serde_json::json!({"request_search": "hello", "request_replace": "roxy"}),
            )
            .await
            .expect("set settings");

        let response = manager
            .invoke(
                "cfg",
                PluginInvocation {
                    hook: "hook".to_string(),
                    payload: serde_json::json!({}),
                },
            )
            .await
            .expect("invoke plugin");

        assert_eq!(response.output["settings"]["request_search"], "hello");
        assert_eq!(response.output["settings"]["request_replace"], "roxy");
    }

    #[tokio::test]
    async fn publishes_plugin_events_for_realtime_consumers() {
        let tmp = TempDir::new().expect("tempdir");
        let script = tmp.path().join("plugin.py");
        std::fs::write(&script, "print('{}')\n").expect("write script");

        let manager = PluginManager::default();
        let mut events = manager.subscribe_events();

        manager
            .register(PluginRegistration {
                name: "events".to_string(),
                script_path: script,
                hooks: vec!["on_request_pre_capture".to_string()],
            })
            .await
            .expect("register plugin");

        match timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("register event timeout")
            .expect("register event")
        {
            PluginManagerEvent::PluginRegistered(payload) => {
                assert_eq!(payload.name, "events");
                assert_eq!(payload.hooks, vec!["on_request_pre_capture"]);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        manager
            .set_settings("events", serde_json::json!({"rule_count": 1}))
            .await
            .expect("set settings");

        match timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("settings event timeout")
            .expect("settings event")
        {
            PluginManagerEvent::PluginSettingsUpdated { name } => {
                assert_eq!(name, "events");
            }
            other => panic!("unexpected event: {other:?}"),
        }

        manager
            .record_alteration(PluginAlteration {
                plugin: "events".to_string(),
                hook: "on_request_pre_capture".to_string(),
                request_id: Some("abc-123".to_string()),
                unix_ms: 42,
                summary: "mutated request".to_string(),
            })
            .await
            .expect("record alteration");

        match timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("alteration event timeout")
            .expect("alteration event")
        {
            PluginManagerEvent::PluginAlterationRecorded(payload) => {
                assert_eq!(payload.plugin, "events");
                assert_eq!(payload.request_id.as_deref(), Some("abc-123"));
                assert_eq!(payload.summary, "mutated request");
            }
            other => panic!("unexpected event: {other:?}"),
        }

        assert!(manager.unregister("events").await);
        match timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("unregister event timeout")
            .expect("unregister event")
        {
            PluginManagerEvent::PluginUnregistered { name } => {
                assert_eq!(name, "events");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}
