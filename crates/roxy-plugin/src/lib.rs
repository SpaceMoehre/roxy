//! Python plugin lifecycle manager.
//!
//! Plugins are standalone Python scripts that communicate over a JSON
//! stdin/stdout protocol. Each plugin declares the **hooks** it
//! supports (e.g. `on_request_pre_capture`, `on_response_pre_capture`)
//! and the [`PluginManager`] dispatches [`PluginInvocation`]s to the
//! appropriate script.
//!
//! ## Protocol
//!
//! 1. The manager serialises a [`PluginInvocation`] as JSON and writes
//!    it to the child process’s **stdin**, then closes the pipe.
//! 2. The script reads stdin, executes its logic, and writes a single
//!    JSON object to **stdout**.
//! 3. Non-zero exit codes or unparseable output are treated as errors.
//!
//! ## Settings
//!
//! Per-plugin settings are stored as a `serde_json::Value` map and
//! injected into every invocation payload under the
//! `"plugin_settings"` key so the script can read them without
//! additional I/O.
//!
//! ## Events
//!
//! All lifecycle changes (`register`, `unregister`, `settings_updated`,
//! `alteration_recorded`) are broadcast via a
//! [`broadcast`] channel as
//! [`PluginManagerEvent`]s.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::{RwLock, broadcast, mpsc},
    time::{Duration, timeout},
};

/// Metadata captured when a plugin is registered with the manager.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginRegistration {
    /// Unique, human-readable plugin name (e.g. `"string-substitute"`).
    pub name: String,
    /// Absolute path to the Python entry-point script.
    pub script_path: PathBuf,
    /// Hook names the plugin declares support for.
    pub hooks: Vec<String>,
}

/// A single call dispatched to a plugin.
///
/// Serialised to JSON and written to the child process’s stdin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginInvocation {
    /// Hook being invoked (e.g. `"on_request_pre_capture"`).
    pub hook: String,
    /// Arbitrary JSON payload for the hook.
    pub payload: Value,
}

/// The result returned by a plugin invocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginResponse {
    /// Name of the plugin that produced this response.
    pub plugin: String,
    /// Hook that was invoked.
    pub hook: String,
    /// Parsed JSON from the script’s stdout.
    pub output: Value,
}

/// Record of a mutation performed by a plugin on a proxied request or
/// response, stored for audit purposes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginAlteration {
    /// Plugin that performed the alteration.
    pub plugin: String,
    /// Hook that triggered it.
    pub hook: String,
    /// UUID of the affected request, if applicable.
    pub request_id: Option<String>,
    /// When the alteration occurred (Unix epoch, ms).
    pub unix_ms: u128,
    /// Human-readable description of what changed.
    pub summary: String,
}

/// Lightweight view of a plugin used in broadcast events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginEventRegistration {
    /// Plugin name.
    pub name: String,
    /// Hooks the plugin supports.
    pub hooks: Vec<String>,
}

/// Real-time lifecycle event broadcast by the plugin subsystem.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", content = "payload", rename_all = "snake_case")]
pub enum PluginManagerEvent {
    /// A new plugin was registered.
    PluginRegistered(PluginEventRegistration),
    /// A plugin was removed.
    PluginUnregistered {
        /// Name of the removed plugin.
        name: String,
    },
    /// A plugin’s settings map was replaced.
    PluginSettingsUpdated {
        /// Name of the affected plugin.
        name: String,
    },
    /// A plugin reported a mutation on a proxied exchange.
    PluginAlterationRecorded(PluginAlteration),
}

/// Central plugin registry and executor.
///
/// Cheaply cloneable — all inner state is behind [`Arc`] + [`RwLock`].
/// Create one via [`Default::default()`] then [`register`](Self::register)
/// plugins as they are discovered.
#[derive(Clone)]
pub struct PluginManager {
    /// Plugin name → registration metadata.
    registry: Arc<RwLock<HashMap<String, PluginRegistration>>>,
    /// Plugin name → settings JSON map.
    settings: Arc<RwLock<HashMap<String, Value>>>,
    /// Plugin name → alteration audit log (capped at 1 000 per plugin).
    alterations: Arc<RwLock<HashMap<String, Vec<PluginAlteration>>>>,
    /// Fan-out channel for [`PluginManagerEvent`]s.
    events_tx: Arc<broadcast::Sender<PluginManagerEvent>>,
    /// Path to the Python interpreter binary.
    python_path: Arc<RwLock<PathBuf>>,
}

impl Default for PluginManager {
    fn default() -> Self {
        let (events_tx, _) = broadcast::channel(4096);
        Self {
            registry: Arc::new(RwLock::new(HashMap::new())),
            settings: Arc::new(RwLock::new(HashMap::new())),
            alterations: Arc::new(RwLock::new(HashMap::new())),
            events_tx: Arc::new(events_tx),
            python_path: Arc::new(RwLock::new(PathBuf::from("python3"))),
        }
    }
}

impl PluginManager {
    /// Returns a new receiver for plugin lifecycle events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<PluginManagerEvent> {
        self.events_tx.subscribe()
    }

    /// Sets the Python interpreter path used to execute plugin scripts.
    pub async fn set_python_path(&self, path: PathBuf) {
        *self.python_path.write().await = path;
    }

    /// Returns the currently configured Python interpreter path.
    pub async fn python_path(&self) -> PathBuf {
        self.python_path.read().await.clone()
    }

    fn publish_event(&self, event: PluginManagerEvent) {
        let _ = self.events_tx.send(event);
    }

    /// Adds a plugin to the registry.
    ///
    /// An empty settings map is initialised for the plugin and a
    /// [`PluginManagerEvent::PluginRegistered`] event is broadcast.
    ///
    /// # Errors
    ///
    /// Returns an error if the plugin’s `script_path` does not exist.
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

    /// Removes a plugin from the registry.
    ///
    /// Returns `true` if the plugin existed. A
    /// [`PluginManagerEvent::PluginUnregistered`] event is broadcast
    /// on successful removal.
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

    /// Returns all registered plugins sorted alphabetically by name.
    pub async fn list(&self) -> Vec<PluginRegistration> {
        let mut rows: Vec<PluginRegistration> =
            self.registry.read().await.values().cloned().collect();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        rows
    }

    /// Returns the registration for the given plugin name, if it exists.
    pub async fn get_registration(&self, name: &str) -> Option<PluginRegistration> {
        self.registry.read().await.get(name).cloned()
    }

    /// Invokes a specific hook on a single named plugin.
    ///
    /// The invocation payload is enriched with the plugin’s current
    /// settings before being sent.
    ///
    /// # Errors
    ///
    /// Returns an error if the plugin is unknown, does not expose the
    /// requested hook, or the subprocess fails.
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
        let python = self.python_path.read().await.clone();
        run_python_plugin(&python, &plugin, invocation).await
    }

    /// Spawns a plugin invocation that streams its stderr lines into the
    /// returned receiver.  The final [`PluginResponse`] from stdout is sent
    /// on the `result_tx` oneshot when the process exits.
    pub async fn invoke_streaming(
        &self,
        plugin_name: &str,
        invocation: PluginInvocation,
    ) -> Result<(
        mpsc::Receiver<String>,
        tokio::sync::oneshot::Receiver<Result<PluginResponse>>,
    )> {
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
        let python = self.python_path.read().await.clone();
        let (line_tx, line_rx) = mpsc::channel::<String>(512);
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let result = run_python_plugin_streaming(&python, &plugin, invocation, line_tx).await;
            let _ = result_tx.send(result);
        });

        Ok((line_rx, result_rx))
    }

    /// Invokes a hook on **every** plugin that declares it, with a
    /// per-plugin timeout.
    ///
    /// Returns one `Result<PluginResponse>` per invoked plugin.
    /// Plugins whose settings indicate they should be skipped (e.g.
    /// `string-substitute` with no rules) are omitted silently.
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
            let python = self.python_path.read().await.clone();
            let response = timeout(
                timeout_per_plugin,
                run_python_plugin(&python, &plugin, invocation),
            )
            .await
            .map_err(|_| anyhow!("plugin '{}' timed out", plugin.name))
            .and_then(|r| r);
            out.push(response);
        }

        out
    }

    /// Replaces the settings map for a plugin.
    ///
    /// Non-object values are wrapped in `{"value": …}`. A
    /// [`PluginManagerEvent::PluginSettingsUpdated`] event is broadcast.
    ///
    /// # Errors
    ///
    /// Returns an error if the plugin is unknown.
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

    /// Returns the current settings JSON map for a plugin.
    ///
    /// # Errors
    ///
    /// Returns an error if the plugin is unknown.
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

    /// Appends an alteration record for a plugin.
    ///
    /// Only the most recent 1 000 entries per plugin are retained.
    ///
    /// # Errors
    ///
    /// Returns an error if the plugin is unknown.
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

    /// Returns the most recent alterations for a plugin, newest first.
    ///
    /// `limit` is clamped to `1..=1_000`.
    ///
    /// # Errors
    ///
    /// Returns an error if the plugin is unknown.
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
    python: &Path,
    plugin: &PluginRegistration,
    invocation: PluginInvocation,
) -> Result<PluginResponse> {
    let input = serde_json::to_vec(&invocation).context("failed serializing plugin invocation")?;

    let mut command = Command::new(python);
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

/// Like [`run_python_plugin`] but streams each stderr line into `line_tx`
/// as it is produced, enabling real-time progress updates.
async fn run_python_plugin_streaming(
    python: &Path,
    plugin: &PluginRegistration,
    invocation: PluginInvocation,
    line_tx: mpsc::Sender<String>,
) -> Result<PluginResponse> {
    let input = serde_json::to_vec(&invocation).context("failed serializing plugin invocation")?;

    let mut command = Command::new(python);
    command.arg(&plugin.script_path);
    command.stdin(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = command
        .spawn()
        .with_context(|| format!("failed spawning python plugin {}", plugin.name))?;

    // Write the invocation JSON to stdin.
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

    // Stream stderr lines in real time.
    let stderr = child
        .stderr
        .take()
        .context("failed to capture plugin stderr")?;
    let mut stderr_reader = BufReader::new(stderr).lines();

    // Read stdout in a separate task so we don't deadlock.
    let stdout = child
        .stdout
        .take()
        .context("failed to capture plugin stdout")?;
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut tokio::io::BufReader::new(stdout), &mut buf)
            .await
            .map(|_| buf)
    });

    while let Some(line) = stderr_reader.next_line().await.unwrap_or(None) {
        let _ = line_tx.send(line).await;
    }

    let status = child.wait().await.context("failed waiting for plugin")?;
    let stdout_bytes = stdout_task
        .await
        .context("stdout reader task panicked")?
        .context("failed reading plugin stdout")?;

    if !status.success() {
        return Err(anyhow!(
            "plugin '{}' exited with status {}",
            plugin.name,
            status,
        ));
    }

    let value: Value = serde_json::from_slice(&stdout_bytes)
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
