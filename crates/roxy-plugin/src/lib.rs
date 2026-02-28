use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::AsyncWriteExt,
    process::Command,
    sync::RwLock,
    time::{Duration, timeout},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginRegistration {
    pub name: String,
    pub script_path: PathBuf,
    pub hooks: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginInvocation {
    pub hook: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginResponse {
    pub plugin: String,
    pub hook: String,
    pub output: Value,
}

#[derive(Clone, Default)]
pub struct PluginManager {
    registry: Arc<RwLock<HashMap<String, PluginRegistration>>>,
}

impl PluginManager {
    pub async fn register(&self, registration: PluginRegistration) -> Result<()> {
        if !registration.script_path.exists() {
            return Err(anyhow!(
                "plugin script does not exist: {:?}",
                registration.script_path
            ));
        }

        self.registry
            .write()
            .await
            .insert(registration.name.clone(), registration);
        Ok(())
    }

    pub async fn unregister(&self, name: &str) -> bool {
        self.registry.write().await.remove(name).is_some()
    }

    pub async fn list(&self) -> Vec<PluginRegistration> {
        let mut rows: Vec<PluginRegistration> =
            self.registry.read().await.values().cloned().collect();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        rows
    }

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

        run_python_plugin(&plugin, invocation).await
    }

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

        let mut out = Vec::with_capacity(plugins.len());
        for plugin in plugins {
            let invocation = PluginInvocation {
                hook: hook.to_string(),
                payload: payload.clone(),
            };
            let response = timeout(timeout_per_plugin, run_python_plugin(&plugin, invocation))
                .await
                .map_err(|_| anyhow!("plugin '{}' timed out", plugin.name))
                .and_then(|r| r);
            out.push(response);
        }

        out
    }
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
    }
}
