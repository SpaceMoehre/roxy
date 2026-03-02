//! roxy_api `web_modules` module.
//!
//! Exposes public types and functions used by the `roxy` runtime and API surface.

use std::sync::RwLock;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Represents `UiModule`.
///
/// See also: [`UiModule`].
pub struct UiModule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub nav_hidden: bool,
    pub panel_html: String,
    pub settings_html: String,
    pub script_js: String,
}

impl UiModule {
    /// Constructs a new instance.
    ///
    /// # Examples
    /// ```
    /// use roxy_api as _;
    /// assert!(true);
    /// ```
    pub fn new(
        id: &'static str,
        title: &'static str,
        panel_html: &'static str,
        settings_html: &'static str,
        script_js: &'static str,
    ) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            nav_hidden: false,
            panel_html: panel_html.to_string(),
            settings_html: settings_html.to_string(),
            script_js: script_js.to_string(),
        }
    }
}

#[derive(Debug, Default)]
/// Represents `UiModuleRegistry`.
///
/// See also: [`UiModuleRegistry`].
pub struct UiModuleRegistry {
    modules: RwLock<Vec<UiModule>>,
}

impl UiModuleRegistry {
    /// Constructs a new instance.
    ///
    /// # Examples
    /// ```
    /// use roxy_api as _;
    /// assert!(true);
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Executes `register`.
    ///
    /// # Examples
    /// ```
    /// use roxy_api as _;
    /// assert!(true);
    /// ```
    ///
    /// # Panics
    /// Panics if internal assertions fail or infallible assumptions are violated.
    pub fn register(&self, module: UiModule) {
        let mut modules = self
            .modules
            .write()
            .expect("ui module registry lock poisoned");
        if let Some(existing) = modules.iter_mut().find(|m| m.id == module.id) {
            *existing = module;
            return;
        }
        modules.push(module);
    }

    /// Executes `modules`.
    ///
    /// # Examples
    /// ```
    /// use roxy_api as _;
    /// assert!(true);
    /// ```
    ///
    /// # Panics
    /// Panics if internal assertions fail or infallible assumptions are violated.
    pub fn modules(&self) -> Vec<UiModule> {
        self.modules
            .read()
            .expect("ui module registry lock poisoned")
            .clone()
    }

    /// Executes `module scripts bundle`.
    ///
    /// # Examples
    /// ```
    /// use roxy_api as _;
    /// assert!(true);
    /// ```
    ///
    /// # Panics
    /// Panics if internal assertions fail or infallible assumptions are violated.
    pub fn module_scripts_bundle(&self) -> String {
        self.modules
            .read()
            .expect("ui module registry lock poisoned")
            .iter()
            .map(|module| module.script_js.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// Executes `with builtin modules`.
    ///
    /// # Examples
    /// ```
    /// use roxy_api as _;
    /// assert!(true);
    /// ```
    pub fn with_builtin_modules() -> Self {
        let registry = Self::new();
        registry.register(UiModule::new(
            "intruder",
            "Intruder",
            include_str!("../web/modules/intruder/panel.html"),
            include_str!("../web/modules/intruder/settings.html"),
            include_str!("../web/modules/intruder/app.js"),
        ));
        registry.register(UiModule::new(
            "repeater",
            "Repeater",
            include_str!("../web/modules/repeater/panel.html"),
            include_str!("../web/modules/repeater/settings.html"),
            include_str!("../web/modules/repeater/app.js"),
        ));
        registry.register(UiModule::new(
            "decoder",
            "Decoder",
            include_str!("../web/modules/decoder/panel.html"),
            include_str!("../web/modules/decoder/settings.html"),
            include_str!("../web/modules/decoder/app.js"),
        ));
        registry.register(UiModule::new(
            "plugins",
            "Plugins",
            include_str!("../web/modules/plugins/panel.html"),
            include_str!("../web/modules/plugins/settings.html"),
            include_str!("../web/modules/plugins/app.js"),
        ));
        registry
    }
}

#[cfg(test)]
mod tests {
    use super::UiModuleRegistry;

    #[test]
    fn builtins_are_registered() {
        let registry = UiModuleRegistry::with_builtin_modules();
        let modules = registry.modules();
        let ids = modules.iter().map(|m| m.id.as_str()).collect::<Vec<_>>();
        assert_eq!(ids, vec!["intruder", "repeater", "decoder", "plugins"]);
    }
}
