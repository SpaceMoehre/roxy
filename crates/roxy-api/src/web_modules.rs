//! Dynamic UI module registry.
//!
//! Plugins and built-in features contribute dashboard panels to the
//! web UI by registering [`UiModule`]s with the
//! [`UiModuleRegistry`].  The registry is read at render time to
//! produce the navigation, panel HTML, settings dialogs, and a single
//! concatenated JavaScript bundle.

use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// A self-contained dashboard panel contributed by a plugin or built-in
/// feature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UiModule {
    /// Unique identifier used as the DOM id and route key.
    pub id: String,
    /// Human-readable label shown in the navigation sidebar.
    pub title: String,
    /// When `true` the module is loaded but hidden from the nav bar.
    #[serde(default)]
    pub nav_hidden: bool,
    /// HTML fragment rendered into the main panel area.
    pub panel_html: String,
    /// HTML fragment rendered inside the global settings dialog.
    pub settings_html: String,
    /// JavaScript source evaluated after the DOM is ready.
    pub script_js: String,
}

impl UiModule {
    /// Creates a module from `&'static str` slices (ideal for
    /// `include_str!` at compile time).
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

/// Thread-safe registry of [`UiModule`]s.
///
/// Internally guarded by an [`RwLock`] so modules can be registered
/// from any thread.
#[derive(Debug, Default)]
pub struct UiModuleRegistry {
    modules: RwLock<Vec<UiModule>>,
}

impl UiModuleRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces a module (matched by `id`).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
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

    /// Returns a snapshot of all registered modules.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn modules(&self) -> Vec<UiModule> {
        self.modules
            .read()
            .expect("ui module registry lock poisoned")
            .clone()
    }

    /// Concatenates every module’s `script_js` into a single string
    /// separated by blank lines.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    pub fn module_scripts_bundle(&self) -> String {
        self.modules
            .read()
            .expect("ui module registry lock poisoned")
            .iter()
            .map(|module| module.script_js.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// Creates a registry pre-populated with the four built-in
    /// modules: *Intruder*, *Repeater*, *Decoder*, and *Plugins*.
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
