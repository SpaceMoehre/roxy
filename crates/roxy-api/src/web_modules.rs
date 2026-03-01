use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct UiModule {
    pub id: String,
    pub title: String,
    pub panel_html: String,
    pub settings_html: String,
    #[serde(skip_serializing)]
    pub script_js: String,
}

impl UiModule {
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
            panel_html: panel_html.to_string(),
            settings_html: settings_html.to_string(),
            script_js: script_js.to_string(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct UiModuleRegistry {
    modules: Vec<UiModule>,
}

impl UiModuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, module: UiModule) {
        if let Some(existing) = self.modules.iter_mut().find(|m| m.id == module.id) {
            *existing = module;
            return;
        }
        self.modules.push(module);
    }

    pub fn modules(&self) -> &[UiModule] {
        &self.modules
    }

    pub fn module_scripts_bundle(&self) -> String {
        self.modules
            .iter()
            .map(|module| module.script_js.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    pub fn with_builtin_modules() -> Self {
        let mut registry = Self::new();
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
        registry
    }
}

#[cfg(test)]
mod tests {
    use super::UiModuleRegistry;

    #[test]
    fn builtins_are_registered() {
        let registry = UiModuleRegistry::with_builtin_modules();
        let ids = registry
            .modules()
            .iter()
            .map(|m| m.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["intruder", "repeater", "decoder"]);
    }
}
