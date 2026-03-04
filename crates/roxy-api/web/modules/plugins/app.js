(() => {
  let _settingsJson = "{}";
  let _loadedPluginTemplate = null;

  function selectedPluginId(ctx) {
    return ctx.qs("plugins-select")?.value || "";
  }

  function safeParseJson(text, fallback = {}) {
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
      return fallback;
    } catch {
      return fallback;
    }
  }

  function getPluginUI(pluginId) {
    return (window.RoxyPluginUI && window.RoxyPluginUI[pluginId]) || null;
  }

  async function loadPlugins(ctx) {
    const select = ctx.qs("plugins-select");
    const rows = await ctx.api("/plugins");
    const current = select.value;
    const preferred =
      window.__roxySelectedPlugin || localStorage.getItem("roxy-selected-plugin-v1") || "";
    select.innerHTML = "";

    if (!rows.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No plugins registered";
      select.appendChild(option);
      select.value = "";
      return;
    }

    for (const row of rows) {
      const option = document.createElement("option");
      option.value = row.name;
      option.textContent = row.name;
      select.appendChild(option);
    }

    if (rows.some((row) => row.name === current)) {
      select.value = current;
    } else if (preferred && rows.some((row) => row.name === preferred)) {
      select.value = preferred;
    } else {
      select.selectedIndex = 0;
    }
    window.__roxySelectedPlugin = select.value || "";
  }

  async function loadPluginTemplate(ctx, pluginId) {
    const container = ctx.qs("plugins-template-container");
    container.innerHTML = "";
    _loadedPluginTemplate = null;

    if (!pluginId) {
      container.innerHTML = '<p class="hint">Select a plugin to configure.</p>';
      return;
    }

    try {
      const html = await fetch(`/api/v1/plugins/${encodeURIComponent(pluginId)}/template/panel.html`);
      if (!html.ok) {
        container.innerHTML = '<p class="hint">No custom settings UI for this plugin.</p>';
        return;
      }
      const htmlText = await html.text();
      container.innerHTML = htmlText;

      // Load and execute the plugin script if not already loaded.
      if (!getPluginUI(pluginId)) {
        try {
          const jsResp = await fetch(`/api/v1/plugins/${encodeURIComponent(pluginId)}/template/script.js`);
          if (jsResp.ok) {
            const jsText = await jsResp.text();
            const script = document.createElement("script");
            script.textContent = jsText;
            document.head.appendChild(script);
          }
        } catch (_) {
          // Script is optional.
        }
      }

      _loadedPluginTemplate = pluginId;
    } catch (_) {
      container.innerHTML = '<p class="hint">No custom settings UI for this plugin.</p>';
    }
  }

  async function loadSettings(ctx) {
    const pluginId = selectedPluginId(ctx);

    // Load the plugin template if it changed.
    if (_loadedPluginTemplate !== pluginId) {
      await loadPluginTemplate(ctx, pluginId);
    }

    if (!pluginId) {
      _settingsJson = "{}";
      return;
    }

    try {
      const settings = await ctx.api(`/plugins/${encodeURIComponent(pluginId)}/settings`);
      _settingsJson = JSON.stringify(settings || {}, null, 2);

      // Initialize plugin UI with settings.
      const ui = getPluginUI(pluginId);
      const container = ctx.qs("plugins-template-container");
      if (ui && ui.init) {
        ui.init(container, settings || {}, ctx);
      }

      // Deliver any pending request sent via the right-click context menu.
      if (
        window.__roxyPendingPluginRequest &&
        window.__roxyPendingPluginRequest.pluginName === pluginId
      ) {
        const pending = window.__roxyPendingPluginRequest;
        window.__roxyPendingPluginRequest = null;
        if (ui && typeof ui.onRequestReceived === "function") {
          try {
            ui.onRequestReceived(container, pending.request, ctx);
          } catch (err) {
            ctx.toast(`Plugin failed to receive request: ${err.message}`);
          }
        }
      }

      if (ui && ui.loadAlterations) {
        ui.loadAlterations(container, pluginId, ctx);
      }
    } catch (err) {
      _settingsJson = "{}";
      ctx.toast(`Load plugin settings failed: ${err.message}`);
    }
  }

  async function loadAlterations(ctx) {
    const pluginId = selectedPluginId(ctx);
    const ui = getPluginUI(pluginId);
    if (ui && ui.loadAlterations) {
      const container = ctx.qs("plugins-template-container");
      ui.loadAlterations(container, pluginId, ctx);
    }
  }

  async function saveSettings(ctx) {
    const pluginId = selectedPluginId(ctx);
    if (!pluginId) {
      ctx.toast("Select a plugin first.");
      return;
    }

    let settings = safeParseJson(_settingsJson, null);
    if (!settings) {
      settings = {};
    }

    // Let the plugin UI merge its settings.
    const ui = getPluginUI(pluginId);
    if (ui && ui.readSettings) {
      const container = ctx.qs("plugins-template-container");
      settings = ui.readSettings(container, settings);
    }

    try {
      await ctx.api(`/plugins/${encodeURIComponent(pluginId)}/settings`, {
        method: "PUT",
        body: JSON.stringify(settings),
      });
      _settingsJson = JSON.stringify(settings, null, 2);
      ctx.toast("Plugin settings saved");
      const savedUi = getPluginUI(pluginId);
      if (savedUi && savedUi.loadAlterations) {
        savedUi.loadAlterations(ctx.qs("plugins-template-container"), pluginId, ctx);
      }
    } catch (err) {
      ctx.toast(`Save settings failed: ${err.message}`);
    }
  }

  function onSettingsLoaded(ctx) {
    const refreshMs = Number(ctx.getModuleSetting("refresh_ms", 4000));
    if (ctx.qs("setting-plugins-refresh-ms")) {
      ctx.qs("setting-plugins-refresh-ms").value = String(refreshMs);
    }
  }

  function onSettingsSave(ctx) {
    const refreshMs = Number(ctx.qs("setting-plugins-refresh-ms")?.value || 4000);
    const normalizedRefresh = Number.isFinite(refreshMs) ? Math.max(1000, refreshMs) : 4000;
    ctx.setModuleSetting("refresh_ms", normalizedRefresh);
  }

  window.RoxyModuleHost.registerModule({
    id: "plugins",
    async init(ctx) {
      ctx.qs("plugins-refresh").addEventListener("click", async () => {
        await loadPlugins(ctx);
        _loadedPluginTemplate = null;
        await loadSettings(ctx);
      });
      ctx.qs("plugins-select").addEventListener("change", async () => {
        window.__roxySelectedPlugin = selectedPluginId(ctx);
        if (window.__roxySelectedPlugin) {
          localStorage.setItem("roxy-selected-plugin-v1", window.__roxySelectedPlugin);
        }
        _loadedPluginTemplate = null;
        await loadSettings(ctx);
      });
      ctx.qs("plugins-save-settings").addEventListener("click", () => saveSettings(ctx));

      onSettingsLoaded(ctx);
      await loadPlugins(ctx);
      await loadSettings(ctx);
    },
    async refresh(ctx) {
      await loadPlugins(ctx);
    },
    refreshIntervalMs() {
      return 0;
    },
    async onRealtimeEvent(ctx, event) {
      if (!event || typeof event !== "object") {
        return;
      }

      if (event.event === "plugin_alteration_recorded" && event.payload) {
        const altPluginId = event.payload.plugin;
        if (selectedPluginId(ctx) === altPluginId) {
          const altUi = getPluginUI(altPluginId);
          if (altUi && altUi.onRealtimeEvent) {
            altUi.onRealtimeEvent(ctx.qs("plugins-template-container"), event, ctx);
          }
        }
        return;
      }

      if (
        (event.event === "plugin_stream_output" || event.event === "plugin_stream_complete") &&
        event.payload
      ) {
        const streamPluginId = event.payload.plugin;
        if (selectedPluginId(ctx) === streamPluginId) {
          const streamUi = getPluginUI(streamPluginId);
          if (streamUi && streamUi.onRealtimeEvent) {
            streamUi.onRealtimeEvent(ctx.qs("plugins-template-container"), event, ctx);
          }
        }
        return;
      }

      if (event.event === "plugin_registered" || event.event === "plugin_unregistered") {
        await loadPlugins(ctx);
        _loadedPluginTemplate = null;
        await loadSettings(ctx);
        return;
      }

      if (event.event === "plugin_settings_updated" && event.payload?.name === selectedPluginId(ctx)) {
        await loadSettings(ctx);
      }
    },
    onSettingsLoaded,
    onSettingsSave,
  });
})();
