(() => {
  const STRING_PLUGIN = "string-substitute";
  const VALID_SCOPES = new Set(["request", "response", "both"]);

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

  function normalizeScope(value) {
    const scope = String(value || "both").toLowerCase();
    return VALID_SCOPES.has(scope) ? scope : "both";
  }

  function normalizeRules(settings) {
    if (!settings || typeof settings !== "object") {
      return [];
    }

    if (Array.isArray(settings.rules)) {
      return settings.rules
        .map((row) => ({
          search: String(row?.search || ""),
          replace: String(row?.replace || ""),
          scope: normalizeScope(row?.scope),
        }))
        .filter((row) => row.search.length > 0);
    }

    // Legacy compatibility for older demo-substitute settings.
    const out = [];
    const requestSearch = String(settings.request_search || "");
    if (requestSearch) {
      out.push({
        search: requestSearch,
        replace: String(settings.request_replace || ""),
        scope: "request",
      });
    }
    const responseSearch = String(settings.response_search || "");
    if (responseSearch) {
      out.push({
        search: responseSearch,
        replace: String(settings.response_replace || ""),
        scope: "response",
      });
    }
    return out;
  }

  function readRulesFromUi(ctx) {
    const root = ctx.qs("plugins-string-substitute-rules");
    const rows = root ? Array.from(root.querySelectorAll(".plugins-substitution-row")) : [];
    return rows
      .map((row) => ({
        search: row.querySelector(".plugins-rule-search")?.value || "",
        replace: row.querySelector(".plugins-rule-replace")?.value || "",
        scope: normalizeScope(row.querySelector(".plugins-rule-scope")?.value || "both"),
      }))
      .filter((row) => row.search.length > 0);
  }

  function updateSettingsJsonFromRuleUi(ctx) {
    if (selectedPluginId(ctx) !== STRING_PLUGIN) {
      return;
    }
    const current = safeParseJson(ctx.qs("plugins-settings-json").value || "{}", {});
    current.rules = readRulesFromUi(ctx);
    ctx.qs("plugins-settings-json").value = JSON.stringify(current, null, 2);
  }

  function createRuleRow(ctx, rule = { search: "", replace: "", scope: "both" }) {
    const row = document.createElement("div");
    row.className = "plugins-substitution-row";

    const search = document.createElement("input");
    search.className = "plugins-rule-search";
    search.placeholder = "Search";
    search.value = String(rule.search || "");

    const replace = document.createElement("input");
    replace.className = "plugins-rule-replace";
    replace.placeholder = "Replace";
    replace.value = String(rule.replace || "");

    const scope = document.createElement("select");
    scope.className = "plugins-rule-scope";
    for (const value of ["both", "request", "response"]) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = value;
      scope.appendChild(option);
    }
    scope.value = normalizeScope(rule.scope);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "warn plugins-rule-remove";
    remove.textContent = "Remove";

    const onEdit = () => updateSettingsJsonFromRuleUi(ctx);
    search.addEventListener("input", onEdit);
    replace.addEventListener("input", onEdit);
    scope.addEventListener("change", onEdit);
    remove.addEventListener("click", () => {
      row.remove();
      updateSettingsJsonFromRuleUi(ctx);
    });

    row.appendChild(search);
    row.appendChild(replace);
    row.appendChild(scope);
    row.appendChild(remove);
    return row;
  }

  function renderRuleRows(ctx, rules) {
    const root = ctx.qs("plugins-string-substitute-rules");
    root.innerHTML = "";
    if (!rules.length) {
      const empty = document.createElement("div");
      empty.className = "hint";
      empty.textContent = "No substitutions configured yet.";
      root.appendChild(empty);
      return;
    }
    for (const rule of rules) {
      root.appendChild(createRuleRow(ctx, rule));
    }
  }

  function syncStringSubstituteContextFromSettings(ctx, settings) {
    const visible = selectedPluginId(ctx) === STRING_PLUGIN;
    const wrap = ctx.qs("plugins-string-substitute-settings");
    wrap.style.display = visible ? "block" : "none";
    if (!visible) {
      return;
    }

    renderRuleRows(ctx, normalizeRules(settings));
    updateSettingsJsonFromRuleUi(ctx);
  }

  function syncSettingsFromStringSubstituteContext(ctx, settings) {
    if (selectedPluginId(ctx) !== STRING_PLUGIN) {
      return settings;
    }
    return {
      ...settings,
      rules: readRulesFromUi(ctx),
    };
  }

  function renderAlterations(ctx, rows) {
    const root = ctx.qs("plugins-alterations");
    root.innerHTML = "";

    if (!Array.isArray(rows) || rows.length === 0) {
      root.innerHTML = '<div class="scroll-item">No recorded alterations yet.</div>';
      return;
    }

    for (const row of rows) {
      const div = document.createElement("div");
      div.className = "scroll-item";
      const when = row.unix_ms ? new Date(Number(row.unix_ms)).toLocaleTimeString() : "-";
      div.innerHTML = `
        <strong>${row.hook || "hook"}</strong> ${row.request_id || ""}<br>
        <small>${when}</small><br>
        <small>${row.summary || ""}</small>
      `;
      root.appendChild(div);
    }
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
    } else if (rows.some((row) => row.name === STRING_PLUGIN)) {
      select.value = STRING_PLUGIN;
    } else {
      select.selectedIndex = 0;
    }
    window.__roxySelectedPlugin = select.value || "";
  }

  async function loadSettings(ctx) {
    const pluginId = selectedPluginId(ctx);
    if (!pluginId) {
      ctx.qs("plugins-settings-json").value = "{}";
      syncStringSubstituteContextFromSettings(ctx, {});
      return;
    }

    try {
      const settings = await ctx.api(`/plugins/${encodeURIComponent(pluginId)}/settings`);
      ctx.qs("plugins-settings-json").value = JSON.stringify(settings || {}, null, 2);
      syncStringSubstituteContextFromSettings(ctx, settings || {});
    } catch (err) {
      ctx.qs("plugins-settings-json").value = "{}";
      syncStringSubstituteContextFromSettings(ctx, {});
      ctx.toast(`Load plugin settings failed: ${err.message}`);
    }
  }

  async function loadAlterations(ctx) {
    const pluginId = selectedPluginId(ctx);
    if (!pluginId) {
      renderAlterations(ctx, []);
      return;
    }

    try {
      const rows = await ctx.api(`/plugins/${encodeURIComponent(pluginId)}/alterations?limit=300`);
      renderAlterations(ctx, rows);
    } catch (err) {
      renderAlterations(ctx, []);
      ctx.toast(`Load alterations failed: ${err.message}`);
    }
  }

  async function saveSettings(ctx) {
    const pluginId = selectedPluginId(ctx);
    if (!pluginId) {
      ctx.toast("Select a plugin first.");
      return;
    }

    const input = ctx.qs("plugins-settings-json").value || "{}";
    let settings = safeParseJson(input, null);
    if (!settings) {
      ctx.toast("Settings must be valid JSON object.");
      return;
    }

    settings = syncSettingsFromStringSubstituteContext(ctx, settings);

    try {
      await ctx.api(`/plugins/${encodeURIComponent(pluginId)}/settings`, {
        method: "PUT",
        body: JSON.stringify(settings),
      });
      ctx.qs("plugins-settings-json").value = JSON.stringify(settings, null, 2);
      ctx.toast("Plugin settings saved");
      await loadAlterations(ctx);
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
        await loadSettings(ctx);
        await loadAlterations(ctx);
      });
      ctx.qs("plugins-refresh-alterations").addEventListener("click", () => loadAlterations(ctx));
      ctx.qs("plugins-select").addEventListener("change", async () => {
        window.__roxySelectedPlugin = selectedPluginId(ctx);
        if (window.__roxySelectedPlugin) {
          localStorage.setItem("roxy-selected-plugin-v1", window.__roxySelectedPlugin);
        }
        await loadSettings(ctx);
        await loadAlterations(ctx);
      });
      ctx.qs("plugins-save-settings").addEventListener("click", () => saveSettings(ctx));
      ctx.qs("plugins-string-substitute-add-rule").addEventListener("click", () => {
        const root = ctx.qs("plugins-string-substitute-rules");
        const emptyHint = root.querySelector(".hint");
        if (emptyHint) {
          emptyHint.remove();
        }
        root.appendChild(createRuleRow(ctx));
        updateSettingsJsonFromRuleUi(ctx);
      });

      onSettingsLoaded(ctx);
      await loadPlugins(ctx);
      await loadSettings(ctx);
      await loadAlterations(ctx);
    },
    async refresh(ctx) {
      await loadPlugins(ctx);
      await loadAlterations(ctx);
    },
    refreshIntervalMs(ctx) {
      return Number(ctx.getModuleSetting("refresh_ms", 4000));
    },
    onSettingsLoaded,
    onSettingsSave,
  });
})();
