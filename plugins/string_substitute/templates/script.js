(function () {
  const PLUGIN_ID = "string-substitute";
  const VALID_SCOPES = new Set(["request", "response", "both"]);

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

  function createRuleRow(rule = { search: "", replace: "", scope: "both" }) {
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
    remove.addEventListener("click", () => row.remove());

    row.appendChild(search);
    row.appendChild(replace);
    row.appendChild(scope);
    row.appendChild(remove);
    return row;
  }

  function readRulesFromContainer(container) {
    const rows = Array.from(container.querySelectorAll(".plugins-substitution-row"));
    return rows
      .map((row) => ({
        search: row.querySelector(".plugins-rule-search")?.value || "",
        replace: row.querySelector(".plugins-rule-replace")?.value || "",
        scope: normalizeScope(row.querySelector(".plugins-rule-scope")?.value || "both"),
      }))
      .filter((row) => row.search.length > 0);
  }

  function renderRuleRows(container, rules) {
    const root = container.querySelector(".plugin-rules");
    if (!root) return;
    root.innerHTML = "";
    if (!rules.length) {
      const empty = document.createElement("div");
      empty.className = "hint";
      empty.textContent = "No substitutions configured yet.";
      root.appendChild(empty);
      return;
    }
    for (const rule of rules) {
      root.appendChild(createRuleRow(rule));
    }
  }

  function createAlterationRowElement(row) {
    const div = document.createElement("div");
    div.className = "scroll-item";
    const when = row.unix_ms ? new Date(Number(row.unix_ms)).toLocaleTimeString() : "-";
    div.innerHTML = `
      <strong>${row.hook || "hook"}</strong> ${row.request_id || ""}<br>
      <small>${when}</small><br>
      <small>${row.summary || ""}</small>
    `;
    return div;
  }

  function renderAlterations(container, rows) {
    const root = container.querySelector(".plugin-alterations");
    if (!root) return;
    root.innerHTML = "";
    if (!Array.isArray(rows) || rows.length === 0) {
      root.innerHTML = '<div class="scroll-item">No recorded alterations yet.</div>';
      return;
    }
    for (const row of rows) {
      root.appendChild(createAlterationRowElement(row));
    }
  }

  function prependAlteration(container, row) {
    const root = container.querySelector(".plugin-alterations");
    if (!root) return;
    if (root.children.length === 1 && root.textContent.includes("No recorded alterations yet.")) {
      root.innerHTML = "";
    }
    root.prepend(createAlterationRowElement(row));
    while (root.children.length > 300) {
      root.removeChild(root.lastElementChild);
    }
  }

  window.RoxyPluginUI = window.RoxyPluginUI || {};
  window.RoxyPluginUI[PLUGIN_ID] = {
    init(container, settings, ctx) {
      renderRuleRows(container, normalizeRules(settings));

      const addBtn = container.querySelector(".plugin-add-rule");
      if (addBtn) {
        addBtn.addEventListener("click", () => {
          const root = container.querySelector(".plugin-rules");
          if (!root) return;
          const emptyHint = root.querySelector(".hint");
          if (emptyHint) emptyHint.remove();
          root.appendChild(createRuleRow());
        });
      }

      const refreshBtn = container.querySelector(".plugin-refresh-alterations");
      if (refreshBtn) {
        const self = window.RoxyPluginUI[PLUGIN_ID];
        refreshBtn.addEventListener("click", () => {
          self.loadAlterations(container, PLUGIN_ID, ctx);
        });
      }
    },
    readSettings(container, currentSettings) {
      return {
        ...(currentSettings || {}),
        rules: readRulesFromContainer(container),
      };
    },
    async loadAlterations(container, pluginId, ctx) {
      try {
        const rows = await ctx.api(
          `/plugins/${encodeURIComponent(pluginId)}/alterations?limit=300`
        );
        renderAlterations(container, rows);
      } catch (err) {
        renderAlterations(container, []);
        ctx.toast(`Load alterations failed: ${err.message}`);
      }
    },
    onRealtimeEvent(container, event) {
      if (event.event === "plugin_alteration_recorded" && event.payload) {
        prependAlteration(container, event.payload);
      }
    },
  };

  // Also register as a UI module for the settings panel rule count display.
  async function syncRuleCount(ctx) {
    const input = ctx.qs("setting-string-substitute-rule-count");
    if (!input) return;
    try {
      const settings = await ctx.api(
        "/plugins/" + encodeURIComponent(PLUGIN_ID) + "/settings"
      );
      const rules = normalizeRules(settings || {});
      input.value = String(rules.length);
    } catch (_) {
      input.value = "0";
    }
  }

  window.RoxyModuleHost.registerModule({
    id: "string-substitute",
    init(ctx) { syncRuleCount(ctx); },
    onSettingsLoaded(ctx) { syncRuleCount(ctx); },
  });
})();
