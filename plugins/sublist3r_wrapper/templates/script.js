(function () {
  const PLUGIN_ID = "sublist3r-wrapper";

  // ---- State ----
  let _lastResults = [];
  let _enumerating = false;
  let _currentScanId = null;

  // ---- Helpers ----

  function qs(container, sel) {
    return container.querySelector("." + sel);
  }

  function setStatus(container, msg, isError) {
    const el = qs(container, "sublist3r-status");
    if (!el) return;
    el.textContent = msg;
    el.style.color = isError ? "var(--color-danger, #e74c3c)" : "";
  }

  function createSubdomainRow(subdomain) {
    const div = document.createElement("div");
    div.className = "scroll-item sublist3r-sub-row";
    div.style.cssText = "display:flex;align-items:center;gap:.5rem;padding:.25rem .4rem;";

    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.className = "sublist3r-row-check";
    cb.value = subdomain;

    const label = document.createElement("span");
    label.textContent = subdomain;
    label.style.fontFamily = "var(--font-mono, monospace)";

    div.appendChild(cb);
    div.appendChild(label);
    return div;
  }

  function renderResults(container, data) {
    const section = container.querySelector("#plugins-sublist3r-results");
    const list = qs(container, "sublist3r-list");
    const countBadge = qs(container, "sublist3r-result-count");
    const sourcesEl = qs(container, "sublist3r-sources");
    if (!section || !list) return;

    _lastResults = data.subdomains || [];

    if (_lastResults.length === 0) {
      section.style.display = "";
      list.innerHTML = '<div class="scroll-item hint">No subdomains discovered.</div>';
      if (countBadge) countBadge.textContent = "0";
      if (sourcesEl) sourcesEl.textContent = "";
      return;
    }

    section.style.display = "";
    list.innerHTML = "";
    for (const sub of _lastResults) {
      list.appendChild(createSubdomainRow(sub));
    }
    if (countBadge) countBadge.textContent = String(_lastResults.length);
    if (sourcesEl) {
      const parts = [];
      if (data.sources && data.sources.length) {
        parts.push("Sources: " + data.sources.join(", "));
      }
      if (data.elapsed_seconds != null) {
        parts.push("Time: " + data.elapsed_seconds + "s");
      }
      if (data.errors && data.errors.length) {
        parts.push("Errors: " + data.errors.join("; "));
      }
      sourcesEl.textContent = parts.join("  |  ");
    }
  }

  function getSelectedSubdomains(container) {
    const checks = container.querySelectorAll(".sublist3r-row-check:checked");
    return Array.from(checks).map((cb) => cb.value);
  }

  async function addHostsToScope(ctx, hosts) {
    let added = 0;
    for (const host of hosts) {
      try {
        await ctx.api("/target/scope", {
          method: "POST",
          body: JSON.stringify({ host }),
        });
        added++;
      } catch (_) {
        // Scope add may fail for duplicates, continue.
      }
    }
    return added;
  }

  function clearLiveOutput(container) {
    const out = qs(container, "sublist3r-live-output");
    if (out) out.textContent = "";
    const details = container.querySelector(".sublist3r-output-details");
    if (details) details.open = true;
  }

  function appendLiveOutput(container, line) {
    const out = qs(container, "sublist3r-live-output");
    if (!out) return;
    const span = document.createElement("div");
    span.textContent = line;
    out.appendChild(span);
    out.scrollTop = out.scrollHeight;
    // Auto-open when first line arrives.
    const details = container.querySelector(".sublist3r-output-details");
    if (details && !details.open) details.open = true;
  }

  // ---- Enumerate action ----

  async function doEnumerate(container, ctx) {
    if (_enumerating) return;

    const domainInput = qs(container, "sublist3r-domain");
    const domain = (domainInput?.value || "").trim();
    if (!domain) {
      setStatus(container, "Enter a domain first.", true);
      return;
    }

    const btn = qs(container, "sublist3r-enumerate-btn");
    _enumerating = true;
    _currentScanId = null;
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Enumerating\u2026";
    }
    setStatus(container, "Enumerating subdomains for " + domain + "\u2026", false);
    clearLiveOutput(container);

    try {
      const resp = await ctx.api(
        `/plugins/${encodeURIComponent(PLUGIN_ID)}/invoke-stream`,
        {
          method: "POST",
          body: JSON.stringify({
            hook: "enumerate",
            payload: { domain },
          }),
        }
      );

      if (resp?.scan_id) {
        _currentScanId = resp.scan_id;
        appendLiveOutput(container, "[scan started: " + resp.scan_id.slice(0, 8) + "]");
      } else {
        // Fallback: endpoint returned an error before streaming started.
        setStatus(container, "Failed to start scan.", true);
        _enumerating = false;
        if (btn) {
          btn.disabled = false;
          btn.textContent = "Enumerate";
        }
      }
    } catch (err) {
      setStatus(container, "Enumerate failed: " + err.message, true);
      _enumerating = false;
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Enumerate";
      }
    }
    // NOTE: Button stays disabled until plugin_stream_complete arrives via WS.
  }

  // ---- RoxyPluginUI interface ----

  window.RoxyPluginUI = window.RoxyPluginUI || {};
  window.RoxyPluginUI[PLUGIN_ID] = {
    init(container, settings, ctx) {
      // Populate source checkboxes from settings.
      const optApi = qs(container, "sublist3r-opt-api");
      const optCrt = qs(container, "sublist3r-opt-crtsh");
      const optFull = qs(container, "sublist3r-opt-full");
      const optBrute = qs(container, "sublist3r-opt-brute");
      if (optApi) optApi.checked = settings.use_sublist3r_api !== false;
      if (optCrt) optCrt.checked = settings.use_crtsh !== false;
      if (optFull) optFull.checked = !!settings.use_full_sublist3r;
      if (optBrute) optBrute.checked = !!settings.bruteforce;

      // Enumerate button.
      const enumBtn = qs(container, "sublist3r-enumerate-btn");
      if (enumBtn) {
        enumBtn.addEventListener("click", () => doEnumerate(container, ctx));
      }

      // Allow Enter key on domain input.
      const domainInput = qs(container, "sublist3r-domain");
      if (domainInput) {
        domainInput.addEventListener("keydown", (e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            doEnumerate(container, ctx);
          }
        });
      }

      // Add All to Scope.
      const addAllBtn = qs(container, "sublist3r-add-all");
      if (addAllBtn) {
        addAllBtn.addEventListener("click", async () => {
          if (!_lastResults.length) {
            ctx.toast("No subdomains to add.");
            return;
          }
          addAllBtn.disabled = true;
          addAllBtn.textContent = "Adding\u2026";
          try {
            const added = await addHostsToScope(ctx, _lastResults);
            ctx.toast(`Added ${added} host${added !== 1 ? "s" : ""} to scope.`);
          } catch (err) {
            ctx.toast("Failed: " + err.message);
          } finally {
            addAllBtn.disabled = false;
            addAllBtn.textContent = "Add All to Scope";
          }
        });
      }

      // Add Selected to Scope.
      const addSelectedBtn = qs(container, "sublist3r-add-selected");
      if (addSelectedBtn) {
        addSelectedBtn.addEventListener("click", async () => {
          const selected = getSelectedSubdomains(container);
          if (!selected.length) {
            ctx.toast("No subdomains selected.");
            return;
          }
          addSelectedBtn.disabled = true;
          addSelectedBtn.textContent = "Adding\u2026";
          try {
            const added = await addHostsToScope(ctx, selected);
            ctx.toast(`Added ${added} host${added !== 1 ? "s" : ""} to scope.`);
          } catch (err) {
            ctx.toast("Failed: " + err.message);
          } finally {
            addSelectedBtn.disabled = false;
            addSelectedBtn.textContent = "Add Selected to Scope";
          }
        });
      }

      // Select All toggle.
      const selectAllCb = qs(container, "sublist3r-select-all");
      if (selectAllCb) {
        selectAllCb.addEventListener("change", () => {
          const checks = container.querySelectorAll(".sublist3r-row-check");
          for (const cb of checks) {
            cb.checked = selectAllCb.checked;
          }
        });
      }
    },

    readSettings(container, currentSettings) {
      return {
        ...(currentSettings || {}),
        use_sublist3r_api: qs(container, "sublist3r-opt-api")?.checked !== false,
        use_crtsh: qs(container, "sublist3r-opt-crtsh")?.checked !== false,
        use_full_sublist3r: !!qs(container, "sublist3r-opt-full")?.checked,
        bruteforce: !!qs(container, "sublist3r-opt-brute")?.checked,
      };
    },

    loadAlterations() {
      // No alterations tracking for this plugin.
    },

    onRealtimeEvent(container, event, ctx) {
      if (!event || !event.payload) return;
      const payload = event.payload;

      // Only handle events for our current scan.
      if (payload.plugin !== PLUGIN_ID) return;
      if (_currentScanId && payload.scan_id !== _currentScanId) return;

      if (event.event === "plugin_stream_output") {
        // Parse the line — Python emits JSON with a "message" field.
        let msg = payload.line || "";
        try {
          const parsed = JSON.parse(msg);
          msg = parsed.message || msg;
        } catch (_) {
          // Plain text line, use as-is.
        }
        appendLiveOutput(container, msg);
        return;
      }

      if (event.event === "plugin_stream_complete") {
        appendLiveOutput(container, "[scan complete]");

        const btn = qs(container, "sublist3r-enumerate-btn");
        _enumerating = false;
        _currentScanId = null;
        if (btn) {
          btn.disabled = false;
          btn.textContent = "Enumerate";
        }

        const outcome = payload.result || {};
        if (outcome.error) {
          setStatus(container, "Error: " + outcome.error, true);
          return;
        }

        const result =
          outcome?.plugin_result?.output?.result ||
          outcome?.plugin_result?.result ||
          outcome?.result ||
          {};

        if (result.error) {
          setStatus(container, "Error: " + result.error, true);
          return;
        }

        renderResults(container, result);
        const count = (result.subdomains || []).length;
        setStatus(
          container,
          `Found ${count} subdomain${count !== 1 ? "s" : ""} for ${result.domain || "unknown"}.`,
          false
        );
        return;
      }
    },
  };

  // Register for settings panel.
  window.RoxyModuleHost.registerModule({
    id: "sublist3r",
    init() {},
    onSettingsLoaded() {},
  });
})();
