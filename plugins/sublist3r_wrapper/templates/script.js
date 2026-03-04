(function () {
  const PLUGIN_ID = "sublist3r-wrapper";

  // ---- Per-job state (supports multiple parallel enumerations) ----
  const _jobs = new Map();       // scanId → { target, domain, status, startTime, subdomains, count, sources, errors, elapsed, error }
  let _selectedJobId = null;     // which job's results are displayed
  let _lastResults = [];         // subdomains of the selected job
  let _container = null;         // saved by init() for queueUrl()
  let _ctx = null;
  let _timerHandle = null;

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

  function extractDomain(urlOrDomain) {
    let d = urlOrDomain.trim().toLowerCase();
    try { d = new URL(d).hostname; } catch (_) {
      d = d.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
    }
    return d;
  }

  // ---- Jobs tracking ----

  function runningCount() {
    let n = 0;
    for (const j of _jobs.values()) if (j.status === "running") n++;
    return n;
  }

  function fmtTime(ms) {
    const s = Math.round(ms / 1000);
    return s >= 60 ? Math.floor(s / 60) + "m " + (s % 60) + "s" : s + "s";
  }

  function renderJobs(container) {
    const list = qs(container, "sublist3r-jobs-list");
    if (!list) return;
    list.innerHTML = "";
    const badge = qs(container, "sublist3r-jobs-count");
    if (badge) {
      const r = runningCount();
      badge.textContent = r > 0 ? r + " running / " + _jobs.size + " total" : String(_jobs.size || "");
    }
    const section = container.querySelector("#plugins-sublist3r-jobs");
    if (section) section.style.display = _jobs.size ? "" : "none";
    if (_jobs.size === 0) return;

    for (const [id, job] of [..._jobs.entries()].reverse()) {
      const row = document.createElement("div");
      row.className = "scroll-item";
      const sel = id === _selectedJobId;
      row.style.cssText =
        "display:flex;align-items:center;gap:.5rem;padding:.35rem .5rem;cursor:pointer;" +
        "border-left:3px solid " + (sel ? "var(--color-accent,#3498db)" : "transparent") + ";" +
        "background:" + (sel ? "var(--color-surface-alt,rgba(52,152,219,.08))" : "transparent") + ";";

      const dot = document.createElement("span");
      dot.style.cssText = "flex-shrink:0;font-size:.85rem;";
      if (job.status === "running") { dot.textContent = "\u25cf"; dot.style.color = "#f39c12"; }
      else if (job.status === "done") { dot.textContent = "\u2713"; dot.style.color = "#2ecc71"; }
      else { dot.textContent = "\u2717"; dot.style.color = "#e74c3c"; }

      const lbl = document.createElement("span");
      lbl.textContent = job.domain;
      lbl.title = job.target;
      lbl.style.cssText =
        "flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" +
        "font-family:var(--font-mono,monospace);font-size:.82rem;";

      const meta = document.createElement("span");
      meta.style.cssText = "font-size:.72rem;color:var(--color-muted,#888);white-space:nowrap;";
      if (job.status === "running") meta.textContent = fmtTime(Date.now() - job.startTime);
      else if (job.status === "done") meta.textContent = (job.count || 0) + " subs";
      else meta.textContent = "error";

      row.append(dot, lbl, meta);
      row.addEventListener("click", () => selectJob(container, id));
      list.appendChild(row);
    }
  }

  function selectJob(container, scanId) {
    _selectedJobId = scanId;
    renderJobs(container);
    const job = _jobs.get(scanId);
    if (!job) return;
    if (job.status === "done" && job.subdomains) {
      renderResults(container, {
        subdomains: job.subdomains, count: job.count,
        sources: job.sources, errors: job.errors, elapsed_seconds: job.elapsed, domain: job.domain,
      });
    } else if (job.status === "error") {
      setStatus(container, "Error: " + (job.error || "unknown"), true);
      const sect = container.querySelector("#plugins-sublist3r-results");
      if (sect) sect.style.display = "none";
    }
  }

  function ensureTimerRunning(container) {
    if (_timerHandle) return;
    _timerHandle = setInterval(() => {
      if (runningCount() > 0) renderJobs(container);
      else { clearInterval(_timerHandle); _timerHandle = null; }
    }, 1000);
  }

  // ---- Enumerate action (parallel — does NOT block on running scans) ----

  async function doEnumerate(container, ctx, targetUrl) {
    const raw = targetUrl || (qs(container, "sublist3r-domain")?.value || "").trim();
    if (!raw) {
      setStatus(container, "Enter a domain or URL first.", true);
      return;
    }

    const domain = extractDomain(raw);

    // Prevent duplicate scan on the same domain.
    for (const j of _jobs.values()) {
      if (j.status === "running" && j.domain === domain) {
        setStatus(container, "Already enumerating " + domain + ".", true);
        return;
      }
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
            payload: { domain, url: raw },
          }),
        }
      );

      if (resp?.scan_id) {
        _jobs.set(resp.scan_id, {
          target: raw, domain, status: "running", startTime: Date.now(),
          subdomains: null, count: 0, sources: null, errors: null, elapsed: null, error: null,
        });
        _selectedJobId = resp.scan_id;
        renderJobs(container);
        ensureTimerRunning(container);
        appendLiveOutput(container, "[" + resp.scan_id.slice(0, 8) + "] Enumerating: " + domain);
        // Clear input for next target.
        const inp = qs(container, "sublist3r-domain");
        if (inp && !targetUrl) inp.value = "";
      } else {
        setStatus(container, "Failed to start scan.", true);
      }
    } catch (err) {
      setStatus(container, "Enumerate failed: " + err.message, true);
    }
    // NOTE: Scan runs in background; results arrive via WS events.
  }

  // ---- RoxyPluginUI interface ----

  window.RoxyPluginUI = window.RoxyPluginUI || {};
  window.RoxyPluginUI[PLUGIN_ID] = {
    /** Queue a URL for subdomain enumeration (called externally, e.g. from request context menu). */
    queueUrl(url) {
      if (_container && _ctx) doEnumerate(_container, _ctx, url);
    },

    init(container, settings, ctx) {
      _container = container;
      _ctx = ctx;

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

      // Initially hide jobs section until first scan.
      const jobsSection = container.querySelector("#plugins-sublist3r-jobs");
      if (jobsSection) jobsSection.style.display = "none";

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
      const p = event.payload;
      if (p.plugin !== PLUGIN_ID) return;

      const scanId = p.scan_id;
      const job = scanId ? _jobs.get(scanId) : null;

      if (event.event === "plugin_stream_output") {
        const raw = p.line || "";
        try {
          const parsed = JSON.parse(raw);
          if (parsed.message && scanId === _selectedJobId) {
            appendLiveOutput(container, parsed.message);
          }
        } catch (_) {}
        return;
      }

      if (event.event === "plugin_stream_complete") {
        if (scanId === _selectedJobId) {
          appendLiveOutput(container, "[scan complete]");
        }

        const outcome = p.result || {};
        const result =
          outcome?.plugin_result?.output?.result ||
          outcome?.plugin_result?.result ||
          outcome?.result || {};

        if (job) {
          if (result.error || outcome.error) {
            job.status = "error";
            job.error = result.error || outcome.error;
          } else {
            job.status = "done";
            job.subdomains = result.subdomains || [];
            job.count = (result.subdomains || []).length;
            job.sources = result.sources;
            job.errors = result.errors;
            job.elapsed = result.elapsed_seconds;
          }
        }

        renderJobs(container);

        if (scanId === _selectedJobId && job) {
          if (job.status === "done") {
            renderResults(container, {
              subdomains: job.subdomains, count: job.count,
              sources: job.sources, errors: job.errors,
              elapsed_seconds: job.elapsed, domain: job.domain,
            });
            const count = job.count || 0;
            setStatus(container,
              "Found " + count + " subdomain" + (count !== 1 ? "s" : "") +
              " for " + job.domain + ".", false);
          } else {
            setStatus(container, "Error: " + (job.error || outcome.error || "unknown"), true);
          }
        }
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
