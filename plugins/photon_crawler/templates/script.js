(function () {
  const PLUGIN_ID = "photon-crawler";

  // ---- Per-job state (supports multiple parallel crawls) ----
  const _jobs = new Map();       // scanId → { target, status, startTime, results, summary, totalFindings, error, elapsed }
  let _selectedJobId = null;     // which job's results are displayed
  let _lastResults = {};         // results of the selected job (for tab rendering)
  let _activeCategory = "internal";
  let _container = null;         // saved by init() for queueUrl()
  let _ctx = null;
  let _timerHandle = null;

  // ---- Helpers ----

  function qs(container, sel) {
    return container.querySelector("." + sel);
  }

  function qsAll(container, sel) {
    return container.querySelectorAll("." + sel);
  }

  function setStatus(container, msg, isError) {
    const el = qs(container, "photon-status");
    if (!el) return;
    el.textContent = msg;
    el.style.color = isError ? "var(--color-danger, #e74c3c)" : "";
  }

  function clearLiveOutput(container) {
    const out = qs(container, "photon-live-output");
    if (out) out.textContent = "";
    const details = container.querySelector(".photon-output-details");
    if (details) details.open = true;
  }

  function appendLiveOutput(container, line) {
    const out = qs(container, "photon-live-output");
    if (!out) return;
    const div = document.createElement("div");
    div.textContent = line;
    out.appendChild(div);
    out.scrollTop = out.scrollHeight;
    const details = container.querySelector(".photon-output-details");
    if (details && !details.open) details.open = true;
  }

  function extractHost(urlStr) {
    try { return new URL(urlStr).hostname; }
    catch (_) { return urlStr.replace(/^https?:\/\//, "").split("/")[0].split(":")[0]; }
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
    const list = qs(container, "photon-jobs-list");
    if (!list) return;
    list.innerHTML = "";
    const badge = qs(container, "photon-jobs-count");
    if (badge) {
      const r = runningCount();
      badge.textContent = r > 0 ? r + " running / " + _jobs.size + " total" : String(_jobs.size || "");
    }
    const section = container.querySelector("#plugins-photon-jobs");
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
      lbl.textContent = extractHost(job.target);
      lbl.title = job.target;
      lbl.style.cssText =
        "flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" +
        "font-family:var(--font-mono,monospace);font-size:.82rem;";

      const meta = document.createElement("span");
      meta.style.cssText = "font-size:.72rem;color:var(--color-muted,#888);white-space:nowrap;";
      if (job.status === "running") meta.textContent = fmtTime(Date.now() - job.startTime);
      else if (job.status === "done") meta.textContent = (job.totalFindings || 0) + " findings";
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
    if (job.status === "done" && job.results) {
      renderResults(container, {
        results: job.results, summary: job.summary,
        total_findings: job.totalFindings, elapsed_seconds: job.elapsed, url: job.target,
      });
    } else if (job.status === "error") {
      setStatus(container, "Error: " + (job.error || "unknown"), true);
      const sect = container.querySelector("#plugins-photon-results");
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

  // ---- Results rendering ----

  const CATEGORY_LABELS = {
    internal: "Internal URLs",
    external: "External URLs",
    fuzzable: "Fuzzable URLs",
    endpoints: "JS Endpoints",
    intel: "Intel",
    files: "Files",
    scripts: "JS Files",
    keys: "Secret Keys",
    robots: "Robots.txt",
    custom: "Custom Regex",
    subdomains: "Subdomains",
  };

  const CATEGORY_COLORS = {
    internal: "#3498db",
    external: "#9b59b6",
    fuzzable: "#e67e22",
    endpoints: "#1abc9c",
    intel: "#e74c3c",
    files: "#2ecc71",
    scripts: "#f1c40f",
    keys: "#e74c3c",
    robots: "#95a5a6",
    custom: "#8e44ad",
    subdomains: "#2980b9",
  };

  function renderSummary(container, summary) {
    const el = qs(container, "photon-summary");
    if (!el) return;
    el.innerHTML = "";

    for (const [cat, count] of Object.entries(summary)) {
      if (count === 0) continue;
      const chip = document.createElement("span");
      chip.className = "badge";
      chip.style.cssText =
        "font-size:.75rem;padding:.15rem .4rem;border-radius:3px;" +
        "background:" + (CATEGORY_COLORS[cat] || "#555") + ";color:#fff;cursor:pointer;";
      chip.textContent = (CATEGORY_LABELS[cat] || cat) + ": " + count;
      chip.title = "Click to view " + (CATEGORY_LABELS[cat] || cat);
      chip.addEventListener("click", () => switchTab(container, cat));
      el.appendChild(chip);
    }
  }

  function switchTab(container, cat) {
    _activeCategory = cat;

    // Update tab button active states.
    const tabs = qsAll(container, "photon-tab");
    for (const tab of tabs) {
      if (tab.dataset.cat === cat) {
        tab.classList.add("active");
        tab.style.fontWeight = "700";
      } else {
        tab.classList.remove("active");
        tab.style.fontWeight = "";
      }
    }

    renderCategoryList(container, cat);
  }

  function renderCategoryList(container, cat) {
    const list = qs(container, "photon-results-list");
    if (!list) return;
    list.innerHTML = "";

    const items = _lastResults[cat] || [];
    if (items.length === 0) {
      list.innerHTML =
        '<div class="scroll-item hint">No items in ' +
        (CATEGORY_LABELS[cat] || cat) +
        ".</div>";
      return;
    }

    for (const item of items) {
      const row = document.createElement("div");
      row.className = "scroll-item";
      row.style.cssText =
        "padding:.2rem .4rem;word-break:break-all;border-bottom:1px solid var(--color-border,#333);";

      // Make URLs clickable.
      if (typeof item === "string" && /^https?:\/\//i.test(item)) {
        const a = document.createElement("a");
        a.href = item;
        a.target = "_blank";
        a.rel = "noopener";
        a.textContent = item;
        a.style.color = "inherit";
        row.appendChild(a);
      } else {
        row.textContent = String(item);
      }
      list.appendChild(row);
    }
  }

  function renderResults(container, data) {
    const section = container.querySelector("#plugins-photon-results");
    if (!section) return;

    _lastResults = data.results || {};
    const summary = data.summary || {};

    section.style.display = "";

    // Total badge.
    const totalBadge = qs(container, "photon-total-count");
    if (totalBadge) totalBadge.textContent = String(data.total_findings || 0);

    // Summary chips.
    renderSummary(container, summary);

    // Elapsed.
    const elapsedEl = qs(container, "photon-elapsed");
    if (elapsedEl) {
      const parts = [];
      if (data.elapsed_seconds != null) parts.push("Time: " + data.elapsed_seconds + "s");
      if (data.url) parts.push("Target: " + data.url);
      elapsedEl.textContent = parts.join("  |  ");
    }

    // Pick the first non-empty category for initial display.
    const cats = [
      "internal", "external", "fuzzable", "endpoints", "intel",
      "files", "scripts", "keys", "robots", "custom", "subdomains",
    ];
    let firstCat = "internal";
    for (const c of cats) {
      if ((_lastResults[c] || []).length > 0) {
        firstCat = c;
        break;
      }
    }

    switchTab(container, firstCat);
  }

  // ---- Scope actions ----

  async function addUrlsToScope(ctx, urls) {
    let added = 0;
    for (const url of urls) {
      try {
        // Extract host from URL.
        let host;
        try {
          host = new URL(url).hostname;
        } catch (_) {
          host = url;
        }
        await ctx.api("/target/scope", {
          method: "POST",
          body: JSON.stringify({ host }),
        });
        added++;
      } catch (_) {
        // Duplicates or invalid entries — continue.
      }
    }
    return added;
  }

  // ---- Gather current options from the UI ----

  function gatherOptions(container) {
    const val = (cls, fallback) => {
      const el = qs(container, cls);
      return el ? el.value : fallback;
    };
    const checked = (cls) => {
      const el = qs(container, cls);
      return el ? el.checked : false;
    };

    return {
      level: parseInt(val("photon-opt-level", "2"), 10) || 2,
      threads: parseInt(val("photon-opt-threads", "2"), 10) || 2,
      delay: parseFloat(val("photon-opt-delay", "0")) || 0,
      timeout: parseFloat(val("photon-opt-timeout", "6")) || 6,
      cookie: val("photon-opt-cookie", ""),
      seeds: val("photon-opt-seeds", ""),
      exclude: val("photon-opt-exclude", ""),
      regex: val("photon-opt-regex", ""),
      user_agent: val("photon-opt-useragent", ""),
      extract_keys: checked("photon-opt-keys"),
      wayback: checked("photon-opt-wayback"),
      dns: checked("photon-opt-dns"),
      ninja: checked("photon-opt-ninja"),
      only_urls: checked("photon-opt-onlyurls"),
      proxy_through_roxy: checked("photon-opt-proxy"),
      roxy_proxy_port: parseInt(val("photon-opt-proxy-port", "8080"), 10) || 8080,
    };
  }

  // ---- Crawl action (parallel — does NOT block on running scans) ----

  async function doCrawl(container, ctx, targetUrl) {
    const rawUrl = targetUrl || (qs(container, "photon-url")?.value || "").trim();
    if (!rawUrl) {
      setStatus(container, "Enter a target URL first.", true);
      return;
    }

    let url = rawUrl;
    if (!/^https?:\/\//i.test(url)) url = "https://" + url;

    // Prevent duplicate scan on the same host.
    const host = extractHost(url);
    for (const [id, j] of _jobs.entries()) {
      if (extractHost(j.target) === host) {
        if (j.status === "running") {
          setStatus(container, "Already scanning " + host + ".", true);
          return;
        }
        // Remove completed/errored job so the new one replaces it.
        _jobs.delete(id);
      }
    }

    const options = gatherOptions(container);
    setStatus(container, "Starting crawl for " + url + "\u2026", false);

    try {
      const resp = await ctx.api(
        `/plugins/${encodeURIComponent(PLUGIN_ID)}/invoke-stream`,
        {
          method: "POST",
          body: JSON.stringify({ hook: "crawl", payload: { url, ...options } }),
        }
      );

      if (resp?.scan_id) {
        _jobs.set(resp.scan_id, {
          target: url, status: "running", startTime: Date.now(),
          results: null, summary: null, totalFindings: 0, error: null, elapsed: null,
        });
        _selectedJobId = resp.scan_id;
        renderJobs(container);
        ensureTimerRunning(container);
        appendLiveOutput(container, "[" + resp.scan_id.slice(0, 8) + "] Crawl started: " + url);
        // Clear input for next target.
        const inp = qs(container, "photon-url");
        if (inp && !targetUrl) inp.value = "";
      } else {
        setStatus(container, "Failed to start crawl.", true);
      }
    } catch (err) {
      setStatus(container, "Crawl failed: " + err.message, true);
    }
  }

  // ---- RoxyPluginUI interface ----

  window.RoxyPluginUI = window.RoxyPluginUI || {};
  window.RoxyPluginUI[PLUGIN_ID] = {
    /** Queue a URL for crawling (called externally, e.g. from request context menu). */
    queueUrl(url) {
      if (_container && _ctx) doCrawl(_container, _ctx, url);
    },

    /**
     * Called when a request is sent to this plugin via the right-click
     * context menu "Send to <plugin>" action.  Builds the full URL from
     * the request and fills the target URL input field.
     */
    onRequestReceived(container, request, _ctx) {
      const host = request?.host || "";
      const uri = request?.uri || "/";
      // uri may already be an absolute URL (e.g. from proxy traffic);
      // only prepend scheme://host when it's a relative path.
      let url;
      if (/^https?:\/\//i.test(uri)) {
        url = uri;
      } else {
        const scheme = (request?.uri || "").startsWith("https") ? "https" : "http";
        url = host ? `${scheme}://${host}${uri.startsWith("/") ? uri : "/" + uri}` : uri;
      }
      const input = qs(container, "photon-url");
      if (input && url) {
        // Photon wants just the origin — strip path/query for the target field.
        try {
          const parsed = new URL(url);
          input.value = parsed.origin;
        } catch (_) {
          input.value = url;
        }
      }
    },

    init(container, settings, ctx) {
      _container = container;
      _ctx = ctx;

      // Apply saved settings to option inputs.
      const setVal = (cls, key, def) => {
        const el = qs(container, cls);
        if (el && settings[key] != null) el.value = settings[key];
        else if (el && def != null) el.value = def;
      };
      const setChecked = (cls, key) => {
        const el = qs(container, cls);
        if (el) el.checked = !!settings[key];
      };

      setVal("photon-opt-level", "level", "2");
      setVal("photon-opt-threads", "threads", "2");
      setVal("photon-opt-delay", "delay", "0");
      setVal("photon-opt-timeout", "timeout", "6");
      setVal("photon-opt-cookie", "cookie", "");
      setVal("photon-opt-seeds", "seeds", "");
      setVal("photon-opt-exclude", "exclude", "");
      setVal("photon-opt-regex", "regex", "");
      setVal("photon-opt-useragent", "user_agent", "");
      setChecked("photon-opt-keys", "extract_keys");
      setChecked("photon-opt-wayback", "wayback");
      setChecked("photon-opt-dns", "dns");
      setChecked("photon-opt-ninja", "ninja");
      setChecked("photon-opt-onlyurls", "only_urls");

      // Proxy settings (default: enabled on port 8080).
      const proxyEl = qs(container, "photon-opt-proxy");
      if (proxyEl) proxyEl.checked = settings.proxy_through_roxy !== false;
      setVal("photon-opt-proxy-port", "roxy_proxy_port", "8080");

      // Crawl button.
      const crawlBtn = qs(container, "photon-crawl-btn");
      if (crawlBtn) {
        crawlBtn.addEventListener("click", () => doCrawl(container, ctx));
      }

      // Enter key on URL input.
      const urlInput = qs(container, "photon-url");
      if (urlInput) {
        urlInput.addEventListener("keydown", (e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            doCrawl(container, ctx);
          }
        });
      }

      // Tab switching.
      const tabs = qsAll(container, "photon-tab");
      for (const tab of tabs) {
        tab.addEventListener("click", () => {
          switchTab(container, tab.dataset.cat);
        });
      }

      // Add Internal to Scope.
      const addInternalBtn = qs(container, "photon-add-internal");
      if (addInternalBtn) {
        addInternalBtn.addEventListener("click", async () => {
          const urls = _lastResults.internal || [];
          if (!urls.length) {
            ctx.toast("No internal URLs to add.");
            return;
          }
          addInternalBtn.disabled = true;
          addInternalBtn.textContent = "Adding\u2026";
          try {
            // Deduplicate hostnames.
            const hosts = new Set();
            for (const u of urls) {
              try { hosts.add(new URL(u).hostname); } catch (_) {}
            }
            const added = await addUrlsToScope(ctx, Array.from(hosts));
            ctx.toast(`Added ${added} host${added !== 1 ? "s" : ""} to scope.`);
          } catch (err) {
            ctx.toast("Failed: " + err.message);
          } finally {
            addInternalBtn.disabled = false;
            addInternalBtn.textContent = "Add Internal to Scope";
          }
        });
      }

      // Add Fuzzable to Scope.
      const addFuzzBtn = qs(container, "photon-add-fuzzable");
      if (addFuzzBtn) {
        addFuzzBtn.addEventListener("click", async () => {
          const urls = _lastResults.fuzzable || [];
          if (!urls.length) {
            ctx.toast("No fuzzable URLs to add.");
            return;
          }
          addFuzzBtn.disabled = true;
          addFuzzBtn.textContent = "Adding\u2026";
          try {
            const hosts = new Set();
            for (const u of urls) {
              try { hosts.add(new URL(u).hostname); } catch (_) {}
            }
            const added = await addUrlsToScope(ctx, Array.from(hosts));
            ctx.toast(`Added ${added} host${added !== 1 ? "s" : ""} to scope.`);
          } catch (err) {
            ctx.toast("Failed: " + err.message);
          } finally {
            addFuzzBtn.disabled = false;
            addFuzzBtn.textContent = "Add Fuzzable to Scope";
          }
        });
      }

      // Show jobs section if there are existing jobs, otherwise hide.
      renderJobs(container);
      if (_selectedJobId && _jobs.has(_selectedJobId)) {
        selectJob(container, _selectedJobId);
      }
    },

    readSettings(container, currentSettings) {
      const val = (cls, fallback) => {
        const el = qs(container, cls);
        return el ? el.value : fallback;
      };
      const checked = (cls) => {
        const el = qs(container, cls);
        return el ? el.checked : false;
      };

      return {
        ...(currentSettings || {}),
        level: parseInt(val("photon-opt-level", "2"), 10) || 2,
        threads: parseInt(val("photon-opt-threads", "2"), 10) || 2,
        delay: parseFloat(val("photon-opt-delay", "0")) || 0,
        timeout: parseFloat(val("photon-opt-timeout", "6")) || 6,
        cookie: val("photon-opt-cookie", ""),
        seeds: val("photon-opt-seeds", ""),
        exclude: val("photon-opt-exclude", ""),
        regex: val("photon-opt-regex", ""),
        user_agent: val("photon-opt-useragent", ""),
        extract_keys: checked("photon-opt-keys"),
        wayback: checked("photon-opt-wayback"),
        dns: checked("photon-opt-dns"),
        ninja: checked("photon-opt-ninja"),
        only_urls: checked("photon-opt-onlyurls"),
        proxy_through_roxy: checked("photon-opt-proxy"),
        roxy_proxy_port: parseInt(val("photon-opt-proxy-port", "8080"), 10) || 8080,
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

      // ---- Streaming output ----
      if (event.event === "plugin_stream_output") {
        const raw = p.line || "";
        try {
          const parsed = JSON.parse(raw);
          if (parsed.message && scanId === _selectedJobId) {
            appendLiveOutput(container, parsed.message);
            setStatus(container, parsed.message, !!parsed.error);
          }
        } catch (_) {
          if (raw.trim() && scanId === _selectedJobId) {
            appendLiveOutput(container, raw.trim());
          }
        }
        return;
      }

      // ---- Scan complete ----
      if (event.event === "plugin_stream_complete") {
        if (scanId === _selectedJobId) {
          appendLiveOutput(container, "[crawl complete]");
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
            job.results = result.results || {};
            job.summary = result.summary || {};
            job.totalFindings = result.total_findings || 0;
            job.elapsed = result.elapsed_seconds;
          }
        }

        renderJobs(container);

        if (scanId === _selectedJobId && job) {
          if (job.status === "done") {
            renderResults(container, {
              results: job.results, summary: job.summary,
              total_findings: job.totalFindings, elapsed_seconds: job.elapsed, url: job.target,
            });
            const total = job.totalFindings || 0;
            setStatus(container,
              "Crawl complete: " + total + " finding" + (total !== 1 ? "s" : "") +
              " from " + extractHost(job.target) + ".", false);
          } else {
            setStatus(container, "Error: " + (job.error || outcome.error || "unknown"), true);
          }
        }

        return;
      }
    },
  };

  // Register with the module host for settings integration.
  window.RoxyModuleHost.registerModule({
    id: "photon-crawler",
    init() {},
    onSettingsLoaded() {},
  });
})();
