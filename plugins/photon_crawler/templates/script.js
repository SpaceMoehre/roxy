(function () {
  const PLUGIN_ID = "photon-crawler";

  // ---- State ----
  let _crawling = false;
  let _currentScanId = null;
  let _lastResults = {};
  let _activeCategory = "internal";

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
    };
  }

  // ---- Crawl action ----

  async function doCrawl(container, ctx) {
    if (_crawling) return;

    const urlInput = qs(container, "photon-url");
    const url = (urlInput?.value || "").trim();
    if (!url) {
      setStatus(container, "Enter a target URL first.", true);
      return;
    }

    const btn = qs(container, "photon-crawl-btn");
    _crawling = true;
    _currentScanId = null;
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Crawling\u2026";
    }
    setStatus(container, "Starting Photon crawl for " + url + "\u2026", false);
    clearLiveOutput(container);

    const options = gatherOptions(container);

    try {
      const resp = await ctx.api(
        `/plugins/${encodeURIComponent(PLUGIN_ID)}/invoke-stream`,
        {
          method: "POST",
          body: JSON.stringify({
            hook: "crawl",
            payload: { url, ...options },
          }),
        }
      );

      if (resp?.scan_id) {
        _currentScanId = resp.scan_id;
        appendLiveOutput(container, "[scan started: " + resp.scan_id.slice(0, 8) + "]");
      } else {
        setStatus(container, "Failed to start crawl.", true);
        _crawling = false;
        if (btn) {
          btn.disabled = false;
          btn.textContent = "Crawl";
        }
      }
    } catch (err) {
      setStatus(container, "Crawl failed: " + err.message, true);
      _crawling = false;
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Crawl";
      }
    }
  }

  // ---- RoxyPluginUI interface ----

  window.RoxyPluginUI = window.RoxyPluginUI || {};
  window.RoxyPluginUI[PLUGIN_ID] = {
    init(container, settings, ctx) {
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
      };
    },

    loadAlterations() {
      // No alterations tracking for this plugin.
    },

    onRealtimeEvent(container, event, ctx) {
      if (!event || !event.payload) return;
      const payload = event.payload;

      if (payload.plugin !== PLUGIN_ID) return;
      if (_currentScanId && payload.scan_id !== _currentScanId) return;

      // ---- Streaming output ----
      if (event.event === "plugin_stream_output") {
        const raw = payload.line || "";
        try {
          const parsed = JSON.parse(raw);
          if (parsed.message) {
            appendLiveOutput(container, parsed.message);
            // Update status with latest progress message.
            setStatus(container, parsed.message, !!parsed.error);
          }
        } catch (_) {
          // Non-JSON output from Photon (e.g. banner, level progress).
          if (raw.trim()) {
            appendLiveOutput(container, raw.trim());
          }
        }
        return;
      }

      // ---- Scan complete ----
      if (event.event === "plugin_stream_complete") {
        appendLiveOutput(container, "[crawl complete]");

        const btn = qs(container, "photon-crawl-btn");
        _crawling = false;
        _currentScanId = null;
        if (btn) {
          btn.disabled = false;
          btn.textContent = "Crawl";
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
        const total = result.total_findings || 0;
        setStatus(
          container,
          `Crawl complete: ${total} finding${total !== 1 ? "s" : ""} from ${result.url || "unknown"}.`,
          false
        );

        // Update settings last count.
        const lastCount = document.getElementById("setting-photon-last-count");
        if (lastCount) lastCount.value = String(total);

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
