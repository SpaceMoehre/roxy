(() => {
  const DEMO_PLUGIN = 'demo-substitute';

  function selectedPluginId(ctx) {
    return ctx.qs('plugins-select')?.value || '';
  }

  function safeParseJson(text, fallback = {}) {
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
      return fallback;
    } catch {
      return fallback;
    }
  }

  function renderAlterations(ctx, rows) {
    const root = ctx.qs('plugins-alterations');
    root.innerHTML = '';

    if (!Array.isArray(rows) || rows.length === 0) {
      root.innerHTML = '<div class="scroll-item">No recorded alterations yet.</div>';
      return;
    }

    for (const row of rows) {
      const div = document.createElement('div');
      div.className = 'scroll-item';
      const when = row.unix_ms ? new Date(Number(row.unix_ms)).toLocaleTimeString() : '-';
      div.innerHTML = `
        <strong>${row.hook || 'hook'}</strong> ${row.request_id || ''}<br>
        <small>${when}</small><br>
        <small>${row.summary || ''}</small>
      `;
      root.appendChild(div);
    }
  }

  async function loadPlugins(ctx) {
    const select = ctx.qs('plugins-select');
    const rows = await ctx.api('/plugins');
    const current = select.value;
    select.innerHTML = '';

    if (!rows.length) {
      const option = document.createElement('option');
      option.value = '';
      option.textContent = 'No plugins registered';
      select.appendChild(option);
      select.value = '';
      return;
    }

    for (const row of rows) {
      const option = document.createElement('option');
      option.value = row.name;
      option.textContent = row.name;
      select.appendChild(option);
    }

    if (rows.some((row) => row.name === current)) {
      select.value = current;
    } else if (rows.some((row) => row.name === DEMO_PLUGIN)) {
      select.value = DEMO_PLUGIN;
    } else {
      select.selectedIndex = 0;
    }
  }

  function syncDemoInputsFromSettings(ctx, settings) {
    const visible = selectedPluginId(ctx) === DEMO_PLUGIN;
    const wrap = ctx.qs('plugins-demo-settings');
    wrap.style.display = visible ? 'block' : 'none';
    if (!visible) {
      return;
    }

    ctx.qs('plugins-demo-request-search').value = settings.request_search || 'hello';
    ctx.qs('plugins-demo-request-replace').value = settings.request_replace || 'roxy';
    ctx.qs('plugins-demo-response-search').value = settings.response_search || 'upstream-ok';
    ctx.qs('plugins-demo-response-replace').value = settings.response_replace || 'plugin-ok';
  }

  function syncSettingsFromDemoInputs(ctx, settings) {
    if (selectedPluginId(ctx) !== DEMO_PLUGIN) {
      return settings;
    }

    return {
      ...settings,
      request_search: ctx.qs('plugins-demo-request-search').value,
      request_replace: ctx.qs('plugins-demo-request-replace').value,
      response_search: ctx.qs('plugins-demo-response-search').value,
      response_replace: ctx.qs('plugins-demo-response-replace').value,
    };
  }

  async function loadSettings(ctx) {
    const pluginId = selectedPluginId(ctx);
    if (!pluginId) {
      ctx.qs('plugins-settings-json').value = '{}';
      syncDemoInputsFromSettings(ctx, {});
      return;
    }

    try {
      const settings = await ctx.api(`/plugins/${encodeURIComponent(pluginId)}/settings`);
      ctx.qs('plugins-settings-json').value = JSON.stringify(settings || {}, null, 2);
      syncDemoInputsFromSettings(ctx, settings || {});
    } catch (err) {
      ctx.qs('plugins-settings-json').value = '{}';
      syncDemoInputsFromSettings(ctx, {});
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
      ctx.toast('Select a plugin first.');
      return;
    }

    const input = ctx.qs('plugins-settings-json').value || '{}';
    let settings = safeParseJson(input, null);
    if (!settings) {
      ctx.toast('Settings must be valid JSON object.');
      return;
    }

    settings = syncSettingsFromDemoInputs(ctx, settings);

    try {
      await ctx.api(`/plugins/${encodeURIComponent(pluginId)}/settings`, {
        method: 'PUT',
        body: JSON.stringify(settings),
      });
      ctx.qs('plugins-settings-json').value = JSON.stringify(settings, null, 2);
      ctx.toast('Plugin settings saved');
      await loadAlterations(ctx);
    } catch (err) {
      ctx.toast(`Save settings failed: ${err.message}`);
    }
  }

  function onSettingsLoaded(ctx) {
    const refreshMs = Number(ctx.getModuleSetting('refresh_ms', 4000));
    if (ctx.qs('setting-plugins-refresh-ms')) {
      ctx.qs('setting-plugins-refresh-ms').value = String(refreshMs);
    }
  }

  function onSettingsSave(ctx) {
    const refreshMs = Number(ctx.qs('setting-plugins-refresh-ms')?.value || 4000);
    const normalizedRefresh = Number.isFinite(refreshMs) ? Math.max(1000, refreshMs) : 4000;
    ctx.setModuleSetting('refresh_ms', normalizedRefresh);
  }

  window.RoxyModuleHost.registerModule({
    id: 'plugins',
    async init(ctx) {
      ctx.qs('plugins-refresh').addEventListener('click', async () => {
        await loadPlugins(ctx);
        await loadSettings(ctx);
        await loadAlterations(ctx);
      });
      ctx.qs('plugins-refresh-alterations').addEventListener('click', () => loadAlterations(ctx));
      ctx.qs('plugins-select').addEventListener('change', async () => {
        await loadSettings(ctx);
        await loadAlterations(ctx);
      });
      ctx.qs('plugins-save-settings').addEventListener('click', () => saveSettings(ctx));

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
      return Number(ctx.getModuleSetting('refresh_ms', 4000));
    },
    onSettingsLoaded,
    onSettingsSave,
  });
})();
