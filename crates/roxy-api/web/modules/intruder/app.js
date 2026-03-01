(() => {
  async function loadIntruderResults(ctx, jobId) {
    try {
      const data = await ctx.api(`/intruder/jobs/${jobId}`);
      const root = ctx.qs('intruder-results');
      root.innerHTML = '';

      if (!data.results.length) {
        root.innerHTML = '<div class="scroll-item">No results yet.</div>';
        return;
      }

      for (const row of data.results) {
        const div = document.createElement('div');
        div.className = 'scroll-item';
        div.innerHTML = `
          <strong>#${row.sequence}</strong> status=${row.status ?? 'ERR'} ${row.duration_ms}ms size=${row.response_size}<br>
          <small>${JSON.stringify(row.payloads)}</small>
        `;
        root.appendChild(div);
      }
    } catch (err) {
      ctx.toast(`Intruder results failed: ${err.message}`);
    }
  }

  async function loadIntruderJobs(ctx) {
    try {
      const rows = await ctx.api('/intruder/jobs');
      const root = ctx.qs('intruder-jobs');
      root.innerHTML = '';

      if (!rows.length) {
        root.innerHTML = '<div class="scroll-item">No jobs.</div>';
        return;
      }

      for (const row of rows) {
        const div = document.createElement('div');
        div.className = 'scroll-item';
        div.innerHTML = `
          <strong>${row.name}</strong><br>
          <small>${row.status} · ${row.completed}/${row.total}</small><br>
          <small>${row.id}</small>
        `;
        div.addEventListener('click', async () => {
          ctx.state.selectedIntruderJob = row.id;
          await loadIntruderResults(ctx, row.id);
        });
        root.appendChild(div);
      }

      if (ctx.state.selectedIntruderJob) {
        const stillExists = rows.some((row) => row.id === ctx.state.selectedIntruderJob);
        if (!stillExists) {
          ctx.state.selectedIntruderJob = null;
          ctx.qs('intruder-results').innerHTML = '<div class="scroll-item">No results yet.</div>';
        }
      }
    } catch (err) {
      ctx.toast(`Intruder jobs failed: ${err.message}`);
    }
  }

  async function submitIntruderForm(event, ctx) {
    event.preventDefault();
    try {
      const payloadSets = JSON.parse(ctx.qs('intruder-payloads').value || '[]');
      const body = {
        name: ctx.qs('intruder-name').value,
        request_blob_template: ctx.qs('intruder-request-template').value,
        default_scheme: ctx.qs('intruder-default-scheme').value,
        payload_sets: payloadSets,
        strategy: ctx.qs('intruder-strategy').value,
        concurrency: Number(ctx.qs('intruder-concurrency').value || 16),
        timeout_ms: 15000,
      };

      const result = await ctx.api('/intruder/jobs', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      ctx.toast(`Intruder job launched: ${result.id}`);
      await loadIntruderJobs(ctx);
    } catch (err) {
      ctx.toast(`Intruder launch failed: ${err.message}`);
    }
  }

  function onSettingsLoaded(ctx) {
    const refreshMs = Number(ctx.getModuleSetting('refresh_ms', 5000));
    const defaultScheme = ctx.getModuleSetting('default_scheme', 'http');

    if (ctx.qs('setting-intruder-refresh-ms')) {
      ctx.qs('setting-intruder-refresh-ms').value = String(refreshMs);
    }
    if (ctx.qs('setting-intruder-default-scheme')) {
      ctx.qs('setting-intruder-default-scheme').value = defaultScheme;
    }
    if (ctx.qs('intruder-default-scheme')) {
      ctx.qs('intruder-default-scheme').value = defaultScheme;
    }
  }

  function onSettingsSave(ctx) {
    const refreshMs = Number(ctx.qs('setting-intruder-refresh-ms')?.value || 5000);
    const normalizedRefresh = Number.isFinite(refreshMs) ? Math.max(1000, refreshMs) : 5000;
    const defaultScheme = ctx.qs('setting-intruder-default-scheme')?.value || 'http';
    ctx.setModuleSetting('refresh_ms', normalizedRefresh);
    ctx.setModuleSetting('default_scheme', defaultScheme);
    if (ctx.qs('intruder-default-scheme')) {
      ctx.qs('intruder-default-scheme').value = defaultScheme;
    }
  }

  window.RoxyModuleHost.registerModule({
    id: 'intruder',
    init(ctx) {
      ctx.qs('intruder-form').addEventListener('submit', (event) =>
        submitIntruderForm(event, ctx),
      );
      ctx.qs('refresh-intruder').addEventListener('click', () => loadIntruderJobs(ctx));
      onSettingsLoaded(ctx);
    },
    refresh(ctx) {
      return loadIntruderJobs(ctx);
    },
    refreshIntervalMs(ctx) {
      return Number(ctx.getModuleSetting('refresh_ms', 5000));
    },
    onSettingsLoaded,
    onSettingsSave,
  });
})();
