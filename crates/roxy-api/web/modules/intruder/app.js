(() => {
  const MARKER_PAYLOAD_KEY = 'marker';

  function parsePayloadLines(raw) {
    return String(raw || '')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));
  }

  function syncSourceModeVisibility(ctx) {
    const mode = ctx.qs('intruder-source-mode')?.value || 'upload';
    const upload = ctx.qs('intruder-source-upload');
    const url = ctx.qs('intruder-source-url-wrap');
    const numbers = ctx.qs('intruder-source-numbers-wrap');

    if (upload) upload.hidden = mode !== 'upload';
    if (url) url.hidden = mode !== 'url';
    if (numbers) numbers.hidden = mode !== 'numbers';
  }

  async function loadPayloadsFromUrl(ctx, rawUrl) {
    const url = String(rawUrl || '').trim();
    if (!url) {
      throw new Error('payload URL is empty');
    }

    const response = await ctx.api('/intruder/payload-source/fetch', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
    return parsePayloadLines(response.text || '');
  }

  async function loadPayloadsFromFile(ctx) {
    const input = ctx.qs('intruder-source-file');
    const file = input?.files?.[0];
    if (!file) {
      throw new Error('no payload file selected');
    }
    const text = await file.text();
    return parsePayloadLines(text);
  }

  function loadPayloadsFromNumbers(ctx) {
    const start = Number(ctx.qs('intruder-num-start').value || 0);
    const end = Number(ctx.qs('intruder-num-end').value || 0);
    const stepRaw = Number(ctx.qs('intruder-num-step').value || 1);
    const padWidth = Math.max(0, Number(ctx.qs('intruder-num-pad').value || 0));
    const prefix = ctx.qs('intruder-num-prefix').value || '';
    const suffix = ctx.qs('intruder-num-suffix').value || '';

    if (!Number.isFinite(start) || !Number.isFinite(end) || !Number.isFinite(stepRaw)) {
      throw new Error('number generator fields are invalid');
    }
    if (stepRaw === 0) {
      throw new Error('number generator step cannot be 0');
    }

    const step = start <= end ? Math.abs(stepRaw) : -Math.abs(stepRaw);
    const values = [];
    for (let n = start; step > 0 ? n <= end : n >= end; n += step) {
      const abs = Math.abs(Math.trunc(n));
      const sign = n < 0 ? '-' : '';
      const base = padWidth > 0 ? `${sign}${String(abs).padStart(padWidth, '0')}` : String(n);
      values.push(`${prefix}${base}${suffix}`);
      if (values.length > 200_000) {
        throw new Error('number generator produced too many values');
      }
    }
    return values;
  }

  async function resolveIntruderPayloadValues(ctx) {
    const mode = ctx.qs('intruder-source-mode')?.value || 'upload';
    if (mode === 'upload') {
      return loadPayloadsFromFile(ctx);
    }
    if (mode === 'url') {
      return loadPayloadsFromUrl(ctx, ctx.qs('intruder-source-url').value);
    }
    if (mode === 'numbers') {
      return loadPayloadsFromNumbers(ctx);
    }
    throw new Error(`unknown payload source mode '${mode}'`);
  }

  async function loadIntruderResults(ctx, jobId) {
    try {
      const data = await ctx.api(`/intruder/jobs/${jobId}`);
      const root = ctx.qs('intruder-results');
      root.innerHTML = '';

      if (!data.results.length) {
        root.innerHTML = '<div class="scroll-item">No results yet.</div>';
        clearIntruderResultDetail(ctx);
        return;
      }

      let selectedRow = null;
      for (const row of data.results) {
        const div = createIntruderResultRow(ctx, root, row);
        if (ctx.state.selectedIntruderResultSequence === row.sequence) {
          div.classList.add('active');
          selectedRow = row;
        }
        root.appendChild(div);
      }

      if (!selectedRow) {
        selectedRow = data.results[0];
        ctx.state.selectedIntruderResultSequence = selectedRow.sequence;
      }
      renderIntruderResultDetail(ctx, selectedRow);
    } catch (err) {
      ctx.toast(`Intruder results failed: ${err.message}`);
    }
  }

  function createIntruderResultRow(ctx, root, row) {
    const div = document.createElement('div');
    div.className = 'scroll-item';
    div.dataset.intruderResultSequence = String(row.sequence);
    div.innerHTML = `
      <strong>#${row.sequence}</strong> status=${row.status ?? 'ERR'} ${row.duration_ms}ms size=${row.response_size}<br>
      <small>${JSON.stringify(row.payloads)}</small>
    `;
    div.addEventListener('click', () => {
      ctx.state.selectedIntruderResultSequence = row.sequence;
      renderIntruderResultDetail(ctx, row);
      for (const el of root.children) {
        el.classList.remove('active');
      }
      div.classList.add('active');
    });
    return div;
  }

  function clearIntruderResultDetail(ctx) {
    const wrap = ctx.qs('intruder-result-detail');
    if (wrap) {
      wrap.hidden = true;
    }
    const req = ctx.qs('intruder-result-request');
    const resp = ctx.qs('intruder-result-response');
    if (req) req.textContent = '';
    if (resp) resp.textContent = '';
  }

  function renderIntruderResultDetail(ctx, row) {
    const wrap = ctx.qs('intruder-result-detail');
    const req = ctx.qs('intruder-result-request');
    const resp = ctx.qs('intruder-result-response');
    if (!wrap || !req || !resp) {
      return;
    }
    req.textContent = row.request_blob || '<request unavailable>';
    if (row.response_blob) {
      resp.textContent = row.response_blob;
    } else if (row.error) {
      resp.textContent = `<error>\n${row.error}`;
    } else {
      resp.textContent = '<response unavailable>';
    }
    wrap.hidden = false;
  }

  function wrapIntruderSelectionWithMarkers(ctx) {
    const textarea = ctx.qs('intruder-request-template');
    if (!textarea) {
      return;
    }

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    if (typeof start !== 'number' || typeof end !== 'number' || start === end) {
      ctx.toast('Highlight part of the request template first.');
      return;
    }

    const text = textarea.value;
    const selected = text.slice(start, end);
    const nextValue = `${text.slice(0, start)}§${selected}§${text.slice(end)}`;
    textarea.value = nextValue;
    textarea.focus();
    textarea.selectionStart = start;
    textarea.selectionEnd = end + 2;
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
        root.appendChild(createIntruderJobRow(ctx, row));
      }

      if (ctx.state.selectedIntruderJob) {
        const stillExists = rows.some((row) => row.id === ctx.state.selectedIntruderJob);
        if (!stillExists) {
          ctx.state.selectedIntruderJob = null;
          ctx.state.selectedIntruderResultSequence = null;
          ctx.qs('intruder-results').innerHTML = '<div class="scroll-item">No results yet.</div>';
          clearIntruderResultDetail(ctx);
        }
      }
    } catch (err) {
      ctx.toast(`Intruder jobs failed: ${err.message}`);
    }
  }

  function createIntruderJobRow(ctx, row) {
    const div = document.createElement('div');
    div.className = 'scroll-item';
    div.dataset.intruderJobId = row.id;
    div.innerHTML = `
      <strong>${row.name}</strong><br>
      <small>${row.status} · ${row.completed}/${row.total}</small><br>
      <small>${row.id}</small>
    `;
    div.addEventListener('click', async () => {
      ctx.state.selectedIntruderJob = row.id;
      ctx.state.selectedIntruderResultSequence = null;
      await loadIntruderResults(ctx, row.id);
    });
    return div;
  }

  function upsertIntruderJobRow(ctx, snapshot) {
    if (!snapshot || !snapshot.id) {
      return;
    }
    const root = ctx.qs('intruder-jobs');
    const existing = root.querySelector(`[data-intruder-job-id="${snapshot.id}"]`);
    const row = createIntruderJobRow(ctx, snapshot);

    if (existing) {
      existing.replaceWith(row);
    } else {
      if (root.children.length === 1 && root.textContent.includes('No jobs.')) {
        root.innerHTML = '';
      }
      root.prepend(row);
    }
  }

  function appendRealtimeIntruderResult(ctx, payload) {
    if (!payload || !payload.job_id || !payload.result) {
      return;
    }
    if (ctx.state.selectedIntruderJob !== payload.job_id) {
      return;
    }

    const root = ctx.qs('intruder-results');
    if (root.children.length === 1 && root.textContent.includes('No results yet.')) {
      root.innerHTML = '';
    }
    const sequence = String(payload.result.sequence);
    if (root.querySelector(`[data-intruder-result-sequence="${sequence}"]`)) {
      return;
    }

    const div = createIntruderResultRow(ctx, root, payload.result);
    root.appendChild(div);
    if (ctx.state.selectedIntruderResultSequence == null) {
      ctx.state.selectedIntruderResultSequence = payload.result.sequence;
      renderIntruderResultDetail(ctx, payload.result);
      div.classList.add('active');
    }
  }

  async function submitIntruderForm(event, ctx) {
    event.preventDefault();
    try {
      const template = ctx.qs('intruder-request-template').value;
      const markerCount = (template.match(/§/g) || []).length;
      if (markerCount < 2) {
        throw new Error('request template must include at least one marked section using §...§');
      }
      if (markerCount % 2 !== 0) {
        throw new Error('request template has unmatched § marker');
      }

      const values = await resolveIntruderPayloadValues(ctx);
      if (!values.length) {
        throw new Error('payload source produced no values');
      }

      const body = {
        name: ctx.qs('intruder-name').value,
        request_blob_template: template,
        payload_sets: [{ key: MARKER_PAYLOAD_KEY, values }],
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

    if (ctx.qs('setting-intruder-refresh-ms')) {
      ctx.qs('setting-intruder-refresh-ms').value = String(refreshMs);
    }
    syncSourceModeVisibility(ctx);
  }

  function onSettingsSave(ctx) {
    const refreshMs = Number(ctx.qs('setting-intruder-refresh-ms')?.value || 5000);
    const normalizedRefresh = Number.isFinite(refreshMs) ? Math.max(1000, refreshMs) : 5000;
    ctx.setModuleSetting('refresh_ms', normalizedRefresh);
  }

  window.RoxyModuleHost.registerModule({
    id: 'intruder',
    init(ctx) {
      ctx.qs('intruder-form').addEventListener('submit', (event) =>
        submitIntruderForm(event, ctx),
      );
      ctx.qs('refresh-intruder').addEventListener('click', () => loadIntruderJobs(ctx));
      ctx.qs('intruder-mark-selection').addEventListener('click', () => {
        wrapIntruderSelectionWithMarkers(ctx);
      });
      ctx.qs('intruder-source-mode').addEventListener('change', () => {
        syncSourceModeVisibility(ctx);
      });
      onSettingsLoaded(ctx);
    },
    refresh(ctx) {
      return loadIntruderJobs(ctx);
    },
    refreshIntervalMs() {
      return 0;
    },
    onRealtimeEvent(ctx, event) {
      if (!event || typeof event !== 'object') {
        return;
      }
      if (event.event === 'job_updated') {
        upsertIntruderJobRow(ctx, event.payload);
      }
      if (event.event === 'job_result') {
        appendRealtimeIntruderResult(ctx, event.payload);
      }
    },
    onSettingsLoaded,
    onSettingsSave,
  });
})();
