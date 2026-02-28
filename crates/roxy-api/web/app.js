const apiBase = '/api/v1';

const appState = {
  selectedRequest: null,
  selectedResponse: null,
  selectedIntruderJob: null,
  selectedProxyHistoryId: null,
  proxyHistoryRows: [],
  proxyHistoryMode: 'both',
  ws: null,
  toastTimer: null,
};

function qs(id) {
  return document.getElementById(id);
}

async function api(path, options = {}) {
  const response = await fetch(`${apiBase}${path}`, {
    headers: {
      'content-type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${text}`);
  }

  const ct = response.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    return response.json();
  }
  return response.text();
}

function toast(msg) {
  const el = qs('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(appState.toastTimer);
  appState.toastTimer = setTimeout(() => el.classList.remove('show'), 1800);
}

function setHealth(ok, text) {
  qs('health-label').textContent = text;
  qs('health-dot').classList.toggle('ok', ok);
}

function renderTabs() {
  const tabs = Array.from(document.querySelectorAll('.tab'));
  const panels = Array.from(document.querySelectorAll('.panel'));

  for (const tab of tabs) {
    tab.addEventListener('click', () => {
      activateTab(tab.dataset.tab);
    });
  }
}

function activateTab(tabName) {
  const tabs = Array.from(document.querySelectorAll('.tab'));
  const panels = Array.from(document.querySelectorAll('.panel'));
  for (const t of tabs) t.classList.remove('active');
  for (const p of panels) p.classList.remove('active');

  const selectedTab = tabs.find((t) => t.dataset.tab === tabName);
  if (selectedTab) selectedTab.classList.add('active');
  const selectedPanel = qs(`tab-${tabName}`);
  if (selectedPanel) selectedPanel.classList.add('active');
}

function renderProxySubtabs() {
  const tabs = Array.from(document.querySelectorAll('.proxy-subtab'));
  for (const tab of tabs) {
    tab.addEventListener('click', () => {
      activateProxySubtab(tab.dataset.proxyTab);
    });
  }
}

function activateProxySubtab(tabName) {
  const tabs = Array.from(document.querySelectorAll('.proxy-subtab'));
  const panels = Array.from(document.querySelectorAll('.proxy-subpanel'));
  for (const t of tabs) t.classList.remove('active');
  for (const p of panels) p.classList.remove('active');

  const selectedTab = tabs.find((t) => t.dataset.proxyTab === tabName);
  if (selectedTab) selectedTab.classList.add('active');
  const selectedPanel = qs(`proxy-subpanel-${tabName}`);
  if (selectedPanel) selectedPanel.classList.add('active');
}

function parseHeadersText(text) {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const idx = line.indexOf(':');
      if (idx < 1) {
        return null;
      }
      return {
        name: line.slice(0, idx).trim(),
        value: line.slice(idx + 1).trim(),
      };
    })
    .filter(Boolean);
}

function headersToText(headers = []) {
  return headers.map((h) => `${h.name}: ${h.value}`).join('\n');
}

function encodeBody(text) {
  return btoa(unescape(encodeURIComponent(text || '')));
}

function decodeBodyField(bodyField) {
  if (Array.isArray(bodyField)) {
    return new TextDecoder().decode(Uint8Array.from(bodyField));
  }

  if (typeof bodyField === 'string') {
    try {
      const decoded = decodeURIComponent(escape(atob(bodyField)));
      if (btoa(unescape(encodeURIComponent(decoded))) === bodyField) {
        return decoded;
      }
      return bodyField;
    } catch {
      return bodyField;
    }
  }

  return '';
}

function requestBlobFromLegacy(request) {
  const method = request.method || 'GET';
  const target = request.uri || '/';
  const headers = headersToText(request.headers || []);
  const body = decodeBodyField(request.body);
  const head = `${method} ${target} HTTP/1.1`;
  const headerBlock = headers ? `${headers}\r\n` : '';
  return `${head}\r\n${headerBlock}\r\n${body}`;
}

function requestBlobText(request) {
  const raw = decodeBodyField(request?.raw);
  if (raw) {
    return raw;
  }
  return requestBlobFromLegacy(request || {});
}

function responseBlobText(response) {
  if (!response) {
    return 'No response captured.';
  }
  const head = `HTTP/1.1 ${response.status ?? 0}`;
  const headers = headersToText(response.headers || []);
  const body = decodeBodyField(response.body);
  const headerBlock = headers ? `${headers}\r\n` : '';
  return `${head}\r\n${headerBlock}\r\n${body}`;
}

function setProxyHistoryMode(mode) {
  if (!['request', 'response', 'both'].includes(mode)) {
    return;
  }
  appState.proxyHistoryMode = mode;
  for (const btn of document.querySelectorAll('.history-mode-btn')) {
    btn.classList.toggle('active', btn.dataset.historyMode === mode);
  }
  renderProxyHistoryDetail();
}

function selectedProxyHistoryRow() {
  return appState.proxyHistoryRows.find((row) => row.id === appState.selectedProxyHistoryId) || null;
}

function renderProxyHistoryList() {
  const root = qs('proxy-history-list');
  root.innerHTML = '';

  if (!appState.proxyHistoryRows.length) {
    root.innerHTML = '<div class="scroll-item">No captured requests yet.</div>';
    return;
  }

  for (const row of appState.proxyHistoryRows) {
    const req = row.exchange.request;
    const resp = row.exchange.response;
    const item = document.createElement('div');
    item.className = 'scroll-item';
    if (row.id === appState.selectedProxyHistoryId) {
      item.classList.add('active');
    }

    item.innerHTML = `
      <strong>${req.method}</strong> ${req.uri}<br>
      <small>${req.host} · ${resp ? resp.status : 'no response'} · ${row.exchange.duration_ms}ms</small>
    `;

    item.addEventListener('click', () => {
      appState.selectedProxyHistoryId = row.id;
      renderProxyHistoryList();
      renderProxyHistoryDetail();
    });

    item.addEventListener('dblclick', () => {
      qs('repeater-request').value = requestBlobText(req);
      activateTab('repeater');
      toast('Request sent to Repeater form');
    });

    item.addEventListener('contextmenu', (event) => {
      event.preventDefault();
      qs('intruder-name').value = `from-history-${req.id.slice(0, 8)}`;
      qs('intruder-request-template').value = requestBlobText(req);
      activateTab('intruder');
      toast('Request sent to Intruder form');
    });

    root.appendChild(item);
  }
}

function renderProxyHistoryDetail() {
  const row = selectedProxyHistoryRow();
  const empty = qs('proxy-history-empty');
  const reqWrap = qs('proxy-history-request-wrap');
  const respWrap = qs('proxy-history-response-wrap');
  const reqOut = qs('proxy-history-request');
  const respOut = qs('proxy-history-response');
  const meta = qs('proxy-history-meta');

  if (!row) {
    empty.style.display = 'block';
    reqWrap.style.display = 'none';
    respWrap.style.display = 'none';
    meta.textContent = 'No request selected';
    return;
  }

  const req = row.exchange.request;
  const resp = row.exchange.response;
  empty.style.display = 'none';
  meta.textContent = `${req.method} ${req.uri} · ${resp ? resp.status : 'no response'} · ${row.exchange.duration_ms}ms`;

  reqOut.textContent = requestBlobText(req);
  respOut.textContent = responseBlobText(resp);

  const mode = appState.proxyHistoryMode;
  reqWrap.style.display = mode === 'response' ? 'none' : 'block';
  respWrap.style.display = mode === 'request' ? 'none' : 'block';
}

function renderHistoryRows(root, rows, emptyText) {
  root.innerHTML = '';

  if (!rows.length) {
    root.innerHTML = `<div class="scroll-item">${emptyText}</div>`;
    return;
  }

  for (const row of rows) {
    const req = row.exchange.request;
    const resp = row.exchange.response;
    const item = document.createElement('div');
    item.className = 'scroll-item';
    item.innerHTML = `
      <strong>${req.method}</strong> ${req.uri}<br>
      <small>${req.host} · ${resp ? resp.status : 'no response'} · ${row.exchange.duration_ms}ms</small>
    `;
    item.addEventListener('click', () => {
      qs('repeater-request').value = requestBlobText(req);
      activateTab('repeater');
      toast('Request sent to Repeater form');
    });
    item.addEventListener('contextmenu', (event) => {
      event.preventDefault();
      qs('intruder-name').value = `from-history-${req.id.slice(0, 8)}`;
      qs('intruder-request-template').value = requestBlobText(req);
      activateTab('intruder');
      toast('Request sent to Intruder form');
    });
    root.appendChild(item);
  }
}

function renderList(rootId, items, mapper, onClick, activeKey) {
  const root = qs(rootId);
  root.innerHTML = '';
  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'scroll-item';
    empty.textContent = 'No entries.';
    root.appendChild(empty);
    return;
  }

  for (const item of items) {
    const li = document.createElement('li');
    li.innerHTML = mapper(item);
    const key = item.id || item.request_id || item.snapshot?.id;
    if (key && key === activeKey) li.classList.add('active');
    li.addEventListener('click', () => onClick(item));
    root.appendChild(li);
  }
}

async function loadHealth() {
  try {
    const health = await api('/health');
    setHealth(true, `API OK · ${new Date(Number(health.unix_ms)).toLocaleTimeString()}`);
  } catch (err) {
    setHealth(false, 'API unavailable');
  }
}

async function loadSiteMap() {
  try {
    const rows = await api('/target/site-map');
    const root = qs('site-map');
    root.innerHTML = '';
    if (!rows.length) {
      root.innerHTML = '<div class="scroll-item">Site map is empty.</div>';
      return;
    }

    for (const row of rows) {
      const host = document.createElement('div');
      host.className = 'scroll-item';
      host.innerHTML = `<strong>${row.host}</strong><br>${row.paths.join('<br>')}`;
      root.appendChild(host);
    }
  } catch (err) {
    toast(`Site map load failed: ${err.message}`);
  }
}

async function loadScope() {
  try {
    const data = await api('/target/scope');
    const root = qs('scope-list');
    root.innerHTML = '';

    if (!data.hosts || !data.hosts.length) {
      root.innerHTML = '<div class="scroll-item">Scope empty (all hosts allowed).</div>';
      return;
    }

    for (const host of data.hosts) {
      const row = document.createElement('div');
      row.className = 'scroll-item';
      row.innerHTML = `<strong>${host}</strong>`;
      row.addEventListener('click', async () => {
        try {
          await api(`/target/scope/${encodeURIComponent(host)}`, { method: 'DELETE' });
          await loadScope();
          await loadSiteMap();
          toast(`Removed scope: ${host}`);
        } catch (err) {
          toast(`Remove scope failed: ${err.message}`);
        }
      });
      root.appendChild(row);
    }
  } catch (err) {
    toast(`Scope load failed: ${err.message}`);
  }
}

async function loadHistory(query = '') {
  try {
    const q = encodeURIComponent(query);
    const rows = await api(`/history/search?q=${q}&limit=100`);
    const root = qs('history-results');
    renderHistoryRows(root, rows, 'No matches.');
  } catch (err) {
    toast(`History search failed: ${err.message}`);
  }
}

async function loadProxyHistory() {
  try {
    const rows = await api('/history/recent?limit=300');
    appState.proxyHistoryRows = Array.isArray(rows) ? rows : [];
    if (
      appState.proxyHistoryRows.length > 0
      && !appState.proxyHistoryRows.some((row) => row.id === appState.selectedProxyHistoryId)
    ) {
      appState.selectedProxyHistoryId = appState.proxyHistoryRows[0].id;
    }
    if (!appState.proxyHistoryRows.length) {
      appState.selectedProxyHistoryId = null;
    }
    renderProxyHistoryList();
    renderProxyHistoryDetail();
  } catch (err) {
    toast(`Proxy history load failed: ${err.message}`);
  }
}

async function loadProxyToggles() {
  try {
    const [intercept, interceptResp, mitm] = await Promise.all([
      api('/proxy/intercept'),
      api('/proxy/intercept-response'),
      api('/proxy/mitm'),
    ]);

    qs('toggle-intercept').checked = intercept.enabled;
    qs('toggle-intercept-response').checked = interceptResp.enabled;
    qs('toggle-mitm').checked = mitm.enabled;
  } catch (err) {
    toast(`Proxy toggle load failed: ${err.message}`);
  }
}

function fillRequestForm(request) {
  qs('request-blob').value = requestBlobText(request);
}

function fillResponseForm(response) {
  qs('response-status').value = response.status || 200;
  qs('response-headers').value = headersToText(response.headers || []);
  qs('response-body').value = decodeBodyField(response.body);
}

async function loadInterceptQueues() {
  try {
    const [requests, responses] = await Promise.all([
      api('/proxy/intercepts'),
      api('/proxy/response-intercepts'),
    ]);

    renderList(
      'request-queue',
      requests,
      (item) => {
        const firstLine = requestBlobText(item).split(/\r?\n/, 1)[0];
        return `<strong>${firstLine || 'request'}</strong><br><small>${item.id}</small>`;
      },
      (item) => {
        appState.selectedRequest = item;
        fillRequestForm(item);
        loadInterceptQueues();
      },
      appState.selectedRequest?.id,
    );

    renderList(
      'response-queue',
      responses,
      (item) => `<strong>${item.status}</strong> response<br><small>${item.request_id}</small>`,
      (item) => {
        appState.selectedResponse = item;
        fillResponseForm(item);
        loadInterceptQueues();
      },
      appState.selectedResponse?.request_id,
    );
  } catch (err) {
    toast(`Queue load failed: ${err.message}`);
  }
}

async function setProxyToggle(path, enabled) {
  await api(path, {
    method: 'PUT',
    body: JSON.stringify({ enabled }),
  });
}

async function continueRequest(decision) {
  const selected = appState.selectedRequest;
  if (!selected) {
    toast('Select a pending request first.');
    return;
  }

  const body = { decision };
  if (decision === 'mutate') {
    body.mutation = {
      raw_base64: encodeBody(qs('request-blob').value),
    };
  }

  await api(`/proxy/intercepts/${selected.id}/continue`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
  appState.selectedRequest = null;
  await loadInterceptQueues();
}

async function continueResponse(decision) {
  const selected = appState.selectedResponse;
  if (!selected) {
    toast('Select a pending response first.');
    return;
  }

  const body = { decision };
  if (decision === 'mutate') {
    body.mutation = {
      status: Number(qs('response-status').value || 200),
      headers: parseHeadersText(qs('response-headers').value),
      body_base64: encodeBody(qs('response-body').value),
    };
  }

  await api(`/proxy/response-intercepts/${selected.request_id}/continue`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
  appState.selectedResponse = null;
  await loadInterceptQueues();
}

async function submitIntruderForm(event) {
  event.preventDefault();
  try {
    const payloadSets = JSON.parse(qs('intruder-payloads').value || '[]');
    const body = {
      name: qs('intruder-name').value,
      request_blob_template: qs('intruder-request-template').value,
      default_scheme: qs('intruder-default-scheme').value,
      payload_sets: payloadSets,
      strategy: qs('intruder-strategy').value,
      concurrency: Number(qs('intruder-concurrency').value || 16),
      timeout_ms: 15000,
    };

    const result = await api('/intruder/jobs', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    toast(`Intruder job launched: ${result.id}`);
    await loadIntruderJobs();
  } catch (err) {
    toast(`Intruder launch failed: ${err.message}`);
  }
}

async function loadIntruderJobs() {
  try {
    const rows = await api('/intruder/jobs');
    const root = qs('intruder-jobs');
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
        appState.selectedIntruderJob = row.id;
        await loadIntruderResults(row.id);
      });
      root.appendChild(div);
    }
  } catch (err) {
    toast(`Intruder jobs failed: ${err.message}`);
  }
}

async function loadIntruderResults(jobId) {
  try {
    const data = await api(`/intruder/jobs/${jobId}`);
    const root = qs('intruder-results');
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
    toast(`Intruder results failed: ${err.message}`);
  }
}

async function submitRepeater(event) {
  event.preventDefault();
  try {
    const body = {
      request_blob_base64: encodeBody(qs('repeater-request').value),
      default_scheme: qs('repeater-default-scheme').value,
    };

    const result = await api('/repeater/send', {
      method: 'POST',
      body: JSON.stringify(body),
    });

    let decodedBody = '';
    try {
      decodedBody = decodeURIComponent(escape(atob(result.body_base64 || '')));
    } catch {
      decodedBody = '<non-text body>';
    }

    qs('repeater-output').textContent = JSON.stringify(
      {
        status: result.status,
        headers: result.headers,
        body: decodedBody,
      },
      null,
      2,
    );
  } catch (err) {
    toast(`Repeater failed: ${err.message}`);
  }
}

async function submitDecoder(event) {
  event.preventDefault();
  try {
    const body = {
      mode: qs('decoder-mode').value,
      payload: qs('decoder-input').value,
    };
    const result = await api('/decoder/transform', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    qs('decoder-output').textContent = result.result || '';
  } catch (err) {
    toast(`Decoder failed: ${err.message}`);
  }
}

function prependEventLine(text) {
  const root = qs('event-feed');
  const line = document.createElement('div');
  line.className = 'scroll-item';
  line.textContent = `${new Date().toLocaleTimeString()}  ${text}`;
  root.prepend(line);

  while (root.childElementCount > 180) {
    root.removeChild(root.lastElementChild);
  }
}

function connectWebSocket(url) {
  if (appState.ws) {
    appState.ws.close();
    appState.ws = null;
  }

  const ws = new WebSocket(url);
  appState.ws = ws;

  ws.addEventListener('open', () => {
    qs('ws-status').textContent = `connected · ${url}`;
    toast('WebSocket connected');
  });

  ws.addEventListener('close', () => {
    qs('ws-status').textContent = 'disconnected';
  });

  ws.addEventListener('error', () => {
    qs('ws-status').textContent = `error · ${url}`;
  });

  ws.addEventListener('message', (event) => {
    prependEventLine(event.data);
  });
}

async function resolveDefaultWsUrl() {
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const fallback = `${scheme}://${location.hostname}:3001`;

  try {
    const stats = await api('/ws/stats');
    const port = Number(stats.ws_port || 0);
    if (Number.isFinite(port) && port > 0 && port <= 65535) {
      return `${scheme}://${location.hostname}:${port}`;
    }
  } catch {
    // ignore and fallback
  }

  return fallback;
}

function bindEvents() {
  qs('refresh-site-map').addEventListener('click', loadSiteMap);
  qs('refresh-proxy').addEventListener('click', loadInterceptQueues);
  qs('refresh-proxy-history').addEventListener('click', loadProxyHistory);
  qs('refresh-intruder').addEventListener('click', loadIntruderJobs);

  qs('toggle-intercept').addEventListener('change', async (e) => {
    try {
      await setProxyToggle('/proxy/intercept', e.target.checked);
      toast('Request interception updated');
    } catch (err) {
      toast(`Update failed: ${err.message}`);
      await loadProxyToggles();
    }
  });

  qs('toggle-intercept-response').addEventListener('change', async (e) => {
    try {
      await setProxyToggle('/proxy/intercept-response', e.target.checked);
      toast('Response interception updated');
    } catch (err) {
      toast(`Update failed: ${err.message}`);
      await loadProxyToggles();
    }
  });

  qs('toggle-mitm').addEventListener('change', async (e) => {
    try {
      await setProxyToggle('/proxy/mitm', e.target.checked);
      toast('MITM mode updated');
    } catch (err) {
      toast(`Update failed: ${err.message}`);
      await loadProxyToggles();
    }
  });

  qs('request-forward').addEventListener('click', () => continueRequest('forward'));
  qs('request-drop').addEventListener('click', () => continueRequest('drop'));
  qs('request-mutate').addEventListener('click', () => continueRequest('mutate'));

  qs('response-forward').addEventListener('click', () => continueResponse('forward'));
  qs('response-drop').addEventListener('click', () => continueResponse('drop'));
  qs('response-mutate').addEventListener('click', () => continueResponse('mutate'));

  for (const btn of document.querySelectorAll('.history-mode-btn')) {
    btn.addEventListener('click', () => {
      setProxyHistoryMode(btn.dataset.historyMode || 'both');
    });
  }

  qs('history-form').addEventListener('submit', (e) => {
    e.preventDefault();
    loadHistory(qs('history-q').value.trim());
  });

  qs('scope-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const host = qs('scope-host').value.trim();
    if (!host) {
      return;
    }
    try {
      await api('/target/scope', {
        method: 'POST',
        body: JSON.stringify({ host }),
      });
      qs('scope-host').value = '';
      await loadScope();
      await loadSiteMap();
      toast(`Scope added: ${host}`);
    } catch (err) {
      toast(`Scope add failed: ${err.message}`);
    }
  });

  qs('scope-clear').addEventListener('click', async () => {
    try {
      await api('/target/scope', {
        method: 'PUT',
        body: JSON.stringify({ hosts: [] }),
      });
      await loadScope();
      await loadSiteMap();
      toast('Scope cleared');
    } catch (err) {
      toast(`Scope clear failed: ${err.message}`);
    }
  });

  qs('intruder-form').addEventListener('submit', submitIntruderForm);
  qs('repeater-form').addEventListener('submit', submitRepeater);
  qs('decoder-form').addEventListener('submit', submitDecoder);

  qs('regenerate-ca').addEventListener('click', async () => {
    try {
      await api('/proxy/settings/ca/regenerate', { method: 'POST' });
      toast('CA regenerated');
    } catch (err) {
      toast(`CA regeneration failed: ${err.message}`);
    }
  });

  qs('ws-form').addEventListener('submit', (e) => {
    e.preventDefault();
    connectWebSocket(qs('ws-url').value.trim());
  });
}

async function init() {
  renderTabs();
  renderProxySubtabs();
  setProxyHistoryMode('both');
  bindEvents();

  qs('ws-url').value = await resolveDefaultWsUrl();

  await Promise.all([
    loadHealth(),
    loadScope(),
    loadSiteMap(),
    loadHistory(''),
    loadProxyToggles(),
    loadInterceptQueues(),
    loadProxyHistory(),
    loadIntruderJobs(),
  ]);

  setInterval(loadHealth, 10000);
  setInterval(loadInterceptQueues, 5000);
  setInterval(loadProxyHistory, 5000);
  setInterval(loadIntruderJobs, 5000);
}

init().catch((err) => {
  setHealth(false, 'Initialization failed');
  toast(`Init error: ${err.message}`);
});
