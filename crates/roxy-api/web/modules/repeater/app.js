(() => {
  const repeaterState = {
    history: [],
    cursor: -1,
    maxEntries: 300,
  };

  function decodeBase64ToText(base64) {
    try {
      const raw = atob(base64 || '');
      const bytes = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i += 1) {
        bytes[i] = raw.charCodeAt(i);
      }
      return new TextDecoder().decode(bytes);
    } catch {
      return '<invalid-base64-body>';
    }
  }

  function maybePrettyJson(text, enabled) {
    if (!enabled) {
      return text;
    }
    try {
      const parsed = JSON.parse(text);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return text;
    }
  }

  function responseBlobFromResult(ctx, result, prettyJson) {
    const bodyText = maybePrettyJson(
      decodeBase64ToText(result.body_base64 || ''),
      prettyJson,
    );
    const headers = ctx.headersToText(result.headers || []);
    const head = `HTTP/1.1 ${result.status}`;
    const headerBlock = headers ? `${headers}\r\n` : '';
    return `${head}\r\n${headerBlock}\r\n${bodyText}`;
  }

  function updateHistoryControls(ctx) {
    const total = repeaterState.history.length;
    const position = repeaterState.cursor >= 0 ? repeaterState.cursor + 1 : 0;

    const prev = ctx.qs('repeater-history-prev');
    const next = ctx.qs('repeater-history-next');
    const index = ctx.qs('repeater-history-index');

    if (index) {
      index.textContent = `${position} / ${total}`;
    }
    if (prev) {
      prev.disabled = total === 0 || repeaterState.cursor <= 0;
    }
    if (next) {
      next.disabled = total === 0 || repeaterState.cursor >= total - 1;
    }
  }

  function renderHistoryEntry(ctx) {
    const entry = repeaterState.history[repeaterState.cursor];
    if (!entry) {
      ctx.qs('repeater-output').textContent = 'No response yet.';
      updateHistoryControls(ctx);
      return;
    }

    ctx.qs('repeater-request').value = entry.requestBlob;
    ctx.qs('repeater-output').textContent = entry.responseBlob;
    updateHistoryControls(ctx);
  }

  function pushHistoryEntry(ctx, requestBlob, responseBlob) {
    if (repeaterState.cursor < repeaterState.history.length - 1) {
      repeaterState.history = repeaterState.history.slice(0, repeaterState.cursor + 1);
    }

    repeaterState.history.push({ requestBlob, responseBlob });
    if (repeaterState.history.length > repeaterState.maxEntries) {
      repeaterState.history.shift();
    }
    repeaterState.cursor = repeaterState.history.length - 1;
    renderHistoryEntry(ctx);
  }

  function navigateHistory(ctx, delta) {
    if (!repeaterState.history.length) {
      updateHistoryControls(ctx);
      return;
    }

    const nextCursor = repeaterState.cursor + delta;
    if (nextCursor < 0 || nextCursor >= repeaterState.history.length) {
      return;
    }

    repeaterState.cursor = nextCursor;
    renderHistoryEntry(ctx);
  }

  async function submitRepeater(event, ctx) {
    event.preventDefault();
    try {
      const requestBlob = ctx.qs('repeater-request').value;
      const body = {
        request_blob_base64: ctx.encodeBody(requestBlob),
        default_scheme: ctx.qs('repeater-default-scheme').value,
      };

      const result = await ctx.api('/repeater/send', {
        method: 'POST',
        body: JSON.stringify(body),
      });

      const prettyJson = Boolean(ctx.getModuleSetting('pretty_json', true));
      const responseBlob = responseBlobFromResult(ctx, result, prettyJson);
      pushHistoryEntry(ctx, requestBlob, responseBlob);
    } catch (err) {
      ctx.toast(`Repeater failed: ${err.message}`);
    }
  }

  function onSettingsLoaded(ctx) {
    const defaultScheme = ctx.getModuleSetting('default_scheme', 'http');
    const prettyJson = Boolean(ctx.getModuleSetting('pretty_json', true));
    if (ctx.qs('setting-repeater-default-scheme')) {
      ctx.qs('setting-repeater-default-scheme').value = defaultScheme;
    }
    if (ctx.qs('setting-repeater-pretty-json')) {
      ctx.qs('setting-repeater-pretty-json').checked = prettyJson;
    }
    if (ctx.qs('repeater-default-scheme')) {
      ctx.qs('repeater-default-scheme').value = defaultScheme;
    }
  }

  function onSettingsSave(ctx) {
    const defaultScheme = ctx.qs('setting-repeater-default-scheme')?.value || 'http';
    const prettyJson = Boolean(ctx.qs('setting-repeater-pretty-json')?.checked);
    ctx.setModuleSetting('default_scheme', defaultScheme);
    ctx.setModuleSetting('pretty_json', prettyJson);
    if (ctx.qs('repeater-default-scheme')) {
      ctx.qs('repeater-default-scheme').value = defaultScheme;
    }
  }

  window.RoxyModuleHost.registerModule({
    id: 'repeater',
    init(ctx) {
      ctx.qs('repeater-form').addEventListener('submit', (event) =>
        submitRepeater(event, ctx),
      );
      ctx.qs('repeater-history-prev').addEventListener('click', () => {
        navigateHistory(ctx, -1);
      });
      ctx.qs('repeater-history-next').addEventListener('click', () => {
        navigateHistory(ctx, 1);
      });
      onSettingsLoaded(ctx);
      updateHistoryControls(ctx);
    },
    onSettingsLoaded,
    onSettingsSave,
  });
})();
