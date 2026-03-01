(() => {
  function decodeBase64ToText(base64) {
    try {
      return decodeURIComponent(escape(atob(base64 || '')));
    } catch {
      return '<non-text body>';
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

  async function submitRepeater(event, ctx) {
    event.preventDefault();
    try {
      const body = {
        request_blob_base64: ctx.encodeBody(ctx.qs('repeater-request').value),
        default_scheme: ctx.qs('repeater-default-scheme').value,
      };

      const result = await ctx.api('/repeater/send', {
        method: 'POST',
        body: JSON.stringify(body),
      });

      const prettyJson = Boolean(ctx.getModuleSetting('pretty_json', true));
      const decodedBody = maybePrettyJson(
        decodeBase64ToText(result.body_base64 || ''),
        prettyJson,
      );

      ctx.qs('repeater-output').textContent = JSON.stringify(
        {
          status: result.status,
          headers: result.headers,
          body: decodedBody,
        },
        null,
        2,
      );
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
      onSettingsLoaded(ctx);
    },
    onSettingsLoaded,
    onSettingsSave,
  });
})();
