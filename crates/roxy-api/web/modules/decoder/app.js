(() => {
  async function submitDecoder(event, ctx) {
    event.preventDefault();
    try {
      const body = {
        mode: ctx.qs('decoder-mode').value,
        payload: ctx.qs('decoder-input').value,
      };
      const result = await ctx.api('/decoder/transform', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      ctx.qs('decoder-output').textContent = result.result || '';
    } catch (err) {
      ctx.toast(`Decoder failed: ${err.message}`);
    }
  }

  function onSettingsLoaded(ctx) {
    const mode = ctx.getModuleSetting('default_mode', 'base64_encode');
    if (ctx.qs('setting-decoder-default-mode')) {
      ctx.qs('setting-decoder-default-mode').value = mode;
    }
    if (ctx.qs('decoder-mode')) {
      ctx.qs('decoder-mode').value = mode;
    }
  }

  function onSettingsSave(ctx) {
    const mode = ctx.qs('setting-decoder-default-mode')?.value || 'base64_encode';
    ctx.setModuleSetting('default_mode', mode);
    if (ctx.qs('decoder-mode')) {
      ctx.qs('decoder-mode').value = mode;
    }
  }

  window.RoxyModuleHost.registerModule({
    id: 'decoder',
    init(ctx) {
      ctx.qs('decoder-form').addEventListener('submit', (event) =>
        submitDecoder(event, ctx),
      );
      onSettingsLoaded(ctx);
    },
    onSettingsLoaded,
    onSettingsSave,
  });
})();
