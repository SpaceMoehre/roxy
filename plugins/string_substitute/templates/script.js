(function () {
  const pluginId = "string-substitute";

  function normalizeRules(settings) {
    if (!settings || !Array.isArray(settings.rules)) {
      return [];
    }
    return settings.rules
      .map((rule) => ({
        search: String(rule?.search || ""),
        replace: String(rule?.replace || ""),
        scope: ["request", "response", "both"].includes(
          String(rule?.scope || "both")
        )
          ? String(rule.scope)
          : "both",
      }))
      .filter((rule) => rule.search.length > 0);
  }

  async function syncRuleCount(ctx) {
    const input = ctx.qs("setting-string-substitute-rule-count");
    if (!input) {
      return;
    }

    try {
      const settings = await ctx.api(
        "/plugins/" + encodeURIComponent(pluginId) + "/settings"
      );
      const rules = normalizeRules(settings || {});
      input.value = String(rules.length);
    } catch (_) {
      input.value = "0";
    }
  }

  window.RoxyModuleHost.registerModule({
    id: "string-substitute",
    init(ctx) {
      syncRuleCount(ctx);
    },
    onSettingsLoaded(ctx) {
      syncRuleCount(ctx);
    },
  });
})();
