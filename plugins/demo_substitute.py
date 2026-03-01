#!/usr/bin/env python3
from pathlib import Path
import sys

SDK_SRC = Path(__file__).resolve().parents[1] / "python" / "roxy-plugin-sdk" / "src"
if SDK_SRC.exists():
    sys.path.insert(0, str(SDK_SRC))

from roxy_plugin_sdk import PluginBuilder, UiModuleDefinition, run_plugin


def _setting(settings: dict, key: str, fallback: str) -> str:
    value = settings.get(key, fallback)
    return str(value) if value is not None else fallback


def handle(hook: str, payload: dict) -> dict:
    builder = PluginBuilder()
    settings = payload.get("plugin_settings", {}) or {}

    request_search = _setting(settings, "request_search", "hello")
    request_replace = _setting(settings, "request_replace", "roxy")
    response_search = _setting(settings, "response_search", "upstream-ok")
    response_replace = _setting(settings, "response_replace", "plugin-ok")

    if hook == "on_load":
        builder.register_ui_module(
            UiModuleDefinition(
                id="demo-substitute",
                title="Demo Substitute",
                panel_html=(
                    "<article class='card'>"
                    "<h3>Demo Substitute Plugin</h3>"
                    "<p>Substitutes request and response strings through middleware hooks.</p>"
                    "</article>"
                ),
                settings_html=(
                    "<h3>Demo Substitute</h3>"
                    "<div class='stack'>"
                    "<label for='setting-demo-substitute-request-search'>Request Search</label>"
                    "<input id='setting-demo-substitute-request-search' placeholder='hello' />"
                    "<label for='setting-demo-substitute-request-replace'>Request Replace</label>"
                    "<input id='setting-demo-substitute-request-replace' placeholder='roxy' />"
                    "<label for='setting-demo-substitute-response-search'>Response Search</label>"
                    "<input id='setting-demo-substitute-response-search' placeholder='upstream-ok' />"
                    "<label for='setting-demo-substitute-response-replace'>Response Replace</label>"
                    "<input id='setting-demo-substitute-response-replace' placeholder='plugin-ok' />"
                    "</div>"
                ),
                script_js=(
                    "(function(){"
                    "const pluginId='demo-substitute';"
                    "async function loadSettings(ctx){"
                    "try{const s=await ctx.api('/plugins/'+encodeURIComponent(pluginId)+'/settings');"
                    "ctx.qs('setting-demo-substitute-request-search').value=s.request_search||'hello';"
                    "ctx.qs('setting-demo-substitute-request-replace').value=s.request_replace||'roxy';"
                    "ctx.qs('setting-demo-substitute-response-search').value=s.response_search||'upstream-ok';"
                    "ctx.qs('setting-demo-substitute-response-replace').value=s.response_replace||'plugin-ok';"
                    "}catch(_){}}"
                    "async function saveSettings(ctx){"
                    "const body={"
                    "request_search:ctx.qs('setting-demo-substitute-request-search')?.value||'hello',"
                    "request_replace:ctx.qs('setting-demo-substitute-request-replace')?.value||'roxy',"
                    "response_search:ctx.qs('setting-demo-substitute-response-search')?.value||'upstream-ok',"
                    "response_replace:ctx.qs('setting-demo-substitute-response-replace')?.value||'plugin-ok'"
                    "};"
                    "await ctx.api('/plugins/'+encodeURIComponent(pluginId)+'/settings',{method:'PUT',body:JSON.stringify(body)});"
                    "}"
                    "window.RoxyModuleHost.registerModule({"
                    "id:'demo-substitute',"
                    "init(ctx){loadSettings(ctx);},"
                    "onSettingsLoaded(ctx){loadSettings(ctx);},"
                    "onSettingsSave(ctx){return saveSettings(ctx);}"
                    "});"
                    "})();"
                ),
            )
        )
        return builder.to_dict()

    if hook == "on_request_pre_capture":
        raw = payload.get("request", {}).get("raw_text", "")
        if raw and request_search:
            builder.set_request_raw_text(raw.replace(request_search, request_replace))
        return builder.to_dict()

    if hook == "on_response_pre_capture":
        body_text = payload.get("response", {}).get("body_text", "")
        if body_text and response_search:
            builder.set_response_body_text(body_text.replace(response_search, response_replace))
        return builder.to_dict()

    return {}


if __name__ == "__main__":
    run_plugin(handle)
