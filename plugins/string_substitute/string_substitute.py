#!/usr/bin/env python3
from pathlib import Path
from typing import Optional
import sys


def _find_sdk_src(start: Path) -> Optional[Path]:
    for candidate_root in [start] + list(start.parents):
        sdk_src = candidate_root / "python" / "roxy-plugin-sdk" / "src"
        if sdk_src.exists():
            return sdk_src
    return None


BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
SDK_SRC = _find_sdk_src(BASE_DIR)
if SDK_SRC is not None:
    sys.path.insert(0, str(SDK_SRC))

from roxy_plugin_sdk import PluginBuilder, UiModuleDefinition, run_plugin


def _read_template(name: str, fallback: str) -> str:
    path = TEMPLATE_DIR / name
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return fallback


PANEL_HTML = _read_template(
    "panel.html",
    "<article class='card'><h3>String Substitute</h3><p>panel template missing</p></article>",
)
SETTINGS_HTML = _read_template(
    "settings.html",
    "<h3>String Substitute</h3><p>settings template missing</p>",
)
SCRIPT_JS = _read_template(
    "script.js",
    "window.RoxyModuleHost.registerModule({id:'string-substitute'});",
)


def _normalize_scope(value: object) -> str:
    text = str(value).strip().lower() if value is not None else ""
    if text in {"request", "response", "both"}:
        return text
    return "both"


def _normalize_rules(settings: dict) -> list[dict[str, str]]:
    rules: list[dict[str, str]] = []
    raw_rules = settings.get("rules")
    if isinstance(raw_rules, list):
        for raw in raw_rules:
            if not isinstance(raw, dict):
                continue
            search = str(raw.get("search", ""))
            if not search:
                continue
            replace = str(raw.get("replace", ""))
            scope = _normalize_scope(raw.get("scope", "both"))
            rules.append({"search": search, "replace": replace, "scope": scope})

    if rules:
        return rules

    # Legacy fallback for previously used demo settings.
    request_search = str(settings.get("request_search", ""))
    request_replace = str(settings.get("request_replace", ""))
    response_search = str(settings.get("response_search", ""))
    response_replace = str(settings.get("response_replace", ""))
    if request_search:
        rules.append(
            {"search": request_search, "replace": request_replace, "scope": "request"}
        )
    if response_search:
        rules.append(
            {"search": response_search, "replace": response_replace, "scope": "response"}
        )

    return rules


def _apply_rules(blob: str, rules: list[dict[str, str]], side: str) -> str:
    out = blob
    for rule in rules:
        if rule.get("scope") not in {side, "both"}:
            continue
        search = rule.get("search", "")
        if not search:
            continue
        out = out.replace(search, rule.get("replace", ""))
    return out


def handle(hook: str, payload: dict) -> dict:
    builder = PluginBuilder()
    settings = payload.get("plugin_settings", {}) or {}
    rules = _normalize_rules(settings)

    if hook == "on_load":
        builder.register_ui_module(
            UiModuleDefinition(
                id="string-substitute",
                title="String Substitute",
                nav_hidden=True,
                panel_html=PANEL_HTML,
                settings_html=SETTINGS_HTML,
                script_js=SCRIPT_JS,
            )
        )
        return builder.to_dict()

    if hook == "on_request_pre_capture":
        raw = payload.get("request", {}).get("raw_text", "")
        if raw and rules:
            builder.set_request_raw_text(_apply_rules(raw, rules, "request"))
        return builder.to_dict()

    if hook == "on_response_pre_capture":
        body_text = payload.get("response", {}).get("body_text", "")
        if body_text and rules:
            builder.set_response_body_text(_apply_rules(body_text, rules, "response"))
        return builder.to_dict()

    return {}


if __name__ == "__main__":
    run_plugin(handle)
