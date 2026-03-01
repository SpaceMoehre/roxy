from __future__ import annotations

import base64
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List, Optional


@dataclass
class UiModuleDefinition:
    id: str
    title: str
    panel_html: str
    settings_html: str
    script_js: str
    nav_hidden: bool = False


class PluginBuilder:
    def __init__(self) -> None:
        self._out: Dict[str, Any] = {}

    def set_result(self, value: Any) -> "PluginBuilder":
        self._out["result"] = value
        return self

    def set_request_raw_text(self, text: str) -> "PluginBuilder":
        self._out["request_raw_text"] = text
        return self

    def set_request_raw_bytes(self, blob: bytes) -> "PluginBuilder":
        self._out["request_raw_base64"] = base64.b64encode(blob).decode("ascii")
        return self

    def set_response_body_text(self, text: str) -> "PluginBuilder":
        self._out["response_body_text"] = text
        return self

    def set_response_body_bytes(self, blob: bytes) -> "PluginBuilder":
        self._out["response_body_base64"] = base64.b64encode(blob).decode("ascii")
        return self

    def set_response_status(self, status: int) -> "PluginBuilder":
        self._out["response_status"] = int(status)
        return self

    def set_response_headers(self, headers: List[Dict[str, str]]) -> "PluginBuilder":
        self._out["response_headers"] = headers
        return self

    def add_state_op(self, op: Dict[str, Any]) -> "PluginBuilder":
        self._out.setdefault("state_ops", []).append(op)
        return self

    def register_ui_module(self, module: UiModuleDefinition) -> "PluginBuilder":
        self._out.setdefault("register_ui_modules", []).append(asdict(module))
        return self

    def to_dict(self) -> Dict[str, Any]:
        return self._out


class RoxyClient:
    def __init__(self, base_url: str = "http://127.0.0.1:3000/api/v1", timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Any:
        data = None
        headers = {"content-type": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url=f"{self.base_url}{path}",
            method=method,
            data=data,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                ctype = resp.headers.get("content-type", "")
                if "application/json" in ctype:
                    return json.loads(raw.decode("utf-8"))
                return raw.decode("utf-8")
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8", "replace")
            raise RuntimeError(f"HTTP {err.code} {err.reason}: {body}") from err

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/health")

    def list_plugins(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/plugins")

    def register_plugin(self, name: str, path: str, hooks: List[str]) -> Any:
        return self._request(
            "POST",
            "/plugins",
            {"name": name, "path": path, "hooks": hooks},
        )

    def invoke_plugin(self, name: str, hook: str, payload: Dict[str, Any]) -> Any:
        return self._request(
            "POST",
            f"/plugins/{name}/invoke",
            {"hook": hook, "payload": payload},
        )

    def get_plugin_settings(self, name: str) -> Dict[str, Any]:
        return self._request("GET", f"/plugins/{name}/settings")

    def set_plugin_settings(self, name: str, settings: Dict[str, Any]) -> Any:
        return self._request("PUT", f"/plugins/{name}/settings", settings)

    def list_plugin_alterations(self, name: str, limit: int = 200) -> List[Dict[str, Any]]:
        return self._request("GET", f"/plugins/{name}/alterations?limit={int(limit)}")

    def list_ui_modules(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/ui/modules")

    def register_ui_module(self, module: UiModuleDefinition) -> Any:
        return self._request("POST", "/ui/modules", asdict(module))

    def set_intercept_requests(self, enabled: bool) -> Any:
        return self._request("PUT", "/proxy/intercept", {"enabled": bool(enabled)})

    def set_intercept_responses(self, enabled: bool) -> Any:
        return self._request("PUT", "/proxy/intercept-response", {"enabled": bool(enabled)})


def decode_b64(field_value: str) -> bytes:
    return base64.b64decode(field_value.encode("ascii"))


def run_plugin(handler: Callable[[str, Dict[str, Any]], Dict[str, Any]]) -> None:
    raw = sys.stdin.read()
    invocation = json.loads(raw) if raw.strip() else {}
    hook = invocation.get("hook", "")
    payload = invocation.get("payload", {}) or {}
    result = handler(hook, payload) or {}
    json.dump(result, sys.stdout)
