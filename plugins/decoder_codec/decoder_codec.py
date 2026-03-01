#!/usr/bin/env python3
from __future__ import annotations

import base64
import binascii
import html
from pathlib import Path
from typing import Optional
import sys
import urllib.parse


def _find_sdk_src(start: Path) -> Optional[Path]:
    for candidate_root in [start] + list(start.parents):
        sdk_src = candidate_root / "python" / "roxy-plugin-sdk" / "src"
        if sdk_src.exists():
            return sdk_src
    return None


BASE_DIR = Path(__file__).resolve().parent
SDK_SRC = _find_sdk_src(BASE_DIR)
if SDK_SRC is not None:
    sys.path.insert(0, str(SDK_SRC))

from roxy_plugin_sdk import PluginBuilder, run_plugin


OPERATIONS: dict[str, tuple[str, str]] = {
    "base64_encode": ("Base64 Encode", "Encode input using RFC 4648 Base64"),
    "base64_decode": ("Base64 Decode", "Decode Base64 input"),
    "base32_encode": ("Base32 Encode", "Encode input using RFC 4648 Base32"),
    "base32_decode": ("Base32 Decode", "Decode Base32 input"),
    "hex_encode": ("Hex Encode", "Encode input to hexadecimal"),
    "hex_decode": ("Hex Decode", "Decode hexadecimal input"),
    "url_encode": ("URL Encode", "Percent-encode input for URLs"),
    "url_decode": ("URL Decode", "Decode percent-encoded URL input"),
    "html_encode": ("HTML Encode", "Escape HTML entities"),
    "html_decode": ("HTML Decode", "Unescape HTML entities"),
}


def _normalize_text(payload: dict) -> str:
    return str(payload.get("payload", ""))


def _normalize_mode(payload: dict) -> str:
    explicit = str(payload.get("plugin_mode", "")).strip().lower()
    if explicit:
        return explicit

    raw_mode = str(payload.get("mode", "")).strip()
    if raw_mode.startswith("plugin:"):
        raw_mode = raw_mode[len("plugin:") :]
    if ":" in raw_mode:
        _, suffix = raw_mode.split(":", 1)
        return suffix.strip().lower()
    return raw_mode.strip().lower()


def _result_for(mode: str, text: str) -> str:
    if mode == "base64_encode":
        return base64.b64encode(text.encode("utf-8")).decode("ascii")
    if mode == "base64_decode":
        decoded = base64.b64decode(text.encode("ascii"), validate=True)
        return decoded.decode("utf-8", "replace")
    if mode == "base32_encode":
        return base64.b32encode(text.encode("utf-8")).decode("ascii")
    if mode == "base32_decode":
        decoded = base64.b32decode(text.encode("ascii"), casefold=True)
        return decoded.decode("utf-8", "replace")
    if mode == "hex_encode":
        return text.encode("utf-8").hex()
    if mode == "hex_decode":
        normalized = "".join(text.split())
        decoded = bytes.fromhex(normalized)
        return decoded.decode("utf-8", "replace")
    if mode == "url_encode":
        return urllib.parse.quote(text, safe="")
    if mode == "url_decode":
        return urllib.parse.unquote(text)
    if mode == "html_encode":
        return html.escape(text, quote=True)
    if mode == "html_decode":
        return html.unescape(text)
    if mode in {"list", "help", "modes"}:
        lines = [f"{k}: {v[1]}" for k, v in OPERATIONS.items()]
        return "\n".join(lines)
    raise ValueError(f"unsupported decoder operation '{mode}'")


def handle(hook: str, payload: dict) -> dict:
    if hook != "decoder":
        return {}

    builder = PluginBuilder()
    text = _normalize_text(payload)
    mode = _normalize_mode(payload)
    if not mode:
        mode = "base64_encode"

    try:
        builder.set_result(_result_for(mode, text))
    except (ValueError, binascii.Error) as err:
        builder.set_result(f"decoder-codec error: {err}")
    return builder.to_dict()


if __name__ == "__main__":
    run_plugin(handle)
