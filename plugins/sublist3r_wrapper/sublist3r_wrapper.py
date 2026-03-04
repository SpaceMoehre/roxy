#!/usr/bin/env python3
"""Roxy plugin: Sublist3r subdomain enumeration wrapper.

Enumerates subdomains for a given domain using multiple passive sources.
Results can be added to the proxy scope (all or selected) from the UI.

Supported sources:
  - Sublist3r PassiveDNS API  (api.sublist3r.com)
  - crt.sh Certificate Transparency logs
  - Full Sublist3r tool (if installed)
"""
from __future__ import annotations

import importlib
import json
import re
import socket
import ssl
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen, build_opener, ProxyHandler, HTTPSHandler
import sys


# ---------------------------------------------------------------------------
# SDK bootstrap
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Dependency auto-install
# ---------------------------------------------------------------------------

def _ensure_packages(*packages: str) -> None:
    """Install missing packages via pip at runtime."""
    missing: list[str] = []
    for pkg in packages:
        import_name = pkg.replace("-", "_")
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pkg)
    if not missing:
        return
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", *missing],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    # Refresh the import machinery so newly installed packages are visible.
    importlib.invalidate_caches()


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def _read_template(name: str, fallback: str) -> str:
    path = TEMPLATE_DIR / name
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return fallback


PANEL_HTML = _read_template(
    "panel.html",
    "<article class='card'><h3>Sublist3r</h3><p>panel template missing</p></article>",
)
SETTINGS_HTML = _read_template(
    "settings.html",
    "<h3>Sublist3r</h3><p>settings template missing</p>",
)
SCRIPT_JS = _read_template(
    "script.js",
    "window.RoxyModuleHost.registerModule({id:'sublist3r'});",
)


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


def _clean_domain(raw: str) -> str:
    """Normalize and validate a domain string."""
    domain = raw.strip().lower()
    # Strip common protocol prefixes.
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/").split("/")[0]
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"invalid domain: {raw!r}")
    return domain


# ---------------------------------------------------------------------------
# Subdomain enumeration sources
# ---------------------------------------------------------------------------

_SSL_CTX: ssl.SSLContext | None = None
_PROXY_URL: str | None = None


def _get_ssl_ctx() -> ssl.SSLContext:
    global _SSL_CTX
    if _SSL_CTX is None:
        _SSL_CTX = ssl.create_default_context()
        _SSL_CTX.check_hostname = False
        _SSL_CTX.verify_mode = ssl.CERT_NONE
    return _SSL_CTX


def _set_proxy(proxy_url: str | None) -> None:
    """Configure the module-level proxy URL for HTTP helpers."""
    global _PROXY_URL
    _PROXY_URL = proxy_url


def _build_opener_with_proxy():
    """Build a urllib opener that routes through the configured proxy.

    When a proxy is configured, we attach an HTTPSHandler with certificate
    verification disabled so that the MITM certificate presented by Roxy
    is accepted.
    """
    if _PROXY_URL:
        return build_opener(
            ProxyHandler({"http": _PROXY_URL, "https": _PROXY_URL}),
            HTTPSHandler(context=_get_ssl_ctx()),
        )
    return None


def _is_timeout_error(exc: BaseException) -> bool:
    """Best-effort timeout detection for urllib/socket wrapped exceptions."""
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    reason = getattr(exc, "reason", None)
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return True
    text = str(exc).lower()
    return "timed out" in text or "timeout" in text


def _fetch_response_bytes(req: Request, timeout: float) -> bytes:
    """Fetch URL bytes, retrying direct if a proxied request times out."""
    opener = _build_opener_with_proxy()
    if opener:
        try:
            with opener.open(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as proxy_exc:
            # Common failure mode: plugin requests routed through Roxy while
            # interception is enabled can stall; retry directly once.
            if _is_timeout_error(proxy_exc):
                try:
                    with urlopen(req, timeout=timeout, context=_get_ssl_ctx()) as resp:
                        return resp.read()
                except Exception as direct_exc:
                    raise RuntimeError(
                        f"proxy request timed out; direct retry failed: {direct_exc}"
                    ) from direct_exc
            raise

    with urlopen(req, timeout=timeout, context=_get_ssl_ctx()) as resp:
        return resp.read()


def _http_get_json(url: str, timeout: float = 15.0) -> Any:
    """Perform a simple HTTPS GET and parse JSON."""
    req = Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Roxy Proxy Plugin)",
        "Accept": "application/json",
    })
    return json.loads(_fetch_response_bytes(req, timeout).decode("utf-8", "replace"))


def _http_get_text(url: str, timeout: float = 15.0) -> str:
    """Perform a simple HTTPS GET and return text."""
    req = Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Roxy Proxy Plugin)",
        "Accept": "text/html,application/json",
    })
    return _fetch_response_bytes(req, timeout).decode("utf-8", "replace")


def _source_sublist3r_api(domain: str) -> List[str]:
    """Query the Sublist3r PassiveDNS API."""
    url = f"https://api.sublist3r.com/search.php?domain={domain}"
    data = _http_get_json(url, timeout=20.0)
    if isinstance(data, list):
        return [str(s).strip().lower() for s in data if s]
    return []


def _source_crtsh(domain: str) -> List[str]:
    """Query crt.sh Certificate Transparency logs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains: set[str] = set()
    data = _http_get_json(url, timeout=20.0)
    if isinstance(data, list):
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                sub = line.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    if "*" not in sub and "@" not in sub:
                        subdomains.add(sub)
    return list(subdomains)


# Engines known to be broken or unmaintained in the sublist3r package.
_BROKEN_ENGINES = {"dnsdumpster"}

# Default engine list with broken ones removed.
_DEFAULT_ENGINES = "baidu,yahoo,google,bing,ask,netcraft,virustotal,threatcrowd,ssl,passivedns"


def _source_full_sublist3r(domain: str, threads: int = 30,
                            engines: Optional[str] = None,
                            bruteforce: bool = False) -> List[str]:
    """Use the full Sublist3r tool, auto-installing it if necessary."""
    _ensure_packages("sublist3r", "requests", "dnspython")

    # Default to the curated engine list that excludes broken scrapers.
    if not engines:
        engines = _DEFAULT_ENGINES

    try:
        import sublist3r  # type: ignore[import-untyped]
        import io, os

        # Suppress sublist3r's internal multiprocessing stderr noise;
        # we emit structured progress via _progress() instead.
        devnull = open(os.devnull, "w")
        old_stderr = sys.stderr
        sys.stderr = devnull
        try:
            results = sublist3r.main(
                domain,
                threads,
                None,       # savefile
                ports=None,
                silent=True,
                verbose=False,
                enable_bruteforce=bruteforce,
                engines=engines,
            )
        finally:
            sys.stderr = old_stderr
            devnull.close()

        if isinstance(results, (list, set)):
            return [str(s).strip().lower() for s in results if s]
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Progress helpers (stderr → streaming WS output)
# ---------------------------------------------------------------------------

def _progress(msg: str, **kwargs: Any) -> None:
    """Emit a progress line to stderr (JSON). Rust reads these line-by-line."""
    payload = {"type": "progress", "message": msg}
    payload.update(kwargs)
    print(json.dumps(payload), file=sys.stderr, flush=True)


def _extract_domain_from_url(url: str) -> str:
    """Extract the domain from a full URL string."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        host = parsed.hostname or parsed.path.split("/")[0]
        if host:
            return host.lower().strip()
    except Exception:
        pass
    d = url.strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    return d.rstrip("/").split("/")[0].split(":")[0]


def _setting_bool(settings: Dict[str, Any], key: str, default: bool) -> bool:
    value = settings.get(key, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
    return default


# ---------------------------------------------------------------------------
# Main enumeration logic
# ---------------------------------------------------------------------------

def enumerate_subdomains(domain: str, settings: Dict[str, Any]) -> Dict[str, Any]:
    """Run subdomain enumeration and return structured results."""
    domain = _clean_domain(domain)
    use_sublist3r_api = _setting_bool(settings, "use_sublist3r_api", True)
    use_crtsh = _setting_bool(settings, "use_crtsh", True)
    use_full_tool = _setting_bool(settings, "use_full_sublist3r", False)
    bruteforce = _setting_bool(settings, "bruteforce", False)
    threads = int(settings.get("threads", 30))
    engines = settings.get("engines") or None

    # Configure proxy if the user opted in (default: enabled).
    if _setting_bool(settings, "proxy_through_roxy", True):
        proxy_port = int(settings.get("roxy_proxy_port", 8080))
        _set_proxy(f"http://127.0.0.1:{proxy_port}")
    else:
        _set_proxy(None)

    all_subs: set[str] = set()
    sources_used: List[str] = []
    errors: List[str] = []
    t0 = time.time()

    _progress(f"Starting enumeration for {domain}")

    # Source 1: Sublist3r PassiveDNS API
    if use_sublist3r_api:
        _progress("Querying Sublist3r PassiveDNS API\u2026")
        try:
            results = _source_sublist3r_api(domain)
            all_subs.update(results)
            sources_used.append(f"sublist3r-api ({len(results)})")
            _progress(f"Sublist3r API returned {len(results)} subdomain(s)", found=len(results))
        except Exception as exc:
            errors.append(f"sublist3r-api: {exc}")
            _progress(f"Sublist3r API error: {exc}", error=True)
    else:
        _progress("Skipping Sublist3r API (disabled)")

    # Source 2: crt.sh
    if use_crtsh:
        _progress("Querying crt.sh Certificate Transparency\u2026")
        try:
            results = _source_crtsh(domain)
            all_subs.update(results)
            sources_used.append(f"crt.sh ({len(results)})")
            _progress(f"crt.sh returned {len(results)} subdomain(s)", found=len(results))
        except Exception as exc:
            errors.append(f"crt.sh: {exc}")
            _progress(f"crt.sh error: {exc}", error=True)
    else:
        _progress("Skipping crt.sh (disabled)")

    # Source 3: Full Sublist3r tool
    if use_full_tool:
        _progress("Running full Sublist3r tool (may take a while)\u2026")
        try:
            results = _source_full_sublist3r(domain, threads, engines, bruteforce)
            all_subs.update(results)
            sources_used.append(f"sublist3r-full ({len(results)})")
            _progress(f"Sublist3r full returned {len(results)} subdomain(s)", found=len(results))
        except Exception as exc:
            errors.append(f"sublist3r-full: {exc}")
            _progress(f"Sublist3r-full error: {exc}", error=True)

    # Remove the apex domain itself from results (user likely already knows it).
    all_subs.discard(domain)

    elapsed = round(time.time() - t0, 2)
    sorted_subs = sorted(all_subs)

    _progress(
        f"Enumeration complete: {len(sorted_subs)} subdomain(s) in {elapsed}s",
        done=True,
        count=len(sorted_subs),
    )

    return {
        "domain": domain,
        "subdomains": sorted_subs,
        "count": len(sorted_subs),
        "sources": sources_used,
        "errors": errors,
        "elapsed_seconds": elapsed,
    }


# ---------------------------------------------------------------------------
# Plugin handler
# ---------------------------------------------------------------------------

def handle(hook: str, payload: dict) -> dict:
    builder = PluginBuilder()
    settings = payload.get("plugin_settings", {}) or {}

    if hook == "on_load":
        builder.register_ui_module(
            UiModuleDefinition(
                id="sublist3r",
                title="Sublist3r",
                nav_hidden=True,
                accepts_request=True,
                panel_html=PANEL_HTML,
                settings_html=SETTINGS_HTML,
                script_js=SCRIPT_JS,
            )
        )
        return builder.to_dict()

    if hook == "enumerate":
        domain = payload.get("domain", "")
        # Runtime settings coming from the Sublist3r panel take precedence
        # over persisted plugin settings for this invocation.
        runtime_settings = payload.get("settings")
        if isinstance(runtime_settings, dict):
            settings = {**settings, **runtime_settings}
        # Accept a full URL and extract the domain from it.
        if not domain:
            url = payload.get("url", "")
            if url:
                domain = _extract_domain_from_url(url)
        if not domain:
            builder.set_result({"error": "no domain or URL provided"})
            return builder.to_dict()

        try:
            result = enumerate_subdomains(domain, settings)
            builder.set_result(result)
        except ValueError as exc:
            builder.set_result({"error": str(exc)})
        except Exception as exc:
            builder.set_result({"error": f"enumeration failed: {exc}"})

        return builder.to_dict()

    return {}


if __name__ == "__main__":
    run_plugin(handle)
