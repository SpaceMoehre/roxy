#!/usr/bin/env python3
"""Roxy plugin: Photon OSINT web crawler wrapper.

Wraps the Photon crawler (https://github.com/s0md3v/Photon) to perform
fast, recursive web crawling and data extraction from the Roxy UI.

Extracted data categories:
  - Internal & external URLs
  - URLs with parameters (fuzzable)
  - Intel (emails, social media accounts, AWS buckets, etc.)
  - Files (pdf, png, xml, etc.)
  - Secret keys (API keys, auth tokens, high-entropy strings)
  - JavaScript files & endpoints discovered within them
  - Robots.txt entries
  - Subdomains & DNS data (optional)
  - Custom regex matches
"""
from __future__ import annotations

import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


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
    "<article class='card'><h3>Photon Crawler</h3><p>panel template missing</p></article>",
)
SETTINGS_HTML = _read_template(
    "settings.html",
    "<h3>Photon Crawler</h3><p>settings template missing</p>",
)
SCRIPT_JS = _read_template(
    "script.js",
    "window.RoxyModuleHost.registerModule({id:'photon-crawler'});",
)


# ---------------------------------------------------------------------------
# Photon tool management
# ---------------------------------------------------------------------------

_ROXY_DATA = Path(".roxy-data").resolve()
_TOOLS_DIR = _ROXY_DATA / "tools"
_PHOTON_DIR = _TOOLS_DIR / "photon"
_PHOTON_REPO = "https://github.com/s0md3v/Photon.git"


_PHOTON_DEPS_MARKER = _PHOTON_DIR / ".roxy-deps-ok"


def _ensure_deps_installed() -> None:
    """Ensure Photon's Python dependencies are present (idempotent)."""
    if _PHOTON_DEPS_MARKER.exists():
        return

    req_file = _PHOTON_DIR / "requirements.txt"
    _progress("Installing Photon dependencies…")
    pip_cmd = [
        sys.executable, "-m", "pip", "install", "--quiet",
        "--disable-pip-version-check",
    ]
    if req_file.exists():
        pip_cmd.extend(["-r", str(req_file)])
    # Extra deps missing from Photon's requirements.txt
    pip_cmd.append("tld")
    try:
        subprocess.check_call(
            pip_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        _PHOTON_DEPS_MARKER.write_text("ok")
    except subprocess.CalledProcessError as exc:
        _progress(f"pip install warning: {exc}", error=True)


def _ensure_photon_installed() -> Path:
    """Clone or update the Photon repository. Returns path to photon.py."""
    photon_script = (_PHOTON_DIR / "photon.py").resolve()

    if photon_script.exists():
        _ensure_deps_installed()
        return photon_script

    _TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    _progress("Cloning Photon repository…")
    try:
        subprocess.check_call(
            ["git", "clone", "--depth", "1", _PHOTON_REPO, str(_PHOTON_DIR)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "git is not installed; cannot clone Photon. "
            "Install git or manually place Photon in .roxy-data/tools/photon/"
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"git clone failed: {exc}")

    if not photon_script.exists():
        raise RuntimeError(
            f"Photon clone succeeded but {photon_script} not found"
        )

    _ensure_deps_installed()

    _progress("Photon installed successfully")
    return photon_script


def _update_photon() -> str:
    """Pull latest changes for the Photon repository."""
    if not (_PHOTON_DIR / ".git").exists():
        _ensure_photon_installed()
        return "Photon installed (fresh clone)"

    try:
        subprocess.check_call(
            ["git", "-C", str(_PHOTON_DIR), "pull", "--ff-only"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        return "Photon updated successfully"
    except subprocess.CalledProcessError as exc:
        return f"Update failed: {exc}"


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
    r"(:\d+)?"
    r"(/.*)?$"
)


def _clean_url(raw: str) -> str:
    """Normalize and validate a target URL."""
    url = raw.strip()
    if not url:
        raise ValueError("no URL provided")

    # Add scheme if missing.
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    if not _URL_RE.match(url):
        raise ValueError(f"invalid URL: {raw!r}")
    return url


# ---------------------------------------------------------------------------
# Progress helpers (stderr -> streaming WS output)
# ---------------------------------------------------------------------------

def _progress(msg: str, **kwargs: Any) -> None:
    """Emit a progress line to stderr (JSON). Rust reads these line-by-line."""
    payload = {"type": "progress", "message": msg}
    payload.update(kwargs)
    print(json.dumps(payload), file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Main crawl logic
# ---------------------------------------------------------------------------

def _build_photon_cmd(
    photon_script: Path,
    url: str,
    settings: Dict[str, Any],
    output_dir: str,
) -> List[str]:
    """Build the Photon command line from plugin settings."""
    cmd = [
        sys.executable,
        str(Path(photon_script).resolve()),
        "-u", url,
        "-o", str(Path(output_dir).resolve()),
        "-e", "json",
    ]

    # Crawl depth (default: 2).
    level = int(settings.get("level", 2))
    if level > 0:
        cmd.extend(["-l", str(level)])

    # Thread count (default: 2).
    threads = int(settings.get("threads", 2))
    if threads > 0:
        cmd.extend(["-t", str(threads)])

    # Delay between requests (default: 0).
    delay = float(settings.get("delay", 0))
    if delay > 0:
        cmd.extend(["-d", str(delay)])

    # HTTP timeout (default: 6).
    timeout_s = float(settings.get("timeout", 6))
    if timeout_s > 0:
        cmd.extend(["--timeout", str(timeout_s)])

    # Cookie header.
    cookie = str(settings.get("cookie", "")).strip()
    if cookie:
        cmd.extend(["-c", cookie])

    # Custom regex.
    regex = str(settings.get("regex", "")).strip()
    if regex:
        cmd.extend(["-r", regex])

    # Seed URLs.
    seeds = str(settings.get("seeds", "")).strip()
    if seeds:
        cmd.extend(["-s"] + [s.strip() for s in seeds.split(",") if s.strip()])

    # Exclude pattern.
    exclude = str(settings.get("exclude", "")).strip()
    if exclude:
        cmd.extend(["--exclude", exclude])

    # User-Agent(s).
    user_agent = str(settings.get("user_agent", "")).strip()
    if user_agent:
        cmd.extend(["--user-agent", user_agent])

    # Boolean switches.
    if settings.get("extract_keys", False):
        cmd.append("--keys")
    if settings.get("wayback", False):
        cmd.append("--wayback")
    if settings.get("dns", False):
        cmd.append("--dns")
    if settings.get("only_urls", False):
        cmd.append("--only-urls")
    if settings.get("ninja", False):
        cmd.append("--ninja")

    # Always verbose for progress streaming.
    cmd.append("-v")

    return cmd


def _parse_output_dir(output_dir: str) -> Dict[str, Any]:
    """Parse Photon's output files from the output directory."""
    results: Dict[str, Any] = {}
    output_path = Path(output_dir)

    if not output_path.exists():
        return results

    # Check for exported JSON first (from --export json).
    json_files = list(output_path.glob("*.json"))
    for jf in json_files:
        try:
            data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                results.update(data)
                return results
        except (json.JSONDecodeError, OSError):
            pass

    # Fall back to reading individual text files.
    categories = [
        "internal", "external", "fuzzable", "files", "intel",
        "scripts", "endpoints", "keys", "robots", "custom",
        "failed", "subdomains",
    ]
    for cat in categories:
        txt_file = output_path / f"{cat}.txt"
        if txt_file.exists():
            try:
                lines = txt_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                results[cat] = [line.strip() for line in lines if line.strip()]
            except OSError:
                pass

    return results


def run_photon_crawl(url: str, settings: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a Photon crawl and return structured results."""
    url = _clean_url(url)
    t0 = time.time()

    _progress(f"Preparing Photon crawl for {url}")

    # Ensure Photon is available.
    try:
        photon_script = _ensure_photon_installed()
    except RuntimeError as exc:
        return {"error": str(exc)}

    # Create a temporary output directory (absolute paths to avoid cwd issues).
    tmp_base = _ROXY_DATA / "tmp" / "photon-runs"
    tmp_base.mkdir(parents=True, exist_ok=True)
    output_dir = str(Path(tempfile.mkdtemp(dir=str(tmp_base), prefix="crawl-")).resolve())

    cmd = _build_photon_cmd(photon_script, url, settings, output_dir)
    _progress(f"Starting Photon: depth={settings.get('level', 2)}, "
              f"threads={settings.get('threads', 2)}")

    # Run Photon as a subprocess, streaming output for progress.
    stdout_lines: List[str] = []
    stderr_lines: List[str] = []

    # Compute a generous timeout: base 300s + 60s per crawl level.
    max_timeout = int(settings.get("max_timeout", 600))
    level = int(settings.get("level", 2))
    effective_timeout = min(max_timeout, 300 + 60 * level)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(_PHOTON_DIR.resolve()),
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"},
        )

        # Stream stdout in real-time for progress.
        assert proc.stdout is not None
        assert proc.stderr is not None

        import selectors
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        sel.register(proc.stderr, selectors.EVENT_READ)

        deadline = time.time() + effective_timeout
        active_streams = 2

        while active_streams > 0:
            remaining = deadline - time.time()
            if remaining <= 0:
                proc.kill()
                _progress("Photon timed out", error=True)
                break

            events = sel.select(timeout=min(remaining, 5.0))
            for key, _ in events:
                line = key.fileobj.readline()  # type: ignore[union-attr]
                if not line:
                    sel.unregister(key.fileobj)
                    active_streams -= 1
                    continue

                line = line.rstrip("\n")
                if key.fileobj is proc.stdout:
                    stdout_lines.append(line)
                    # Parse Photon's colored output for progress messages.
                    clean = _strip_ansi(line)
                    if clean.strip():
                        _progress(clean.strip())
                else:
                    stderr_lines.append(line)
                    # Surface subprocess errors to the user immediately.
                    clean = _strip_ansi(line).strip()
                    if clean:
                        _progress(f"[stderr] {clean}", error=True)

        sel.close()
        proc.wait(timeout=10)
        returncode = proc.returncode

        if returncode != 0:
            _progress(f"Photon exited with code {returncode}", error=True)

    except subprocess.TimeoutExpired:
        _progress("Photon process timed out", error=True)
        returncode = -1
    except FileNotFoundError:
        return {"error": "Python executable not found"}
    except Exception as exc:
        return {"error": f"Failed to run Photon: {exc}"}

    # Parse output.
    _progress("Parsing Photon results…")
    raw_results = _parse_output_dir(output_dir)

    # Clean up the temp directory.
    try:
        shutil.rmtree(output_dir, ignore_errors=True)
    except OSError:
        pass

    elapsed = round(time.time() - t0, 2)

    # Build summary counts.
    summary: Dict[str, int] = {}
    categories = [
        "internal", "external", "fuzzable", "files", "intel",
        "scripts", "endpoints", "keys", "robots", "custom",
        "failed", "subdomains",
    ]
    for cat in categories:
        items = raw_results.get(cat, [])
        if isinstance(items, list):
            summary[cat] = len(items)
        elif isinstance(items, (set, frozenset)):
            summary[cat] = len(items)
            raw_results[cat] = sorted(items)

    total_findings = sum(summary.values())
    _progress(
        f"Crawl complete: {total_findings} total findings in {elapsed}s",
        done=True,
        count=total_findings,
    )

    return {
        "url": url,
        "results": raw_results,
        "summary": summary,
        "total_findings": total_findings,
        "elapsed_seconds": elapsed,
        "returncode": returncode,
        "errors": stderr_lines[-5:] if returncode != 0 else [],
    }


# ---------------------------------------------------------------------------
# ANSI escape stripping
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


# ---------------------------------------------------------------------------
# Plugin handler
# ---------------------------------------------------------------------------

def handle(hook: str, payload: dict) -> dict:
    builder = PluginBuilder()
    settings = payload.get("plugin_settings", {}) or {}

    if hook == "on_load":
        builder.register_ui_module(
            UiModuleDefinition(
                id="photon-crawler",
                title="Photon Crawler",
                nav_hidden=True,
                panel_html=PANEL_HTML,
                settings_html=SETTINGS_HTML,
                script_js=SCRIPT_JS,
            )
        )
        return builder.to_dict()

    if hook == "crawl":
        url = payload.get("url", "")
        if not url:
            builder.set_result({"error": "no URL provided"})
            return builder.to_dict()

        try:
            result = run_photon_crawl(url, settings)
            builder.set_result(result)
        except ValueError as exc:
            builder.set_result({"error": str(exc)})
        except Exception as exc:
            builder.set_result({"error": f"crawl failed: {exc}"})

        return builder.to_dict()

    if hook == "update":
        try:
            msg = _update_photon()
            builder.set_result({"message": msg})
        except Exception as exc:
            builder.set_result({"error": f"update failed: {exc}"})
        return builder.to_dict()

    if hook == "status":
        photon_script = _PHOTON_DIR / "photon.py"
        installed = photon_script.exists()
        builder.set_result({
            "installed": installed,
            "path": str(_PHOTON_DIR) if installed else None,
        })
        return builder.to_dict()

    return {}


if __name__ == "__main__":
    run_plugin(handle)
