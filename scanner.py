"""Local safe vuln-scan module.

Detection-only reflected-input check (a classic XSS *signal*).
It sends a unique marker and observes whether it is reflected.
This NEVER executes a payload or performs any injection — detection only.
"""
from __future__ import annotations
import http.client
import urllib.parse
from config import Config

MARKER = "pc_probe_8f3a1c"


def reflected_input_signal(target: str, port: int, timeout: float = 3.0) -> dict:
    path = "/?q=" + urllib.parse.quote(MARKER)
    result = {"check": "reflected_input", "marker": MARKER, "reflected": False}
    try:
        conn = http.client.HTTPConnection(target, port, timeout=timeout)
        conn.request("GET", path)
        body = conn.getresponse().read().decode("utf-8", "replace")
        conn.close()
        result["reflected"] = MARKER in body
        result["severity"] = "info" if not result["reflected"] else "medium"
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
    return result
