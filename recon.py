"""Safe recon module.

Detection-only: grabs HTTP response headers / status from the target.
No intrusive actions, no external calls beyond the configured target.
"""
from __future__ import annotations
import http.client
from config import Config


def grab(target: str, port: int, timeout: float = 3.0) -> dict:
    out = {"target": target, "port": port, "status": None, "server": None, "headers": {}}
    try:
        conn = http.client.HTTPConnection(target, port, timeout=timeout)
        conn.request("GET", "/")
        resp = conn.getresponse()
        out["status"] = resp.status
        out["server"] = resp.getheader("Server")
        out["headers"] = {k: v for k, v in resp.getheaders()}
        conn.close()
    except Exception as e:  # noqa: BLE001 - recon must fail soft
        out["error"] = str(e)
    return out
