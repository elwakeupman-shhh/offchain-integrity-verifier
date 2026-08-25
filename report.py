"""Report & validation-matrix seed.

Produces a structured finding that the blue-team layer can consume to
verify whether a defense (WAF/EDR/SIEM rule) would have blocked it.
"""
from __future__ import annotations
import json
import datetime


def build(recon: dict, scan: dict) -> dict:
    return {
        "engine": "integrity-chain",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": recon.get("target"),
        "findings": [
            {
                "id": "PC-REFLECT-001",
                "type": scan.get("check"),
                "reflected": scan.get("reflected"),
                "severity": scan.get("severity", "info"),
                # Validation matrix row: filled by blue-team layer later.
                "defense_blocked": None,
                "defense_rule": None,
            }
        ],
        "recon": recon,
    }


def dump(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)
