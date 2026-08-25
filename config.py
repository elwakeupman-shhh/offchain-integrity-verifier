"""Configuration & secret handling for integrity-chain.

SECURITY (per a past credential-exposure incident):
  - Never hardcode secrets. Read everything from environment.
  - .env.example documents required vars with PLACEHOLDER values only.
  - Sensitive values are read at runtime and never written to disk/logs.
"""
from __future__ import annotations
import os
from dataclasses import dataclass


@dataclass
class Config:
    target: str = os.environ.get("PC_TARGET", "127.0.0.1")
    target_port: int = int(os.environ.get("PC_TARGET_PORT", "8080"))
    allow_external: bool = os.environ.get("PC_ALLOW_EXTERNAL", "0") == "1"
    # Optional. Loaded at runtime only; never logged or reported.
    api_token: str | None = os.environ.get("PC_API_TOKEN") or None

    @property
    def is_loopback(self) -> bool:
        return self.target in ("127.0.0.1", "localhost", "::1")
