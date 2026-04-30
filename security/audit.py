"""
Append-only audit log — one JSON line per gateway decision.

Every allow AND deny is recorded so:
  - Security team can reconstruct what each agent called and when
  - Anomaly detection can flag sudden changes in call patterns
  - Forensics has an immutable trail after an incident

Log file: audit.jsonl (configurable via AUDIT_LOG env var)
"""

import hashlib
import json
import os
import time
from pathlib import Path

_LOG_PATH = Path(os.getenv("AUDIT_LOG", "audit.jsonl"))


def _hash(data: dict) -> str:
    """Stable SHA-256 prefix of request body — tamper-evident without storing raw params."""
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


def log(
    *,
    agent_id: str,
    role: str,
    tool: str,                                  # tool name, or "message.{to_agent}" for messages
    allowed: bool,
    delegated_by: str = "",
    delegation_depth: int = 0,
    params: dict | None = None,
    injection_rules: list[str] | None = None,   # rule names that fired in the sanitizer
    detail: str = "",                            # "opa_deny", "injection_detected_in_tool_response", etc.
) -> None:
    """Write one audit entry. Never raises — logging must not break the request path."""
    try:
        entry = {
            "ts":               time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "agent_id":         agent_id,
            "role":             role,
            "tool":             tool,
            "allowed":          allowed,
            "delegated_by":     delegated_by or None,
            "delegation_depth": delegation_depth or None,
            # Hash instead of raw params — params may contain PII or secrets
            "params_hash":      _hash(params or {}),
            "injection_rules":  injection_rules or None,
            "detail":           detail or None,
        }
        # Strip None values to keep log lines compact and easy to grep
        entry = {k: v for k, v in entry.items() if v is not None}

        # Append mode — each log() call adds one line; file never gets rewritten
        with _LOG_PATH.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        # Swallow all errors — a broken audit log must not take down the gateway
        pass


def tail(n: int = 20) -> list[dict]:
    """Return the last n audit entries (useful for debug / test assertions)."""
    if not _LOG_PATH.exists():
        return []
    lines = _LOG_PATH.read_text().splitlines()
    return [json.loads(l) for l in lines[-n:] if l.strip()]
