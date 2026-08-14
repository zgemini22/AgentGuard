"""Append-only JSONL audit log for AgentGuard policy decisions.

v1 is intentionally a plain append-only log, not tamper-evident yet.
Hash-chaining each entry to its predecessor (so the log can be verified
offline) is planned for the injection-detection/redaction milestone,
not this one — no point hashing a log format that's still settling.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from .policy import Decision


class AuditLog:
    def __init__(self, path: str = "agentguard_audit.log"):
        self.path = Path(path)

    def record(self, tool_name: str, arguments: dict, decision: Decision) -> dict:
        entry = {
            "ts": time.time(),
            "tool": tool_name,
            "arguments": arguments,
            "allowed": decision.allowed,
            "category": decision.category,
            "reason": decision.reason,
            "matched_rule": decision.matched_rule,
        }
        with self.path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        return entry
