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
from typing import List, Optional

from .policy import Decision


class AuditLog:
    def __init__(self, path: str = "agentguard_audit.log"):
        self.path = Path(path)

    def record(self, tool_name: str, arguments: dict, decision: Decision) -> dict:
        entry = {
            "ts": time.time(),
            "event": "policy_decision",
            "tool": tool_name,
            "arguments": arguments,
            "allowed": decision.allowed,
            "category": decision.category,
            "reason": decision.reason,
            "matched_rule": decision.matched_rule,
        }
        self._append(entry)
        return entry

    def record_redaction(self, tool_name: str, rule_names: List[str]) -> dict:
        """Logs that secrets were masked in a tool's output. Never logs the
        secret values themselves — only which rules matched and how many
        times, so the audit log itself can't leak what it caught."""
        entry = {
            "ts": time.time(),
            "event": "redaction",
            "tool": tool_name,
            "rules_matched": rule_names,
            "count": len(rule_names),
        }
        self._append(entry)
        return entry

    def _append(self, entry: dict) -> None:
        with self.path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
