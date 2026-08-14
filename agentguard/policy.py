"""Policy engine: evaluates MCP tool calls against a YAML rule set.

v1 scope: three independent rule categories (file access, command
execution, network access), matched against tool-call arguments by
key name. A call is denied if any argument matches a deny rule in its
category; everything else defaults to allow. Categories the config
doesn't mention are skipped, not denied — this is a MVP allowlist/
denylist engine, not a full sandbox.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import yaml

# Argument key names (case-insensitive) treated as carrying a value of
# the given category. MCP servers don't share a schema, so we match on
# common conventions rather than a fixed tool allowlist.
PATH_ARG_KEYS = {
    "path", "file_path", "filepath", "file", "filename",
    "target", "dest", "destination", "source", "src",
}
COMMAND_ARG_KEYS = {"command", "cmd", "script", "shell"}
URL_ARG_KEYS = {"url", "uri", "endpoint", "host", "domain"}


@dataclass
class Decision:
    allowed: bool
    category: str
    reason: str
    matched_rule: Optional[str] = None


@dataclass
class _CategoryRule:
    enabled: bool = True
    deny_patterns: list = field(default_factory=list)
    allow_patterns: list = field(default_factory=list)
    default_action: str = "allow"  # applies only when allow_patterns is non-empty


class PolicyEngine:
    def __init__(self, config: dict):
        config = config or {}
        self._file_rule = self._load_category(config.get("file_access", {}))
        self._command_rule = self._load_category(config.get("command_exec", {}))
        self._network_rule = self._load_category(config.get("network", {}))

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyEngine":
        with open(path, "r") as f:
            raw = yaml.safe_load(f) or {}
        return cls(raw)

    @staticmethod
    def _load_category(raw: dict) -> _CategoryRule:
        raw = raw or {}
        return _CategoryRule(
            enabled=raw.get("enabled", True),
            deny_patterns=raw.get("deny_patterns", []) or [],
            allow_patterns=raw.get("allow_patterns", []) or [],
            default_action=raw.get("default_action", "allow"),
        )

    def evaluate(self, tool_name: str, arguments: dict) -> Decision:
        checked_categories = []
        for key, value in (arguments or {}).items():
            if not isinstance(value, str):
                continue
            key_l = key.lower()
            decision = None
            if key_l in PATH_ARG_KEYS and self._file_rule.enabled:
                checked_categories.append("file_access")
                decision = self._check_deny_glob(value, self._file_rule, "file_access")
            elif key_l in COMMAND_ARG_KEYS and self._command_rule.enabled:
                checked_categories.append("command_exec")
                decision = self._check_deny_regex(value, self._command_rule, "command_exec")
            elif key_l in URL_ARG_KEYS and self._network_rule.enabled:
                checked_categories.append("network")
                decision = self._check_network(value, self._network_rule)
            if decision is not None:
                return decision
        if checked_categories:
            return Decision(
                allowed=True,
                category=checked_categories[0],
                reason=f"tool '{tool_name}' call checked against {', '.join(checked_categories)}; no deny rule matched",
            )
        return Decision(
            allowed=True,
            category="none",
            reason=f"tool '{tool_name}' call has no arguments matching a configured policy category",
        )

    @staticmethod
    def _check_deny_glob(value: str, rule: _CategoryRule, category: str) -> Optional[Decision]:
        expanded = os.path.expanduser(value)
        for pattern in rule.deny_patterns:
            if fnmatch.fnmatch(expanded, os.path.expanduser(pattern)):
                return Decision(
                    False, category,
                    f"value '{value}' matches deny pattern '{pattern}'",
                    pattern,
                )
        return None

    @staticmethod
    def _check_deny_regex(value: str, rule: _CategoryRule, category: str) -> Optional[Decision]:
        for pattern in rule.deny_patterns:
            if re.search(pattern, value):
                return Decision(
                    False, category,
                    f"value '{value}' matches deny pattern '{pattern}'",
                    pattern,
                )
        return None

    @staticmethod
    def _check_network(value: str, rule: _CategoryRule) -> Optional[Decision]:
        host = urlparse(value).hostname or value
        if not rule.allow_patterns:
            return None
        if any(fnmatch.fnmatch(host, pattern) for pattern in rule.allow_patterns):
            return None
        if rule.default_action == "deny":
            return Decision(
                False, "network",
                f"host '{host}' is not in the network allowlist",
            )
        return None
