"""Policy engine: evaluates MCP tool calls against a YAML rule set.

Three independent rule categories (file access, command execution,
network access), matched against tool-call arguments. Which category an
argument belongs to is decided by `agentguard.classify` — by the tool's
declared schema when the proxy has seen one, by key-name conventions
otherwise. A call is denied if any argument matches a deny rule in its
category; everything else defaults to allow. Categories the config
doesn't mention are skipped, not denied — this is an allowlist/denylist
engine, not a full sandbox.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple
from urllib.parse import urlparse

import yaml

from .classify import (  # noqa: F401  (re-exported for backward compatibility)
    COMMAND_ARG_KEYS,
    COMMAND_EXEC,
    FILE_ACCESS,
    NETWORK,
    PATH_ARG_KEYS,
    URL_ARG_KEYS,
    ArgumentClassifier,
)


@dataclass
class ClassifiedArgument:
    """One string-valued argument and what the classifier made of it.
    `category` is None for an argument nothing recognized."""
    key: str
    value: str
    category: Optional[str]
    source: str


@dataclass
class Decision:
    allowed: bool
    category: str
    reason: str
    matched_rule: Optional[str] = None
    arguments: List[ClassifiedArgument] = field(default_factory=list)

    @property
    def argument_categories(self) -> dict:
        """`{key: category}` for every classified argument, with
        "unclassified" for the ones nothing recognized. This is what the
        audit log records, so a reader can tell which arguments the
        policy actually looked at."""
        return {a.key: (a.category or "unclassified") for a in self.arguments}


@dataclass
class _CategoryRule:
    enabled: bool = True
    deny_patterns: list = field(default_factory=list)
    allow_patterns: list = field(default_factory=list)
    default_action: str = "allow"  # applies only when allow_patterns is non-empty


def iter_string_arguments(arguments, prefix: str = "") -> Iterator[Tuple[str, str]]:
    """Yields `(key, value)` for every string anywhere in the arguments,
    descending into lists and nested objects. A list of paths under
    `paths` yields each path under the key `paths`; a nested
    `{"options": {"path": ...}}` yields under `options.path`. Numbers,
    booleans and nulls can't carry a path or a URL and are skipped."""
    if not isinstance(arguments, dict):
        return
    for key, value in arguments.items():
        full_key = f"{prefix}{key}"
        if isinstance(value, str):
            yield full_key, value
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    yield full_key, item
                elif isinstance(item, dict):
                    yield from iter_string_arguments(item, f"{full_key}.")
        elif isinstance(value, dict):
            yield from iter_string_arguments(value, f"{full_key}.")


class PolicyEngine:
    def __init__(self, config: dict, classifier: Optional[ArgumentClassifier] = None):
        config = config or {}
        self._file_rule = self._load_category(config.get("file_access", {}))
        self._command_rule = self._load_category(config.get("command_exec", {}))
        self._network_rule = self._load_category(config.get("network", {}))
        # Shared with the proxy, which feeds it `tools/list` schemas as
        # they go by. Without any registered schema it classifies by key
        # name alone, which is the v1 behavior.
        self.classifier = classifier if classifier is not None else ArgumentClassifier()

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

    def _rule_for(self, category: str) -> _CategoryRule:
        return {
            FILE_ACCESS: self._file_rule,
            COMMAND_EXEC: self._command_rule,
            NETWORK: self._network_rule,
        }[category]

    def classify_arguments(self, tool_name: str, arguments: dict) -> List[ClassifiedArgument]:
        classified = []
        for key, value in iter_string_arguments(arguments):
            # Nested keys are classified by their leaf name; the schema
            # lookup only knows top-level properties.
            leaf = key.rsplit(".", 1)[-1]
            result = self.classifier.classify(tool_name, leaf)
            if result is None:
                classified.append(ClassifiedArgument(key, value, None, "unclassified"))
            else:
                classified.append(ClassifiedArgument(key, value, result.category, result.source))
        return classified

    def evaluate(self, tool_name: str, arguments: dict) -> Decision:
        classified = self.classify_arguments(tool_name, arguments)
        checked_categories: List[str] = []
        for arg in classified:
            if arg.category is None:
                continue
            rule = self._rule_for(arg.category)
            if not rule.enabled:
                continue
            if arg.category not in checked_categories:
                checked_categories.append(arg.category)
            decision = self._check(arg.category, arg.value, rule)
            if decision is not None:
                decision.arguments = classified
                return decision
        if checked_categories:
            return Decision(
                allowed=True,
                category=checked_categories[0],
                reason=f"tool '{tool_name}' call checked against {', '.join(checked_categories)}; no deny rule matched",
                arguments=classified,
            )
        return Decision(
            allowed=True,
            category="none",
            reason=f"tool '{tool_name}' call has no arguments matching a configured policy category",
            arguments=classified,
        )

    def _check(self, category: str, value: str, rule: _CategoryRule) -> Optional[Decision]:
        if category == FILE_ACCESS:
            return self._check_deny_glob(value, rule, category)
        if category == COMMAND_EXEC:
            return self._check_deny_regex(value, rule, category)
        return self._check_network(value, rule)

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
