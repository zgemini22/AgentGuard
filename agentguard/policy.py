"""Policy engine: evaluates MCP tool calls against a YAML rule set.

Three independent rule categories (file access, command execution,
network access), matched against tool-call arguments. Which category an
argument belongs to is decided by `agentguard.classify` — by the tool's
declared schema when the proxy has seen one, by key-name conventions
otherwise. Every category has the same shape: `deny_patterns` (a match
denies), then `allow_patterns` + `default_action` (a value on no
allow pattern is denied when `default_action: deny`). File and network
patterns are globs (on the expanded path / on the hostname); command
patterns are regexes. Categories the config doesn't mention are
skipped, not denied — this is an allowlist/denylist engine, not a full
sandbox.

The config is validated strictly on load (`agentguard.validate`): an
unknown key or a broken pattern is a startup error, never a silently
disabled rule.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from .validate import PolicyError, load_policy, validate_policy  # noqa: F401
from .classify import (  # noqa: F401  (re-exported for backward compatibility)
    COMMAND_ARG_KEYS,
    COMMAND_EXEC,
    FILE_ACCESS,
    NETWORK,
    PATH_ARG_KEYS,
    URL_ARG_KEYS,
    ArgumentClassifier,
)

# Decision.category for a call whose string arguments matched no
# classifier rule at all. Distinct from "none" (no string arguments to
# classify) because they mean different things to a reader of the log:
# "none" is inert, "unclassified" is a gap the policy couldn't see into.
UNCLASSIFIED = "unclassified"
UNCLASSIFIED_ALLOW = "allow"
UNCLASSIFIED_DENY = "deny"

BUDGET_KEY_FOR_CATEGORY = {
    FILE_ACCESS: "max_file_calls",
    NETWORK: "max_network_calls",
    COMMAND_EXEC: "max_command_calls",
}


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
    default_action: str = "allow"  # what happens to a value on no allow pattern; only matters when allow_patterns is set


def file_uri_path(value: str) -> Optional[str]:
    """`file:///home/u/x` -> `/home/u/x`; `file:///C:/x` -> `C:/x`. None
    for anything that isn't a file URI."""
    parsed = urlparse(value)
    if parsed.scheme.lower() != "file":
        return None
    path = unquote(parsed.path)
    if parsed.netloc and parsed.netloc != "localhost":
        # file://host/share/x — a UNC-style path; keep the host in it.
        path = f"//{parsed.netloc}{path}"
    elif re.match(r"^/[A-Za-z]:", path):
        path = path[1:]
    return path or "/"


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
        # Strict: an unknown key, a non-compiling regex, a string where a
        # bool belongs — all fail here, at construction, rather than
        # silently loading as a default. See agentguard.validate.
        errors = validate_policy(config)
        if errors:
            raise PolicyError(errors)
        self.config = config
        self._file_rule = self._load_category(config.get("file_access", {}))
        self._command_rule = self._load_category(config.get("command_exec", {}))
        self._network_rule = self._load_category(config.get("network", {}))
        # What to do with a string argument no classifier rule recognized.
        # `allow` is the v1 behavior and the default for compatibility;
        # `deny` is the secure setting — it closes the rename-the-argument
        # bypass entirely, at the cost of rejecting calls to tools whose
        # schemas the classifier can't read. Check with
        # `agentguard check-policy --probe` before flipping it.
        self.unclassified_arguments = config.get("unclassified_arguments", UNCLASSIFIED_ALLOW)
        # Per-session ceilings; the Session holds the counters. A missing
        # key means unlimited.
        self.budgets: dict = dict(config.get("budgets") or {})
        # Shared with the proxy, which feeds it `tools/list` schemas as
        # they go by. Without any registered schema it classifies by key
        # name alone, which is the v1 behavior.
        self.classifier = classifier if classifier is not None else ArgumentClassifier()

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyEngine":
        return cls(load_policy(path))

    @property
    def tracks_output_size(self) -> bool:
        return "max_output_bytes_per_call" in self.budgets or "max_total_output_bytes" in self.budgets

    def output_budget_exceeded(self, nbytes: int) -> Optional[str]:
        """Reason a single result of `nbytes` breaks the per-call budget,
        or None."""
        limit = self.budgets.get("max_output_bytes_per_call")
        if limit is not None and nbytes > limit:
            return f"result is {nbytes} bytes, over the session budget max_output_bytes_per_call ({limit})"
        return None

    def _session_budget_exceeded(self, session, categories: List[str]) -> Optional[Decision]:
        limit = self.budgets.get("max_total_output_bytes")
        if limit is not None and session.output_bytes >= limit:
            return Decision(
                False, "budget",
                f"session budget max_total_output_bytes exhausted "
                f"({session.output_bytes} of {limit} bytes already delivered)",
                "max_total_output_bytes",
            )
        for category in categories:
            key = BUDGET_KEY_FOR_CATEGORY[category]
            limit = self.budgets.get(key)
            if limit is not None and session.call_counts.get(category, 0) >= limit:
                return Decision(
                    False, "budget",
                    f"session budget {key} exhausted ({limit} {category} calls already allowed)",
                    key,
                )
        return None

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
                continue
            category, source = result.category, result.source
            if category == NETWORK:
                # A file:// URI under a URL-shaped argument is a file
                # read wearing a network hat; judge it by the path rules.
                file_path = file_uri_path(value)
                if file_path is not None:
                    category, source, value = FILE_ACCESS, source + ":file-uri", file_path
            classified.append(ClassifiedArgument(key, value, category, source))
        return classified

    def evaluate(self, tool_name: str, arguments: dict, session=None) -> Decision:
        """Judges one call. With a `session`, the cross-call rules —
        budgets — apply too; without one (check-policy --probe) the
        call is judged on its own, as v1 did."""
        classified = self.classify_arguments(tool_name, arguments)
        checked_categories: List[str] = []
        touched_categories: List[str] = []
        unclassified_keys: List[str] = []
        for arg in classified:
            if arg.category is None:
                if arg.key not in unclassified_keys:
                    unclassified_keys.append(arg.key)
                continue
            if arg.category not in touched_categories:
                touched_categories.append(arg.category)
            rule = self._rule_for(arg.category)
            if not rule.enabled:
                continue
            if arg.category not in checked_categories:
                checked_categories.append(arg.category)
            decision = self._check(arg.category, arg.value, rule)
            if decision is not None:
                decision.arguments = classified
                return decision

        if unclassified_keys and self.unclassified_arguments == UNCLASSIFIED_DENY:
            return Decision(
                False, UNCLASSIFIED,
                f"tool '{tool_name}' argument(s) {', '.join(repr(k) for k in unclassified_keys)} "
                "could not be classified and unclassified_arguments is 'deny'",
                arguments=classified,
            )
        if session is not None:
            decision = self._session_budget_exceeded(session, touched_categories)
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
        if unclassified_keys:
            return Decision(
                allowed=True,
                category=UNCLASSIFIED,
                reason=f"tool '{tool_name}' argument(s) {', '.join(repr(k) for k in unclassified_keys)} "
                       "matched no policy category; allowed because unclassified_arguments is 'allow'",
                arguments=classified,
            )
        return Decision(
            allowed=True,
            category="none",
            reason=f"tool '{tool_name}' call has no string arguments for the policy to classify",
            arguments=classified,
        )

    def _check(self, category: str, value: str, rule: _CategoryRule) -> Optional[Decision]:
        """Same semantics for every category: a deny pattern match denies;
        otherwise, if there's an allowlist and the value isn't on it,
        `default_action` decides. What a "match" means differs — glob on
        the expanded path, glob on the hostname, regex on the command."""
        subject, matches = self._matcher(category, value)
        for pattern in rule.deny_patterns:
            if matches(pattern):
                return Decision(
                    False, category,
                    f"value '{value}' matches deny pattern '{pattern}'",
                    pattern,
                )
        if not rule.allow_patterns or any(matches(p) for p in rule.allow_patterns):
            return None
        if rule.default_action == "deny":
            noun = "host" if category == NETWORK else "value"
            return Decision(
                False, category,
                f"{noun} '{subject}' is not in the {category} allowlist",
            )
        return None

    @staticmethod
    def _matcher(category: str, value: str) -> Tuple[str, Callable[[str], bool]]:
        """Returns (what is being matched, pattern -> bool)."""
        if category == FILE_ACCESS:
            expanded = os.path.expanduser(value)
            return expanded, lambda p: fnmatch.fnmatch(expanded, os.path.expanduser(p))
        if category == NETWORK:
            host = urlparse(value).hostname or value
            return host, lambda p: fnmatch.fnmatch(host, p)
        return value, lambda p: re.search(p, value) is not None
