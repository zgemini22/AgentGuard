"""Strict validation of a policy config before anything is built from it.

Every section of the policy used to load with `.get(key, default)`,
which meant a misspelled key was a silent no-op: `deny_pattern:` gave
you an empty deny list and no error, `enabled: "false"` (a string) was
truthy, a regex that didn't compile blew up on the first call instead
of at startup. For a security tool, a typo that turns a rule off
without saying so is a bug in the tool, not the config.

This module is the one place that knows the full shape of a policy
file. It's deliberately declarative — a table of sections, keys, and
value checks — so that adding a policy feature means adding a row here,
and forgetting to is a test failure (`test_validate.py` asserts every
key the engines read is a key the validator knows).

Validation returns a list of human-readable errors (empty means valid)
rather than raising on the first one, so a user fixing a config sees
all of it at once. `load_policy()` is the raise-on-error wrapper the
CLI and `PolicyEngine` use.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional

import yaml

ACTIONS = ("allow", "deny", "ask")
# Where an `ask` makes no sense (a budget or sequence rule has already
# said "not by default"), the choice is only deny-or-ask.
TRIP_ACTIONS = ("deny", "ask")


class PolicyError(ValueError):
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__("invalid policy:\n  " + "\n  ".join(errors))


Check = Callable[[Any, str, List[str]], None]


def _is_bool(value, where, errors):
    if not isinstance(value, bool):
        errors.append(f"{where}: expected true/false, got {value!r}")


def _is_str(value, where, errors):
    if not isinstance(value, str) or not value:
        errors.append(f"{where}: expected a non-empty string, got {value!r}")


def _is_action(value, where, errors, allowed=ACTIONS):
    if value not in allowed:
        errors.append(f"{where}: expected one of {', '.join(allowed)}, got {value!r}")


def _is_trip_action(value, where, errors):
    _is_action(value, where, errors, TRIP_ACTIONS)


def _is_regex(value, where, errors):
    if not isinstance(value, str):
        errors.append(f"{where}: expected a regex string, got {value!r}")
        return
    try:
        re.compile(value)
    except re.error as e:
        errors.append(f"{where}: regex does not compile: {e}")


def _list_of(item_check: Check) -> Check:
    def check(value, where, errors):
        if value is None:
            return  # an explicitly empty list in YAML
        if not isinstance(value, list):
            errors.append(f"{where}: expected a list, got {type(value).__name__}")
            return
        for i, item in enumerate(value):
            item_check(item, f"{where}[{i}]", errors)
    return check


def _mapping(keys: Dict[str, Check], *, required: tuple = ()) -> Check:
    """A dict whose keys must all be in `keys`; each value is checked."""
    def check(value, where, errors):
        if value is None:
            return  # `section:` with nothing under it
        if not isinstance(value, dict):
            errors.append(f"{where}: expected a mapping, got {type(value).__name__}")
            return
        for key in value:
            if key not in keys:
                hint = _closest(key, keys)
                errors.append(
                    f"{where}: unknown key {key!r}"
                    + (f" (did you mean {hint!r}?)" if hint else "")
                    + f"; known keys: {', '.join(sorted(keys))}"
                )
        for key in required:
            if key not in value:
                errors.append(f"{where}: missing required key {key!r}")
        for key, val in value.items():
            if key in keys:
                keys[key](val, f"{where}.{key}", errors)
    return check


def _map_of(value_check: Check) -> Check:
    """A dict with arbitrary (non-empty string) keys, each value checked."""
    def check(value, where, errors):
        if value is None:
            return
        if not isinstance(value, dict):
            errors.append(f"{where}: expected a mapping, got {type(value).__name__}")
            return
        for key, val in value.items():
            if not isinstance(key, str) or not key:
                errors.append(f"{where}: keys must be non-empty strings, got {key!r}")
                continue
            value_check(val, f"{where}.{key}", errors)
    return check


def _closest(key: str, candidates) -> Optional[str]:
    """Cheap typo hint: the candidate sharing the longest common prefix
    with `key`, if that prefix is most of the key."""
    best, best_len = None, 0
    for candidate in candidates:
        n = 0
        for a, b in zip(key, candidate):
            if a != b:
                break
            n += 1
        if n > best_len:
            best, best_len = candidate, n
    return best if best and best_len >= max(3, len(key) - 2) else None


def _is_positive_int(value, where, errors):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        errors.append(f"{where}: expected a positive integer, got {value!r}")


def _is_positive_number(value, where, errors):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        errors.append(f"{where}: expected a positive number, got {value!r}")


def _named_rule(pattern_check: Check) -> Check:
    return _mapping({"name": _is_str, "pattern": pattern_check}, required=("name", "pattern"))


def _deny_entry(pattern_check: Check) -> Check:
    """A deny_patterns item: a bare pattern, or {pattern, action: deny|ask}."""
    as_mapping = _mapping({"pattern": pattern_check, "action": _is_trip_action}, required=("pattern",))

    def check(value, where, errors):
        if isinstance(value, dict):
            as_mapping(value, where, errors)
        else:
            pattern_check(value, where, errors)
    return check


def _category(pattern_check: Check) -> Check:
    return _mapping({
        "enabled": _is_bool,
        "deny_patterns": _list_of(_deny_entry(pattern_check)),
        "allow_patterns": _list_of(pattern_check),
        "default_action": _is_action,
    })


def _rules_section() -> Check:
    return _mapping({
        "enabled": _is_bool,
        "rules": _list_of(_named_rule(_is_regex)),
    })


# The full shape of a policy file. Order here is the order check-policy
# prints sections in.
BUDGET_KEYS = (
    "max_file_calls",
    "max_network_calls",
    "max_command_calls",
    "max_output_bytes_per_call",
    "max_total_output_bytes",
)

# What a `tools.<name>:` override may contain: the same three category
# sections and unclassified_arguments as the top level, plus `enabled`
# to switch a tool off entirely.
TOOL_OVERRIDE_SCHEMA: Dict[str, Check] = {
    "enabled": _is_bool,
    "unclassified_arguments": _is_action,
    "file_access": _category(_is_str),
    "command_exec": _category(_is_regex),
    "network": _category(_is_str),
}

# Exactly three named cross-call patterns. This is a fixed menu on
# purpose — see agentguard/session.py — not the seed of a rule DSL.
SEQUENCE_SCHEMA: Dict[str, Check] = {
    "deny_network_after_sensitive_read": _mapping({
        "enabled": _is_bool,
        "sensitive_patterns": _list_of(_is_str),
    }),
    "max_distinct_directories": _is_positive_int,
    "deny_exec_after_fetch": _is_bool,
}

POLICY_SCHEMA: Dict[str, Check] = {
    "unclassified_arguments": _is_action,
    # Where `ask` verdicts go: a Unix socket path the proxy listens on
    # for `agentguard approve`, and how long an ask waits (seconds)
    # before it is denied.
    "approval_socket": _is_str,
    "approval_timeout": _is_positive_number,
    # The grants.yaml overlay `always` answers are written to. Unset
    # means `always` behaves as `session`.
    "grants_file": _is_str,
    "file_access": _category(_is_str),
    "command_exec": _category(_is_regex),
    "network": _category(_is_str),
    "tools": _map_of(_mapping(TOOL_OVERRIDE_SCHEMA)),
    "budgets": _mapping({**{key: _is_positive_int for key in BUDGET_KEYS}, "on_exceed": _is_trip_action}),
    "sequences": _mapping({**SEQUENCE_SCHEMA, "on_trip": _is_trip_action}),
    "redaction": _rules_section(),
    "injection_detection": _rules_section(),
}


def validate_policy(raw) -> List[str]:
    """Returns every problem found with `raw` as a policy config. An
    empty list means the config is valid. `None` (an empty file) is a
    valid, empty policy."""
    errors: List[str] = []
    if raw is None:
        return errors
    _mapping(POLICY_SCHEMA)(raw, "policy", errors)
    return errors


def load_policy(path: str) -> dict:
    """Parses and validates a policy YAML file. Raises PolicyError with
    every problem found, FileNotFoundError / yaml.YAMLError as usual."""
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    errors = validate_policy(raw)
    if errors:
        raise PolicyError(errors)
    return raw or {}
