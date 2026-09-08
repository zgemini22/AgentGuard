"""`tools.<name>:` overrides — per-tool rules merged field-by-field over
the global ones."""

import pytest

from agentguard.cli import main
from agentguard.policy import PolicyEngine, PolicyError

BASE = {
    "file_access": {"deny_patterns": ["**/.env"]},
    "network": {"allow_patterns": ["*.github.com", "*.example.com"], "default_action": "deny"},
    "command_exec": {"deny_patterns": [r"rm\s+-rf\s+/"]},
}


def test_override_replaces_only_the_fields_it_sets():
    engine = PolicyEngine({**BASE, "tools": {
        "fetch": {"network": {"allow_patterns": ["api.github.com"]}},
    }})
    # fetch: narrower allowlist, but inherits default_action: deny from global.
    assert engine.evaluate("fetch", {"url": "https://api.github.com/x"}).allowed is True
    denied = engine.evaluate("fetch", {"url": "https://docs.example.com/x"})
    assert denied.allowed is False
    assert "(under tools.fetch override)" in denied.reason
    # Other tools keep the global allowlist.
    assert engine.evaluate("other", {"url": "https://docs.example.com/x"}).allowed is True


def test_override_inherits_deny_patterns_when_only_allowlist_is_set():
    engine = PolicyEngine({**BASE, "tools": {
        "read_file": {"file_access": {"allow_patterns": ["/project/**"], "default_action": "deny"}},
    }})
    assert engine.evaluate("read_file", {"path": "/project/src/x.py"}).allowed is True
    assert engine.evaluate("read_file", {"path": "/etc/passwd"}).allowed is False
    assert engine.evaluate("read_file", {"path": "/project/.env"}).allowed is False  # global deny still applies
    assert engine.evaluate("read_other", {"path": "/etc/passwd"}).allowed is True  # global has no allowlist


def test_override_can_disable_a_tool_entirely():
    engine = PolicyEngine({**BASE, "tools": {"shell": {"enabled": False}}})
    decision = engine.evaluate("shell", {"command": "ls"})
    assert decision.allowed is False
    assert decision.category == "tool"
    assert decision.matched_rule == "tools.shell.enabled"
    assert engine.evaluate("shell", {}).allowed is False  # even with no arguments


def test_override_can_set_unclassified_arguments_per_tool():
    engine = PolicyEngine({**BASE, "tools": {"strict_tool": {"unclassified_arguments": "deny"}}})
    assert engine.evaluate("strict_tool", {"mystery": "x"}).allowed is False
    assert engine.evaluate("lax_tool", {"mystery": "x"}).allowed is True


def test_override_can_disable_a_category_for_one_tool():
    engine = PolicyEngine({**BASE, "tools": {"trusted": {"file_access": {"enabled": False}}}})
    assert engine.evaluate("trusted", {"path": "/app/.env"}).allowed is True
    assert engine.evaluate("untrusted", {"path": "/app/.env"}).allowed is False


def test_override_keys_are_validated():
    with pytest.raises(PolicyError) as exc_info:
        PolicyEngine({"tools": {
            "fetch": {"netwerk": {}, "budgets": {}},
            "": {},
        }})
    joined = "\n".join(exc_info.value.errors)
    assert "tools.fetch: unknown key 'netwerk'" in joined
    assert "tools.fetch: unknown key 'budgets'" in joined
    assert "keys must be non-empty strings" in joined


def test_check_policy_prints_tool_overrides(tmp_path, capsys):
    policy = tmp_path / "p.yaml"
    policy.write_text(
        "network:\n  allow_patterns: ['*.github.com']\n  default_action: deny\n"
        "tools:\n  fetch:\n    network:\n      allow_patterns: ['api.github.com']\n"
        "  shell:\n    enabled: false\n"
    )
    assert main(["check-policy", "--config", str(policy)]) == 0
    out = capsys.readouterr().out
    assert "tools: 2 override(s)" in out
    assert "  fetch: network.allow_patterns=['api.github.com']" in out
    assert "  shell: DISABLED" in out
