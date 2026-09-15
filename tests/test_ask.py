"""The `ask` verdict: a third answer besides allow and deny, and what
happens to it when nobody is there to answer."""

import pytest

from agentguard.cli import main
from agentguard.policy import ASK, DENY, Decision, PolicyEngine, PolicyError
from agentguard.session import Session
from tests.test_proxy import run_proxy

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}


def test_decision_action_derives_from_allowed_for_old_callers():
    assert Decision(True, "file_access", "ok").action == "allow"
    assert Decision(False, "file_access", "no").action == "deny"


def test_ask_decision_is_not_allowed_until_resolved():
    ask = Decision(False, "file_access", "sensitive", "**/.env", action=ASK)
    assert ask.allowed is False
    assert ask.action == ASK
    approved = ask.resolved(True, "approved_once", "approved by operator")
    assert approved.allowed is True and approved.action == "allow"
    assert approved.ask_resolution == "approved_once"
    assert approved.reason.endswith("— approved by operator")
    assert approved.matched_rule == "**/.env"
    denied = ask.resolved(False, "timeout", "no answer in 60s")
    assert denied.allowed is False and denied.action == "deny"


def test_deny_pattern_entry_can_carry_action_ask():
    engine = PolicyEngine({"file_access": {"deny_patterns": [
        "**/.ssh/**",
        {"pattern": "**/.env", "action": "ask"},
        {"pattern": "**/*.pem"},  # dict form without action is a plain deny
    ]}})
    assert engine.evaluate("read_file", {"path": "/x/.ssh/id_rsa"}).action == DENY
    env = engine.evaluate("read_file", {"path": "/x/.env"})
    assert env.action == ASK
    assert env.allowed is False
    assert env.matched_rule == "**/.env"
    assert "matches ask pattern '**/.env'" in env.reason
    assert engine.evaluate("read_file", {"path": "/x/a.pem"}).action == DENY


def test_default_action_ask_on_allowlist_miss():
    engine = PolicyEngine({"network": {"allow_patterns": ["*.github.com"], "default_action": "ask"}})
    assert engine.evaluate("fetch", {"url": "https://api.github.com/x"}).action == "allow"
    decision = engine.evaluate("fetch", {"url": "https://docs.python.org/x"})
    assert decision.action == ASK
    assert "not in the network allowlist" in decision.reason


def test_unclassified_arguments_ask():
    engine = PolicyEngine({"unclassified_arguments": "ask"})
    decision = engine.evaluate("t", {"mystery": "x"})
    assert decision.action == ASK
    assert "unclassified_arguments is 'ask'" in decision.reason


def test_budget_on_exceed_ask():
    engine = PolicyEngine({"budgets": {"max_file_calls": 1, "on_exceed": "ask"}})
    assert "on_exceed" not in engine.budgets  # not a limit
    session = Session.new([])
    engine.note_allowed(session, engine.evaluate("read_file", {"path": "/a"}, session))
    decision = engine.evaluate("read_file", {"path": "/b"}, session)
    assert decision.action == ASK
    assert decision.matched_rule == "max_file_calls"


def test_sequence_on_trip_ask():
    engine = PolicyEngine({"sequences": {"deny_exec_after_fetch": True, "on_trip": "ask"}})
    session = Session.new([])
    engine.note_allowed(session, engine.evaluate("fetch", {"url": "https://x.example.com"}, session))
    assert engine.evaluate("sh", {"command": "ls"}, session).action == ASK


def test_ask_is_validated_where_it_makes_sense():
    with pytest.raises(PolicyError) as exc_info:
        PolicyEngine({
            "file_access": {"deny_patterns": [{"pattern": "**/.env", "action": "allow"}, {"action": "ask"}]},
            "budgets": {"on_exceed": "allow"},
            "sequences": {"on_trip": "maybe"},
        })
    joined = "\n".join(exc_info.value.errors)
    assert "file_access.deny_patterns[0].action: expected one of deny, ask, got 'allow'" in joined
    assert "file_access.deny_patterns[1]: missing required key 'pattern'" in joined
    assert "budgets.on_exceed: expected one of deny, ask" in joined
    assert "sequences.on_trip: expected one of deny, ask" in joined


def test_without_an_approval_channel_ask_degrades_to_deny_and_says_so(tmp_path):
    env = tmp_path / ".env"
    env.write_text("SECRET=1")
    config = {"file_access": {"deny_patterns": [{"pattern": "**/.env", "action": "ask"}]}}
    requests = [INIT, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": str(env)}},
    }]
    responses, audit = run_proxy(requests, config=config)
    response = next(r for r in responses if r["id"] == 2)
    assert "error" in response
    assert "SECRET=1" not in str(response)
    assert "no approval channel configured" in response["error"]["message"]
    entry = next(e for e in audit if e["event"] == "policy_decision")
    assert entry["allowed"] is False
    assert entry["action"] == "deny"
    assert entry["ask_resolution"] == "no_channel"
    assert entry["matched_rule"] == "**/.env"


def test_check_policy_probe_reports_ask(tmp_path, capsys):
    policy = tmp_path / "p.yaml"
    policy.write_text("file_access:\n  deny_patterns:\n    - pattern: '**/.env'\n      action: ask\n")
    code = main(["check-policy", "--config", str(policy), "--probe", "read_file", '{"path": "/app/.env"}'])
    out = capsys.readouterr().out
    assert code == 4
    assert "decision: ASK  category=file_access  matched_rule=**/.env" in out
    assert "needs an approval channel" in out


def test_check_policy_prints_ask_entries_by_action(tmp_path, capsys):
    policy = tmp_path / "p.yaml"
    policy.write_text("file_access:\n  deny_patterns:\n    - '**/.ssh/**'\n    - pattern: '**/.env'\n      action: ask\n")
    assert main(["check-policy", "--config", str(policy)]) == 0
    out = capsys.readouterr().out
    assert "  deny   **/.ssh/**" in out
    assert "  ask    **/.env" in out
