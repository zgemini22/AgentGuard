"""Operator grants: `session` lives on the Session, `always` lives in a
grants.yaml overlay — never in the policy file."""

import io
import json
import os
import sys
import threading

import pytest

from agentguard.approval import ApprovalBroker
from agentguard.audit import AuditLog
from agentguard.cli import main
from agentguard.grants import Grant, GrantStore, validate_grants
from agentguard.injection import InjectionDetector
from agentguard.policy import ASK, PolicyEngine, PolicyError, grant_scope
from agentguard.proxy import MCPProxy
from agentguard.redact import SecretRedactor
from agentguard.report import build_report
from agentguard.session import Session
from tests.test_proxy import DEMO_SERVER

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
ASK_ENV = {"file_access": {"deny_patterns": [{"pattern": "**/.env", "action": "ask"}]}}


# --- the store ---------------------------------------------------------

def test_store_without_path_is_not_persistent():
    store = GrantStore(None)
    assert store.persistent is False
    store.add(Grant.now("t:c:r", "t", "s"))
    assert store.scopes() == {"t:c:r"}  # kept in memory for the process


def test_store_round_trips_through_yaml(tmp_path):
    path = str(tmp_path / "sub" / "grants.yaml")
    store = GrantStore(path)
    assert store.grants == []
    store.add(Grant.now("read_file:file_access:**/.env", "read_file", "abc"))
    store.add(Grant.now("fetch:network:docs.python.org", "fetch", "abc"))
    text = open(path).read()
    assert text.startswith("# Persistent operator grants")
    assert "read_file:file_access:**/.env" in text
    assert not os.path.exists(path + ".tmp")

    reloaded = GrantStore(path)
    assert reloaded.scopes() == {"read_file:file_access:**/.env", "fetch:network:docs.python.org"}
    assert reloaded.grants[0].tool == "read_file"
    assert reloaded.grants[0].session_id == "abc"


def test_malformed_grants_file_is_a_startup_error(tmp_path):
    path = tmp_path / "grants.yaml"
    path.write_text("grants:\n  - scope: ''\n  - tool: x\n  - scope: ok\n    extra: 1\nother: 2\n")
    with pytest.raises(PolicyError) as exc_info:
        PolicyEngine({"grants_file": str(path)})
    joined = "\n".join(exc_info.value.errors)
    assert "grants[0]: missing or empty `scope`" in joined
    assert "grants[1]: missing or empty `scope`" in joined
    assert "grants[2]: unknown key 'extra'" in joined
    assert "unknown key 'other'" in joined
    assert validate_grants("nope") == ["expected a mapping with a `grants` list"]
    assert validate_grants({"grants": "nope"}) == ["`grants` must be a list"]
    assert validate_grants(None) == []


# --- grants turn asks into allows --------------------------------------

def test_session_grant_covers_the_same_scope_only():
    engine = PolicyEngine(ASK_ENV)
    session = Session.new([])
    first = engine.evaluate("read_file", {"path": "/a/.env"}, session)
    assert first.action == ASK
    session.grants.add(grant_scope("read_file", first))

    again = engine.evaluate("read_file", {"path": "/b/.env"}, session)  # same rule -> same scope
    assert again.allowed is True
    assert again.ask_resolution == "granted"
    assert "covered by session grant 'read_file:file_access:**/.env'" in again.reason
    # A different tool tripping the same rule is a different scope.
    assert engine.evaluate("read_document", {"file_location": "/a/.env"}, session).action == ASK
    # A different session has no such grant.
    assert engine.evaluate("read_file", {"path": "/a/.env", }, Session.new([])).action == ASK


def test_persistent_grant_applies_even_without_a_session(tmp_path):
    path = str(tmp_path / "grants.yaml")
    GrantStore(path).add(Grant.now("read_file:file_access:**/.env", "read_file", "old"))
    engine = PolicyEngine({**ASK_ENV, "grants_file": path})
    decision = engine.evaluate("read_file", {"path": "/a/.env"})
    assert decision.allowed is True
    assert "covered by persistent grant" in decision.reason


def test_a_hard_deny_is_never_granted(tmp_path):
    path = str(tmp_path / "grants.yaml")
    GrantStore(path).add(Grant.now("read_file:file_access:**/.ssh/**", "read_file", "old"))
    engine = PolicyEngine({"file_access": {"deny_patterns": ["**/.ssh/**"]}, "grants_file": path})
    session = Session.new([])
    session.grants.add("read_file:file_access:**/.ssh/**")
    assert engine.evaluate("read_file", {"path": "/x/.ssh/id_rsa"}, session).allowed is False


def test_allowlist_miss_grant_is_per_value():
    engine = PolicyEngine({"network": {"allow_patterns": ["*.github.com"], "default_action": "ask"}})
    session = Session.new([])
    first = engine.evaluate("fetch", {"url": "https://docs.python.org/3"}, session)
    session.grants.add(grant_scope("fetch", first))
    assert engine.evaluate("fetch", {"url": "https://docs.python.org/3"}, session).allowed is True
    assert engine.evaluate("fetch", {"url": "https://evil.example.net/"}, session).action == ASK


# --- through the proxy: the broker's grant handler ---------------------

class InstantApprover:
    """An approver that answers every ask with a fixed verdict via the
    broker, so the proxy's grant handler runs without a socket."""

    def __init__(self, verdicts):
        self.broker = ApprovalBroker(timeout=5)
        self.verdicts = iter(verdicts)
        self.broker.add_listener(self._on_event)

    def _on_event(self, event, request):
        if event == "ask":
            verdict = next(self.verdicts)
            threading.Thread(target=lambda: self.broker.resolve(request.id, verdict), daemon=True).start()

    def ask(self, session, tool, arguments, decision):
        return self.broker.ask(session, tool, arguments, decision)


def run_with_approver(tmp_path, config, verdicts, n_calls):
    env = tmp_path / ".env"
    env.write_text("SECRET=1")
    requests = [INIT] + [
        {"jsonrpc": "2.0", "id": i + 2, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {"path": str(env)}}}
        for i in range(n_calls)
    ]
    audit_path = str(tmp_path / "audit.log")
    policy = PolicyEngine(config)
    stdout = io.StringIO()
    proxy = MCPProxy(
        [sys.executable, DEMO_SERVER], policy, AuditLog(audit_path),
        redactor=SecretRedactor.from_config({"redaction": {"enabled": False}}),
        injection_detector=InjectionDetector.from_config(config),
        stdin=io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n"),
        stdout=stdout, stderr=sys.__stderr__, approver=InstantApprover(verdicts),
    )
    proxy.run()
    responses = [json.loads(l) for l in stdout.getvalue().splitlines() if l.strip()]
    with open(audit_path) as f:
        entries = [json.loads(l) for l in f if l.strip()]
    return responses, entries, audit_path


def test_session_verdict_grants_for_the_rest_of_the_session(tmp_path):
    responses, entries, audit_path = run_with_approver(tmp_path, ASK_ENV, ["session"], 3)
    assert all("result" in next(r for r in responses if r["id"] == i) for i in (2, 3, 4))
    decisions = [e for e in entries if e["event"] == "policy_decision"]
    assert [d["ask_resolution"] for d in decisions] == ["approved_for_session", "granted", "granted"]
    grants = [e for e in entries if e["event"] == "grant"]
    assert len(grants) == 1
    assert grants[0]["duration"] == "session"
    assert grants[0]["scope"] == "read_file:file_access:**/.env"
    report = build_report(audit_path)["sessions"][0]
    assert report["grants"][0]["scope"] == "read_file:file_access:**/.env"


def test_always_verdict_persists_when_grants_file_is_configured(tmp_path):
    grants_path = str(tmp_path / "grants.yaml")
    config = {**ASK_ENV, "grants_file": grants_path}
    _, entries, _ = run_with_approver(tmp_path, config, ["always"], 2)
    grant = next(e for e in entries if e["event"] == "grant")
    assert grant["duration"] == "always"
    assert grant["grants_file"] == grants_path
    assert GrantStore(grants_path).scopes() == {"read_file:file_access:**/.env"}

    # A brand-new proxy with the same policy never asks again.
    engine = PolicyEngine(config)
    assert engine.evaluate("read_file", {"path": "/elsewhere/.env"}).allowed is True


def test_always_without_grants_file_degrades_to_session_and_says_so(tmp_path):
    _, entries, _ = run_with_approver(tmp_path, ASK_ENV, ["always"], 2)
    grant = next(e for e in entries if e["event"] == "grant")
    assert grant["duration"] == "session"
    assert "no grants_file is configured" in grant["note"]
    assert [e["ask_resolution"] for e in entries if e["event"] == "policy_decision"] == ["approved_always", "granted"]


def test_always_never_touches_the_policy_file(tmp_path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "file_access:\n  deny_patterns:\n    - pattern: '**/.env'\n      action: ask\n"
        f"grants_file: {(tmp_path / 'grants.yaml').as_posix()}\n"
    )
    before = policy_path.read_text()
    import yaml
    config = yaml.safe_load(before)
    run_with_approver(tmp_path, config, ["always"], 1)
    assert policy_path.read_text() == before
    assert (tmp_path / "grants.yaml").exists()


def test_check_policy_lists_persistent_grants_separately(tmp_path, capsys):
    grants_path = tmp_path / "grants.yaml"
    GrantStore(str(grants_path)).add(Grant.now("fetch:network:docs.python.org", "fetch", "abcdef123456789"))
    policy = tmp_path / "p.yaml"
    policy.write_text(f"grants_file: {grants_path.as_posix()}\n")
    assert main(["check-policy", "--config", str(policy)]) == 0
    out = capsys.readouterr().out
    assert "1 persistent grant(s) — operator `always` answers, not policy" in out
    assert "  grant  fetch:network:docs.python.org" in out
    assert "session abcdef123456" in out
