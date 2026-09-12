"""The approval channel. The broker tests run everywhere; the socket
tests need AF_UNIX (Linux/macOS — CI's ubuntu runs them; Windows skips)."""

import io
import json
import os
import sys
import tempfile
import threading
import time

import pytest

from agentguard.approval import (
    ApprovalBroker,
    ApprovalClient,
    ApprovalServer,
    format_request,
    grant_scope,
    supports_unix_sockets,
    terminal_prompt,
)
from agentguard.audit import AuditLog
from agentguard.injection import InjectionDetector
from agentguard.policy import ASK, ClassifiedArgument, Decision, PolicyEngine
from agentguard.proxy import MCPProxy
from agentguard.redact import SecretRedactor
from agentguard.session import Session
from tests.test_proxy import DEMO_SERVER

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
unix_only = pytest.mark.skipif(not supports_unix_sockets(), reason="needs Unix domain sockets")


def ask_decision(rule="**/.env", category="file_access", value="/app/.env"):
    return Decision(False, category, f"value '{value}' matches ask pattern '{rule}'", rule,
                    [ClassifiedArgument("path", value, category, "key_name")], action=ASK)


# --- grant scope -------------------------------------------------------

def test_grant_scope_is_tool_category_rule_or_value():
    assert grant_scope("read_file", ask_decision()) == "read_file:file_access:**/.env"
    miss = Decision(False, "network", "host 'x' is not in the network allowlist", None,
                    [ClassifiedArgument("url", "https://docs.python.org/3", "network", "key_name")], action=ASK)
    assert grant_scope("fetch", miss) == "fetch:network:https://docs.python.org/3"
    assert grant_scope("t", Decision(False, "budget", "x", None, [], action=ASK)) == "t:budget:*"


# --- broker ------------------------------------------------------------

def test_broker_times_out_to_deny():
    broker = ApprovalBroker(timeout=0.2)
    session = Session.new([])
    t0 = time.monotonic()
    decision = broker.ask(session, "read_file", {"path": "/app/.env"}, ask_decision())
    assert time.monotonic() - t0 >= 0.2
    assert decision.allowed is False
    assert decision.ask_resolution == "timeout"
    assert "no answer from operator within 0.2s" in decision.reason
    assert broker.pending() == []


def _answer_when_asked(broker, verdict, delay=0.05):
    """A fake approver: waits for the first pending request and answers it."""
    seen = {}

    def on_event(event, request):
        if event == "ask":
            seen["request"] = request

    broker.add_listener(on_event)

    def run():
        deadline = time.monotonic() + 2
        while "request" not in seen and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(delay)
        seen["accepted"] = broker.resolve(seen["request"].id, verdict)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return seen, thread


@pytest.mark.parametrize("verdict,allowed,resolution", [
    ("deny", False, "denied_by_operator"),
    ("once", True, "approved_once"),
    ("session", True, "approved_for_session"),
    ("always", True, "approved_always"),
])
def test_broker_delivers_each_verdict(verdict, allowed, resolution):
    grants = []
    broker = ApprovalBroker(timeout=2, grant_handler=lambda s, v, r, d: grants.append((v, r.scope)))
    seen, thread = _answer_when_asked(broker, verdict)
    decision = broker.ask(Session.new([]), "read_file", {"path": "/app/.env"}, ask_decision())
    thread.join()
    assert seen["accepted"] is True
    assert decision.allowed is allowed
    assert decision.ask_resolution == resolution
    assert decision.action == ("allow" if allowed else "deny")
    assert seen["request"].scope == "read_file:file_access:**/.env"
    expected_grants = [(verdict, "read_file:file_access:**/.env")] if verdict in ("session", "always") else []
    assert grants == expected_grants


def test_broker_rejects_unknown_ids_bad_verdicts_and_double_answers():
    broker = ApprovalBroker(timeout=1)
    assert broker.resolve("nope", "once") is False
    seen, thread = _answer_when_asked(broker, "once")
    broker.ask(Session.new([]), "t", {}, ask_decision())
    thread.join()
    assert broker.resolve(seen["request"].id, "deny") is False  # already resolved and gone
    events = []
    broker.add_listener(lambda e, r: events.append(e))
    # A listener that raises must not break ask().
    broker.add_listener(lambda e, r: 1 / 0)
    broker.timeout = 0.05
    broker.ask(Session.new([]), "t", {}, ask_decision())
    assert events == ["ask", "resolved"]


def test_broker_listener_sees_ask_then_resolved_with_verdict():
    broker = ApprovalBroker(timeout=1)
    events = []
    broker.add_listener(lambda e, r: events.append((e, r.verdict)))
    _, thread = _answer_when_asked(broker, "once")
    broker.ask(Session.new([]), "t", {}, ask_decision())
    thread.join()
    assert events == [("ask", None), ("resolved", "once")]


# --- rendering and the terminal prompt ---------------------------------

def sample_request():
    return {
        "id": "abc123", "session_id": "s", "tool": "read_file",
        "arguments": {"path": "/app/.env", "n": 1},
        "category": "file_access", "reason": "value '/app/.env' matches ask pattern '**/.env'",
        "matched_rule": "**/.env", "argument_categories": {"path": "file_access", "n": "unclassified"},
        "scope": "read_file:file_access:**/.env",
        "created_at": time.time(), "expires_at": time.time() + 60,
    }


def test_format_request_shows_everything_an_operator_needs():
    text = format_request(sample_request())
    assert "approval needed  [abc123]" in text
    assert "tool:      read_file" in text
    assert 'path:      "/app/.env"   [file_access]' in text
    assert "rule:      **/.env" in text
    assert "would grant: read_file:file_access:**/.env" in text


def test_terminal_prompt_accepts_letters_and_words_and_eof():
    out = io.StringIO()
    answers = iter(["x", "o"])
    assert terminal_prompt(sample_request(), input_fn=lambda _: next(answers), output=out) == "once"
    assert "approval needed" in out.getvalue()
    assert terminal_prompt(sample_request(), input_fn=lambda _: "ALWAYS", output=out) == "always"

    def eof(_):
        raise EOFError
    assert terminal_prompt(sample_request(), input_fn=eof, output=out) == "deny"


# --- socket transport (POSIX) ------------------------------------------

def socket_path(tmp_path):
    # AF_UNIX paths are limited to ~100 bytes; pytest's tmp_path can be
    # long, so use the system temp dir with a short name instead.
    return os.path.join(tempfile.gettempdir(), f"ag-{os.getpid()}-{time.time_ns() % 10**6}.sock")


@unix_only
def test_server_and_client_round_trip(tmp_path):
    broker = ApprovalBroker(timeout=5)
    session = Session.new(["srv"])
    path = socket_path(tmp_path)
    server = ApprovalServer(broker, path, session=session)
    server.start()
    try:
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"
        out = io.StringIO()
        prompts = []

        def prompt(request):
            prompts.append(request)
            return "session"

        client = ApprovalClient(path, prompt, output=out)
        client_thread = threading.Thread(target=lambda: client.run(max_answers=1), daemon=True)
        client_thread.start()
        time.sleep(0.2)  # let the client connect and get the hello

        decision = broker.ask(session, "read_file", {"path": "/app/.env"}, ask_decision())
        client_thread.join(timeout=5)
        assert decision.allowed is True
        assert decision.ask_resolution == "approved_for_session"
        assert prompts[0]["tool"] == "read_file"
        assert prompts[0]["scope"] == "read_file:file_access:**/.env"
        assert "connected: session" in out.getvalue()
    finally:
        server.stop()
    assert not os.path.exists(path)


@unix_only
def test_client_sees_requests_pending_before_it_connected(tmp_path):
    broker = ApprovalBroker(timeout=5)
    path = socket_path(tmp_path)
    server = ApprovalServer(broker, path)
    server.start()
    try:
        results = {}
        asker = threading.Thread(
            target=lambda: results.update(d=broker.ask(Session.new([]), "t", {"path": "/x"}, ask_decision())),
            daemon=True,
        )
        asker.start()
        time.sleep(0.2)
        assert len(broker.pending()) == 1
        client = ApprovalClient(path, lambda r: "deny", output=io.StringIO())
        assert client.run(max_answers=1) == 1
        asker.join(timeout=5)
        assert results["d"].ask_resolution == "denied_by_operator"
    finally:
        server.stop()


@unix_only
def test_server_refuses_to_unlink_a_non_socket_at_the_path(tmp_path):
    path = socket_path(tmp_path)
    with open(path, "w") as f:
        f.write("not a socket")
    try:
        with pytest.raises(OSError, match="not a socket"):
            ApprovalServer(ApprovalBroker(), path).start()
    finally:
        os.unlink(path)


@unix_only
def test_server_replaces_a_stale_socket(tmp_path):
    path = socket_path(tmp_path)
    first = ApprovalServer(ApprovalBroker(), path)
    first.start()
    first._stopping.set()  # simulate a crash: socket file left behind
    first._server.close()
    assert os.path.exists(path)
    second = ApprovalServer(ApprovalBroker(), path)
    second.start()
    second.stop()
    assert not os.path.exists(path)


@unix_only
def test_end_to_end_ask_through_the_proxy(tmp_path):
    env = tmp_path / ".env"
    env.write_text("SECRET=1")
    config = {
        "file_access": {"deny_patterns": [{"pattern": "**/.env", "action": "ask"}]},
        "redaction": {"enabled": False},
    }
    path = socket_path(tmp_path)
    policy = PolicyEngine(config)
    session = Session.new([sys.executable, DEMO_SERVER], policy.classifier)
    server = ApprovalServer(ApprovalBroker(timeout=5), path, session=session)
    requests = [INIT] + [
        {"jsonrpc": "2.0", "id": i, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {"path": str(env)}}}
        for i in (2, 3)
    ]
    stdout = io.StringIO()
    audit_path = str(tmp_path / "audit.log")
    proxy = MCPProxy(
        [sys.executable, DEMO_SERVER], policy, AuditLog(audit_path),
        redactor=SecretRedactor.from_config(config),
        injection_detector=InjectionDetector.from_config(config),
        stdin=io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n"),
        stdout=stdout, stderr=sys.__stderr__, session=session, approver=server,
    )
    verdicts = iter(["once", "deny"])
    approver_thread = threading.Thread(
        target=lambda: _connect_when_listening(path, lambda r: next(verdicts)), daemon=True,
    )
    approver_thread.start()
    proxy.run()
    approver_thread.join(timeout=5)

    responses = [json.loads(l) for l in stdout.getvalue().splitlines() if l.strip()]
    first = next(r for r in responses if r["id"] == 2)
    second = next(r for r in responses if r["id"] == 3)
    assert first["result"]["content"][0]["text"] == "SECRET=1"   # approved once
    assert "error" in second and "denied by operator" in second["error"]["message"]
    with open(audit_path) as f:
        decisions = [json.loads(l) for l in f if '"policy_decision"' in l]
    assert [d["ask_resolution"] for d in decisions] == ["approved_once", "denied_by_operator"]
    assert not os.path.exists(path)  # cleaned up on exit


def _connect_when_listening(path, prompt):
    deadline = time.monotonic() + 5
    while not os.path.exists(path) and time.monotonic() < deadline:
        time.sleep(0.02)
    ApprovalClient(path, prompt, output=io.StringIO()).run(max_answers=2)
