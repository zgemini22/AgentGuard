"""The three sequence rules — cross-call reasoning the threat model used
to disclaim, scoped to exactly three named questions."""

import os

import pytest

from agentguard.policy import DEFAULT_SENSITIVE_PATTERNS, PolicyEngine, PolicyError
from agentguard.session import Session, parent_directory
from tests.test_proxy import run_proxy

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}


def allow_and_note(engine, session, tool, args):
    decision = engine.evaluate(tool, args, session)
    assert decision.allowed is True, decision.reason
    engine.note_allowed(session, decision)
    return decision


# --- deny_network_after_sensitive_read ---------------------------------

def test_network_call_is_denied_after_a_sensitive_read():
    engine = PolicyEngine({"sequences": {"deny_network_after_sensitive_read": {
        "sensitive_patterns": ["**/.env", "**/*.pem"],
    }}})
    session = Session.new([])
    allow_and_note(engine, session, "read_file", {"path": "/app/README.md"})
    assert engine.evaluate("fetch", {"url": "https://x.example.com"}, session).allowed is True
    allow_and_note(engine, session, "read_file", {"path": "/app/.env"})
    assert session.sensitive_reads == ["/app/.env"]
    decision = engine.evaluate("fetch", {"url": "https://x.example.com"}, session)
    assert decision.allowed is False
    assert decision.category == "sequence"
    assert decision.matched_rule == "deny_network_after_sensitive_read"
    assert "after a sensitive file read ('/app/.env')" in decision.reason
    # Non-network calls are unaffected.
    assert engine.evaluate("read_file", {"path": "/app/other"}, session).allowed is True


def test_sensitive_patterns_default_to_builtin_list():
    engine = PolicyEngine({"sequences": {"deny_network_after_sensitive_read": {}}})
    assert engine.sensitive_patterns == DEFAULT_SENSITIVE_PATTERNS
    session = Session.new([])
    allow_and_note(engine, session, "read_file", {"path": "/home/u/.aws/credentials"})
    assert engine.evaluate("fetch", {"url": "https://x.example.com"}, session).allowed is False


def test_sensitive_read_rule_can_be_disabled_explicitly():
    engine = PolicyEngine({"sequences": {"deny_network_after_sensitive_read": {"enabled": False}}})
    session = Session.new([])
    allow_and_note(engine, session, "read_file", {"path": "/app/.env"})
    assert engine.evaluate("fetch", {"url": "https://x.example.com"}, session).allowed is True


def test_reason_counts_additional_sensitive_reads():
    engine = PolicyEngine({"sequences": {"deny_network_after_sensitive_read": {}}})
    session = Session.new([])
    allow_and_note(engine, session, "read_file", {"path": "/a/.env"})
    allow_and_note(engine, session, "read_file", {"path": "/b/server.pem"})
    decision = engine.evaluate("fetch", {"url": "https://x.example.com"}, session)
    assert "('/a/.env' and 1 more)" in decision.reason


# --- deny_exec_after_fetch ---------------------------------------------

def test_command_is_denied_after_a_network_call():
    engine = PolicyEngine({"sequences": {"deny_exec_after_fetch": True}})
    session = Session.new([])
    assert engine.evaluate("sh", {"command": "ls"}, session).allowed is True
    allow_and_note(engine, session, "fetch", {"url": "https://x.example.com/page"})
    assert session.fetched is True
    decision = engine.evaluate("sh", {"command": "ls"}, session)
    assert decision.allowed is False
    assert decision.matched_rule == "deny_exec_after_fetch"


def test_deny_exec_after_fetch_off_by_default():
    engine = PolicyEngine({})
    session = Session.new([])
    allow_and_note(engine, session, "fetch", {"url": "https://x.example.com/page"})
    assert engine.evaluate("sh", {"command": "ls"}, session).allowed is True


# --- max_distinct_directories ------------------------------------------

def test_parent_directory_normalizes():
    assert parent_directory("/a/./b/x.txt") == os.path.normpath("/a/b")
    assert parent_directory("/a/b/../c/x.txt") == os.path.normpath("/a/c")
    assert parent_directory("x.txt") == "."


def test_distinct_directory_ceiling():
    engine = PolicyEngine({"sequences": {"max_distinct_directories": 2}})
    session = Session.new([])
    allow_and_note(engine, session, "read_file", {"path": "/p/src/a.py"})
    allow_and_note(engine, session, "read_file", {"path": "/p/src/b.py"})  # same dir, fine
    allow_and_note(engine, session, "read_file", {"path": "/p/tests/t.py"})
    assert len(session.directories) == 2
    decision = engine.evaluate("read_file", {"path": "/etc/passwd"}, session)
    assert decision.allowed is False
    assert decision.matched_rule == "max_distinct_directories"
    assert "would touch 3 distinct directories" in decision.reason
    assert "max_distinct_directories is 2" in decision.reason
    # A directory already touched is still fine.
    assert engine.evaluate("read_file", {"path": "/p/src/c.py"}, session).allowed is True


def test_one_call_spanning_many_new_directories_is_judged_as_a_whole():
    engine = PolicyEngine({"sequences": {"max_distinct_directories": 2}})
    session = Session.new([])
    assert engine.evaluate("read_many", {"paths": ["/a/x", "/b/y", "/c/z"]}, session).allowed is False
    assert engine.evaluate("read_many", {"paths": ["/a/x", "/b/y"]}, session).allowed is True


# --- validation and shape ----------------------------------------------

def test_sequence_keys_are_validated_and_there_are_exactly_three():
    with pytest.raises(PolicyError) as exc_info:
        PolicyEngine({"sequences": {
            "deny_network_after_sensitive_read": {"sensitive_globs": []},
            "max_distinct_directories": 0,
            "deny_exec_after_fetch": "yes",
            "deny_write_after_read": True,
        }})
    joined = "\n".join(exc_info.value.errors)
    assert "unknown key 'sensitive_globs'" in joined
    assert "sequences.max_distinct_directories: expected a positive integer" in joined
    assert "sequences.deny_exec_after_fetch: expected true/false" in joined
    assert "sequences: unknown key 'deny_write_after_read'" in joined
    from agentguard.validate import SEQUENCE_SCHEMA
    assert len(SEQUENCE_SCHEMA) == 3  # the hard cap; a fourth is a design conversation


def test_without_a_session_sequences_are_not_applied():
    engine = PolicyEngine({"sequences": {"deny_exec_after_fetch": True}})
    assert engine.evaluate("sh", {"command": "ls"}).allowed is True


# --- end to end --------------------------------------------------------

def test_exfiltration_sequence_end_to_end(tmp_path):
    env = tmp_path / ".env"
    env.write_text("SECRET=1")
    config = {
        "redaction": {"enabled": False},
        "sequences": {"deny_network_after_sensitive_read": {"sensitive_patterns": ["**/.env"]}},
    }
    requests = [
        INIT,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "read_file", "arguments": {"path": str(env)}}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "fetch_url", "arguments": {"url": "https://docs.example.com/readme"}}},
    ]
    responses, audit = run_proxy(requests, config=config)
    assert "result" in next(r for r in responses if r["id"] == 2)  # the read itself is allowed
    fetch = next(r for r in responses if r["id"] == 3)
    assert "error" in fetch
    assert "after a sensitive file read" in fetch["error"]["message"]
    decisions = [e for e in audit if e["event"] == "policy_decision"]
    assert decisions[1]["category"] == "sequence"
    assert decisions[1]["matched_rule"] == "deny_network_after_sensitive_read"
