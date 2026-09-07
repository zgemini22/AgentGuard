"""Session budgets: per-category call ceilings and output-size ceilings
that a session can't exceed, however each individual call looks."""

import json

import pytest

from agentguard.policy import PolicyEngine, PolicyError
from agentguard.session import Session
from tests.test_proxy import run_proxy

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}


def read_call(i, path):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": path}}}


def fetch_call(i, url):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": "fetch_url", "arguments": {"url": url}}}


# --- engine + session, no proxy ----------------------------------------

def test_budget_keys_are_validated():
    with pytest.raises(PolicyError) as exc_info:
        PolicyEngine({"budgets": {"max_file_reads": 3, "max_network_calls": 0, "max_command_calls": "5"}})
    joined = "\n".join(exc_info.value.errors)
    assert "unknown key 'max_file_reads'" in joined
    assert "budgets.max_network_calls: expected a positive integer, got 0" in joined
    assert "budgets.max_command_calls: expected a positive integer, got '5'" in joined


def test_file_call_budget_denies_after_limit():
    engine = PolicyEngine({"budgets": {"max_file_calls": 2}})
    session = Session.new([])
    for _ in range(2):
        decision = engine.evaluate("read_file", {"path": "/tmp/x"}, session)
        assert decision.allowed is True
        session.note_allowed_call(decision)
    decision = engine.evaluate("read_file", {"path": "/tmp/x"}, session)
    assert decision.allowed is False
    assert decision.category == "budget"
    assert decision.matched_rule == "max_file_calls"
    assert "max_file_calls exhausted (2 file_access calls already allowed)" in decision.reason
    # Other categories are unaffected.
    assert engine.evaluate("fetch", {"url": "https://x.example.com"}, session).allowed is True


def test_denied_calls_do_not_consume_budget():
    engine = PolicyEngine({"file_access": {"deny_patterns": ["**/.env"]}, "budgets": {"max_file_calls": 1}})
    session = Session.new([])
    denied = engine.evaluate("read_file", {"path": "/app/.env"}, session)
    assert denied.allowed is False and denied.category == "file_access"
    assert session.call_counts == {}
    assert engine.evaluate("read_file", {"path": "/app/README"}, session).allowed is True


def test_one_call_with_many_paths_counts_once():
    engine = PolicyEngine({"budgets": {"max_file_calls": 1}})
    session = Session.new([])
    decision = engine.evaluate("read_many", {"paths": ["/a", "/b", "/c"]}, session)
    session.note_allowed_call(decision)
    assert session.call_counts == {"file_access": 1}


def test_without_a_session_budgets_are_not_applied():
    engine = PolicyEngine({"budgets": {"max_file_calls": 1}})
    for _ in range(3):
        assert engine.evaluate("read_file", {"path": "/tmp/x"}).allowed is True


def test_total_output_budget_denies_every_further_call():
    engine = PolicyEngine({"budgets": {"max_total_output_bytes": 100}})
    session = Session.new([])
    session.note_output(100)
    decision = engine.evaluate("read_file", {"path": "/tmp/x"}, session)
    assert decision.allowed is False
    assert decision.matched_rule == "max_total_output_bytes"
    assert "100 of 100 bytes already delivered" in decision.reason


# --- end to end --------------------------------------------------------

def test_network_budget_end_to_end():
    config = {"budgets": {"max_network_calls": 2}}
    requests = [INIT] + [fetch_call(i, "https://docs.example.com/readme") for i in (2, 3, 4)]
    responses, audit = run_proxy(requests, config=config)
    assert "result" in next(r for r in responses if r["id"] == 2)
    assert "result" in next(r for r in responses if r["id"] == 3)
    third = next(r for r in responses if r["id"] == 4)
    assert "error" in third
    assert "max_network_calls exhausted" in third["error"]["message"]
    decisions = [e for e in audit if e["event"] == "policy_decision"]
    assert [d["allowed"] for d in decisions] == [True, True, False]
    assert decisions[-1]["category"] == "budget"


def test_per_call_output_budget_withholds_oversized_result(tmp_path):
    big = tmp_path / "big.txt"
    big.write_text("x" * 5000)
    small = tmp_path / "small.txt"
    small.write_text("tiny")
    config = {"budgets": {"max_output_bytes_per_call": 1000}}
    responses, audit = run_proxy([INIT, read_call(2, str(big)), read_call(3, str(small))], config=config)
    blocked = next(r for r in responses if r["id"] == 2)
    assert blocked["result"]["isError"] is True
    assert "x" * 100 not in json.dumps(blocked)
    assert "max_output_bytes_per_call" in blocked["result"]["content"][0]["text"]
    assert next(r for r in responses if r["id"] == 3)["result"]["content"][0]["text"] == "tiny"
    block = next(e for e in audit if e["event"] == "budget_block")
    assert block["budget"] == "max_output_bytes_per_call"
    assert block["bytes"] > 5000
    assert block["tool"] == "read_file"


def test_total_output_budget_end_to_end(tmp_path):
    f = tmp_path / "f.txt"
    f.write_text("y" * 300)
    config = {"budgets": {"max_total_output_bytes": 500}}
    responses, audit = run_proxy([INIT, read_call(2, str(f)), read_call(3, str(f)), read_call(4, str(f))], config=config)
    assert "result" in next(r for r in responses if r["id"] == 2)
    # Second read is allowed (300 < 500 delivered so far) and pushes the
    # total over; the third is denied on the way in.
    assert "result" in next(r for r in responses if r["id"] == 3)
    third = next(r for r in responses if r["id"] == 4)
    assert "error" in third
    assert "max_total_output_bytes exhausted" in third["error"]["message"]


def test_output_budgets_work_without_any_scanner_enabled(tmp_path):
    big = tmp_path / "big.txt"
    big.write_text("x" * 5000)
    config = {
        "redaction": {"enabled": False},
        "injection_detection": {"enabled": False},
        "budgets": {"max_output_bytes_per_call": 1000},
    }
    responses, _ = run_proxy([INIT, read_call(2, str(big))], config=config)
    assert next(r for r in responses if r["id"] == 2)["result"]["isError"] is True
