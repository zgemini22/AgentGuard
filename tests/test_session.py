import os

import agentguard
from agentguard.audit import AuditLog, verify_audit_log
from agentguard.classify import ArgumentClassifier
from agentguard.policy import Decision
from agentguard.session import Session, file_sha256
from tests.test_proxy import run_proxy

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
TOOLS_LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
DEFAULT_POLICY = os.path.join(os.path.dirname(__file__), "..", "policies", "default.yaml")


def test_new_session_has_unique_id_and_policy_hash():
    a = Session.new(["python3", "server.py"], policy_path=DEFAULT_POLICY)
    b = Session.new(["python3", "server.py"], policy_path=DEFAULT_POLICY)
    assert a.id != b.id
    assert len(a.id) == 32
    assert a.policy_sha256 == file_sha256(DEFAULT_POLICY)
    assert a.server_cmd == ["python3", "server.py"]
    assert Session.new([], policy_path="/nonexistent").policy_sha256 is None


def test_register_tools_feeds_inventory_and_classifier():
    classifier = ArgumentClassifier()
    session = Session.new([], classifier)
    n = session.register_tools([
        {"name": "t1", "inputSchema": {"properties": {"where": {"format": "uri"}}}},
        {"name": "t2"},
        "junk",
    ])
    assert n == 2
    assert sorted(session.tools) == ["t1", "t2"]
    assert classifier.classify("t1", "where").category == "network"
    assert session.register_tools(None) == 0


def test_start_and_end_metadata():
    session = Session.new(["srv"], policy_path=DEFAULT_POLICY)
    start = session.start_metadata()
    assert start["server_cmd"] == ["srv"]
    assert start["policy_path"] == DEFAULT_POLICY
    assert start["agentguard_version"] == agentguard.__version__
    session.register_tools([{"name": "b"}, {"name": "a"}])
    end = session.end_metadata(0)
    assert end["exit_code"] == 0
    assert end["tools_seen"] == ["a", "b"]
    assert end["duration_seconds"] >= 0


def test_audit_entries_carry_session_id_only_after_begin(tmp_path):
    log = AuditLog(str(tmp_path / "audit.log"))
    before = log.record("t", {}, Decision(True, "none", "ok"))
    assert "session_id" not in before

    session = Session.new(["srv"])
    start = log.begin_session(session)
    during = log.record("t", {}, Decision(True, "none", "ok"))
    end = log.end_session(session, 0)
    assert start["event"] == "session_start"
    assert start["session_id"] == during["session_id"] == end["session_id"] == session.id
    assert end["event"] == "session_end"
    assert verify_audit_log(str(tmp_path / "audit.log")).valid is True


def test_proxy_brackets_run_with_session_entries():
    _, audit = run_proxy([INIT, TOOLS_LIST])
    assert audit[0]["event"] == "session_start"
    assert audit[-1]["event"] == "session_end"
    session_ids = {e["session_id"] for e in audit}
    assert len(session_ids) == 1
    assert audit[0]["server_cmd"][-1].endswith("vulnerable_server.py")
    assert "read_file" in audit[-1]["tools_seen"]
    assert audit[-1]["exit_code"] == 0


def test_two_runs_in_one_log_have_distinct_session_ids(tmp_path):
    # Simulate two `agentguard run` processes appending to the same file.
    path = str(tmp_path / "audit.log")
    for _ in range(2):
        log = AuditLog(path)
        session = Session.new(["srv"])
        log.begin_session(session)
        log.record("t", {}, Decision(True, "none", "ok"))
        log.end_session(session, 0)
    import json
    with open(path) as f:
        entries = [json.loads(l) for l in f if l.strip()]
    assert len({e["session_id"] for e in entries}) == 2
    assert verify_audit_log(path).valid is True
