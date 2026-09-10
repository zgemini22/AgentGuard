"""`agentguard report`: the audit log, answered."""

import io
import json
import os
import sys

from agentguard.audit import AuditLog
from agentguard.cli import main
from agentguard.injection import InjectionDetector
from agentguard.policy import Decision, PolicyEngine
from agentguard.proxy import MCPProxy
from agentguard.redact import SecretRedactor
from agentguard.report import build_report, load_entries, render_text
from agentguard.session import Session
from tests.test_proxy import DEMO_SERVER

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "policies", "default.yaml")


def run_session(audit_path, requests, config):
    """Like tests.test_proxy.run_proxy but against a caller-owned log
    path, so several sessions can share one file."""
    stdin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
    policy = PolicyEngine(config)
    proxy = MCPProxy(
        [sys.executable, DEMO_SERVER], policy, AuditLog(audit_path),
        redactor=SecretRedactor.from_config(config),
        injection_detector=InjectionDetector.from_config(config),
        stdin=stdin, stdout=io.StringIO(), stderr=sys.__stderr__,  # capsys-safe: Popen needs a real fileno
        session=Session.new([sys.executable, DEMO_SERVER], policy.classifier, policy_path=POLICY_PATH),
    )
    proxy.run()
    return proxy.session.id


def busy_session(tmp_path, audit_path):
    """One session that exercises every kind of entry."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "README.md").write_text("hello")
    (project / "src").mkdir()
    (project / "src" / "main.py").write_text("print(1)")
    (project / "deploy.txt").write_text("key AKIAABCDEFGHIJKLMNOP")
    ssh = tmp_path / ".ssh"
    ssh.mkdir()
    (ssh / "id_rsa").write_text("SECRET")

    config = {
        "file_access": {"deny_patterns": ["**/.ssh/**"]},
        "network": {"allow_patterns": ["*.example.com"], "default_action": "deny"},
        "budgets": {"max_network_calls": 5},
    }
    calls = [
        ("read_file", {"path": str(project / "README.md")}),
        ("read_file", {"path": str(project / "src" / "main.py")}),
        ("read_file", {"path": str(project / "README.md")}),
        ("read_file", {"path": str(ssh / "id_rsa")}),
        ("read_file", {"path": str(project / "deploy.txt")}),
        ("fetch_url", {"url": "https://docs.example.com/readme"}),
        ("fetch_url", {"url": "https://blog.example.com/cookie-recipe"}),
        ("fetch_url", {"url": "https://evil.example.net/x"}),
        ("screenshot", {}),
    ]
    requests = [INIT, {"jsonrpc": "2.0", "id": 100, "method": "tools/list", "params": {}}] + [
        {"jsonrpc": "2.0", "id": i + 2, "method": "tools/call", "params": {"name": n, "arguments": a}}
        for i, (n, a) in enumerate(calls)
    ]
    return run_session(str(audit_path), requests, config), project, ssh


def test_report_groups_files_by_directory_and_flags_blocks(tmp_path):
    audit_path = tmp_path / "audit.log"
    session_id, project, ssh = busy_session(tmp_path, audit_path)
    report = build_report(str(audit_path))
    assert report["chain"]["valid"] is True
    assert len(report["sessions"]) == 1
    s = report["sessions"][0]
    assert s["id"] == session_id
    assert s["policy_path"] == POLICY_PATH
    assert s["exit_code"] == 0
    assert "read_file" in s["tools_seen"]

    files = s["files"]
    assert set(files) == {str(project), str(project / "src"), str(ssh)}
    readme = files[str(project)][str(project / "README.md")]
    assert readme == {"tool": "read_file", "allowed": True, "reason": None, "count": 2}
    key = files[str(ssh)][str(ssh / "id_rsa")]
    assert key["allowed"] is False
    assert "deny pattern" in key["reason"]

    assert set(s["hosts"]) == {"docs.example.com", "blog.example.com", "evil.example.net"}
    assert s["hosts"]["evil.example.net"]["allowed"] is False
    assert s["commands"] == []
    assert [b["tool"] for b in s["blocked"]] == ["read_file", "fetch_url"]
    assert s["redactions"][0]["rules"] == ["aws_access_key_id"]
    assert s["injections"][0]["tool"] == "fetch_url"
    assert s["unscannable"][0]["kinds"] == ["image"]
    assert s["calls"] == {"allowed": 7, "denied": 2, "by_category": {"file_access": 4, "network": 2}}
    assert s["timeline"][0]["event"] == "session_start"
    assert s["timeline"][-1]["event"] == "session_end"


def test_render_text_reads_like_the_answer(tmp_path):
    audit_path = tmp_path / "audit.log"
    busy_session(tmp_path, audit_path)
    text = render_text(build_report(str(audit_path)))
    assert "chain: OK" in text
    assert "== session " in text
    assert "policy: " in text and "sha256" in text
    assert "calls: 7 allowed, 2 denied" in text
    assert "files touched: 4" in text
    assert "README.md" in text and "x2" in text
    assert "id_rsa" in text and "BLOCKED" in text
    assert "hosts contacted: 3" in text
    assert "evil.example.net" in text
    assert "commands run: none" in text
    assert "blocked calls: 2" in text
    assert "redactions: 1" in text and "aws_access_key_id" in text
    assert "injection blocks: 1" in text
    assert "unscannable content passed through: 1" in text
    assert "budgets: allowed calls by category: file_access 4, network 2" in text
    assert "timeline:" in text
    assert "DENY   read_file" in text


def test_report_cli_json_and_session_filter(tmp_path, capsys):
    audit_path = tmp_path / "audit.log"
    first, _, _ = busy_session(tmp_path, audit_path)
    second = run_session(str(audit_path), [INIT], {})
    assert first != second

    assert main(["report", str(audit_path), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [s["id"] for s in data["sessions"]] == [first, second]

    assert main(["report", str(audit_path), "--session", second[:8]]) == 0
    out = capsys.readouterr().out
    assert f"== session {second[:12]}" in out
    assert first[:12] not in out
    assert "calls: 0 allowed, 0 denied" in out


def test_report_on_tampered_log_says_so_and_exits_one(tmp_path, capsys):
    audit_path = tmp_path / "audit.log"
    busy_session(tmp_path, audit_path)
    lines = audit_path.read_text().splitlines()
    entry = json.loads(lines[2])
    entry["allowed"] = not entry["allowed"]
    lines[2] = json.dumps(entry)
    audit_path.write_text("\n".join(lines) + "\n")

    assert main(["report", str(audit_path)]) == 1
    out = capsys.readouterr().out
    assert "chain: TAMPERED" in out
    assert "reported as written" in out


def test_report_handles_missing_log_and_v1_entries(tmp_path, capsys):
    assert main(["report", str(tmp_path / "nope.log")]) == 0
    assert "no sessions found" in capsys.readouterr().out

    # A v1-era entry: no session_id, no argument_categories.
    log = AuditLog(str(tmp_path / "old.log"))
    log.record("read_file", {"path": "/old/x.txt"}, Decision(True, "file_access", "ok"))
    entries = load_entries(str(tmp_path / "old.log"))
    del entries[0]["argument_categories"]
    (tmp_path / "old.log").write_text(json.dumps(entries[0]) + "\n")
    report = build_report(str(tmp_path / "old.log"))
    assert report["chain"]["valid"] is False  # we broke the hash, and the report says so
    s = report["sessions"][0]
    assert s["id"] == "(no session)"
    assert os.path.normpath("/old") in {os.path.normpath(d) for d in s["files"]}
