import io
import json
import os
import sys
import tempfile

from agentguard.audit import AuditLog
from agentguard.policy import PolicyEngine
from agentguard.proxy import MCPProxy

DEMO_SERVER = os.path.join(os.path.dirname(__file__), "..", "demo", "vulnerable_server.py")

CONFIG = {
    "file_access": {
        "enabled": True,
        "deny_patterns": ["**/.ssh/**", "**/id_rsa*"],
    },
}


def run_proxy(requests, config=CONFIG):
    with tempfile.TemporaryDirectory() as tmp:
        audit_path = os.path.join(tmp, "audit.log")
        stdin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
        stdout = io.StringIO()
        proxy = MCPProxy(
            [sys.executable, DEMO_SERVER],
            PolicyEngine(config),
            AuditLog(audit_path),
            stdin=stdin,
            stdout=stdout,
            stderr=sys.stderr,
        )
        proxy.run()
        responses = [json.loads(l) for l in stdout.getvalue().splitlines() if l.strip()]
        if os.path.exists(audit_path):
            with open(audit_path) as f:
                audit_entries = [json.loads(l) for l in f if l.strip()]
        else:
            audit_entries = []
        return responses, audit_entries


def test_blocks_ssh_key_read_and_never_reaches_server(tmp_path):
    key_path = tmp_path / ".ssh" / "id_rsa"
    key_path.parent.mkdir()
    key_path.write_text("SUPER-SECRET-KEY")

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": str(key_path)}},
        },
    ]
    responses, audit_entries = run_proxy(requests)

    call_response = next(r for r in responses if r.get("id") == 2)
    assert "error" in call_response
    assert "SUPER-SECRET-KEY" not in json.dumps(call_response)

    denied = [e for e in audit_entries if e["tool"] == "read_file"]
    assert len(denied) == 1
    assert denied[0]["allowed"] is False


def test_allows_normal_file_read_end_to_end(tmp_path):
    notes_path = tmp_path / "notes.txt"
    notes_path.write_text("hello world")

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": str(notes_path)}},
        },
    ]
    responses, audit_entries = run_proxy(requests)

    call_response = next(r for r in responses if r.get("id") == 2)
    assert call_response["result"]["content"][0]["text"] == "hello world"

    allowed = [e for e in audit_entries if e["tool"] == "read_file"]
    assert len(allowed) == 1
    assert allowed[0]["allowed"] is True


def test_non_tool_call_messages_pass_through_untouched():
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}]
    responses, audit_entries = run_proxy(requests)

    assert len(responses) == 1
    assert responses[0]["result"]["serverInfo"]["name"] == "agentguard-demo-vulnerable-server"
    assert audit_entries == []
