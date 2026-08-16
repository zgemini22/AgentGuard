import io
import json
import os
import sys
import tempfile

from agentguard.audit import AuditLog
from agentguard.injection import InjectionDetector
from agentguard.policy import PolicyEngine
from agentguard.proxy import MCPProxy
from agentguard.redact import SecretRedactor

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
            redactor=SecretRedactor.from_config(config),
            injection_detector=InjectionDetector.from_config(config),
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


def test_redacts_secret_found_in_allowed_tool_output(tmp_path):
    fake_key = "AKIA" + "B" * 16
    creds_path = tmp_path / "creds.txt"
    creds_path.write_text(f"aws key: {fake_key}")

    config = {
        "redaction": {
            "enabled": True,
            "rules": [{"name": "aws_access_key_id", "pattern": r"AKIA[0-9A-Z]{16}"}],
        },
    }
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": str(creds_path)}},
        },
    ]
    responses, audit_entries = run_proxy(requests, config=config)

    call_response = next(r for r in responses if r.get("id") == 2)
    assert fake_key not in json.dumps(call_response)
    assert "[REDACTED:aws_access_key_id]" in call_response["result"]["content"][0]["text"]

    redaction_events = [e for e in audit_entries if e.get("event") == "redaction"]
    assert len(redaction_events) == 1
    assert redaction_events[0]["rules_matched"] == ["aws_access_key_id"]
    assert redaction_events[0]["tool"] == "read_file"


def test_blocks_poisoned_tool_output_as_suspected_injection():
    config = {
        "injection_detection": {
            "enabled": True,
            "rules": [
                {"name": "ignore_instructions", "pattern": r"ignore\s+(all\s+)?(previous|prior)\s+instructions"},
                {
                    "name": "exfiltrate_secret",
                    "pattern": r"send\s+(the\s+user'?s\s+)?private key\s+to\b",
                },
            ],
        },
    }
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "fetch_url", "arguments": {"url": "https://blog.example.com/cookie-recipe"}},
        },
    ]
    responses, audit_entries = run_proxy(requests, config=config)

    call_response = next(r for r in responses if r.get("id") == 2)
    assert call_response["result"]["isError"] is True
    assert "attacker@evil.example.com" not in json.dumps(call_response)
    assert "blocked" in call_response["result"]["content"][0]["text"].lower()

    injection_events = [e for e in audit_entries if e.get("event") == "injection_blocked"]
    assert len(injection_events) == 1
    assert injection_events[0]["tool"] == "fetch_url"
    assert set(injection_events[0]["rules_matched"]) == {"ignore_instructions", "exfiltrate_secret"}


def test_clean_fetched_page_passes_through_unblocked():
    config = {"injection_detection": {"enabled": True}}
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "fetch_url", "arguments": {"url": "https://docs.example.com/readme"}},
        },
    ]
    responses, audit_entries = run_proxy(requests, config=config)

    call_response = next(r for r in responses if r.get("id") == 2)
    assert "isError" not in call_response["result"]
    assert "Project README" in call_response["result"]["content"][0]["text"]
    assert not [e for e in audit_entries if e.get("event") == "injection_blocked"]
