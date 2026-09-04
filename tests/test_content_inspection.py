"""Output inspection beyond `tools/call` + `type: "text"`: resources/read,
prompts/get, embedded resources, structuredContent, and content the
scanners can't read at all."""

import json

from agentguard.policy import PolicyEngine, file_uri_path
from agentguard.proxy import find_content
from tests.test_proxy import run_proxy

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
POISONED_URL = "https://blog.example.com/cookie-recipe"
INJECTION_ONLY = {"injection_detection": {"enabled": True}, "redaction": {"enabled": False}}
REDACTION_ONLY = {"injection_detection": {"enabled": False}, "redaction": {"enabled": True}}


# --- find_content ------------------------------------------------------

def test_find_content_tools_call_text_resource_and_unscannable():
    result = {
        "content": [
            {"type": "text", "text": "a"},
            {"type": "resource", "resource": {"uri": "file:///x", "text": "b"}},
            {"type": "resource", "resource": {"uri": "file:///y", "blob": "AAAA"}},
            {"type": "image", "data": "AAAA", "mimeType": "image/png"},
            {"type": "audio", "data": "AAAA", "mimeType": "audio/wav"},
            "garbage",
        ],
        "structuredContent": {"summary": "c", "items": ["d", {"deep": "e"}], "n": 1},
    }
    slots, unscannable = find_content("tools/call", result)
    assert [s.text for s in slots] == ["a", "b", "c", "d", "e"]
    assert unscannable == ["resource:blob", "image", "audio"]
    slots[1].replace("B")
    assert result["content"][1]["resource"]["text"] == "B"
    slots[3].replace("D")
    assert result["structuredContent"]["items"][0] == "D"


def test_find_content_resources_read():
    result = {"contents": [
        {"uri": "file:///a", "text": "hello"},
        {"uri": "file:///b", "blob": "AAAA", "mimeType": "application/octet-stream"},
    ]}
    slots, unscannable = find_content("resources/read", result)
    assert [s.text for s in slots] == ["hello"]
    assert unscannable == ["resource:blob"]


def test_find_content_prompts_get_single_and_list_content():
    result = {"messages": [
        {"role": "user", "content": {"type": "text", "text": "one"}},
        {"role": "assistant", "content": [{"type": "text", "text": "two"}, {"type": "image", "data": "x"}]},
    ]}
    slots, unscannable = find_content("prompts/get", result)
    assert [s.text for s in slots] == ["one", "two"]
    assert unscannable == ["image"]


def test_find_content_tolerates_malformed_results():
    assert find_content("tools/call", None) == ([], [])
    assert find_content("tools/call", {"content": "not-a-list"}) == ([], [])
    assert find_content("resources/read", {"contents": [None, 3]}) == ([], [])
    assert find_content("unknown/method", {"content": [{"type": "text", "text": "x"}]}) == ([], [])


# --- file:// URIs on the input side ------------------------------------

def test_file_uri_path_forms():
    assert file_uri_path("file:///home/u/.ssh/id_rsa") == "/home/u/.ssh/id_rsa"
    assert file_uri_path("file:///C:/Users/u/.ssh/id_rsa") == "C:/Users/u/.ssh/id_rsa"
    assert file_uri_path("file://localhost/etc/passwd") == "/etc/passwd"
    assert file_uri_path("file://server/share/x") == "//server/share/x"
    assert file_uri_path("file:///with%20space/x") == "/with space/x"
    assert file_uri_path("https://example.com/x") is None
    assert file_uri_path("/plain/path") is None


def test_file_uri_under_url_argument_is_judged_by_file_rules():
    engine = PolicyEngine({
        "file_access": {"deny_patterns": ["**/.ssh/**"]},
        "network": {"allow_patterns": ["*.example.com"], "default_action": "deny"},
    })
    decision = engine.evaluate("fetch", {"url": "file:///home/u/.ssh/id_rsa"})
    assert decision.allowed is False
    assert decision.category == "file_access"
    assert decision.arguments[0].source == "key_name:file-uri"
    assert engine.evaluate("fetch", {"url": "file:///home/u/notes.txt"}).allowed is True


# --- end to end through the demo server --------------------------------

def test_resources_read_of_ssh_key_is_blocked_on_the_way_in(tmp_path):
    key_path = tmp_path / ".ssh" / "id_rsa"
    key_path.parent.mkdir()
    key_path.write_text("SUPER-SECRET-KEY")
    requests = [INIT, {
        "jsonrpc": "2.0", "id": 2, "method": "resources/read",
        "params": {"uri": f"file://{key_path.as_posix()}"},
    }]
    responses, audit = run_proxy(requests, config={"file_access": {"deny_patterns": ["**/.ssh/**"]}})
    response = next(r for r in responses if r.get("id") == 2)
    assert "error" in response
    assert "SUPER-SECRET-KEY" not in json.dumps(response)
    entry = next(e for e in audit if e["event"] == "policy_decision")
    assert entry["tool"] == "resources/read"
    assert entry["allowed"] is False
    assert entry["argument_categories"] == {"uri": "file_access"}


def test_resources_read_poisoned_content_is_blocked_on_the_way_out():
    requests = [INIT, {
        "jsonrpc": "2.0", "id": 2, "method": "resources/read",
        "params": {"uri": "demo://blog.example.com"},
    }]
    responses, audit = run_proxy(requests, config=INJECTION_ONLY)
    response = next(r for r in responses if r.get("id") == 2)
    assert "error" in response
    assert "attacker@evil.example.com" not in json.dumps(response)
    assert "suspected prompt injection" in response["error"]["message"]
    block = next(e for e in audit if e["event"] == "injection_blocked")
    assert block["method"] == "resources/read"
    assert block["tool"] == "demo://blog.example.com"


def test_resources_read_secret_is_redacted(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("aws key: AKIAABCDEFGHIJKLMNOP end")
    requests = [INIT, {
        "jsonrpc": "2.0", "id": 2, "method": "resources/read",
        "params": {"uri": f"file://{notes.as_posix()}"},
    }]
    responses, audit = run_proxy(requests, config=REDACTION_ONLY)
    response = next(r for r in responses if r.get("id") == 2)
    text = response["result"]["contents"][0]["text"]
    assert "AKIAABCDEFGHIJKLMNOP" not in text
    assert text == "aws key: [REDACTED:aws_access_key_id] end"
    assert response["result"]["contents"][0]["uri"].startswith("file://")  # rest of the item intact
    redaction = next(e for e in audit if e["event"] == "redaction")
    assert redaction["method"] == "resources/read"


def test_prompts_get_poisoned_messages_are_blocked():
    requests = [INIT, {
        "jsonrpc": "2.0", "id": 2, "method": "prompts/get",
        "params": {"name": "summarize_page", "arguments": {"url": POISONED_URL}},
    }]
    responses, audit = run_proxy(requests, config=INJECTION_ONLY)
    response = next(r for r in responses if r.get("id") == 2)
    assert "error" in response
    assert "IGNORE ALL PREVIOUS" not in json.dumps(response)
    block = next(e for e in audit if e["event"] == "injection_blocked")
    assert block["method"] == "prompts/get"
    assert block["tool"] == "summarize_page"
    # prompts/get is not policy-gated on the way in: no decision entry.
    assert not [e for e in audit if e["event"] == "policy_decision"]


def test_prompts_get_clean_messages_pass_through():
    requests = [INIT, {
        "jsonrpc": "2.0", "id": 2, "method": "prompts/get",
        "params": {"name": "summarize_page", "arguments": {"url": "https://docs.example.com/readme"}},
    }]
    responses, audit = run_proxy(requests, config=INJECTION_ONLY)
    response = next(r for r in responses if r.get("id") == 2)
    assert "Project README" in response["result"]["messages"][0]["content"]["text"]
    assert audit == []


def test_unscannable_content_is_passed_through_and_logged():
    requests = [INIT, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "screenshot", "arguments": {}},
    }]
    responses, audit = run_proxy(requests, config=INJECTION_ONLY)
    response = next(r for r in responses if r.get("id") == 2)
    assert response["result"]["content"][0]["type"] == "image"
    assert response["result"]["content"][0]["data"] == "iVBORw0KGgo="
    unscannable = next(e for e in audit if e["event"] == "unscannable_content")
    assert unscannable == {
        **unscannable,
        "tool": "screenshot", "method": "tools/call", "kinds": ["image"],
    }
