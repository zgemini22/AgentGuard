"""The MCP stdio transport is UTF-8 whatever the locale is. On a Windows
machine with a cp936 or cp1252 code page the proxy used to decode the
server's UTF-8 with the locale codec, which crashed on some input and, on
other input, paired a secret's first byte with the character before it so
the redaction rule missed it and the bytes went out intact."""

import json
import os
import subprocess
import sys

from agentguard.cli import DEFAULT_POLICY
from tests.test_response_correlation import run

SERVER = os.path.join(os.path.dirname(__file__), "scripted_server.py")
SECRET = "AKIAABCDEFGHIJKLMNOP"
CHINESE = "你好，世界"


def test_utf8_result_with_a_secret_after_a_multibyte_character_is_redacted(tmp_path):
    text = f"{CHINESE} — {SECRET}"
    result = json.dumps({"jsonrpc": "2.0", "id": "__ID__", "result": {"content": [
        {"type": "text", "text": text}]}}, ensure_ascii=False).replace('"__ID__"', "__ID__")
    out, audit, _ = run({"tools/call": [result]}, tmp_path=tmp_path)
    delivered = next(m for m in out if m.get("id") == 2)["result"]["content"][0]["text"]
    assert SECRET not in delivered
    assert delivered.startswith(CHINESE + " — [REDACTED:")


def test_agentguard_run_speaks_utf8_even_when_its_stdio_codec_is_not(tmp_path):
    echo = ('{"jsonrpc": "2.0", "id": __ID__, "result": {"content": [{"type": "text", '
            '"text": __ARGS__}, {"type": "text", "text": "— ' + SECRET + '"}]}}')
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "search", "arguments": {"query": CHINESE}}},
    ]
    stdin = ("\n".join(json.dumps(r, ensure_ascii=False) for r in requests) + "\n").encode("utf-8")
    env = dict(os.environ, PYTHONIOENCODING="latin-1", PYTHONUTF8="0")
    proc = subprocess.run(
        [sys.executable, "-m", "agentguard.cli", "run", "--config", DEFAULT_POLICY,
         "--audit-log", str(tmp_path / "audit.log"), "--",
         sys.executable, SERVER, json.dumps({"tools/call": [echo]})],
        input=stdin, capture_output=True, env=env, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    lines = proc.stdout.decode("utf-8").splitlines()  # must be valid UTF-8
    response = next(json.loads(l) for l in lines if json.loads(l).get("id") == 2)
    texts = [item["text"] for item in response["result"]["content"]]
    assert json.loads(texts[0]) == {"query": CHINESE}  # arrived at the server intact
    assert SECRET not in texts[1]
    assert "[REDACTED:aws_access_key_id]" in texts[1]
    assert b"\r\n" not in proc.stdout
