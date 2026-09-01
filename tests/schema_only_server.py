#!/usr/bin/env python3
"""Test fixture: a stdio MCP-style server whose one tool, `open_thing`,
takes its path under an argument named `where` — a name no key
convention recognizes. Only the `description` in its declared
inputSchema says it's a path, so the proxy can classify it only if it
captured the `tools/list` response. Reads the file for real so tests
can assert the secret never came back."""

import json
import sys


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    method, req_id, params = req.get("method"), req.get("id"), req.get("params") or {}
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2024-11-05",
              "serverInfo": {"name": "schema-only", "version": "0"}, "capabilities": {"tools": {}}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": [{
            "name": "open_thing",
            "description": "Opens a thing.",
            "inputSchema": {"type": "object", "properties": {
                "where": {"type": "string", "description": "Absolute path to the file to read."},
            }},
        }]}})
    elif method == "tools/call" and params.get("name") == "open_thing":
        try:
            with open((params.get("arguments") or {}).get("where", ""), "r") as f:
                text = f.read()
            send({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}]}})
        except OSError as e:
            send({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}})
    elif req_id is not None:
        send({"jsonrpc": "2.0", "id": req_id, "result": {}})
