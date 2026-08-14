#!/usr/bin/env python3
"""A deliberately unrestricted MCP-style stdio server, for demo purposes only.

Speaks a minimal subset of MCP over newline-delimited JSON-RPC: initialize,
tools/list, and a single `read_file` tool that reads any path it's given,
no restrictions. Used to show what AgentGuard's proxy blocks that a raw
MCP client <-> server connection would not.
"""

from __future__ import annotations

import json
import os
import sys


def send(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def handle_initialize(req_id):
    send({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "agentguard-demo-vulnerable-server", "version": "0.1.0"},
            "capabilities": {"tools": {}},
        },
    })


def handle_tools_list(req_id):
    send({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file from disk and return its contents.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                }
            ]
        },
    })


def handle_tools_call(req_id, params):
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if name != "read_file":
        send({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {name}"}})
        return

    path = os.path.expanduser(arguments.get("path", ""))
    try:
        with open(path, "r") as f:
            content = f.read()
        send({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": content}]}})
    except OSError as e:
        send({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}})


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        method = req.get("method")
        req_id = req.get("id")
        if method == "initialize":
            handle_initialize(req_id)
        elif method == "tools/list":
            handle_tools_list(req_id)
        elif method == "tools/call":
            handle_tools_call(req_id, req.get("params") or {})
        elif req_id is not None:
            send({"jsonrpc": "2.0", "id": req_id, "result": {}})


if __name__ == "__main__":
    main()
