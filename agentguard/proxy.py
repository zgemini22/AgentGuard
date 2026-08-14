"""MCP proxy: sits between an agent client and a real MCP server on stdio.

The MCP stdio transport is newline-delimited JSON-RPC 2.0. Every message
the agent sends is inspected; a `tools/call` request is evaluated by the
PolicyEngine before it is allowed to reach the wrapped server. Denied
calls never leave the proxy — the agent gets a JSON-RPC error back
immediately, and the real server never sees the request. Every other
message (initialize, tools/list, notifications, ...) is passed through
untouched in both directions.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import IO, List

from .audit import AuditLog
from .policy import PolicyEngine

POLICY_VIOLATION_ERROR_CODE = -32001


class MCPProxy:
    def __init__(
        self,
        server_cmd: List[str],
        policy: PolicyEngine,
        audit: AuditLog,
        stdin: IO[str] = sys.stdin,
        stdout: IO[str] = sys.stdout,
        stderr: IO[str] = sys.stderr,
    ):
        self.server_cmd = server_cmd
        self.policy = policy
        self.audit = audit
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr

    def run(self) -> int:
        proc = subprocess.Popen(
            self.server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            text=True,
            bufsize=1,
        )
        server_reader = threading.Thread(
            target=self._pump_server_to_client, args=(proc,), daemon=True
        )
        server_reader.start()
        try:
            self._pump_client_to_server(proc)
        finally:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
            proc.wait()
            server_reader.join(timeout=1)
        return proc.returncode or 0

    def _pump_client_to_server(self, proc: subprocess.Popen) -> None:
        for line in self.stdin:
            line = line.rstrip("\n")
            if not line:
                continue
            forwarded_line = self._handle_client_line(line)
            if forwarded_line is None:
                continue
            proc.stdin.write(forwarded_line + "\n")
            proc.stdin.flush()

    def _handle_client_line(self, line: str) -> str | None:
        """Returns the line to forward to the server, or None to swallow it."""
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            return line

        if message.get("method") != "tools/call":
            return line

        params = message.get("params") or {}
        tool_name = params.get("name", "<unknown>")
        arguments = params.get("arguments") or {}

        decision = self.policy.evaluate(tool_name, arguments)
        self.audit.record(tool_name, arguments, decision)

        if decision.allowed:
            return line

        self._reject(message.get("id"), decision.reason)
        return None

    def _reject(self, request_id, reason: str) -> None:
        error_response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": POLICY_VIOLATION_ERROR_CODE,
                "message": f"AgentGuard: blocked by policy — {reason}",
            },
        }
        self.stdout.write(json.dumps(error_response) + "\n")
        self.stdout.flush()

    def _pump_server_to_client(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:
            self.stdout.write(line)
            self.stdout.flush()
