"""MCP proxy: sits between an agent client and a real MCP server on stdio.

The MCP stdio transport is newline-delimited JSON-RPC 2.0. Every message
the agent sends is inspected; a `tools/call` request is evaluated by the
PolicyEngine before it is allowed to reach the wrapped server. Denied
calls never leave the proxy — the agent gets a JSON-RPC error back
immediately, and the real server never sees the request. Every other
message (initialize, tools/list, notifications, ...) is passed through
untouched in both directions.

Responses are also inspected: a `tools/call` result's text content is
run through the SecretRedactor before being forwarded to the agent, so a
call the policy allowed can still have its output scrubbed of secrets it
happened to return.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import IO, Dict, List, Optional

from .audit import AuditLog
from .policy import PolicyEngine
from .redact import SecretRedactor

POLICY_VIOLATION_ERROR_CODE = -32001


class MCPProxy:
    def __init__(
        self,
        server_cmd: List[str],
        policy: PolicyEngine,
        audit: AuditLog,
        redactor: Optional[SecretRedactor] = None,
        stdin: IO[str] = sys.stdin,
        stdout: IO[str] = sys.stdout,
        stderr: IO[str] = sys.stderr,
    ):
        self.server_cmd = server_cmd
        self.policy = policy
        self.audit = audit
        self.redactor = redactor
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        # Maps a request id to the tool name it called, only for calls the
        # policy allowed through to the real server. Written by the
        # client->server thread, read/popped by the server->client thread.
        self._pending_tool_calls: Dict[object, str] = {}
        self._pending_lock = threading.Lock()

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
            if self.redactor is not None and self.redactor.enabled:
                with self._pending_lock:
                    self._pending_tool_calls[message.get("id")] = tool_name
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
            self.stdout.write(self._handle_server_line(line))
            self.stdout.flush()

    def _handle_server_line(self, line: str) -> str:
        """Returns the line to forward to the client, redacted if needed."""
        if self.redactor is None or not self.redactor.enabled:
            return line

        stripped = line.rstrip("\n")
        if not stripped:
            return line
        try:
            message = json.loads(stripped)
        except json.JSONDecodeError:
            return line

        with self._pending_lock:
            tool_name = self._pending_tool_calls.pop(message.get("id"), None)
        if tool_name is None or "result" not in message:
            return line

        redacted_message, rule_names = self._redact_result(message)
        if not rule_names:
            return line

        self.audit.record_redaction(tool_name, rule_names)
        return json.dumps(redacted_message) + "\n"

    def _redact_result(self, message: dict) -> tuple[dict, List[str]]:
        result = message.get("result") or {}
        content = result.get("content")
        if not isinstance(content, list):
            return message, []

        all_rule_names: List[str] = []
        new_content = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                redacted_text, rule_names = self.redactor.redact(item["text"])
                all_rule_names.extend(rule_names)
                item = {**item, "text": redacted_text}
            new_content.append(item)

        if not all_rule_names:
            return message, []
        return {**message, "result": {**result, "content": new_content}}, all_rule_names
