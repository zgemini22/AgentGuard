"""MCP proxy: sits between an agent client and a real MCP server on stdio.

The MCP stdio transport is newline-delimited JSON-RPC 2.0. Every message
the agent sends is inspected; a `tools/call` request is evaluated by the
PolicyEngine before it is allowed to reach the wrapped server. Denied
calls never leave the proxy — the agent gets a JSON-RPC error back
immediately, and the real server never sees the request. Every other
message (initialize, tools/list, notifications, ...) is passed through
untouched in both directions.

Responses are also inspected, in two passes, for a `tools/call` result
the policy already allowed through:

1. InjectionDetector scans the text content for instruction-shaped text
   (the poisoned-webpage attack: fetched content trying to redirect what
   the agent does next). A hit blocks the *entire* result — it's
   replaced with an isError result — rather than trying to strip just
   the offending sentence.
2. If nothing was blocked, SecretRedactor scans and masks known secret
   formats in what's left, in place.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import IO, Dict, List, Optional, Tuple

from .audit import AuditLog
from .injection import InjectionDetector
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
        injection_detector: Optional[InjectionDetector] = None,
        stdin: IO[str] = sys.stdin,
        stdout: IO[str] = sys.stdout,
        stderr: IO[str] = sys.stderr,
    ):
        self.server_cmd = server_cmd
        self.policy = policy
        self.audit = audit
        self.redactor = redactor
        self.injection_detector = injection_detector
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        # Maps a request id to the tool name it called, only for calls the
        # policy allowed through to the real server. Written by the
        # client->server thread, read/popped by the server->client thread.
        self._pending_tool_calls: Dict[object, str] = {}
        self._pending_lock = threading.Lock()

    def _output_inspection_enabled(self) -> bool:
        return (self.redactor is not None and self.redactor.enabled) or (
            self.injection_detector is not None and self.injection_detector.enabled
        )

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
            if self._output_inspection_enabled():
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
        """Returns the line to forward to the client, blocked/redacted as needed."""
        if not self._output_inspection_enabled():
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

        blocked_message, injection_rules = self._check_injection(message)
        if injection_rules:
            self.audit.record_injection_block(tool_name, injection_rules)
            return json.dumps(blocked_message) + "\n"

        redacted_message, redaction_rules = self._redact_result(message)
        if not redaction_rules:
            return line

        self.audit.record_redaction(tool_name, redaction_rules)
        return json.dumps(redacted_message) + "\n"

    def _check_injection(self, message: dict) -> Tuple[dict, List[str]]:
        if self.injection_detector is None or not self.injection_detector.enabled:
            return message, []

        matched_rules: List[str] = []
        for text in self._iter_text_content(message):
            matched_rules.extend(self.injection_detector.scan(text))
        if not matched_rules:
            return message, []

        matched_rules = sorted(set(matched_rules))
        blocked_result = {
            "content": [{
                "type": "text",
                "text": (
                    "AgentGuard: this tool output was blocked — suspected prompt "
                    f"injection (matched rules: {', '.join(matched_rules)})."
                ),
            }],
            "isError": True,
        }
        return {**message, "result": blocked_result}, matched_rules

    def _redact_result(self, message: dict) -> Tuple[dict, List[str]]:
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

    @staticmethod
    def _iter_text_content(message: dict):
        result = message.get("result") or {}
        content = result.get("content")
        if not isinstance(content, list):
            return
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                yield item["text"]
