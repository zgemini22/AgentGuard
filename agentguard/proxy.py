"""MCP proxy: sits between an agent client and a real MCP server on stdio.

The MCP stdio transport is newline-delimited JSON-RPC 2.0. Every message
the agent sends is inspected; a `tools/call` request is evaluated by the
PolicyEngine before it is allowed to reach the wrapped server, and so is
a `resources/read` (its `uri` goes through the same network/file rules —
a `file://` URI is a file read). Denied calls never leave the proxy —
the agent gets a JSON-RPC error back immediately, and the real server
never sees the request. Every other message (initialize, tools/list,
notifications, ...) is passed through untouched in both directions —
but a `tools/list` *response* is also read on the way past, so the
policy engine's argument classifier knows each tool's declared input
schema before the first call arrives.

Responses are also inspected, in two passes, for any `tools/call`,
`resources/read` or `prompts/get` the proxy let through:

1. InjectionDetector scans every piece of text content — `text` items,
   embedded `resource` items with text, `resources/read` contents,
   `prompts/get` messages, `structuredContent` string leaves — for
   instruction-shaped text (the poisoned-webpage attack: fetched
   content trying to redirect what the agent does next). A hit blocks
   the *entire* result — replaced with an isError result for tool
   calls, a JSON-RPC error otherwise — rather than trying to strip just
   the offending sentence.
2. If nothing was blocked, SecretRedactor scans and masks known secret
   formats in what's left, in place.

Content that can't be scanned as text — images, audio, binary `blob`
resources — is passed through and logged as such, so the audit trail
shows where the scanners had no visibility instead of implying they
looked.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import IO, Dict, List, Optional, Tuple

from .audit import AuditLog
from .injection import InjectionDetector
from .policy import ASK, Decision, PolicyEngine
from .redact import SecretRedactor
from .session import Session

POLICY_VIOLATION_ERROR_CODE = -32001
# How long a tools/call waits for an in-flight tools/list response before
# being evaluated with whatever schemas are known so far.
SCHEMA_WAIT_SECONDS = 5.0
# How long a call waits for earlier results to be counted when a total
# output budget is configured (see _handle_client_line).
RESPONSE_WAIT_SECONDS = 30.0

# Methods whose responses carry content the output scanners look at.
INSPECTED_METHODS = ("tools/call", "resources/read", "prompts/get")


@dataclass
class PendingRequest:
    method: str
    name: str  # tool name, resource uri, or prompt name — what the audit log calls it


@dataclass
class TextSlot:
    """A string inside a result, addressed so it can be replaced in place."""
    container: object  # dict or list
    key: object        # str key or int index

    @property
    def text(self) -> str:
        return self.container[self.key]  # type: ignore[index]

    def replace(self, new_text: str) -> None:
        self.container[self.key] = new_text  # type: ignore[index]


def _content_item_slots(item, slots: List[TextSlot], unscannable: List[str]) -> None:
    """One MCP content object: {type: text|image|audio|resource, ...}."""
    if not isinstance(item, dict):
        return
    kind = item.get("type")
    if kind == "text":
        if isinstance(item.get("text"), str):
            slots.append(TextSlot(item, "text"))
        return
    if kind == "resource":
        resource = item.get("resource")
        if isinstance(resource, dict) and isinstance(resource.get("text"), str):
            slots.append(TextSlot(resource, "text"))
        else:
            unscannable.append("resource:blob")
        return
    unscannable.append(str(kind) if kind else "unknown")


def _string_leaves(node, slots: List[TextSlot]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str):
                slots.append(TextSlot(node, key))
            else:
                _string_leaves(value, slots)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            if isinstance(value, str):
                slots.append(TextSlot(node, index))
            else:
                _string_leaves(value, slots)


def find_content(method: str, result) -> Tuple[List[TextSlot], List[str]]:
    """Locates every scannable string in a result for the given method,
    plus a description of each content item that *can't* be scanned.
    Slots point into `result` itself, so replacing through them edits
    the result in place — pass a copy if that matters."""
    slots: List[TextSlot] = []
    unscannable: List[str] = []
    if not isinstance(result, dict):
        return slots, unscannable

    if method == "tools/call":
        content = result.get("content")
        if isinstance(content, list):
            for item in content:
                _content_item_slots(item, slots, unscannable)
        if "structuredContent" in result:
            _string_leaves(result["structuredContent"], slots)
    elif method == "resources/read":
        contents = result.get("contents")
        if isinstance(contents, list):
            for item in contents:
                if not isinstance(item, dict):
                    continue
                if isinstance(item.get("text"), str):
                    slots.append(TextSlot(item, "text"))
                else:
                    unscannable.append("resource:blob")
    elif method == "prompts/get":
        messages = result.get("messages")
        if isinstance(messages, list):
            for message in messages:
                if not isinstance(message, dict):
                    continue
                content = message.get("content")
                if isinstance(content, list):
                    for item in content:
                        _content_item_slots(item, slots, unscannable)
                else:
                    _content_item_slots(content, slots, unscannable)
    return slots, unscannable


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
        session: Optional[Session] = None,
        approver=None,
    ):
        self.server_cmd = server_cmd
        self.policy = policy
        self.audit = audit
        self.redactor = redactor
        self.injection_detector = injection_detector
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        # Whatever resolves `ask` verdicts — anything with
        # ask(session, name, arguments, decision) -> Decision. None means
        # there is no human to ask and every ask degrades to deny.
        self.approver = approver
        # The session wraps the policy engine's classifier so tools/list
        # feeds both the inventory and the schema cache in one call.
        self.session = session if session is not None else Session.new(server_cmd, policy.classifier)
        # Maps a request id to what was asked, only for requests the
        # policy allowed through to the real server. Written by the
        # client->server thread, read/popped by the server->client thread.
        self._pending: Dict[object, PendingRequest] = {}
        # Request ids of in-flight `tools/list` calls, so the matching
        # response can be recognized and its schemas registered. A
        # `tools/call` that arrives while one is in flight waits for it
        # (bounded by SCHEMA_WAIT_SECONDS), so a pipelining client can't
        # slip a call past the policy before its schema is known.
        self._pending_tools_list: set = set()
        self._pending_lock = threading.Lock()
        self._pending_changed = threading.Condition(self._pending_lock)

    def _output_inspection_enabled(self) -> bool:
        return (self.redactor is not None and self.redactor.enabled) or (
            self.injection_detector is not None and self.injection_detector.enabled
        )

    def run(self) -> int:
        self.audit.begin_session(self.session)
        if hasattr(self.approver, "start"):
            self.approver.start()
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
            if hasattr(self.approver, "stop"):
                self.approver.stop()
        exit_code = proc.returncode or 0
        self.audit.end_session(self.session, exit_code)
        return exit_code

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

        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params") or {}

        if method == "tools/list" and request_id is not None:
            with self._pending_lock:
                self._pending_tools_list.add(request_id)
            return line

        if method == "tools/call":
            name = params.get("name", "<unknown>")
            arguments = params.get("arguments") or {}
            self._wait_for_pending_tools_list()
        elif method == "resources/read":
            # A resource read is a file or network access under another
            # name; the same rules apply to its uri.
            name = "resources/read"
            arguments = {"uri": params.get("uri")}
        elif method == "prompts/get":
            # Nothing dangerous to gate on the way in; tracked so the
            # returned messages get scanned on the way out.
            self._track(request_id, method, str(params.get("name", "<unknown>")))
            return line
        else:
            return line

        if "max_total_output_bytes" in self.policy.budgets:
            # The total is only exact if every earlier result has been
            # counted; a pipelining client would otherwise get several
            # calls judged against a stale number. Nothing else pays
            # this serialization cost.
            self._wait_for_pending_responses()

        decision = self.policy.evaluate(name, arguments, self.session)
        if decision.action == ASK:
            decision = self._resolve_ask(name, arguments, decision)
        self.audit.record(name, arguments, decision)

        if decision.allowed:
            self.policy.note_allowed(self.session, decision)
            self._track(request_id, method, name if method == "tools/call" else str(arguments["uri"]))
            return line

        self._reject(request_id, decision.reason)
        return None

    def _resolve_ask(self, name: str, arguments: dict, decision: Decision) -> Decision:
        """Turns an `ask` verdict into allow or deny. With no approval
        channel there is nobody to ask, so the answer is deny — and the
        audit entry says that's why, rather than pretending a rule did."""
        if self.approver is None:
            return decision.resolved(False, "no_channel", "ask: no approval channel configured, denied")
        return self.approver.ask(self.session, name, arguments, decision)

    def _inspects_responses(self) -> bool:
        return self._output_inspection_enabled() or self.policy.tracks_output_size

    def _track(self, request_id, method: str, name: str) -> None:
        if request_id is None or not self._inspects_responses():
            return
        with self._pending_lock:
            self._pending[request_id] = PendingRequest(method, name)

    def _wait_for_pending_tools_list(self) -> None:
        self._wait_until(lambda: not self._pending_tools_list, SCHEMA_WAIT_SECONDS)

    def _wait_for_pending_responses(self) -> None:
        self._wait_until(lambda: not self._pending, RESPONSE_WAIT_SECONDS)

    def _wait_until(self, condition, timeout: float) -> None:
        """Blocks the client->server thread until `condition()` holds
        (checked under the pending lock, woken by the server->client
        thread) or `timeout` elapses."""
        deadline = time.monotonic() + timeout
        with self._pending_changed:
            while not condition():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                self._pending_changed.wait(remaining)

    def _reject(self, request_id, reason: str) -> None:
        self.stdout.write(json.dumps(self._error_response(request_id, reason)) + "\n")
        self.stdout.flush()

    @staticmethod
    def _error_response(request_id, reason: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": POLICY_VIOLATION_ERROR_CODE,
                "message": f"AgentGuard: blocked by policy — {reason}",
            },
        }

    def _pump_server_to_client(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:
            self.stdout.write(self._handle_server_line(line))
            self.stdout.flush()

    def _handle_server_line(self, line: str) -> str:
        """Returns the line to forward to the client, blocked/redacted as needed."""
        stripped = line.rstrip("\n")
        if not stripped:
            return line
        try:
            message = json.loads(stripped)
        except json.JSONDecodeError:
            return line

        message_id = message.get("id")
        with self._pending_changed:
            is_tools_list = message_id in self._pending_tools_list
            if is_tools_list:
                result = message.get("result")
                if isinstance(result, dict):
                    self.session.register_tools(result.get("tools"))
                self._pending_tools_list.discard(message_id)
                self._pending_changed.notify_all()
        if is_tools_list:
            return line

        if not self._inspects_responses():
            return line

        with self._pending_changed:
            pending = self._pending.get(message_id)
            if pending is None:
                return line
            # Size first: a result over the per-call budget is withheld
            # before anything bothers to scan it, and only delivered
            # bytes count toward the session total. Counted before the
            # request is dropped from pending, so a call waiting on
            # _wait_for_pending_responses sees the new total.
            over = None
            nbytes = 0
            if "result" in message:
                nbytes = len(json.dumps(message["result"]).encode("utf-8"))
                over = self.policy.output_budget_exceeded(nbytes)
                if over is None:
                    self.session.note_output(nbytes)
            del self._pending[message_id]
            self._pending_changed.notify_all()

        if "result" not in message:
            return line
        if over is not None:
            self.audit.record_budget_block(pending.name, pending.method, "max_output_bytes_per_call", nbytes)
            return json.dumps(self._withheld_response(message, pending.method, over)) + "\n"

        if not self._output_inspection_enabled():
            return line

        # Slots point into the message; work on a copy so a blocked or
        # redacted response is built without mutating what was parsed.
        message = copy.deepcopy(message)
        slots, unscannable = find_content(pending.method, message.get("result"))
        if unscannable:
            self.audit.record_unscannable(pending.name, pending.method, unscannable)

        injection_rules = self._check_injection(slots)
        if injection_rules:
            self.audit.record_injection_block(pending.name, injection_rules, pending.method)
            reason = (
                "this tool output was blocked — suspected prompt injection "
                f"(matched rules: {', '.join(injection_rules)})"
            )
            return json.dumps(self._withheld_response(message, pending.method, reason)) + "\n"

        redaction_rules = self._redact(slots)
        if not redaction_rules:
            return line

        self.audit.record_redaction(pending.name, redaction_rules, pending.method)
        return json.dumps(message) + "\n"

    def _check_injection(self, slots: List[TextSlot]) -> List[str]:
        if self.injection_detector is None or not self.injection_detector.enabled:
            return []
        matched_rules: List[str] = []
        for slot in slots:
            matched_rules.extend(self.injection_detector.scan(slot.text))
        return sorted(set(matched_rules))

    def _withheld_response(self, message: dict, method: str, reason: str) -> dict:
        """The response the agent gets instead of a result AgentGuard
        refused to deliver."""
        if method == "tools/call":
            # A tool-level error, which is how MCP says a tool reports
            # failure; the agent sees a normal result shape with isError.
            return {
                **message,
                "result": {
                    "content": [{"type": "text", "text": f"AgentGuard: {reason}."}],
                    "isError": True,
                },
            }
        # resources/read and prompts/get results have no isError; the
        # only way to withhold them is a JSON-RPC error.
        return self._error_response(message.get("id"), reason)

    def _redact(self, slots: List[TextSlot]) -> List[str]:
        if self.redactor is None or not self.redactor.enabled:
            return []
        all_rule_names: List[str] = []
        for slot in slots:
            redacted_text, rule_names = self.redactor.redact(slot.text)
            if rule_names:
                all_rule_names.extend(rule_names)
                slot.replace(redacted_text)
        return all_rule_names
