"""The approval channel: how an `ask` verdict reaches a human and how
the answer comes back.

The proxy has no terminal of its own — its stdin/stdout *are* the MCP
transport and its stderr belongs to the wrapped server — so the human
has to be somewhere else. The honest minimal design is a Unix domain
socket: the proxy listens on a path from the policy
(`approval_socket:`), and `agentguard approve --socket <path>` in
another terminal connects, sees each pending call, and answers.

Two layers, so the logic is testable without a socket:

- `ApprovalBroker` owns the queue of pending asks and the blocking
  wait. `ask()` is called on the proxy's client->server thread and
  blocks that thread until an approver answers or the timeout expires
  (default 60s -> deny). It knows nothing about sockets; anything that
  can call `resolve(request_id, verdict)` is an approver.
- `ApprovalServer` is the Unix-socket transport over a broker: it
  pushes pending and new asks to every connected approver as
  newline-delimited JSON and feeds their verdicts back. The socket file
  is created mode 0600, so only the user who runs the proxy can answer.

Verdicts: `deny`, `once` (allow this call), `session` (allow this and
anything with the same grant scope for the rest of the session), and
`always` (also remember it across sessions). What `session` and
`always` grant, and where `always` is written, is the broker's
`grant_handler`'s business — see agentguard/grants.py.

Wire protocol (both directions are one JSON object per line):

  server -> approver   {"type": "hello", "session_id": ..., "server_cmd": [...]}
                       {"type": "ask", "request": {id, tool, arguments, category,
                                                   reason, matched_rule,
                                                   argument_categories, scope,
                                                   created_at, expires_at}}
                       {"type": "resolved", "id": ..., "verdict": ...}
  approver -> server   {"type": "verdict", "id": ..., "verdict": "deny|once|session|always"}

On platforms without AF_UNIX (Windows), there is no channel and every
ask degrades to deny; the proxy says so on stderr at startup. Named
pipes are a 0.3 item.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional

from .policy import Decision

VERDICT_DENY = "deny"
VERDICT_ONCE = "once"
VERDICT_SESSION = "session"
VERDICT_ALWAYS = "always"
VERDICTS = (VERDICT_DENY, VERDICT_ONCE, VERDICT_SESSION, VERDICT_ALWAYS)
DEFAULT_TIMEOUT_SECONDS = 60.0

_RESOLUTION_FOR_VERDICT = {
    VERDICT_DENY: (False, "denied_by_operator", "denied by operator"),
    VERDICT_ONCE: (True, "approved_once", "approved by operator (once)"),
    VERDICT_SESSION: (True, "approved_for_session", "approved by operator for this session"),
    VERDICT_ALWAYS: (True, "approved_always", "approved by operator (always)"),
}


def supports_unix_sockets() -> bool:
    return hasattr(socket, "AF_UNIX")


def grant_scope(tool: str, decision: Decision) -> str:
    """What a `session`/`always` answer would grant: this tool, this
    category, and the rule that tripped — or, for an allowlist miss
    with no rule, the specific value that missed (the host, the path).
    Deliberately narrow: approving one host never approves the next."""
    if decision.matched_rule:
        return f"{tool}:{decision.category}:{decision.matched_rule}"
    for arg in decision.arguments:
        if arg.category == decision.category:
            return f"{tool}:{decision.category}:{arg.value}"
    return f"{tool}:{decision.category}:*"


@dataclass
class ApprovalRequest:
    id: str
    session_id: str
    tool: str
    arguments: dict
    category: str
    reason: str
    matched_rule: Optional[str]
    argument_categories: dict
    scope: str
    created_at: float
    expires_at: float
    verdict: Optional[str] = field(default=None)

    def to_wire(self) -> dict:
        data = asdict(self)
        data.pop("verdict")
        return data


class ApprovalBroker:
    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        grant_handler: Optional[Callable[[object, str, ApprovalRequest, Decision], None]] = None,
    ):
        self.timeout = timeout
        # Called with (session, verdict, request, decision) for `session`
        # and `always` verdicts, so grants are recorded somewhere the
        # policy engine will consult next time. See agentguard/grants.py.
        self.grant_handler = grant_handler
        self._lock = threading.Lock()
        self._changed = threading.Condition(self._lock)
        self._pending: Dict[str, ApprovalRequest] = {}
        self._listeners: List[Callable[[str, ApprovalRequest], None]] = []

    # --- approver side ---------------------------------------------------

    def pending(self) -> List[ApprovalRequest]:
        with self._lock:
            return sorted(self._pending.values(), key=lambda r: r.created_at)

    def add_listener(self, callback: Callable[[str, ApprovalRequest], None]) -> None:
        """`callback(event, request)` with event "ask" for a new request
        and "resolved" once it has an answer (from anyone, or timeout)."""
        with self._lock:
            self._listeners.append(callback)

    def remove_listener(self, callback) -> None:
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def resolve(self, request_id: str, verdict: str) -> bool:
        """Answers a pending request. False if it's unknown or already
        answered — an approver racing a timeout just loses quietly."""
        if verdict not in VERDICTS:
            return False
        with self._changed:
            request = self._pending.get(request_id)
            if request is None or request.verdict is not None:
                return False
            request.verdict = verdict
            self._changed.notify_all()
        return True

    # --- proxy side ------------------------------------------------------

    def ask(self, session, tool: str, arguments: dict, decision: Decision) -> Decision:
        """Blocks until an approver answers or the timeout expires."""
        now = time.time()
        request = ApprovalRequest(
            id=uuid.uuid4().hex[:12],
            session_id=session.id,
            tool=tool,
            arguments=arguments,
            category=decision.category,
            reason=decision.reason,
            matched_rule=decision.matched_rule,
            argument_categories=decision.argument_categories,
            scope=grant_scope(tool, decision),
            created_at=now,
            expires_at=now + self.timeout,
        )
        with self._changed:
            self._pending[request.id] = request
            listeners = list(self._listeners)
        self._notify(listeners, "ask", request)

        deadline = time.monotonic() + self.timeout
        with self._changed:
            while request.verdict is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._changed.wait(remaining)
            verdict = request.verdict
            del self._pending[request.id]
            listeners = list(self._listeners)
        if verdict is None:
            request.verdict = "timeout"
            self._notify(listeners, "resolved", request)
            return decision.resolved(False, "timeout", f"ask: no answer from operator within {self.timeout:g}s, denied")
        self._notify(listeners, "resolved", request)

        allowed, resolution, note = _RESOLUTION_FOR_VERDICT[verdict]
        if verdict in (VERDICT_SESSION, VERDICT_ALWAYS) and self.grant_handler is not None:
            self.grant_handler(session, verdict, request, decision)
        return decision.resolved(allowed, resolution, f"ask: {note}")

    @staticmethod
    def _notify(listeners, event: str, request: ApprovalRequest) -> None:
        for callback in listeners:
            try:
                callback(event, request)
            except Exception:  # a broken approver connection must not take the proxy down
                pass


class ApprovalServer:
    """Unix-socket transport over an ApprovalBroker. Also quacks like an
    approver for the proxy (`ask`), and has start()/stop() so the proxy
    can bracket its lifetime."""

    def __init__(self, broker: ApprovalBroker, path: str, session=None):
        if not supports_unix_sockets():
            raise OSError("Unix domain sockets are not available on this platform")
        self.broker = broker
        self.path = path
        self.session = session
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()
        self._clients: List[socket.socket] = []
        self._clients_lock = threading.Lock()

    def ask(self, session, tool: str, arguments: dict, decision: Decision) -> Decision:
        return self.broker.ask(session, tool, arguments, decision)

    def start(self) -> None:
        if os.path.exists(self.path):
            # A stale socket from a crashed proxy. Only remove it if it
            # is a socket — never an arbitrary file at that path.
            if stat.S_ISSOCK(os.stat(self.path).st_mode):
                os.unlink(self.path)
            else:
                raise OSError(f"approval_socket path exists and is not a socket: {self.path}")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Restrict before bind would be ideal; umask does that, and the
        # chmod right after bind closes the window for other users on
        # the same box.
        old_umask = os.umask(0o177)
        try:
            server.bind(self.path)
        finally:
            os.umask(old_umask)
        os.chmod(self.path, 0o600)
        server.listen(4)
        server.settimeout(0.5)
        self._server = server
        self._thread = threading.Thread(target=self._accept_loop, name="agentguard-approval", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stopping.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
        with self._clients_lock:
            for client in self._clients:
                try:
                    client.close()
                except OSError:
                    pass
            self._clients.clear()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if os.path.exists(self.path):
            try:
                os.unlink(self.path)
            except OSError:
                pass

    def _accept_loop(self) -> None:
        assert self._server is not None
        while not self._stopping.is_set():
            try:
                client, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._clients_lock:
                self._clients.append(client)
            threading.Thread(target=self._serve_client, args=(client,), daemon=True).start()

    def _serve_client(self, client: socket.socket) -> None:
        send_lock = threading.Lock()

        def send(message: dict) -> None:
            data = (json.dumps(message) + "\n").encode("utf-8")
            with send_lock:
                client.sendall(data)

        def on_event(event: str, request: ApprovalRequest) -> None:
            if event == "ask":
                send({"type": "ask", "request": request.to_wire()})
            else:
                send({"type": "resolved", "id": request.id, "verdict": request.verdict})

        try:
            hello = {"type": "hello"}
            if self.session is not None:
                hello.update(session_id=self.session.id, server_cmd=self.session.server_cmd)
            send(hello)
            # Register before replaying pending so nothing falls between.
            self.broker.add_listener(on_event)
            for request in self.broker.pending():
                send({"type": "ask", "request": request.to_wire()})
            buffer = b""
            while not self._stopping.is_set():
                chunk = client.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    self._handle_line(line, send)
        except OSError:
            pass
        finally:
            self.broker.remove_listener(on_event)
            with self._clients_lock:
                if client in self._clients:
                    self._clients.remove(client)
            try:
                client.close()
            except OSError:
                pass

    def _handle_line(self, line: bytes, send) -> None:
        try:
            message = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            send({"type": "error", "message": "not valid JSON"})
            return
        if not isinstance(message, dict) or message.get("type") != "verdict":
            send({"type": "error", "message": "expected {type: verdict, id, verdict}"})
            return
        ok = self.broker.resolve(str(message.get("id")), str(message.get("verdict")))
        send({"type": "ack", "id": message.get("id"), "accepted": ok})


class ApprovalClient:
    """The `agentguard approve` side: connects to the proxy's socket,
    shows each ask, takes an answer from `prompt`, sends it back.
    `prompt(request) -> verdict` is injectable so it can be driven by
    tests; the CLI wires it to the terminal."""

    def __init__(self, path: str, prompt: Callable[[dict], str], output=None):
        if not supports_unix_sockets():
            raise OSError("Unix domain sockets are not available on this platform")
        self.path = path
        self.prompt = prompt
        self.output = output
        self._sock: Optional[socket.socket] = None
        self._queue: List[dict] = []
        self._resolved: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._wakeup = threading.Condition(self._lock)
        self._closed = False

    def _say(self, text: str) -> None:
        if self.output is not None:
            self.output.write(text + "\n")
            self.output.flush()

    def run(self, max_answers: Optional[int] = None) -> int:
        """Serves asks until the proxy goes away (or `max_answers` have
        been given, for tests). Returns the number of verdicts sent."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.path)
        self._sock = sock
        reader = threading.Thread(target=self._read_loop, daemon=True)
        reader.start()
        answered = 0
        while True:
            with self._wakeup:
                while not self._queue and not self._closed:
                    self._wakeup.wait(0.5)
                if not self._queue and self._closed:
                    break
                request = self._queue.pop(0)
                already = self._resolved.pop(request["id"], None)
            if already is not None:
                self._say(f"(request {request['id']} already resolved: {already})")
                continue
            verdict = self.prompt(request)
            if verdict not in VERDICTS:
                self._say(f"unknown verdict {verdict!r}; treating as deny")
                verdict = VERDICT_DENY
            sock.sendall((json.dumps({"type": "verdict", "id": request["id"], "verdict": verdict}) + "\n").encode("utf-8"))
            answered += 1
            if max_answers is not None and answered >= max_answers:
                break
        sock.close()
        return answered

    def _read_loop(self) -> None:
        assert self._sock is not None
        buffer = b""
        try:
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    self._handle(json.loads(line.decode("utf-8")))
        except (OSError, ValueError):
            pass
        finally:
            with self._wakeup:
                self._closed = True
                self._wakeup.notify_all()

    def _handle(self, message: dict) -> None:
        kind = message.get("type")
        if kind == "hello":
            cmd = " ".join(message.get("server_cmd") or []) or "?"
            self._say(f"connected: session {str(message.get('session_id', '?'))[:12]}  server: {cmd}")
            self._say("waiting for the proxy to ask something...")
        elif kind == "ask":
            with self._wakeup:
                self._queue.append(message["request"])
                self._wakeup.notify_all()
        elif kind == "resolved":
            with self._wakeup:
                self._resolved[message["id"]] = str(message.get("verdict"))
        elif kind == "error":
            self._say(f"proxy: {message.get('message')}")


def format_request(request: dict) -> str:
    """The human-facing rendering of one ask."""
    lines = [
        "",
        f"=== approval needed  [{request['id']}]  expires in {max(0, int(request['expires_at'] - time.time()))}s",
        f"  tool:      {request['tool']}",
        f"  category:  {request['category']}",
    ]
    for key, value in (request.get("arguments") or {}).items():
        category = (request.get("argument_categories") or {}).get(key, "")
        lines.append(f"  {key + ':':<10} {json.dumps(value)}" + (f"   [{category}]" if category else ""))
    if request.get("matched_rule"):
        lines.append(f"  rule:      {request['matched_rule']}")
    lines.append(f"  reason:    {request['reason']}")
    lines.append(f"  'session'/'always' would grant: {request['scope']}")
    return "\n".join(lines)


def terminal_prompt(request: dict, input_fn=input, output=None) -> str:
    text = format_request(request)
    if output is not None:
        output.write(text + "\n")
        output.flush()
    else:
        print(text)
    aliases = {"d": VERDICT_DENY, "o": VERDICT_ONCE, "s": VERDICT_SESSION, "a": VERDICT_ALWAYS}
    while True:
        try:
            answer = input_fn("  [d]eny / [o]nce / [s]ession / [a]lways > ").strip().lower()
        except EOFError:
            return VERDICT_DENY
        if answer in VERDICTS:
            return answer
        if answer in aliases:
            return aliases[answer]
