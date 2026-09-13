"""One proxy run, as an object.

v1 judged every call alone: the proxy had no memory of the previous
call, no idea which server it was wrapping, and no way to say "this
call and that call happened in the same run." The audit log inherited
that — entries from every run of every server landed in one file with
nothing to group them by.

A `Session` is the unit that fixes both. It's created when the proxy
starts and lives until it exits, and it carries:

- an id that every audit entry from this run is stamped with, plus a
  `session_start` / `session_end` pair that brackets them in the log
  (the wrapped command, the policy file's hash, when it ran);
- the tool inventory from `tools/list`, which the argument classifier
  reads schemas from;
- the cross-call state later commits build on — budgets, sequence
  rules, and operator grants all live here, because they're facts
  about *this run*, not about the policy.

It deliberately holds no policy of its own. Rules come from the
PolicyEngine; the session is what the engine consults to answer "given
what's happened so far, is this call still allowed?"
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import platform
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from . import __version__
from .classify import FILE_ACCESS, NETWORK, ArgumentClassifier


def file_sha256(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


@dataclass
class Session:
    id: str
    started_at: float
    server_cmd: List[str]
    classifier: ArgumentClassifier
    policy_path: Optional[str] = None
    policy_sha256: Optional[str] = None
    # name -> the tool entry exactly as the server declared it.
    tools: Dict[str, dict] = field(default_factory=dict)
    # Budget counters: allowed calls per category, and output bytes the
    # agent has actually been handed. Only calls that were forwarded
    # count — a denied call consumed nothing.
    call_counts: Dict[str, int] = field(default_factory=dict)
    output_bytes: int = 0
    # Sequence-rule state, also fed only by forwarded calls:
    #   sensitive_reads — file paths matched a `sensitive_patterns` glob
    #   directories     — parent directory of every file path touched
    #   fetched         — any network call has gone through
    # These three facts are the whole cross-call memory. They exist to
    # answer three specific questions (see PolicyEngine._check_sequences),
    # not to be a general event log — the audit log is that.
    sensitive_reads: List[str] = field(default_factory=list)
    directories: Set[str] = field(default_factory=set)
    fetched: bool = False
    # Scopes an operator answered `session` (or `always` with no
    # grants_file) to. Consulted by the policy engine before an ask is
    # raised again. See agentguard/grants.py.
    grants: Set[str] = field(default_factory=set)

    def note_allowed_call(self, decision, sensitive_patterns: Sequence[str] = ()) -> None:
        """Called when a call is forwarded. One budget increment per
        category the call touched, however many arguments fell in it —
        a `read_many(paths=[...])` is one file call — plus the sequence
        facts above."""
        for category in sorted({a.category for a in decision.arguments if a.category}):
            self.call_counts[category] = self.call_counts.get(category, 0) + 1
        for arg in decision.arguments:
            if arg.category == FILE_ACCESS:
                self.directories.add(parent_directory(arg.value))
                if any(fnmatch.fnmatch(os.path.expanduser(arg.value), os.path.expanduser(p))
                       for p in sensitive_patterns):
                    self.sensitive_reads.append(arg.value)
            elif arg.category == NETWORK:
                self.fetched = True

    def note_output(self, nbytes: int) -> None:
        self.output_bytes += nbytes

    @classmethod
    def new(
        cls,
        server_cmd: List[str],
        classifier: Optional[ArgumentClassifier] = None,
        policy_path: Optional[str] = None,
    ) -> "Session":
        return cls(
            id=uuid.uuid4().hex,
            started_at=time.time(),
            server_cmd=list(server_cmd),
            classifier=classifier if classifier is not None else ArgumentClassifier(),
            policy_path=policy_path,
            policy_sha256=file_sha256(policy_path) if policy_path else None,
        )

    def register_tools(self, tools) -> int:
        """Records a `tools/list` result: keeps the inventory and feeds
        the classifier. Returns how many tools were registered."""
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                    self.tools[tool["name"]] = tool
        return self.classifier.register_tools(tools)

    def start_metadata(self) -> dict:
        """What the `session_start` audit entry records."""
        return {
            "server_cmd": self.server_cmd,
            "policy_path": self.policy_path,
            "policy_sha256": self.policy_sha256,
            "agentguard_version": __version__,
            "python": platform.python_version(),
            "platform": platform.system().lower(),
        }

    def end_metadata(self, exit_code: int) -> dict:
        """What the `session_end` audit entry records."""
        return {
            "exit_code": exit_code,
            "duration_seconds": round(time.time() - self.started_at, 3),
            "tools_seen": sorted(self.tools),
        }


def parent_directory(path: str) -> str:
    """The directory a file path lives in, normalized so `/a/./b/x` and
    `/a/b/x` count as the same one. A bare filename lives in `.`."""
    normalized = os.path.normpath(os.path.expanduser(path))
    return os.path.dirname(normalized) or "."
