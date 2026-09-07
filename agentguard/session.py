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

import hashlib
import platform
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import __version__
from .classify import ArgumentClassifier


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

    def note_allowed_call(self, decision) -> None:
        """Called by the proxy when a call is forwarded. One increment
        per category the call touched, however many arguments fell in
        it — a `read_many(paths=[...])` is one file call."""
        for category in sorted({a.category for a in decision.arguments if a.category}):
            self.call_counts[category] = self.call_counts.get(category, 0) + 1

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
