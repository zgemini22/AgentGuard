"""Operator grants: what "allow for session" and "always allow" mean,
and where "always" is written.

A grant is a *scope* string — `tool:category:rule-or-value`, computed
by `policy.grant_scope()` from the decision that prompted the ask — and
a scope is deliberately narrow: approving `fetch` for one host never
approves it for the next, and approving `read_file` past the `**/.env`
pattern says nothing about `**/*.pem`.

Session grants live on the Session and die with it. Persistent grants
live in a separate `grants.yaml` overlay (`grants_file:` in the
policy), loaded after the base policy, and appended to when an
operator answers `always`. They do **not** go into the policy file:
THREAT_MODEL.md makes the policy file the trust root, and a tool that
edits its own trust root at runtime is a footgun — one bad "always"
under time pressure and the base policy is quietly weaker forever.
The overlay is a file you can review, diff, and delete, and
`check-policy` shows its contents separately from the policy's.

Either kind of grant only ever converts an `ask` into an allow. A hard
deny never reached an operator, so nothing can have been granted
against it.
"""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass
from typing import List, Optional, Set

import yaml

from .validate import PolicyError


@dataclass
class Grant:
    scope: str
    tool: str
    granted_at: str       # ISO-8601, local time, for humans reading the file
    session_id: str

    @classmethod
    def now(cls, scope: str, tool: str, session_id: str) -> "Grant":
        return cls(scope, tool, time.strftime("%Y-%m-%dT%H:%M:%S"), session_id)


_HEADER = (
    "# Persistent operator grants, written by `agentguard approve` when an\n"
    "# operator answers `always`. Loaded after the policy as an overlay;\n"
    "# each scope turns a matching `ask` verdict into allow. Review and\n"
    "# prune freely — deleting a line revokes it at the next start.\n"
)


class GrantStore:
    """The grants.yaml overlay. `path=None` means persistence is not
    configured: `always` then behaves as `session`, and the audit entry
    says so."""

    def __init__(self, path: Optional[str]):
        self.path = path
        self.grants: List[Grant] = self._load() if path else []

    @property
    def persistent(self) -> bool:
        return self.path is not None

    def scopes(self) -> Set[str]:
        return {g.scope for g in self.grants}

    def _load(self) -> List[Grant]:
        assert self.path is not None
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        errors = validate_grants(raw)
        if errors:
            raise PolicyError([f"grants file {self.path}: {e}" for e in errors])
        return [
            Grant(str(g["scope"]), str(g.get("tool", "")), str(g.get("granted_at", "")), str(g.get("session_id", "")))
            for g in (raw or {}).get("grants") or []
        ]

    def add(self, grant: Grant) -> None:
        """Records the grant and rewrites the overlay. The whole file is
        rewritten (not appended) so it always parses as one document."""
        self.grants.append(grant)
        if self.path is None:
            return
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(_HEADER)
            yaml.safe_dump({"grants": [asdict(g) for g in self.grants]}, f, sort_keys=False)
        os.replace(tmp, self.path)


def validate_grants(raw) -> List[str]:
    """A grants file is `{grants: [{scope, tool?, granted_at?, session_id?}]}`.
    Strict for the same reason the policy is: a malformed overlay must
    not silently load as "no grants"."""
    if raw is None:
        return []
    if not isinstance(raw, dict):
        return ["expected a mapping with a `grants` list"]
    errors = []
    for key in raw:
        if key != "grants":
            errors.append(f"unknown key {key!r}; only `grants` is allowed")
    grants = raw.get("grants")
    if grants is None:
        return errors
    if not isinstance(grants, list):
        return errors + ["`grants` must be a list"]
    for i, g in enumerate(grants):
        if not isinstance(g, dict):
            errors.append(f"grants[{i}]: expected a mapping")
            continue
        if not isinstance(g.get("scope"), str) or not g["scope"]:
            errors.append(f"grants[{i}]: missing or empty `scope`")
        for key in g:
            if key not in ("scope", "tool", "granted_at", "session_id"):
                errors.append(f"grants[{i}]: unknown key {key!r}")
    return errors
