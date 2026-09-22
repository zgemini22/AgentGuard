"""Append-only, hash-chained JSONL audit log for AgentGuard.

Every entry carries `prev_hash` (the previous entry's hash) and `hash`
(sha256 of the entry's own fields plus prev_hash). That makes the log a
hash chain: deleting, reordering, or editing any entry breaks the link
to whatever comes after it, and `verify_audit_log()` can detect that
offline, without needing anything beyond the file itself — no separate
signing key, no external ledger. It's the same construction as a
blockchain's block-linking, minus the consensus problem, because there's
only ever one writer (this process) and the point isn't to agree on a
canonical history, just to make silent tampering with an existing one
detectable.

What the chain alone does *not* protect against: an attacker who can
rewrite the whole file is free to recompute every hash from scratch
and produce a self-consistent forged chain. Tamper-evidence here means
"you can't sneak in a single edit without invalidating everything
after it," not "the file is cryptographically bound to anything
outside itself."

Anchoring is the primitive that closes that gap — partially, and only
with the user's help. An anchor is `(entry count, head hash)` copied
out of the log at some moment (`agentguard anchor`, or the periodic
`anchor_file`) and kept where the log's attacker can't reach: a
different host, a chat message to yourself, an append-only store.
`verify-audit --anchor` then checks the chain still passes through
it. A forged chain can't match an anchor it never saw. What this code
cannot do is put the anchor out of reach for you; an anchor file on
the same disk as the log is a convenience, not a guarantee.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .policy import Decision

GENESIS_HASH = "0" * 64


def compute_entry_hash(entry: dict) -> str:
    """Hashes every field of `entry` except `hash` itself, so the hash
    commits to prev_hash and all the entry's own content. sort_keys makes
    this independent of dict insertion order."""
    payload = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class VerificationResult:
    valid: bool
    entry_count: int
    error: Optional[str] = None
    anchors_checked: int = 0
    head_hash: str = GENESIS_HASH


@dataclass(frozen=True)
class Anchor:
    """A (count, head-hash) pair copied out of the log at some point
    and kept somewhere the log's attacker can't reach. `count` is
    optional: a bare hash just has to appear somewhere in the chain."""
    hash: str
    count: Optional[int] = None

    @classmethod
    def parse(cls, text: str) -> "Anchor":
        """Accepts `<hash>`, `<count> <hash>`, or `<ts> <count> <hash>`
        (an anchor-file line)."""
        parts = text.split()
        if not parts:
            raise ValueError("empty anchor")
        digest = parts[-1].lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"not a sha256 hex digest: {parts[-1]!r}")
        count = None
        if len(parts) >= 2:
            try:
                count = int(parts[-2])
            except ValueError:
                raise ValueError(f"not an entry count: {parts[-2]!r}")
            if count < 1:
                raise ValueError(f"entry count must be positive: {count}")
        return cls(digest, count)


def read_anchor_file(path: str) -> List[Anchor]:
    anchors = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                anchors.append(Anchor.parse(line))
    return anchors


def verify_audit_log(path: str, anchors: Sequence[Anchor] = ()) -> VerificationResult:
    """Walks the whole log and recomputes the chain from GENESIS_HASH,
    checking prev_hash linkage and each entry's own hash. Stops at the
    first problem it finds — a hash chain is only as good as its weakest
    link, so there's no value in cataloguing every entry after a break.

    With `anchors`, also checks that the chain passes through each one:
    entry #count must have exactly that hash (or, for a bare hash, some
    entry must). That's what catches a log rewritten from scratch with
    a fresh self-consistent chain — the one thing the chain alone
    can't — provided the anchor was kept out of the attacker's reach."""
    p = Path(path)
    hashes: List[str] = []
    expected_prev = GENESIS_HASH
    count = 0
    if p.exists():
        with p.open("r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return VerificationResult(False, count, f"line {line_no}: not valid JSON")

                if "hash" not in entry or "prev_hash" not in entry:
                    return VerificationResult(False, count, f"line {line_no}: missing hash/prev_hash field")
                if entry["prev_hash"] != expected_prev:
                    return VerificationResult(
                        False, count,
                        f"line {line_no}: prev_hash does not match the preceding entry's hash — chain broken",
                    )
                if compute_entry_hash(entry) != entry["hash"]:
                    return VerificationResult(False, count, f"line {line_no}: hash does not match entry contents — entry was modified")

                expected_prev = entry["hash"]
                count += 1
                hashes.append(entry["hash"])

    for anchor in anchors:
        if anchor.count is not None:
            if anchor.count > count:
                return VerificationResult(
                    False, count,
                    f"anchor says entry #{anchor.count} exists but the log has only {count} — log truncated?",
                    head_hash=expected_prev,
                )
            if hashes[anchor.count - 1] != anchor.hash:
                return VerificationResult(
                    False, count,
                    f"anchor mismatch at entry #{anchor.count}: log has {hashes[anchor.count - 1][:16]}..., "
                    f"anchor says {anchor.hash[:16]}... — log rewritten since the anchor was taken",
                    head_hash=expected_prev,
                )
        elif anchor.hash not in hashes:
            return VerificationResult(
                False, count,
                f"anchor hash {anchor.hash[:16]}... appears nowhere in the chain — log rewritten or truncated "
                "since the anchor was taken",
                head_hash=expected_prev,
            )

    return VerificationResult(True, count, anchors_checked=len(anchors), head_hash=expected_prev)


class AuditLog:
    def __init__(
        self,
        path: str = "agentguard_audit.log",
        anchor_file: Optional[str] = None,
        anchor_every: int = 100,
    ):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._last_hash, self._count = self._load_tail()
        # Stamped onto every entry once a session begins, so entries
        # from different runs sharing one log file can be told apart.
        self.session_id: Optional[str] = None
        # Optional: every `anchor_every` entries, append "<ts> <count>
        # <head-hash>" to `anchor_file`. Only worth anything if that
        # file is somewhere the log's attacker can't also edit — a
        # different host, an append-only store — which is the user's
        # job, not this code's. See `agentguard anchor`.
        self.anchor_file = anchor_file
        self.anchor_every = anchor_every

    def head(self) -> Tuple[int, str]:
        """(entries so far, hash of the last one) — what an anchor is."""
        with self._lock:
            return self._count, self._last_hash

    def write_anchor(self) -> str:
        """Appends the current head to the anchor file now, regardless
        of anchor_every. Returns the line written."""
        count, digest = self.head()
        line = f"{time.time():.3f} {count} {digest}"
        assert self.anchor_file is not None
        with open(self.anchor_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        return line

    def begin_session(self, session) -> dict:
        """Stamps every subsequent entry with the session id and writes
        the `session_start` entry: what was wrapped, under which policy
        (by content hash, so a later edit to the file is detectable),
        with which AgentGuard."""
        self.session_id = session.id
        entry = {"ts": session.started_at, "event": "session_start", **session.start_metadata()}
        return self._append(entry)

    def end_session(self, session, exit_code: int) -> dict:
        entry = {"ts": time.time(), "event": "session_end", **session.end_metadata(exit_code)}
        return self._append(entry)

    def _load_tail(self) -> Tuple[str, int]:
        if not self.path.exists():
            return GENESIS_HASH, 0
        last_hash = GENESIS_HASH
        count = 0
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                last_hash = entry.get("hash", last_hash)
                count += 1
        return last_hash, count

    def record(self, tool_name: str, arguments: dict, decision: Decision) -> dict:
        entry = {
            "ts": time.time(),
            "event": "policy_decision",
            "tool": tool_name,
            "arguments": arguments,
            # Which category each string argument was classified into
            # ("unclassified" if none) — i.e. what the policy actually
            # looked at, not just what it concluded.
            "argument_categories": decision.argument_categories,
            "allowed": decision.allowed,
            # `action` is the effective verdict; `ask_resolution` is set
            # when the policy said "ask" and records how that was
            # settled (approved/denied by the operator, timed out, no
            # channel configured, ...).
            "action": decision.action,
            "ask_resolution": decision.ask_resolution,
            "category": decision.category,
            "reason": decision.reason,
            "matched_rule": decision.matched_rule,
        }
        return self._append(entry)

    def record_redaction(self, tool_name: str, rule_names: List[str], method: str = "tools/call") -> dict:
        """Logs that secrets were masked in a tool's output. Never logs the
        secret values themselves — only which rules matched and how many
        times, so the audit log itself can't leak what it caught."""
        entry = {
            "ts": time.time(),
            "event": "redaction",
            "method": method,
            "tool": tool_name,
            "rules_matched": rule_names,
            "count": len(rule_names),
        }
        return self._append(entry)

    def record_injection_block(self, tool_name: str, rule_names: List[str], method: str = "tools/call") -> dict:
        """Logs that a tool's entire output was blocked as a suspected
        prompt injection. Rule names only, same reasoning as redaction —
        the log records what was caught, not the payload that triggered it."""
        entry = {
            "ts": time.time(),
            "event": "injection_blocked",
            "method": method,
            "tool": tool_name,
            "rules_matched": rule_names,
        }
        return self._append(entry)

    def record_budget_block(self, tool_name: str, method: str, budget: str, nbytes: int) -> dict:
        """Logs that a result was withheld because it broke a per-call
        output budget. (Calls denied for an exhausted budget are ordinary
        policy_decision entries with category "budget".)"""
        entry = {
            "ts": time.time(),
            "event": "budget_block",
            "method": method,
            "tool": tool_name,
            "budget": budget,
            "bytes": nbytes,
        }
        return self._append(entry)

    def record_grant(self, tool_name: str, scope: str, duration: str,
                     grants_file: Optional[str], note: Optional[str] = None) -> dict:
        """Logs that an operator answered `session` or `always` to an
        ask, so `report` can show "operator approved X at T"."""
        entry = {
            "ts": time.time(),
            "event": "grant",
            "tool": tool_name,
            "scope": scope,
            "duration": duration,
            "grants_file": grants_file,
            "note": note,
        }
        return self._append(entry)

    def record_unscannable(self, tool_name: str, method: str, kinds: List[str]) -> dict:
        """Logs that a response carried content the output scanners could
        not read as text (images, audio, binary blobs). It was passed
        through; this entry is so the log doesn't imply it was checked."""
        entry = {
            "ts": time.time(),
            "event": "unscannable_content",
            "method": method,
            "tool": tool_name,
            "kinds": kinds,
        }
        return self._append(entry)

    def _append(self, entry: dict) -> dict:
        # A single lock around read-last-hash + compute + write keeps the
        # chain valid under concurrent callers (the proxy's client->server
        # and server->client threads can both be recording at once).
        with self._lock:
            if self.session_id is not None:
                entry["session_id"] = self.session_id
            entry["prev_hash"] = self._last_hash
            entry["hash"] = compute_entry_hash(entry)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
            self._last_hash = entry["hash"]
            self._count += 1
            if self.anchor_file and self._count % self.anchor_every == 0:
                with open(self.anchor_file, "a", encoding="utf-8") as f:
                    f.write(f"{time.time():.3f} {self._count} {self._last_hash}\n")
        return entry
