"""Path canonicalization for the file_access rules.

The rules are globs, and a glob only means what it says if it is
matched against the file the server will actually open. The raw
argument string is not that: a relative name is resolved against the
server's working directory, `..` walks out of the directory it names,
a symlink points somewhere else, and on Windows `x.env.` and
`x.env::$DATA` open `x.env`. Matching the raw string let every one of
those through a deny list (the shipped `**/.env` never matched a bare
`.env`) or out of an allowlist (`/project/../etc/passwd` matched
`/project/**`).

So a value is turned into the forms the OS could open before any
pattern sees it:

- `~` expanded, Win32 name aliasing stripped (on Windows only);
- made absolute against `base_dir` — the directory the wrapped server
  runs in, which is the proxy's own working directory, since the proxy
  starts it without changing directory;
- `..` and `.` collapsed (`os.path.normpath`);
- and, as a second form, symlinks resolved (`os.path.realpath`) where
  the path exists.

Patterns get the same treatment where it applies: `~` is expanded, and a
relative pattern that doesn't start with a wildcard is anchored at
`base_dir`. On case-insensitive platforms (Windows, macOS) matching
ignores case, so `.ENV` is `.env`.

A deny pattern denies if it matches *any* form (the raw expanded value
included); an allow pattern only admits a value if *every* canonical
form is on the allowlist. Both directions err towards deny.
"""

from __future__ import annotations

import fnmatch
import ntpath
import os
import re
import sys
from typing import Iterable, List, Optional

CASE_INSENSITIVE = sys.platform in ("win32", "darwin")
_WINDOWS = os.name == "nt"
_SEP_SPLIT = re.compile(r"([\\/])")


def _strip_win32_aliases(path: str) -> str:
    """Win32 drops trailing dots and spaces from each path component, and
    reads `name:stream` as the file `name`. Undo both so `.env.`,
    `.env ` and `.env::$DATA` are all judged as `.env`."""
    drive, rest = ntpath.splitdrive(path)
    out = []
    for part in _SEP_SPLIT.split(rest):
        if part in ("\\", "/") or part in ("", ".", ".."):
            out.append(part)
            continue
        if ":" in part:
            part = part.split(":", 1)[0]
        out.append(part.rstrip(" .") or part)
    return drive + "".join(out)


def _comparable(text: str) -> str:
    if _WINDOWS:
        text = text.replace("\\", "/")
    return text.lower() if CASE_INSENSITIVE else text


def canonical_forms(value: str, base_dir: str) -> List[str]:
    """The absolute, normalized path the value names, then (if different)
    the same path with symlinks resolved. Never empty."""
    expanded = os.path.expanduser(value)
    if _WINDOWS:
        expanded = _strip_win32_aliases(expanded)
    if not os.path.isabs(expanded):
        expanded = os.path.join(base_dir, expanded)
    normalized = os.path.normpath(expanded)
    forms = [normalized]
    try:
        real = os.path.realpath(normalized)
    except (OSError, ValueError):
        real = normalized
    if real != normalized:
        forms.append(real)
    return forms


def canonical_path(value: str, base_dir: str) -> str:
    return canonical_forms(value, base_dir)[0]


def canonical_pattern(pattern: str, base_dir: str) -> str:
    """`~` expanded; a relative pattern anchored at base_dir unless it
    starts with a wildcard (`**/.env`, `*.pem` apply anywhere)."""
    expanded = os.path.expanduser(pattern)
    if not os.path.isabs(expanded) and not expanded.startswith(("*", "?", "[")):
        expanded = os.path.join(base_dir, expanded)
    return expanded


def _glob_match(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(_comparable(path), _comparable(pattern))


class PathMatcher:
    """Matches one value against file_access globs, per the rules above."""

    def __init__(self, value: str, base_dir: str):
        self.value = value
        self.base_dir = base_dir
        self.forms = canonical_forms(value, base_dir)
        raw = os.path.expanduser(value)
        # The raw string is kept as one more thing a *deny* pattern may
        # match; it never helps a value onto an allowlist.
        self._deny_forms = self.forms + ([raw] if raw not in self.forms else [])

    @property
    def subject(self) -> str:
        """What the value was judged as: its canonical absolute path."""
        return self.forms[0]

    def denied_by(self, pattern: str) -> bool:
        pat = canonical_pattern(pattern, self.base_dir)
        raw_pat = os.path.expanduser(pattern)
        return any(_glob_match(f, pat) or _glob_match(f, raw_pat) for f in self._deny_forms)

    def allowed_by_any(self, patterns: Iterable[str]) -> bool:
        pats = [canonical_pattern(p, self.base_dir) for p in patterns]
        return all(any(_glob_match(f, p) for p in pats) for f in self.forms)


def matches_any(value: str, patterns: Iterable[str], base_dir: Optional[str] = None) -> bool:
    """Deny-style match: does any pattern match any form of the value?"""
    matcher = PathMatcher(value, base_dir if base_dir is not None else os.getcwd())
    return any(matcher.denied_by(p) for p in patterns)
