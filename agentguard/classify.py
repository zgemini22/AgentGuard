"""Argument classification: decides which policy category (file_access,
command_exec, network) a tool-call argument belongs to.

v1 classified purely by argument *key name* — `path` is a file, `url`
is a network target, `command` is a shell command. That works for
well-behaved servers and is bypassable by any server (or any attacker
who controls a server's schema) that just calls the argument
`file_location` or `target_host` instead: the argument falls through
unclassified and the policy never looks at it.

This module closes most of that gap by also using the tool's own
declared `inputSchema` from the `tools/list` response, which the proxy
sees before any call is made. The classification order is:

1. an explicit JSON-Schema `format` (`uri`, `url`, `hostname`, `path`,
   ...) — the server said what it is, so that wins;
2. an exact well-known key name (`path`, `url`, `command`, ...) — the
   v1 behavior, kept as-is;
3. a token of the argument name (`file_location`, `targetHost`) —
   needs no schema either, it's just a looser version of step 2;
4. keywords in the property's `description` ("path to the file to
   read", "URL to fetch", "shell command to run").

For a tool with no known schema, only steps 2–3 apply. Anything that
matches nothing is reported as unclassified so the policy can choose
to fail closed (see `unclassified_arguments` in policy.py).

The policy does not stop at the first step that matches. It uses
`classify_property_all`: every category that steps 1–3 assign (every
name token, not just the first — `script_path` is both a script and a
path), with step 4 only as a fallback when 1–3 find nothing. The
argument is judged under each of those categories and the most
restrictive result wins. Separately, a value that is itself an
http(s)/ws(s)/ftp(s) URL is judged as network, and a `file://` URI as a
file path, whatever the argument is called.

Schema-derived classification is a heuristic on text a server chose,
not a guarantee. It raises the bar from "rename one argument" to "lie
convincingly in your own schema," which is a different kind of attacker.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

FILE_ACCESS = "file_access"
COMMAND_EXEC = "command_exec"
NETWORK = "network"
CATEGORIES = (FILE_ACCESS, COMMAND_EXEC, NETWORK)

# Argument key names (case-insensitive) treated as carrying a value of
# the given category. MCP servers don't share a schema, so we match on
# common conventions rather than a fixed tool allowlist.
PATH_ARG_KEYS = {
    "path", "file_path", "filepath", "file", "filename",
    "target", "dest", "destination", "source", "src",
    "directory", "dir", "folder", "cwd",
}
COMMAND_ARG_KEYS = {"command", "cmd", "script", "shell"}
URL_ARG_KEYS = {"url", "uri", "endpoint", "host", "domain", "hostname"}

# JSON-Schema `format` values. `uri`/`uri-reference`/`hostname` are
# standard; the rest are conventions some servers use.
FORMAT_CATEGORIES = {
    "uri": NETWORK,
    "uri-reference": NETWORK,
    "iri": NETWORK,
    "iri-reference": NETWORK,
    "url": NETWORK,
    "hostname": NETWORK,
    "idn-hostname": NETWORK,
    "ipv4": NETWORK,
    "ipv6": NETWORK,
    "path": FILE_ACCESS,
    "file-path": FILE_ACCESS,
    "filepath": FILE_ACCESS,
    "file": FILE_ACCESS,
    "directory": FILE_ACCESS,
    "command": COMMAND_EXEC,
    "shell": COMMAND_EXEC,
}

# Tokens of an argument *name*, after splitting on `_`, `-`, and
# camelCase boundaries, so `file_location` and `targetHost` classify
# but `profile` (merely contains "file") doesn't.
NAME_TOKEN_CATEGORIES = {
    "path": FILE_ACCESS, "paths": FILE_ACCESS,
    "file": FILE_ACCESS, "files": FILE_ACCESS, "filename": FILE_ACCESS,
    "dir": FILE_ACCESS, "directory": FILE_ACCESS, "folder": FILE_ACCESS,
    "url": NETWORK, "urls": NETWORK, "uri": NETWORK, "uris": NETWORK,
    "host": NETWORK, "hostname": NETWORK, "endpoint": NETWORK,
    "domain": NETWORK, "address": NETWORK,
    "command": COMMAND_EXEC, "cmd": COMMAND_EXEC, "commands": COMMAND_EXEC,
    "shell": COMMAND_EXEC, "script": COMMAND_EXEC, "exec": COMMAND_EXEC,
}

# Description keywords: phrases that say what the argument *is*, matched
# as whole words, case-insensitive. Deliberately no bare `file`/`path`
# tier — "the content to write to the file" describes a content
# argument, not a path, and misclassifying it would send the policy's
# path globs at file *contents*.
DESCRIPTION_KEYWORDS = [
    (re.compile(
        r"\b(file\s*path|path\s+(to|of|for)|(absolute|relative|full)\s+path|directory|folder|"
        r"filename|file\s+name|file\s+to\s+(read|write|open|delete|list)|on\s+disk)\b", re.I),
     FILE_ACCESS),
    (re.compile(
        r"\b(shell\s+command|command\s+(to|line)|script\s+to|to\s+execute)\b", re.I),
     COMMAND_EXEC),
    (re.compile(
        r"\b(url|uri|hostname|host\s*name|endpoint|https?|domain\s+name|ip\s+address)\b", re.I),
     NETWORK),
]

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@dataclass(frozen=True)
class Classification:
    category: str
    source: str  # "schema:format" | "key_name" | "key_token" | "schema:description"


def _name_tokens(name: str):
    spaced = _CAMEL_BOUNDARY.sub("_", name)
    return [t for t in re.split(r"[_\-.\s]+", spaced.lower()) if t]


def classify_by_key_name(key: str) -> Optional[Classification]:
    """The v1 rule, unchanged: exact match on a well-known key name."""
    key_l = key.lower()
    if key_l in PATH_ARG_KEYS:
        return Classification(FILE_ACCESS, "key_name")
    if key_l in COMMAND_ARG_KEYS:
        return Classification(COMMAND_EXEC, "key_name")
    if key_l in URL_ARG_KEYS:
        return Classification(NETWORK, "key_name")
    return None


def classify_property(key: str, prop_schema: Optional[dict]) -> Optional[Classification]:
    """Classifies one argument given its (possibly absent) schema entry."""
    if isinstance(prop_schema, dict):
        fmt = prop_schema.get("format")
        if isinstance(fmt, str) and fmt.lower() in FORMAT_CATEGORIES:
            return Classification(FORMAT_CATEGORIES[fmt.lower()], "schema:format")

    by_key = classify_by_key_name(key)
    if by_key is not None:
        return by_key

    for token in _name_tokens(key):
        if token in NAME_TOKEN_CATEGORIES:
            return Classification(NAME_TOKEN_CATEGORIES[token], "key_token")

    if not isinstance(prop_schema, dict):
        return None

    description = prop_schema.get("description")
    if isinstance(description, str) and description:
        for pattern, category in DESCRIPTION_KEYWORDS:
            if pattern.search(description):
                return Classification(category, "schema:description")
    return None


def classify_property_all(key: str, prop_schema: Optional[dict]) -> List[Classification]:
    """Every category any signal assigns the argument, not just the first.

    `classify_property` stops at the first rule that matches, which let a
    weaker signal hide a stronger one: `script_path` is a script *and* a
    path, but its first token made it command-only, so the file rules
    never saw it. The policy judges an argument under every category
    returned here and the most restrictive outcome wins. The schema
    description is still only a fallback: it is free text, and matching
    it on every argument would drag content arguments into the rules."""
    found: List[Classification] = []

    def add(category: str, source: str) -> None:
        if all(c.category != category for c in found):
            found.append(Classification(category, source))

    if isinstance(prop_schema, dict):
        fmt = prop_schema.get("format")
        if isinstance(fmt, str) and fmt.lower() in FORMAT_CATEGORIES:
            add(FORMAT_CATEGORIES[fmt.lower()], "schema:format")
    by_key = classify_by_key_name(key)
    if by_key is not None:
        add(by_key.category, by_key.source)
    for token in _name_tokens(key):
        if token in NAME_TOKEN_CATEGORIES:
            add(NAME_TOKEN_CATEGORIES[token], "key_token")
    if not found and isinstance(prop_schema, dict):
        description = prop_schema.get("description")
        if isinstance(description, str) and description:
            for pattern, category in DESCRIPTION_KEYWORDS:
                if pattern.search(description):
                    add(category, "schema:description")
    return found


class ArgumentClassifier:
    """Holds the per-tool schemas seen on `tools/list` and classifies
    arguments against them. Safe to share between threads: the only
    mutation is a dict assignment on registration."""

    def __init__(self) -> None:
        self._schemas: Dict[str, dict] = {}

    @property
    def known_tools(self):
        return sorted(self._schemas)

    def register_tools(self, tools) -> int:
        """Ingests a `tools/list` result's `tools` array. Malformed entries
        are skipped rather than raising — a server with a broken schema
        just gets v1 key-name classification for that tool."""
        registered = 0
        if not isinstance(tools, list):
            return 0
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name")
            schema = tool.get("inputSchema")
            if not isinstance(name, str) or not name:
                continue
            props = schema.get("properties") if isinstance(schema, dict) else None
            self._schemas[name] = props if isinstance(props, dict) else {}
            registered += 1
        return registered

    def has_schema(self, tool_name: str) -> bool:
        return tool_name in self._schemas

    def property_schema(self, tool_name: str, key: str) -> Optional[dict]:
        props = self._schemas.get(tool_name)
        if not props:
            return None
        prop = props.get(key)
        return prop if isinstance(prop, dict) else None

    def classify(self, tool_name: str, key: str) -> Optional[Classification]:
        return classify_property(key, self.property_schema(tool_name, key))

    def classify_all(self, tool_name: str, key: str) -> List[Classification]:
        return classify_property_all(key, self.property_schema(tool_name, key))
