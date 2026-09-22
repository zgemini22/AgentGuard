"""Policy engine: evaluates MCP tool calls against a YAML rule set.

Three independent rule categories (file access, command execution,
network access), matched against tool-call arguments. Which category an
argument belongs to is decided by `agentguard.classify` — by the tool's
declared schema when the proxy has seen one, by key-name conventions
otherwise. Every category has the same shape: `deny_patterns` (a match
denies), then `allow_patterns` + `default_action` (a value on no
allow pattern is denied when `default_action: deny`). File and network
patterns are globs (on the expanded path / on the hostname); command
patterns are regexes. Categories the config doesn't mention are
skipped, not denied — this is an allowlist/denylist engine, not a full
sandbox.

The config is validated strictly on load (`agentguard.validate`): an
unknown key or a broken pattern is a startup error, never a silently
disabled rule.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from .grants import GrantStore
from .paths import PathMatcher, canonical_path
from .session import parent_directory
from .validate import PolicyError, load_policy, validate_policy  # noqa: F401
from .classify import (  # noqa: F401  (re-exported for backward compatibility)
    COMMAND_ARG_KEYS,
    COMMAND_EXEC,
    FILE_ACCESS,
    NETWORK,
    PATH_ARG_KEYS,
    URL_ARG_KEYS,
    ArgumentClassifier,
)

# Decision.category for a call whose string arguments matched no
# classifier rule at all. Distinct from "none" (no string arguments to
# classify) because they mean different things to a reader of the log:
# "none" is inert, "unclassified" is a gap the policy couldn't see into.
UNCLASSIFIED = "unclassified"

BUDGET_KEY_FOR_CATEGORY = {
    FILE_ACCESS: "max_file_calls",
    NETWORK: "max_network_calls",
    COMMAND_EXEC: "max_command_calls",
}

# What `deny_network_after_sensitive_read` treats as sensitive when the
# policy doesn't say. These are files a session may legitimately be
# *allowed* to read (a deny pattern would never let them through) whose
# contents shouldn't then leave the machine.
DEFAULT_SENSITIVE_PATTERNS = [
    "**/.env", "**/.env.*",
    "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx",
    "**/.ssh/**", "**/.aws/**", "**/.gnupg/**", "**/.kube/**",
    "**/id_rsa*", "**/id_ed25519*", "**/id_ecdsa*",
    "**/credentials", "**/credentials.*", "**/secrets.*", "**/*secret*",
    "**/.netrc", "**/.npmrc", "**/.pypirc", "**/.docker/config.json",
]


@dataclass
class ClassifiedArgument:
    """One string-valued argument and what the classifier made of it.
    `category` is None for an argument nothing recognized."""
    key: str
    value: str
    category: Optional[str]
    source: str
    # For file_access: the absolute, normalized path the value names
    # (see agentguard.paths). What directory counts and reasons use.
    canonical: Optional[str] = None


ALLOW = "allow"
DENY = "deny"
ASK = "ask"
ACTIONS = (ALLOW, DENY, ASK)


@dataclass
class Decision:
    """What the policy says about one call.

    `allowed` is the effective yes/no the proxy acts on; `action` is
    the verdict the policy actually reached, which may be `ask` — "a
    human should decide." An `ask` decision is not allowed until
    something resolves it (`approved()`), and if nothing can, it
    degrades to deny. `allowed` stays a plain field rather than a
    property so `Decision(True, ...)` keeps working."""
    allowed: bool
    category: str
    reason: str
    matched_rule: Optional[str] = None
    arguments: List[ClassifiedArgument] = field(default_factory=list)
    action: str = ""
    # How an `ask` was resolved: no_channel, timeout, denied_by_operator,
    # approved_once, approved_for_session, approved_always, granted.
    ask_resolution: Optional[str] = None
    # The specific thing that tripped the rule: the host or canonical path
    # that missed an allowlist, the value a pattern matched, the argument
    # keys nothing could classify. What a grant scope is keyed on.
    subject: Optional[str] = None
    # For an `ask` raised by several rules in one call: each of them. A
    # grant covers the call only if it covers every part.
    parts: List["Decision"] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.action:
            self.action = ALLOW if self.allowed else DENY
        elif self.action == ASK:
            self.allowed = False

    def resolved(self, allowed: bool, resolution: str, note: str) -> "Decision":
        """A copy of this `ask` decision with the human's (or the
        fallback's) answer applied."""
        return Decision(
            allowed, self.category, f"{self.reason} — {note}", self.matched_rule,
            self.arguments, ALLOW if allowed else DENY, resolution,
        )

    @property
    def argument_categories(self) -> dict:
        """`{key: category}` for every classified argument, with
        "unclassified" for the ones nothing recognized, and categories
        joined with "+" for an argument judged under several. This is
        what the audit log records, so a reader can tell which arguments
        the policy actually looked at."""
        out: dict = {}
        for a in self.arguments:
            category = a.category or "unclassified"
            existing = out.get(a.key)
            if existing is None:
                out[a.key] = category
            elif category not in existing.split("+"):
                out[a.key] = f"{existing}+{category}"
        return out


def _single_scope(tool: str, decision: Decision) -> str:
    if decision.matched_rule:
        return f"{tool}:{decision.category}:{decision.matched_rule}"
    if decision.subject:
        return f"{tool}:{decision.category}:{decision.subject}"
    return f"{tool}:{decision.category}:*"


def grant_scopes(tool: str, decision: Decision) -> List[str]:
    """Every scope a `session`/`always` answer to this decision grants:
    this tool, this category, and the rule that tripped — or, for an
    allowlist miss, the specific host or canonical path that missed (not
    whichever argument of that category came first). Deliberately
    narrow: approving one host never approves the next."""
    parts = decision.parts or [decision]
    scopes: List[str] = []
    for part in parts:
        scope = _single_scope(tool, part)
        if scope not in scopes:
            scopes.append(scope)
    return scopes


def grant_scope(tool: str, decision: Decision) -> str:
    """The scopes of grant_scopes() as one string, for display."""
    return " & ".join(grant_scopes(tool, decision))


@dataclass
class _CategoryRule:
    enabled: bool = True
    deny_patterns: list = field(default_factory=list)
    allow_patterns: list = field(default_factory=list)
    default_action: str = "allow"  # what happens to a value on no allow pattern; only matters when allow_patterns is set


@dataclass
class _ToolRules:
    """The effective rule set for one tool name (see rules_for_tool)."""
    enabled: bool
    categories: dict  # category -> _CategoryRule
    unclassified_arguments: str
    overridden: bool  # whether a tools.<name> section exists for it


def file_uri_path(value: str) -> Optional[str]:
    """`file:///home/u/x` -> `/home/u/x`; `file:///C:/x` -> `C:/x`. None
    for anything that isn't a file URI."""
    parsed = urlparse(value)
    if parsed.scheme.lower() != "file":
        return None
    path = unquote(parsed.path)
    if parsed.netloc and parsed.netloc != "localhost":
        # file://host/share/x — a UNC-style path; keep the host in it.
        path = f"//{parsed.netloc}{path}"
    elif re.match(r"^/[A-Za-z]:", path):
        path = path[1:]
    return path or "/"


_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
_HOST_CHARS = re.compile(r"[a-z0-9._\-]+|[0-9a-f:.]+")


def url_host(value: str) -> Optional[str]:
    """The host a URL or bare hostname names, lowercased, or None when it
    can't be determined *unambiguously*.

    Unambiguously matters: the host that decides the allowlist must be
    the host the server's HTTP client connects to, and parsers disagree
    on some inputs — a backslash ends the authority for browsers, urllib3
    and requests but not for urllib.parse, so `http://a\\@b/` is `a` to
    them and `b` to urlparse. Such values, and anything with whitespace,
    control characters or percent-encoding in the authority, are refused
    rather than guessed at. A value with no scheme is read as
    `//host[:port][/path]`, not matched as a whole string."""
    if not isinstance(value, str) or not value:
        return None
    if "\\" in value or any(ord(c) < 0x21 or ord(c) == 0x7F for c in value):
        return None
    if _SCHEME.match(value):
        parsed = urlparse(value)
        if not parsed.netloc:
            return None  # `http:evil.test`, `mailto:x` — no authority to judge
    else:
        parsed = urlparse(value if value.startswith("//") else "//" + value)
    if "%" in parsed.netloc:
        return None
    try:
        host = parsed.hostname
        parsed.port  # raises ValueError on a malformed port
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    host = host.lower()
    if not host or not _HOST_CHARS.fullmatch(host):
        return None
    return host


# Values that are themselves URLs a server would connect to are judged as
# network whatever the argument is called.
_URL_VALUE = re.compile(r"^(https?|wss?|ftps?)://", re.IGNORECASE)


def iter_string_arguments(arguments, prefix: str = "") -> Iterator[Tuple[str, str]]:
    """Yields `(key, value)` for every string anywhere in the arguments,
    descending into lists (at any depth) and nested objects. A list of
    paths under `paths` yields each path under the key `paths`, and so
    does a list of lists (`moves: [[src, dst]]`); a nested
    `{"options": {"path": ...}}` yields under `options.path`. Numbers,
    booleans and nulls can't carry a path or a URL and are skipped."""
    if not isinstance(arguments, dict):
        return
    for key, value in arguments.items():
        yield from _iter_value(f"{prefix}{key}", value)


def _iter_value(full_key: str, value) -> Iterator[Tuple[str, str]]:
    if isinstance(value, str):
        yield full_key, value
    elif isinstance(value, list):
        for item in value:
            yield from _iter_value(full_key, item)
    elif isinstance(value, dict):
        yield from iter_string_arguments(value, f"{full_key}.")


class PolicyEngine:
    def __init__(self, config: dict, classifier: Optional[ArgumentClassifier] = None,
                 base_dir: Optional[str] = None):
        config = config or {}
        # Relative file paths are resolved against this: the directory the
        # wrapped server runs in, which is ours (the proxy starts it without
        # changing directory). See agentguard.paths.
        self.base_dir = os.path.abspath(base_dir if base_dir is not None else os.getcwd())
        # Strict: an unknown key, a non-compiling regex, a string where a
        # bool belongs — all fail here, at construction, rather than
        # silently loading as a default. See agentguard.validate.
        errors = validate_policy(config)
        if errors:
            raise PolicyError(errors)
        self.config = config
        self._global_rules = {
            FILE_ACCESS: self._load_category(config.get("file_access", {})),
            COMMAND_EXEC: self._load_category(config.get("command_exec", {})),
            NETWORK: self._load_category(config.get("network", {})),
        }
        # What to do with a string argument no classifier rule recognized.
        # `allow` is the v1 behavior and the default for compatibility;
        # `deny` is the secure setting — it closes the rename-the-argument
        # bypass entirely, at the cost of rejecting calls to tools whose
        # schemas the classifier can't read. Check with
        # `agentguard check-policy --probe` before flipping it.
        self.unclassified_arguments = config.get("unclassified_arguments", ALLOW)
        # `tools.<name>:` overrides. A tool's effective rules are the
        # global ones with each *field* the override sets replaced —
        # `tools.fetch.network.allow_patterns` swaps the allowlist for
        # that tool but leaves its deny_patterns and default_action as
        # the global network section has them. Resolved lazily, once
        # per tool name.
        self._tool_overrides: dict = dict(config.get("tools") or {})
        self._tool_rules_cache: dict = {}
        # Per-session ceilings; the Session holds the counters. A missing
        # key means unlimited.
        self.budgets: dict = dict(config.get("budgets") or {})
        self.budget_action: str = self.budgets.pop("on_exceed", DENY)
        # The three cross-call rules. See _check_sequences.
        sequences = config.get("sequences") or {}
        sensitive = sequences.get("deny_network_after_sensitive_read")
        self.deny_network_after_sensitive_read = sensitive is not None and sensitive.get("enabled", True)
        self.sensitive_patterns: List[str] = list(
            (sensitive or {}).get("sensitive_patterns") or DEFAULT_SENSITIVE_PATTERNS
        )
        self.max_distinct_directories: Optional[int] = sequences.get("max_distinct_directories")
        self.deny_exec_after_fetch: bool = bool(sequences.get("deny_exec_after_fetch", False))
        self.sequence_action: str = sequences.get("on_trip", DENY)
        # Persistent operator grants (see agentguard/grants.py). Loaded
        # here so a malformed overlay fails at startup like the policy.
        self.grant_store = GrantStore(config.get("grants_file"))
        # Shared with the proxy, which feeds it `tools/list` schemas as
        # they go by. Without any registered schema it classifies by key
        # name alone, which is the v1 behavior.
        self.classifier = classifier if classifier is not None else ArgumentClassifier()

    @classmethod
    def from_yaml(cls, path: str) -> "PolicyEngine":
        return cls(load_policy(path))

    @property
    def tracks_output_size(self) -> bool:
        return "max_output_bytes_per_call" in self.budgets or "max_total_output_bytes" in self.budgets

    def output_budget_exceeded(self, nbytes: int) -> Optional[str]:
        """Reason a single result of `nbytes` breaks the per-call budget,
        or None."""
        limit = self.budgets.get("max_output_bytes_per_call")
        if limit is not None and nbytes > limit:
            return f"result is {nbytes} bytes, over the session budget max_output_bytes_per_call ({limit})"
        return None

    def _session_budget_exceeded(self, session, categories: List[str]) -> Optional[Decision]:
        limit = self.budgets.get("max_total_output_bytes")
        if limit is not None and session.output_bytes >= limit:
            return Decision(
                False, "budget",
                f"session budget max_total_output_bytes exhausted "
                f"({session.output_bytes} of {limit} bytes already delivered)",
                "max_total_output_bytes", action=self.budget_action,
            )
        for category in categories:
            key = BUDGET_KEY_FOR_CATEGORY[category]
            limit = self.budgets.get(key)
            if limit is not None and session.call_counts.get(category, 0) >= limit:
                return Decision(
                    False, "budget",
                    f"session budget {key} exhausted ({limit} {category} calls already allowed)",
                    key, action=self.budget_action,
                )
        return None

    def _check_sequences(self, session, classified: List[ClassifiedArgument], touched: List[str]) -> Optional[Decision]:
        """The three cross-call rules, judged against what this session
        has already been allowed to do. Deliberately a fixed menu: each
        answers one concrete question the threat model used to disclaim.
        A fourth is a design conversation, not another elif."""
        if self.deny_network_after_sensitive_read and NETWORK in touched and session.sensitive_reads:
            return Decision(
                False, "sequence",
                f"network call after a sensitive file read ('{session.sensitive_reads[0]}'"
                + (f" and {len(session.sensitive_reads) - 1} more" if len(session.sensitive_reads) > 1 else "")
                + ") in this session",
                "deny_network_after_sensitive_read", action=self.sequence_action,
            )
        if self.deny_exec_after_fetch and COMMAND_EXEC in touched and session.fetched:
            return Decision(
                False, "sequence",
                "command execution after a network call in this session",
                "deny_exec_after_fetch", action=self.sequence_action,
            )
        if self.max_distinct_directories is not None and FILE_ACCESS in touched:
            new_dirs = {parent_directory(a.canonical or a.value) for a in classified if a.category == FILE_ACCESS}
            new_dirs -= session.directories
            total = len(session.directories) + len(new_dirs)
            if total > self.max_distinct_directories:
                return Decision(
                    False, "sequence",
                    f"call would touch {total} distinct directories ('{sorted(new_dirs)[0]}' is new); "
                    f"max_distinct_directories is {self.max_distinct_directories}",
                    "max_distinct_directories", action=self.sequence_action,
                )
        return None

    def note_allowed(self, session, decision: Decision) -> None:
        """Records a forwarded call on the session — budget counters and
        the sequence facts — using this policy's notion of "sensitive"."""
        session.note_allowed_call(decision, self.sensitive_patterns, base_dir=self.base_dir)

    @staticmethod
    def _deny_entries(raw_list) -> List[Tuple[str, str]]:
        """deny_patterns entries are a plain pattern (action deny) or
        `{pattern: ..., action: deny|ask}`. Normalized to (pattern, action)."""
        entries = []
        for item in raw_list or []:
            if isinstance(item, dict):
                entries.append((item["pattern"], item.get("action", DENY)))
            else:
                entries.append((item, DENY))
        return entries

    @classmethod
    def _load_category(cls, raw: dict) -> _CategoryRule:
        raw = raw or {}
        return _CategoryRule(
            enabled=raw.get("enabled", True),
            deny_patterns=cls._deny_entries(raw.get("deny_patterns")),
            allow_patterns=raw.get("allow_patterns", []) or [],
            default_action=raw.get("default_action", ALLOW),
        )

    def rules_for_tool(self, tool_name: str) -> "_ToolRules":
        """The effective rules for one tool: global, with that tool's
        override fields applied on top."""
        cached = self._tool_rules_cache.get(tool_name)
        if cached is not None:
            return cached
        override = self._tool_overrides.get(tool_name) or {}
        categories = {}
        for category, base in self._global_rules.items():
            section = override.get(category)
            if section:
                categories[category] = _CategoryRule(
                    enabled=section.get("enabled", base.enabled),
                    deny_patterns=(self._deny_entries(section.get("deny_patterns")) if "deny_patterns" in section else base.deny_patterns),
                    allow_patterns=(section.get("allow_patterns") if "allow_patterns" in section else base.allow_patterns) or [],
                    default_action=section.get("default_action", base.default_action),
                )
            else:
                categories[category] = base
        rules = _ToolRules(
            enabled=override.get("enabled", True),
            categories=categories,
            unclassified_arguments=override.get("unclassified_arguments", self.unclassified_arguments),
            overridden=bool(override),
        )
        self._tool_rules_cache[tool_name] = rules
        return rules

    def classify_arguments(self, tool_name: str, arguments: dict) -> List[ClassifiedArgument]:
        """One entry per (argument, category). An argument that several
        signals place in different categories appears once for each, and
        is judged under all of them (see classify.classify_property_all).
        Independently of its name, a value that *is* a URL is also judged
        as network, and a `file://` URI as a file path."""
        classified = []
        for key, raw_value in iter_string_arguments(arguments):
            # Nested keys are classified by their leaf name; the schema
            # lookup only knows top-level properties.
            leaf = key.rsplit(".", 1)[-1]
            results = [(c.category, c.source) for c in self.classifier.classify_all(tool_name, leaf)]
            file_path = file_uri_path(raw_value)
            if file_path is not None:
                # A file:// URI is a file read whatever the argument is
                # called; judge it by the path rules, never as a host.
                converted = [(FILE_ACCESS, f"{s}:file-uri") for c, s in results if c == NETWORK]
                results = [(c, s) for c, s in results if c != NETWORK]
                if all(c != FILE_ACCESS for c, _ in results):
                    results.append(converted[0] if converted else (FILE_ACCESS, "value:file-uri"))
            elif _URL_VALUE.match(raw_value) and all(c != NETWORK for c, _ in results):
                results.append((NETWORK, "value:url"))
            if not results:
                classified.append(ClassifiedArgument(key, raw_value, None, "unclassified"))
                continue
            for category, source in results:
                value = raw_value
                if category == FILE_ACCESS and file_path is not None:
                    value = file_path
                canonical = canonical_path(value, self.base_dir) if category == FILE_ACCESS else None
                classified.append(ClassifiedArgument(key, value, category, source, canonical))
        return classified

    def evaluate(self, tool_name: str, arguments: dict, session=None) -> Decision:
        """Judges one call. With a `session`, the cross-call rules —
        budgets, sequences, session grants — apply too; without one
        (check-policy --probe) the call is judged on its own, as v1 did,
        though persistent grants still apply."""
        decision = self._evaluate(tool_name, arguments, session)
        if decision.action != ASK:
            return decision
        # An ask the operator has already answered — for every scope it
        # involves. A grant never reaches a hard deny: _evaluate returns a
        # deny whenever any rule denies, before an ask is considered.
        scopes = grant_scopes(tool_name, decision)
        session_grants = session.grants if session is not None else set()
        persistent = self.grant_store.scopes()
        if all(s in session_grants or s in persistent for s in scopes):
            kind = "session" if all(s in session_grants for s in scopes) else "persistent"
            return decision.resolved(
                True, "granted", f"ask: covered by {kind} grant '{' & '.join(scopes)}'")
        return decision

    def _evaluate(self, tool_name: str, arguments: dict, session=None) -> Decision:
        if arguments is not None and not isinstance(arguments, dict):
            # MCP tool arguments are an object. Anything else can't be
            # classified key by key, and a server may still read it.
            return Decision(
                False, UNCLASSIFIED,
                f"tool '{tool_name}' arguments must be a JSON object, not {type(arguments).__name__}",
            )
        classified = self.classify_arguments(tool_name, arguments)
        rules = self.rules_for_tool(tool_name)
        if not rules.enabled:
            return Decision(
                False, "tool",
                f"tool '{tool_name}' is disabled by policy (tools.{tool_name}.enabled: false)",
                f"tools.{tool_name}.enabled",
                arguments=classified,
            )
        checked_categories: List[str] = []
        touched_categories: List[str] = []
        unclassified_keys: List[str] = []
        # Every argument is judged, and every rule that objects is kept:
        # returning at the first objection let an `ask` on one argument
        # hide a hard deny on another, which an approval then let through.
        objections: List[Decision] = []
        for arg in classified:
            if arg.category is None:
                if arg.key not in unclassified_keys:
                    unclassified_keys.append(arg.key)
                continue
            if arg.category not in touched_categories:
                touched_categories.append(arg.category)
            rule = rules.categories[arg.category]
            if not rule.enabled:
                continue
            if arg.category not in checked_categories:
                checked_categories.append(arg.category)
            decision = self._check(arg.category, arg.value, rule)
            if decision is not None:
                if rules.overridden:
                    decision.reason += f" (under tools.{tool_name} override)"
                objections.append(decision)

        if unclassified_keys and rules.unclassified_arguments != ALLOW:
            objections.append(Decision(
                False, UNCLASSIFIED,
                f"tool '{tool_name}' argument(s) {', '.join(repr(k) for k in unclassified_keys)} "
                f"could not be classified and unclassified_arguments is '{rules.unclassified_arguments}'",
                action=rules.unclassified_arguments,
                subject=",".join(sorted(unclassified_keys)),
            ))
        if session is not None:
            for decision in (
                self._session_budget_exceeded(session, touched_categories),
                self._check_sequences(session, classified, touched_categories),
            ):
                if decision is not None:
                    objections.append(decision)

        if objections:
            return self._combine(objections, classified)
        if checked_categories:
            return Decision(
                allowed=True,
                category=checked_categories[0],
                reason=f"tool '{tool_name}' call checked against {', '.join(checked_categories)}; no deny rule matched",
                arguments=classified,
            )
        if unclassified_keys:
            return Decision(
                allowed=True,
                category=UNCLASSIFIED,
                reason=f"tool '{tool_name}' argument(s) {', '.join(repr(k) for k in unclassified_keys)} "
                       "matched no policy category; allowed because unclassified_arguments is 'allow'",
                arguments=classified,
            )
        return Decision(
            allowed=True,
            category="none",
            reason=f"tool '{tool_name}' call has no string arguments for the policy to classify",
            arguments=classified,
        )

    @staticmethod
    def _combine(objections: List[Decision], classified: List[ClassifiedArgument]) -> Decision:
        """Any deny wins. Otherwise every ask is combined into one, so the
        operator answers once and a grant has to cover all of them."""
        for decision in objections:
            if decision.action == DENY:
                decision.arguments = classified
                return decision
        asks = [d for d in objections if d.action == ASK]
        if len(asks) == 1:
            asks[0].arguments = classified
            return asks[0]
        first = asks[0]
        return Decision(
            False, first.category,
            "; ".join(d.reason for d in asks),
            first.matched_rule, arguments=classified, action=ASK,
            subject=first.subject, parts=asks,
        )

    def _check(self, category: str, value: str, rule: _CategoryRule) -> Optional[Decision]:
        """Same semantics for every category: a deny pattern match denies;
        otherwise, if there's an allowlist and the value isn't on it,
        `default_action` decides. What a "match" means differs — glob on
        the canonical path (agentguard.paths), glob on the hostname, regex
        on the command."""
        subject, denied_by, allowed_by_any = self._matcher(category, value)
        if subject is None:
            # A network value whose host can't be determined unambiguously
            # (see url_host). Only matters if the policy judges hosts at all.
            if rule.deny_patterns or rule.allow_patterns:
                return Decision(
                    False, category,
                    f"value '{value}' is not a URL or hostname whose host can be determined unambiguously",
                    action=DENY,
                )
            return None
        shown = f"'{value}'" if subject == value else f"'{value}' (as '{subject}')"
        for pattern, action in rule.deny_patterns:
            if denied_by(pattern):
                return Decision(
                    False, category,
                    f"value {shown} matches {action} pattern '{pattern}'",
                    pattern, action=action, subject=subject,
                )
        if not rule.allow_patterns or allowed_by_any(rule.allow_patterns):
            return None
        if rule.default_action != ALLOW:
            noun = "host" if category == NETWORK else "value"
            return Decision(
                False, category,
                f"{noun} '{subject}' is not in the {category} allowlist",
                action=rule.default_action, subject=subject,
            )
        return None

    def _matcher(self, category: str, value: str):
        """Returns (what is being matched, deny-match fn, allowlist fn)."""
        if category == FILE_ACCESS:
            m = PathMatcher(value, self.base_dir)
            return m.subject, m.denied_by, m.allowed_by_any
        if category == NETWORK:
            host = url_host(value)
            if host is None:
                return None, None, None
            match = lambda p: fnmatch.fnmatchcase(host, p.lower().rstrip("."))  # noqa: E731
            return host, match, lambda ps: any(match(p) for p in ps)
        match = lambda p: re.search(p, value) is not None  # noqa: E731
        return value, match, lambda ps: any(match(p) for p in ps)
