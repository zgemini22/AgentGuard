"""Secret redaction: scans MCP tool *output* for API keys/tokens/private
keys and masks them before they reach the agent's context.

This is separate from PolicyEngine, which only ever looks at tool-call
*input* arguments. A tool can legitimately be allowed to read a file or
fetch a URL and still return something that shouldn't land in the
agent's context verbatim (a checked-in .env dump, a token embedded in an
API response, ...) — redaction is the second layer for that case.

Known secret *formats* via regex (AWS/GitHub/Slack key prefixes, PEM
private key blocks, JWTs, a generic key=value pattern), matched
against the normalized text (agentguard.normalize) so a key split by
zero-width characters or hidden in a base64 blob is still caught. No
entropy-based detection — that's a probabilistic guess and produces
too many false positives/negatives to be worth it before there's real
usage data to tune against.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import List, Tuple

from .normalize import SCAN_LIMIT_RULE, normalize


@dataclass
class RedactionRule:
    name: str
    pattern: str
    compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.compiled = re.compile(self.pattern)


DEFAULT_RULES: List[RedactionRule] = [
    RedactionRule("aws_access_key_id", r"AKIA[0-9A-Z]{16}"),
    RedactionRule("aws_secret_access_key", r"""(?i)aws_secret_access_key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}"""),
    RedactionRule("github_token", r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    RedactionRule("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,255}"),
    RedactionRule("private_key_block", r"-----BEGIN[ A-Z]{0,40}PRIVATE KEY-----(?:[^-]|-(?!----)){0,16384}-----END[ A-Z]{0,40}PRIVATE KEY-----"),
    RedactionRule("jwt", r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,8192}\.[A-Za-z0-9_-]{1,8192}"),
    RedactionRule("generic_api_key", r"""(?i)(api[_-]?key|secret|token)["']?\s{0,16}[:=]\s{0,16}["'][A-Za-z0-9_\-]{16,512}["']"""),
]


class SecretRedactor:
    def __init__(self, rules: List[RedactionRule], enabled: bool = True):
        self.rules = rules
        self.enabled = enabled

    @classmethod
    def from_config(cls, config: dict) -> "SecretRedactor":
        raw = (config or {}).get("redaction") or {}
        enabled = raw.get("enabled", True)
        if "rules" in raw:
            rules = [RedactionRule(r["name"], r["pattern"]) for r in raw["rules"]]
        else:
            rules = DEFAULT_RULES
        return cls(rules, enabled)

    def redact(self, text: str) -> Tuple[str, List[str]]:
        """Returns (redacted_text, rule_names_matched). Never returns the
        matched secret value itself, including to the caller — only which
        rule fired, so audit logs stay safe to store and share.

        Rules are matched against the *normalized* text (and any base64
        payload recovered from it), but the edit is made to the
        *original*: each normalized match is mapped back to the span it
        came from, and a match inside a decoded base64 run replaces the
        whole run. Rules are applied in order and a later rule can't
        match inside a span an earlier one already claimed — the same
        first-rule-wins semantics as sequential substitution had."""
        if not self.enabled or not text:
            return text, []

        nt = normalize(text)
        if nt.incomplete:
            # More encoded content than the scanners will decode: what
            # wasn't decoded wasn't checked, so none of it is delivered.
            return f"[REDACTED:{SCAN_LIMIT_RULE}]", [SCAN_LIMIT_RULE]
        claimed: List[Tuple[int, int, str]] = []  # (orig_start, orig_end, rule_name), in rule order
        # The claimed spans never overlap, so sorted starts and ends are an
        # interval index: a new span only has to be checked against its
        # neighbours, not against every earlier match.
        starts: List[int] = []
        ends: List[int] = []

        def _claim(start: int, end: int, name: str) -> None:
            i = bisect.bisect_right(starts, start)
            if i > 0 and ends[i - 1] > start:
                return
            if i < len(starts) and starts[i] < end:
                return
            starts.insert(i, start)
            ends.insert(i, end)
            claimed.append((start, end, name))

        for rule in self.rules:
            for target, run in nt.scan_targets():
                if run is None:
                    for match in rule.compiled.finditer(target):
                        start, end = nt.map_span(match.start(), match.end())
                        if end > start:
                            _claim(start, end, rule.name)
                elif rule.compiled.search(target):
                    _claim(run.start, run.end, rule.name)

        if not claimed:
            return text, []

        matched_rules = [name for _, _, name in claimed]
        pieces: List[str] = []
        cursor = 0
        for start, end, name in sorted(claimed):
            pieces.append(text[cursor:start])
            pieces.append(f"[REDACTED:{name}]")
            cursor = end
        pieces.append(text[cursor:])
        return "".join(pieces), matched_rules
