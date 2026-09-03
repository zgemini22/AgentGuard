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

import re
from dataclasses import dataclass, field
from typing import List, Tuple

from .normalize import normalize


@dataclass
class RedactionRule:
    name: str
    pattern: str
    compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.compiled = re.compile(self.pattern)


DEFAULT_RULES: List[RedactionRule] = [
    RedactionRule("aws_access_key_id", r"AKIA[0-9A-Z]{16}"),
    RedactionRule("aws_secret_access_key", r"(?i)aws_secret_access_key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}"),
    RedactionRule("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    RedactionRule("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    RedactionRule("private_key_block", r"-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----"),
    RedactionRule("jwt", r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    RedactionRule("generic_api_key", r"(?i)(api[_-]?key|secret|token)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']"),
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
        claimed: List[Tuple[int, int, str]] = []  # (orig_start, orig_end, rule_name)

        def _free(start: int, end: int) -> bool:
            return all(end <= s or start >= e for s, e, _ in claimed)

        for rule in self.rules:
            for target, run in nt.scan_targets():
                if run is None:
                    for match in rule.compiled.finditer(target):
                        start, end = nt.map_span(match.start(), match.end())
                        if end > start and _free(start, end):
                            claimed.append((start, end, rule.name))
                elif rule.compiled.search(target) and _free(run.start, run.end):
                    claimed.append((run.start, run.end, rule.name))

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
