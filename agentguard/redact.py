"""Secret redaction: scans MCP tool *output* for API keys/tokens/private
keys and masks them before they reach the agent's context.

This is separate from PolicyEngine, which only ever looks at tool-call
*input* arguments. A tool can legitimately be allowed to read a file or
fetch a URL and still return something that shouldn't land in the
agent's context verbatim (a checked-in .env dump, a token embedded in an
API response, ...) — redaction is the second layer for that case.

v1 scope: known secret *formats* via regex (AWS/GitHub/Slack key
prefixes, PEM private key blocks, JWTs, a generic key=value pattern).
No entropy-based detection — that's a probabilistic guess and produces
too many false positives/negatives to be worth it before there's real
usage data to tune against.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple


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
        rule fired, so audit logs stay safe to store and share."""
        if not self.enabled or not text:
            return text, []

        matched_rules: List[str] = []
        for rule in self.rules:
            def _replace(match: re.Match, rule_name: str = rule.name) -> str:
                matched_rules.append(rule_name)
                return f"[REDACTED:{rule_name}]"

            text = rule.compiled.sub(_replace, text)
        return text, matched_rules
