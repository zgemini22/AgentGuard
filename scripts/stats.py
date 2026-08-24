#!/usr/bin/env python3
"""Prints real, reproducible numbers about this repo — rule counts,
line counts, dependency count.

Exists so that any number quoted about this project (in the README, in
a resume bullet, wherever) traces back to a command anyone can re-run,
instead of a hardcoded claim that quietly goes stale as the code
changes. Doesn't cover test count or coverage %, which come from
`pytest` and `coverage report` directly — see the commands printed
below and in README.md's "By the numbers" section.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CORE_MODULES = ["policy.py", "redact.py", "injection.py", "audit.py", "proxy.py"]


def count_default_policy_rules() -> dict:
    with open(REPO_ROOT / "policies" / "default.yaml") as f:
        config = yaml.safe_load(f)

    counts = {
        "file_access deny patterns": len(config["file_access"]["deny_patterns"]),
        "command_exec deny patterns": len(config["command_exec"]["deny_patterns"]),
        "network allow patterns": len(config["network"]["allow_patterns"]),
        "redaction rules": len(config["redaction"]["rules"]),
        "injection_detection rules": len(config["injection_detection"]["rules"]),
    }
    return counts


def count_lines(paths) -> int:
    total = 0
    for p in paths:
        with open(p) as f:
            total += sum(1 for _ in f)
    return total


def count_runtime_dependencies() -> list:
    with open(REPO_ROOT / "pyproject.toml") as f:
        content = f.read()
    # Minimal parse: pull the `dependencies = [...]` list out of [project].
    # Not a general TOML parser — just enough for this one file's shape.
    start = content.index("dependencies = [") + len("dependencies = [")
    end = content.index("]", start)
    deps_block = content[start:end]
    return [line.strip().strip('",') for line in deps_block.splitlines() if line.strip()]


def main() -> int:
    rule_counts = count_default_policy_rules()
    total_rules = sum(rule_counts.values())

    core_module_paths = [REPO_ROOT / "agentguard" / name for name in CORE_MODULES]
    core_lines = count_lines(core_module_paths)

    deps = count_runtime_dependencies()

    print("=== policies/default.yaml rule counts ===")
    for name, count in rule_counts.items():
        print(f"  {name}: {count}")
    print(f"  TOTAL: {total_rules}")

    print()
    print(f"=== core module line count (policy/redact/injection/audit/proxy) ===")
    print(f"  {core_lines} lines across {len(CORE_MODULES)} files")

    print()
    print(f"=== runtime dependencies ===")
    print(f"  {len(deps)}: {', '.join(deps) if deps else '(none)'}")

    print()
    print("Not computed here — run these directly for current numbers:")
    print("  test count:        pytest -q | tail -1")
    print("  line coverage:     coverage run -m pytest -q && coverage report --include='agentguard/*'")

    return 0


if __name__ == "__main__":
    sys.exit(main())
