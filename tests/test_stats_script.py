"""Smoke test for scripts/stats.py.

The whole point of that script is to be a source of truth nobody has to
trust blindly — if it silently broke or started printing wrong numbers,
it would defeat that purpose worse than not having the script at all.
This doesn't re-derive the exact counts (that would just duplicate the
script's own logic); it checks the script runs clean and its output
shape matches what README.md's "By the numbers" section quotes.
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def run_stats_script() -> str:
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "stats.py")],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_stats_script_runs_clean():
    output = run_stats_script()
    assert "policies/default.yaml rule counts" in output
    assert "core module line count" in output
    assert "runtime dependencies" in output


def test_stats_script_total_rule_count_matches_readme():
    # Deliberately hardcoded, not re-derived: this is a canary against
    # README drift, not a claim that 34 is eternally correct. Add a
    # policy rule and this test fails on purpose — that's the signal to
    # go update README.md's "By the numbers" table in the same change.
    output = run_stats_script()
    assert "TOTAL: 34" in output


def test_stats_script_dependency_count_matches_readme():
    # Same reasoning: hardcoded on purpose, update alongside README.md
    # if pyproject.toml's dependency list ever changes.
    output = run_stats_script()
    assert "1: PyYAML" in output
