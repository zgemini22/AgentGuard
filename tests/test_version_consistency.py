"""Guards against agentguard/__init__.py's __version__ drifting from
pyproject.toml's [project].version.

There's no single source of truth for the version here — setuptools
reads it from pyproject.toml for packaging, but the importable module
carries its own __version__ string. Nothing keeps them in sync
automatically, and a version bump that only touches one of them (easy
to do — this happened once already, caught before it shipped) would
otherwise go unnoticed until someone compared `pip show` to
`agentguard.__version__` by hand.
"""

import re
from pathlib import Path

import agentguard

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_init_version_matches_pyproject_version():
    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_text, re.MULTILINE)
    assert match, "could not find [project].version in pyproject.toml"
    pyproject_version = match.group(1)

    assert agentguard.__version__ == pyproject_version, (
        f"agentguard/__init__.py __version__ ({agentguard.__version__!r}) does not "
        f"match pyproject.toml's [project].version ({pyproject_version!r})"
    )
