"""File rules are matched against the path the server will open, not the
raw argument string (agentguard/paths.py). Each test here is a form that
used to slip past the shipped default policy or a documented allowlist."""

import os

import pytest

from agentguard import paths
from agentguard.policy import PolicyEngine
from agentguard.session import Session
from tests.test_default_policy import load_default_config


def default_engine(base_dir):
    return PolicyEngine(load_default_config(), base_dir=str(base_dir))


@pytest.mark.parametrize("value", [
    ".env", "./.env", ".env.local", "id_rsa", "id_ed25519", "server.pem", "tls.key",
    ".aws/credentials", ".ssh/authorized_keys", "sub/../.env", "./sub/./.env",
])
def test_default_policy_denies_relative_and_bare_names(tmp_path, value):
    decision = default_engine(tmp_path).evaluate("read_file", {"path": value})
    assert not decision.allowed, f"{value!r} was allowed: {decision.reason}"
    assert decision.category == "file_access"


@pytest.mark.parametrize("value", ["README.md", "src/main.py", "./notes.txt", "docs/env.md"])
def test_default_policy_still_allows_ordinary_relative_files(tmp_path, value):
    assert default_engine(tmp_path).evaluate("read_file", {"path": value}).allowed


def test_deny_reason_shows_the_canonical_path(tmp_path):
    decision = default_engine(tmp_path).evaluate("read_file", {"path": ".env"})
    assert os.path.join(str(tmp_path), ".env") in decision.reason


def _project_allowlist(root):
    return PolicyEngine({"file_access": {
        "allow_patterns": [f"{root}/**"], "default_action": "deny",
    }}, base_dir=str(root))


def test_dotdot_cannot_walk_out_of_an_allowlisted_directory(tmp_path):
    engine = _project_allowlist(tmp_path)
    assert engine.evaluate("read_file", {"path": f"{tmp_path}/src/x.py"}).allowed
    escaped = engine.evaluate("read_file", {"path": f"{tmp_path}/../../../etc/passwd"})
    assert not escaped.allowed
    assert "not in the file_access allowlist" in escaped.reason


def test_relative_path_inside_the_allowlisted_directory_is_allowed(tmp_path):
    assert _project_allowlist(tmp_path).evaluate("read_file", {"path": "src/x.py"}).allowed


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="needs POSIX symlinks")
def test_symlink_to_a_denied_file_is_denied(tmp_path):
    (tmp_path / ".env").write_text("DB_PASSWORD=x\n")
    os.symlink(tmp_path / ".env", tmp_path / "notes.txt")
    decision = default_engine(tmp_path).evaluate("read_file", {"path": "notes.txt"})
    assert not decision.allowed
    assert "**/.env" in decision.reason


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="needs POSIX symlinks")
def test_symlink_out_of_an_allowlisted_directory_is_denied(tmp_path):
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    os.symlink(outside, project / "link")
    engine = _project_allowlist(project)
    assert not engine.evaluate("read_file", {"path": f"{project}/link/secret.txt"}).allowed


def test_case_insensitive_platforms_match_regardless_of_case(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CASE_INSENSITIVE", True)
    engine = default_engine(tmp_path)
    for value in (".ENV", "Server.PEM", ".SSH/authorized_keys"):
        assert not engine.evaluate("read_file", {"path": value}).allowed, value


@pytest.mark.parametrize("raw, expected", [
    (".env.", ".env"),
    (".env ", ".env"),
    (".env. .", ".env"),
    (".env::$DATA", ".env"),
    ("C:\\proj\\.env::$DATA", "C:\\proj\\.env"),
    ("C:\\proj\\sub.\\.env ", "C:\\proj\\sub\\.env"),
    ("..\\x", "..\\x"),
])
def test_win32_name_aliases_are_stripped(raw, expected):
    assert paths._strip_win32_aliases(raw) == expected


def test_relative_deny_pattern_still_matches_relative_values(tmp_path):
    engine = PolicyEngine({"file_access": {"deny_patterns": ["secrets/*"]}}, base_dir=str(tmp_path))
    assert not engine.evaluate("read_file", {"path": "secrets/x"}).allowed
    assert not engine.evaluate("read_file", {"path": f"{tmp_path}/secrets/x"}).allowed
    assert engine.evaluate("read_file", {"path": "public/x"}).allowed


def test_sensitive_read_rule_counts_bare_and_relative_names(tmp_path):
    config = load_default_config()
    config["sequences"] = {"deny_network_after_sensitive_read": {"enabled": True}}
    # Sensitive files that aren't on the default deny list: the read is
    # allowed, and must then count as a sensitive read.
    for value in ("credentials", ".npmrc", "./config/secrets.json"):
        engine = PolicyEngine(config, base_dir=str(tmp_path))
        session = Session.new(["server"])
        read = engine.evaluate("read_file", {"path": value}, session)
        assert read.allowed, (value, read.reason)
        engine.note_allowed(session, read)
        assert session.sensitive_reads == [value]
        # ...and the network call after it is refused.
        fetch = engine.evaluate("fetch", {"url": "https://api.github.com/x"}, session)
        assert not fetch.allowed and fetch.category == "sequence", value
