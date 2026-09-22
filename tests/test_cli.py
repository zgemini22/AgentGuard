import json
import os
import tempfile

import pytest

from agentguard.audit import AuditLog
from agentguard.cli import DEFAULT_POLICY, build_parser, main
from agentguard.policy import Decision


def test_no_subcommand_exits_nonzero(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code != 0


def test_run_without_server_cmd_exits_with_usage_error(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["run", "--config", "agentguard/policies/default.yaml"])
    assert exc_info.value.code == 2
    assert "missing MCP server command" in capsys.readouterr().err


def test_run_with_missing_config_file_exits_cleanly(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["run", "--config", "/nonexistent/path/policy.yaml", "--", "python3", "-c", "pass"])
    assert exc_info.value.code == 2
    assert "policy config file not found" in capsys.readouterr().err


def test_run_with_malformed_yaml_exits_cleanly(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        bad_config = os.path.join(tmp, "bad.yaml")
        with open(bad_config, "w") as f:
            f.write("file_access: [unclosed")

        with pytest.raises(SystemExit) as exc_info:
            main(["run", "--config", bad_config, "--", "python3", "-c", "pass"])
        assert exc_info.value.code == 2
        assert "failed to parse policy config" in capsys.readouterr().err


def test_verify_audit_on_clean_log_prints_ok_and_returns_zero(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.log")
        log = AuditLog(path)
        log.record("read_file", {"path": "/tmp/x"}, Decision(True, "file_access", "ok"))
        log.record("read_file", {"path": "/tmp/y"}, Decision(False, "file_access", "denied"))

        exit_code = main(["verify-audit", path])
        assert exit_code == 0
        assert "OK: 2 entries verified" in capsys.readouterr().out


def test_verify_audit_on_tampered_log_prints_tampered_and_returns_one(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.log")
        log = AuditLog(path)
        log.record("read_file", {"path": "/tmp/x"}, Decision(True, "file_access", "ok"))

        with open(path) as f:
            lines = [l for l in f if l.strip()]
        import json
        entry = json.loads(lines[0])
        entry["allowed"] = False
        with open(path, "w") as f:
            f.write(json.dumps(entry) + "\n")

        exit_code = main(["verify-audit", path])
        assert exit_code == 1
        assert "TAMPERED" in capsys.readouterr().out


def test_verify_audit_on_missing_log_says_missing_and_fails(capsys):
    exit_code = main(["verify-audit", "/nonexistent/audit.log"])
    assert exit_code == 1
    assert "MISSING: no audit log at /nonexistent/audit.log" in capsys.readouterr().out


def test_build_parser_defaults():
    parser = build_parser()
    args = parser.parse_args(["run", "--", "python3", "server.py"])
    assert args.config is None  # resolved to the bundled policy at run time
    assert os.path.isfile(DEFAULT_POLICY), "the default policy must ship inside the package"
    assert args.audit_log == "agentguard_audit.log"
    assert args.server_cmd == ["--", "python3", "server.py"]


def test_check_policy_without_config_uses_the_bundled_policy_from_any_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["check-policy"]) == 0
    captured = capsys.readouterr()
    assert DEFAULT_POLICY in captured.out
    assert "OK: policy is valid." in captured.out
    assert captured.err == ""


def test_legacy_cwd_policy_is_ignored_with_a_warning(tmp_path, monkeypatch, capsys):
    # 0.1.x read ./policies/default.yaml when --config was omitted. It is
    # no longer read implicitly, and the user is told so.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "default.yaml").write_text("this: is not a valid policy\n")
    assert main(["check-policy"]) == 0
    captured = capsys.readouterr()
    assert DEFAULT_POLICY in captured.out
    assert "policies/default.yaml is not read unless you pass --config" in captured.err.replace(os.sep, "/")


def test_default_policy_prints_the_bundled_file(capsys):
    assert main(["default-policy"]) == 0
    with open(DEFAULT_POLICY, encoding="utf-8") as f:
        assert capsys.readouterr().out == f.read()


# --- check-policy ------------------------------------------------------

def test_check_policy_on_default_policy_prints_effective_policy(capsys):
    exit_code = main(["check-policy", "--config", "agentguard/policies/default.yaml"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "OK: policy is valid." in out
    assert "unclassified_arguments: allow  (deny is the secure setting)" in out
    assert "file_access: enabled, 10 deny, 0 allow (glob)" in out
    assert "  deny   ~/.ssh/**" in out
    assert "network: enabled, 0 deny, 6 allow (hostname glob), default_action: deny" in out
    assert "  allow  *.github.com" in out
    assert "injection_detection: enabled, 7 rules: ignore_instructions" in out


def test_check_policy_rejects_typo_and_names_it(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "typo.yaml")
        with open(path, "w") as f:
            f.write("file_access:\n  deny_pattern:\n    - '**/.env'\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["check-policy", "--config", path])
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "is invalid" in err
        assert "unknown key 'deny_pattern'" in err
        assert "did you mean 'deny_patterns'" in err


def test_run_rejects_invalid_policy_before_starting_server(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "typo.yaml")
        with open(path, "w") as f:
            f.write("command_exec:\n  deny_patterns:\n    - '(unclosed'\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["run", "--config", path, "--", "python3", "-c", "pass"])
        assert exc_info.value.code == 2
        assert "regex does not compile" in capsys.readouterr().err


def test_check_policy_probe_explains_a_denial(capsys):
    exit_code = main([
        "check-policy", "--config", "agentguard/policies/default.yaml",
        "--probe", "read_file", '{"path": "~/.ssh/id_rsa", "count": 3}',
    ])
    out = capsys.readouterr().out
    assert exit_code == 3
    assert "probe: read_file" in out
    assert "path = '~/.ssh/id_rsa'  ->  file_access (key_name)" in out
    assert "decision: DENY  category=file_access  matched_rule=~/.ssh/**" in out
    assert "reason: value '~/.ssh/id_rsa' (as '" in out
    assert "matches deny pattern '~/.ssh/**'" in out


def test_check_policy_probe_shows_unclassified_arguments(capsys):
    exit_code = main([
        "check-policy", "--config", "agentguard/policies/default.yaml",
        "--probe", "open_thing", '{"where": "/etc/passwd"}',
    ])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "where = '/etc/passwd'  ->  UNCLASSIFIED (unclassified)" in out
    assert "decision: ALLOW  category=unclassified" in out


def test_check_policy_probe_with_tools_json_classifies_by_schema(capsys):
    with tempfile.TemporaryDirectory() as tmp:
        tools_path = os.path.join(tmp, "tools.json")
        with open(tools_path, "w") as f:
            json.dump({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{
                "name": "open_thing",
                "inputSchema": {"properties": {"where": {"type": "string", "description": "Path to the file"}}},
            }]}}, f)
        exit_code = main([
            "check-policy", "--config", "agentguard/policies/default.yaml", "--tools", tools_path,
            "--probe", "open_thing", '{"where": "/home/u/.aws/credentials"}',
        ])
        out = capsys.readouterr().out
        assert exit_code == 3
        assert "tools: 1 schema(s) loaded" in out
        assert "where = '/home/u/.aws/credentials'  ->  file_access (schema:description)" in out
        assert "decision: DENY" in out


def test_check_policy_probe_rejects_bad_json(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["check-policy", "--config", "agentguard/policies/default.yaml", "--probe", "t", "not json"])
    assert exc_info.value.code == 2
    assert "not valid JSON" in capsys.readouterr().err
