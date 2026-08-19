import os
import tempfile

import pytest

from agentguard.audit import AuditLog
from agentguard.cli import build_parser, main
from agentguard.policy import Decision


def test_no_subcommand_exits_nonzero(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code != 0


def test_run_without_server_cmd_exits_with_usage_error(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["run", "--config", "policies/default.yaml"])
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


def test_verify_audit_on_missing_log_is_valid_with_zero_entries(capsys):
    exit_code = main(["verify-audit", "/nonexistent/audit.log"])
    assert exit_code == 0
    assert "OK: 0 entries verified" in capsys.readouterr().out


def test_build_parser_defaults():
    parser = build_parser()
    args = parser.parse_args(["run", "--", "python3", "server.py"])
    assert args.config == "policies/default.yaml"
    assert args.audit_log == "agentguard_audit.log"
    assert args.server_cmd == ["--", "python3", "server.py"]
