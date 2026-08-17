import json
import os
import tempfile

from agentguard.audit import GENESIS_HASH, AuditLog, compute_entry_hash, verify_audit_log
from agentguard.policy import Decision


def make_log(path):
    return AuditLog(path)


def test_first_entry_chains_to_genesis():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.log")
        log = make_log(path)
        entry = log.record("read_file", {"path": "/tmp/x"}, Decision(True, "file_access", "ok"))
        assert entry["prev_hash"] == GENESIS_HASH
        assert entry["hash"] == compute_entry_hash(entry)


def test_second_entry_chains_to_first():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.log")
        log = make_log(path)
        first = log.record("read_file", {"path": "/tmp/x"}, Decision(True, "file_access", "ok"))
        second = log.record_redaction("read_file", ["aws_access_key_id"])
        assert second["prev_hash"] == first["hash"]


def test_verify_empty_or_missing_log_is_valid():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "nonexistent.log")
        result = verify_audit_log(path)
        assert result.valid is True
        assert result.entry_count == 0


def test_verify_untampered_log_is_valid():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.log")
        log = make_log(path)
        log.record("read_file", {"path": "/tmp/a"}, Decision(True, "file_access", "ok"))
        log.record("read_file", {"path": "/tmp/b"}, Decision(False, "file_access", "denied"))
        log.record_redaction("read_file", ["aws_access_key_id"])
        log.record_injection_block("fetch_url", ["ignore_instructions"])

        result = verify_audit_log(path)
        assert result.valid is True
        assert result.entry_count == 4


def test_verify_detects_edited_entry():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.log")
        log = make_log(path)
        log.record("read_file", {"path": "/tmp/a"}, Decision(True, "file_access", "ok"))
        log.record("read_file", {"path": "/tmp/b"}, Decision(False, "file_access", "denied"))

        lines = _read_lines(path)
        tampered = json.loads(lines[1])
        tampered["allowed"] = True  # flip a denial into an allow after the fact
        lines[1] = json.dumps(tampered)
        _write_lines(path, lines)

        result = verify_audit_log(path)
        assert result.valid is False
        assert "modified" in result.error
        assert result.entry_count == 1  # first entry still verifies fine


def test_verify_detects_deleted_entry():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.log")
        log = make_log(path)
        log.record("read_file", {"path": "/tmp/a"}, Decision(True, "file_access", "ok"))
        log.record("read_file", {"path": "/tmp/b"}, Decision(False, "file_access", "denied"))
        log.record_redaction("read_file", ["aws_access_key_id"])

        lines = _read_lines(path)
        del lines[1]  # remove the middle entry; chain from entry 1 -> entry 3 no longer lines up
        _write_lines(path, lines)

        result = verify_audit_log(path)
        assert result.valid is False
        assert "chain broken" in result.error


def test_verify_detects_appended_forged_entry():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.log")
        log = make_log(path)
        log.record("read_file", {"path": "/tmp/a"}, Decision(True, "file_access", "ok"))

        forged = {"ts": 0, "event": "policy_decision", "tool": "evil", "prev_hash": "not-the-real-hash", "hash": "also-fake"}
        with open(path, "a") as f:
            f.write(json.dumps(forged) + "\n")

        result = verify_audit_log(path)
        assert result.valid is False
        assert result.entry_count == 1


def test_reopening_an_existing_log_continues_the_chain():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "audit.log")
        first_log = make_log(path)
        first_entry = first_log.record("read_file", {"path": "/tmp/a"}, Decision(True, "file_access", "ok"))

        second_log = make_log(path)  # simulates a fresh `agentguard run` process
        second_entry = second_log.record("read_file", {"path": "/tmp/b"}, Decision(True, "file_access", "ok"))

        assert second_entry["prev_hash"] == first_entry["hash"]
        result = verify_audit_log(path)
        assert result.valid is True
        assert result.entry_count == 2


def _read_lines(path):
    with open(path) as f:
        return [l.rstrip("\n") for l in f if l.strip()]


def _write_lines(path, lines):
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
