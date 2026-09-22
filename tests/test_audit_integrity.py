"""What the hash chain can and can't show, and the pieces that make its
guarantees hold in practice: anchors at session boundaries, one chain
across several writers, and honest answers for missing or damaged logs."""

import json
import os
import stat
import subprocess
import sys

import pytest

from agentguard.audit import AuditLog, read_anchor_file, verify_audit_log
from agentguard.cli import main
from agentguard.policy import Decision
from agentguard.session import Session


def run_session(path, anchor_file=None, calls=3):
    log = AuditLog(str(path), anchor_file=str(anchor_file) if anchor_file else None)
    session = Session.new(["server"])
    log.begin_session(session)
    for i in range(calls):
        log.record("read_file", {"path": f"/tmp/{i}"}, Decision(True, "file_access", "ok"))
    log.end_session(session, 0)
    return log


def drop_last_lines(path, n):
    lines = path.read_text().splitlines(keepends=True)
    path.write_text("".join(lines[:-n]))


def test_session_start_and_end_are_anchored(tmp_path):
    log = run_session(tmp_path / "a.log", anchor_file=tmp_path / "anchors")
    anchors = read_anchor_file(str(tmp_path / "anchors"))
    assert [a.count for a in anchors] == [1, log.head()[0]]


def test_deleting_the_tail_is_caught_with_the_session_end_anchor(tmp_path):
    path = tmp_path / "a.log"
    run_session(path, anchor_file=tmp_path / "anchors")
    drop_last_lines(path, 2)
    anchors = read_anchor_file(str(tmp_path / "anchors"))
    result = verify_audit_log(str(path), anchors)
    assert not result.valid
    assert "truncated" in result.error


def test_without_an_anchor_verify_says_the_tail_is_not_covered(tmp_path, capsys):
    path = tmp_path / "a.log"
    run_session(path)
    assert main(["verify-audit", str(path)]) == 0
    assert "without an anchor" in capsys.readouterr().out
    drop_last_lines(path, 2)
    assert main(["verify-audit", str(path)]) == 0  # still a valid prefix...
    assert "the last entry is not a session_end" in capsys.readouterr().out  # ...and verify says so


def test_two_writers_on_one_log_extend_one_chain(tmp_path):
    path = str(tmp_path / "shared.log")
    a, b = AuditLog(path), AuditLog(path)
    for i in range(5):
        a.record("t", {"i": i}, Decision(True, "none", "a"))
        b.record("t", {"i": i}, Decision(True, "none", "b"))
    result = verify_audit_log(path)
    assert result.valid, result.error
    assert result.entry_count == 10


def test_concurrent_processes_extend_one_chain(tmp_path):
    path = str(tmp_path / "shared.log")
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "from agentguard.audit import AuditLog\n"
        "from agentguard.policy import Decision\n"
        "log = AuditLog(%r)\n"
        "for i in range(40):\n"
        "    log.record('t', {'i': i}, Decision(True, 'none', 'x'))\n"
    ) % (os.path.dirname(os.path.dirname(os.path.abspath(__file__))), path)
    procs = [subprocess.Popen([sys.executable, "-c", code]) for _ in range(4)]
    assert all(p.wait(timeout=120) == 0 for p in procs)
    result = verify_audit_log(path)
    assert result.valid, result.error
    assert result.entry_count == 160


def test_a_partial_last_line_is_not_glued_to_the_next_entry(tmp_path):
    path = tmp_path / "a.log"
    run_session(path)
    with open(path, "a") as f:
        f.write('{"event": "policy_decision", "trunc')  # a writer died mid-line
    log = AuditLog(str(path))
    log.record("t", {}, Decision(True, "none", "after the crash"))
    last = path.read_text().splitlines()[-1]
    assert json.loads(last)["reason"] == "after the crash"
    result = verify_audit_log(str(path))
    assert not result.valid and "not valid JSON" in result.error


def test_a_non_object_line_is_reported_not_crashed_on(tmp_path):
    path = tmp_path / "a.log"
    path.write_text("[1, 2, 3]\n")
    result = verify_audit_log(str(path))
    assert not result.valid
    assert "not a JSON object" in result.error


def test_anchor_refuses_an_empty_log(tmp_path, capsys):
    path = tmp_path / "empty.log"
    path.write_text("")
    anchors = tmp_path / "anchors"
    assert main(["anchor", str(path), "--write", str(anchors)]) == 1
    assert not anchors.exists()


def test_unwritable_anchor_file_does_not_crash_the_log(tmp_path, capsys):
    log = run_session(tmp_path / "a.log", anchor_file=tmp_path / "no-such-dir" / "anchors")
    assert verify_audit_log(str(tmp_path / "a.log")).valid
    assert "could not write anchor" in capsys.readouterr().err
    assert log.head()[0] == 5


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_new_log_is_readable_by_its_owner_only(tmp_path):
    path = tmp_path / "a.log"
    run_session(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
