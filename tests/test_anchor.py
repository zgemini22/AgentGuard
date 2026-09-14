"""Audit chain anchoring: the primitive that catches a log rewritten
from scratch, given an anchor kept out of the attacker's reach."""

import json

import pytest

from agentguard.audit import Anchor, AuditLog, read_anchor_file, verify_audit_log
from agentguard.cli import main
from agentguard.policy import Decision


def fill(path, n, **kwargs):
    log = AuditLog(str(path), **kwargs)
    for i in range(n):
        log.record("t", {"path": f"/f{i}"}, Decision(True, "file_access", "ok"))
    return log


def rewrite_from_scratch(path, n):
    """The attack the chain alone can't see: a fresh, self-consistent
    chain with different contents."""
    path.unlink()
    fill(path, n)


# --- Anchor parsing ----------------------------------------------------

def test_anchor_parse_forms():
    h = "ab" * 32
    assert Anchor.parse(h) == Anchor(h, None)
    assert Anchor.parse(f"12 {h}") == Anchor(h, 12)
    assert Anchor.parse(f"1700000000.123 12 {h}") == Anchor(h, 12)
    assert Anchor.parse(h.upper()).hash == h
    for bad in ("", "nothex", f"x {h}", f"0 {h}", "ab" * 31):
        with pytest.raises(ValueError):
            Anchor.parse(bad)


# --- head and periodic anchoring ---------------------------------------

def test_head_counts_entries_and_survives_reopen(tmp_path):
    path = tmp_path / "audit.log"
    log = fill(path, 3)
    count, digest = log.head()
    assert count == 3
    assert verify_audit_log(str(path)).head_hash == digest
    reopened = AuditLog(str(path))
    assert reopened.head() == (3, digest)


def test_periodic_anchor_file(tmp_path):
    path = tmp_path / "audit.log"
    anchors_path = tmp_path / "anchors.txt"
    log = fill(path, 7, anchor_file=str(anchors_path), anchor_every=3)
    anchors = read_anchor_file(str(anchors_path))
    assert [a.count for a in anchors] == [3, 6]
    result = verify_audit_log(str(path), anchors)
    assert result.valid is True
    assert result.anchors_checked == 2
    log.write_anchor()
    assert [a.count for a in read_anchor_file(str(anchors_path))] == [3, 6, 7]


# --- verification against anchors --------------------------------------

def test_anchor_catches_a_rewritten_log(tmp_path):
    path = tmp_path / "audit.log"
    log = fill(path, 5)
    count, digest = log.head()
    anchor = Anchor(digest, count)

    assert verify_audit_log(str(path), [anchor]).valid is True

    rewrite_from_scratch(path, 5)
    assert verify_audit_log(str(path)).valid is True  # the chain alone is fooled
    result = verify_audit_log(str(path), [anchor])
    assert result.valid is False
    assert "anchor mismatch at entry #5" in result.error
    assert "rewritten since the anchor was taken" in result.error


def test_anchor_catches_truncation(tmp_path):
    path = tmp_path / "audit.log"
    log = fill(path, 5)
    count, digest = log.head()
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:3]) + "\n")
    result = verify_audit_log(str(path), [Anchor(digest, count)])
    assert result.valid is False
    assert "log has only 3" in result.error


def test_bare_hash_anchor_matches_anywhere_in_chain(tmp_path):
    path = tmp_path / "audit.log"
    log = fill(path, 3)
    _, digest_at_3 = log.head()
    fill(path, 2)  # reopen and extend
    assert verify_audit_log(str(path), [Anchor(digest_at_3)]).valid is True
    result = verify_audit_log(str(path), [Anchor("ef" * 32)])
    assert result.valid is False
    assert "appears nowhere in the chain" in result.error


def test_older_anchor_still_matches_a_grown_log(tmp_path):
    path = tmp_path / "audit.log"
    log = fill(path, 4)
    count, digest = log.head()
    fill(path, 10)
    assert verify_audit_log(str(path), [Anchor(digest, count)]).valid is True


# --- CLI ---------------------------------------------------------------

def test_anchor_command_prints_and_writes(tmp_path, capsys):
    path = tmp_path / "audit.log"
    fill(path, 4)
    anchors_path = tmp_path / "kept-elsewhere.txt"
    assert main(["anchor", str(path), "--write", str(anchors_path)]) == 0
    out = capsys.readouterr().out.strip()
    count, digest = out.split()
    assert count == "4" and len(digest) == 64
    assert read_anchor_file(str(anchors_path)) == [Anchor(digest, 4)]

    assert main(["verify-audit", str(path), "--anchor", out]) == 0
    assert "1 anchor(s) matched" in capsys.readouterr().out
    assert main(["verify-audit", str(path), "--anchor-file", str(anchors_path)]) == 0
    capsys.readouterr()

    rewrite_from_scratch(path, 4)
    assert main(["verify-audit", str(path)]) == 0  # fooled
    capsys.readouterr()
    assert main(["verify-audit", str(path), "--anchor", out]) == 1
    assert "TAMPERED: anchor mismatch" in capsys.readouterr().out


def test_anchor_command_refuses_a_broken_chain(tmp_path, capsys):
    path = tmp_path / "audit.log"
    fill(path, 2)
    lines = path.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["tool"] = "evil"
    lines[0] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n")
    assert main(["anchor", str(path)]) == 1
    assert "refusing to anchor a broken chain" in capsys.readouterr().out


def test_verify_rejects_malformed_anchor(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["verify-audit", str(tmp_path / "x.log"), "--anchor", "nonsense"])
    assert exc_info.value.code == 2
    assert "bad anchor" in capsys.readouterr().err
