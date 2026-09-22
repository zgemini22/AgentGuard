"""`agentguard report`: turns an audit log into an answer to "what did
the agent actually touch?"

The hash chain (audit.py) answers "was this log edited?" That was
never the question that started this project — the question was "the
agent ran for twenty minutes and I have no record of which files it
read, which hosts it talked to, or what got blocked." This module
answers it, per session, from nothing but the log file:

- files touched, grouped by directory, with what was blocked and why
- hosts contacted
- commands run
- every block, redaction, injection hit, budget event, and content the
  scanners couldn't read
- budget consumption
- a timeline

Text output for people, `--json` for machines. Nothing else: no HTML,
no charts. The chain is verified first and its status printed, because
a report over a tampered log should say so before it says anything.

Entries from before there were sessions (no `session_id`) are grouped
under a synthetic session so old logs still report.
"""

from __future__ import annotations

import json
import os
import time
from collections import OrderedDict
from typing import Dict, List, Optional

from .audit import verify_audit_log
from .classify import COMMAND_EXEC, FILE_ACCESS, NETWORK, classify_by_key_name
from .policy import file_uri_path, iter_string_arguments, url_host
from .session import parent_directory

UNSESSIONED = "(no session)"


def load_entries(path: str) -> List[dict]:
    entries: List[dict] = []
    if not os.path.exists(path):
        return entries
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
    return entries


def _classified_values(entry: dict):
    """Yields (category, value) for every string argument of a
    policy_decision entry, using the recorded classification when the
    entry has one and v1 key-name rules when it doesn't."""
    arguments = entry.get("arguments") or {}
    recorded = entry.get("argument_categories")
    for key, value in iter_string_arguments(arguments):
        if recorded is not None:
            categories = str(recorded.get(key) or "").split("+")
        else:
            guess = classify_by_key_name(key.rsplit(".", 1)[-1])
            categories = [guess.category] if guess else []
        for category in categories:
            if category == FILE_ACCESS:
                yield FILE_ACCESS, file_uri_path(value) or value
            elif category == NETWORK:
                yield NETWORK, url_host(value) or value
            elif category == COMMAND_EXEC:
                yield COMMAND_EXEC, value


def _fmt_time(ts: Optional[float]) -> str:
    if not ts:
        return "?"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _fmt_clock(ts: Optional[float]) -> str:
    if not ts:
        return "??:??:??"
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _new_session(session_id: str) -> dict:
    return {
        "id": session_id,
        "started_at": None,
        "ended_at": None,
        "duration_seconds": None,
        "server_cmd": None,
        "policy_path": None,
        "policy_sha256": None,
        "exit_code": None,
        "tools_seen": [],
        "files": OrderedDict(),      # directory -> [ {path, tool, allowed, reason, count} ]
        "hosts": OrderedDict(),      # host -> {tool, allowed, reason, count}
        "commands": [],
        "blocked": [],
        "redactions": [],
        "injections": [],
        "budget_blocks": [],
        "unscannable": [],
        "grants": [],
        "calls": {"allowed": 0, "denied": 0, "by_category": {}},
        "output_bytes": 0,
        "timeline": [],
    }


def _touch(bucket: dict, key: str, tool: str, allowed: bool, reason: Optional[str]) -> None:
    item = bucket.get(key)
    if item is None:
        bucket[key] = {"tool": tool, "allowed": allowed, "reason": None if allowed else reason, "count": 1}
        return
    item["count"] += 1
    if not allowed and item["allowed"]:
        # A blocked attempt on something also touched successfully is
        # worth surfacing over the success.
        item["allowed"] = False
        item["reason"] = reason


def build_report(path: str, session_filter: Optional[str] = None) -> dict:
    """The whole report as plain data. `session_filter` keeps only the
    session whose id starts with it."""
    verification = verify_audit_log(path)
    entries = load_entries(path)
    sessions: "OrderedDict[str, dict]" = OrderedDict()

    for entry in entries:
        session_id = entry.get("session_id") or UNSESSIONED
        session = sessions.get(session_id)
        if session is None:
            session = sessions[session_id] = _new_session(session_id)
        _fold(session, entry)

    for session in sessions.values():
        if session["started_at"] and session["ended_at"]:
            session["duration_seconds"] = round(session["ended_at"] - session["started_at"], 3)

    selected = [
        s for s in sessions.values()
        if session_filter is None or s["id"].startswith(session_filter)
    ]
    return {
        "log": path,
        "chain": {
            "valid": verification.valid,
            "entries": verification.entry_count,
            "error": verification.error,
        },
        "sessions": selected,
    }


def _fold(session: dict, entry: dict) -> None:
    event = entry.get("event")
    ts = entry.get("ts")
    tool = str(entry.get("tool", "?"))

    if event == "session_start":
        session["started_at"] = ts
        session["server_cmd"] = entry.get("server_cmd")
        session["policy_path"] = entry.get("policy_path")
        session["policy_sha256"] = entry.get("policy_sha256")
        session["timeline"].append({"ts": ts, "event": event, "summary": " ".join(entry.get("server_cmd") or [])})
        return
    if event == "session_end":
        session["ended_at"] = ts
        session["exit_code"] = entry.get("exit_code")
        session["tools_seen"] = list(entry.get("tools_seen") or [])
        session["timeline"].append({"ts": ts, "event": event, "summary": f"exit {entry.get('exit_code')}"})
        return

    if event == "policy_decision":
        allowed = bool(entry.get("allowed"))
        reason = entry.get("reason")
        category = entry.get("category")
        calls = session["calls"]
        calls["allowed" if allowed else "denied"] += 1
        touched = set()
        for arg_category, value in _classified_values(entry):
            touched.add(arg_category)
            if arg_category == FILE_ACCESS:
                directory = parent_directory(value)
                bucket = session["files"].setdefault(directory, OrderedDict())
                _touch(bucket, value, tool, allowed, reason)
            elif arg_category == NETWORK:
                _touch(session["hosts"], value, tool, allowed, reason)
            else:
                session["commands"].append({"command": value, "tool": tool, "allowed": allowed, "reason": None if allowed else reason})
        if allowed:
            for arg_category in touched:
                calls["by_category"][arg_category] = calls["by_category"].get(arg_category, 0) + 1
        else:
            session["blocked"].append({
                "ts": ts, "tool": tool, "category": category,
                "reason": reason, "matched_rule": entry.get("matched_rule"),
            })
        args = entry.get("arguments") or {}
        summary = f"{'ALLOW' if allowed else 'DENY '}  {tool} {_short_args(args)}"
        if not allowed:
            summary += f"  [{category}]"
        session["timeline"].append({"ts": ts, "event": event, "summary": summary})
        return

    if event == "redaction":
        session["redactions"].append({"ts": ts, "tool": tool, "method": entry.get("method"), "rules": entry.get("rules_matched") or []})
        session["timeline"].append({"ts": ts, "event": event, "summary": f"{tool}: {', '.join(entry.get('rules_matched') or [])}"})
    elif event == "injection_blocked":
        session["injections"].append({"ts": ts, "tool": tool, "method": entry.get("method"), "rules": entry.get("rules_matched") or []})
        session["timeline"].append({"ts": ts, "event": event, "summary": f"{tool}: {', '.join(entry.get('rules_matched') or [])}"})
    elif event == "budget_block":
        session["budget_blocks"].append({"ts": ts, "tool": tool, "budget": entry.get("budget"), "bytes": entry.get("bytes")})
        session["timeline"].append({"ts": ts, "event": event, "summary": f"{tool}: {entry.get('budget')} ({entry.get('bytes')} bytes)"})
    elif event == "unscannable_content":
        session["unscannable"].append({"ts": ts, "tool": tool, "method": entry.get("method"), "kinds": entry.get("kinds") or []})
        session["timeline"].append({"ts": ts, "event": event, "summary": f"{tool}: {', '.join(entry.get('kinds') or [])}"})
    elif event == "grant":
        session["grants"].append({k: entry.get(k) for k in ("ts", "scope", "duration", "tool")})
        session["timeline"].append({"ts": ts, "event": event, "summary": f"{entry.get('duration')}: {entry.get('scope')}"})
    else:
        session["timeline"].append({"ts": ts, "event": str(event), "summary": ""})


def _short_args(args: dict, limit: int = 80) -> str:
    text = json.dumps(args, sort_keys=True)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def render_text(report: dict) -> str:
    out: List[str] = []
    out.append(f"audit log: {report['log']}")
    chain = report["chain"]
    if chain["valid"]:
        out.append(f"chain: OK, {chain['entries']} entries verified")
    else:
        out.append(f"chain: TAMPERED — {chain['error']} ({chain['entries']} entries verified before the break)")
        out.append("       everything below is reported as written, including whatever was tampered with")
    if not report["sessions"]:
        out.append("no sessions found")
        return "\n".join(out) + "\n"

    for s in report["sessions"]:
        out.append("")
        header = f"== session {s['id'][:12]}"
        if s["started_at"]:
            header += f"  {_fmt_time(s['started_at'])}"
            if s["ended_at"]:
                header += f" -> {_fmt_clock(s['ended_at'])} ({s['duration_seconds']}s)"
            else:
                header += "  (no session_end — still running, or killed)"
        if s["exit_code"] is not None:
            header += f", exit {s['exit_code']}"
        out.append(header)
        if s["server_cmd"]:
            out.append(f"   server: {' '.join(s['server_cmd'])}")
        if s["policy_path"]:
            sha = f" (sha256 {s['policy_sha256'][:16]}...)" if s["policy_sha256"] else ""
            out.append(f"   policy: {s['policy_path']}{sha}")
        if s["tools_seen"]:
            out.append(f"   tools seen: {', '.join(s['tools_seen'])}")

        calls = s["calls"]
        out.append(f"   calls: {calls['allowed']} allowed, {calls['denied']} denied")

        out.append(_section("files touched", _count_items(s["files"].values())))
        for directory, items in s["files"].items():
            out.append(f"     {directory}{os.sep if not directory.endswith(('/', os.sep)) else ''}")
            for path, item in items.items():
                out.append(_item_line(os.path.basename(path) or path, item))
        out.append(_section("hosts contacted", len(s["hosts"])))
        for host, item in s["hosts"].items():
            out.append(_item_line(host, item))
        out.append(_section("commands run", len(s["commands"])))
        for c in s["commands"]:
            flag = "" if c["allowed"] else f"   BLOCKED  ({c['reason']})"
            out.append(f"     {c['command']!r:<40} {c['tool']}{flag}")

        out.append(_section("blocked calls", len(s["blocked"])))
        for b in s["blocked"]:
            rule = f" [{b['matched_rule']}]" if b["matched_rule"] else ""
            out.append(f"     {_fmt_clock(b['ts'])}  {b['tool']:<20} {b['category']:<14} {b['reason']}{rule}")
        out.append(_section("redactions", len(s["redactions"])))
        for r in s["redactions"]:
            out.append(f"     {_fmt_clock(r['ts'])}  {r['tool']:<20} {', '.join(r['rules'])}")
        out.append(_section("injection blocks", len(s["injections"])))
        for i in s["injections"]:
            out.append(f"     {_fmt_clock(i['ts'])}  {i['tool']:<20} {', '.join(i['rules'])}")
        if s["budget_blocks"]:
            out.append(_section("results withheld for size", len(s["budget_blocks"])))
            for b in s["budget_blocks"]:
                out.append(f"     {_fmt_clock(b['ts'])}  {b['tool']:<20} {b['budget']} ({b['bytes']} bytes)")
        if s["unscannable"]:
            out.append(_section("unscannable content passed through", len(s["unscannable"])))
            for u in s["unscannable"]:
                out.append(f"     {_fmt_clock(u['ts'])}  {u['tool']:<20} {', '.join(u['kinds'])}")
        if s["grants"]:
            out.append(_section("operator grants", len(s["grants"])))
            for g in s["grants"]:
                out.append(f"     {_fmt_clock(g['ts'])}  {g['duration']:<8} {g['scope']}")

        by_cat = ", ".join(f"{k} {v}" for k, v in sorted(calls["by_category"].items())) or "none"
        out.append(f"   budgets: allowed calls by category: {by_cat}")

        out.append("   timeline:")
        for t in s["timeline"]:
            out.append(f"     {_fmt_clock(t['ts'])}  {t['event']:<19} {t['summary']}")
    return "\n".join(out) + "\n"


def _count_items(buckets) -> int:
    return sum(len(b) for b in buckets)


def _section(title: str, count: int) -> str:
    return f"   {title}: {count if count else 'none'}"


def _item_line(name: str, item: dict) -> str:
    times = f"  x{item['count']}" if item["count"] > 1 else ""
    flag = "" if item["allowed"] else f"   BLOCKED  ({item['reason']})"
    return f"       {name:<36} {item['tool']}{times}{flag}"
