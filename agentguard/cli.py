"""CLI entry points:

    agentguard run [--config <policy.yaml>] -- <mcp-server-cmd...>
    agentguard check-policy [--config <policy.yaml>]
                            [--tools tools-list.json]
                            [--probe TOOL '{"arg": "value"}']
    agentguard verify-audit <audit-log-path> [--anchor "<count> <hash>"] [--anchor-file <path>]
    agentguard anchor <audit-log-path> [--write <anchor-file>]
    agentguard report <audit-log-path> [--session ID] [--json]
    agentguard approve --socket <path>      # answer the proxy's `ask` verdicts
    agentguard default-policy               # print the bundled policy, to start your own from
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

import yaml

from .approval import (
    DEFAULT_TIMEOUT_SECONDS,
    ApprovalBroker,
    ApprovalClient,
    ApprovalServer,
    supports_unix_sockets,
    terminal_prompt,
)
from .audit import Anchor, AuditLog, read_anchor_file, verify_audit_log
from .grants import GrantStore
from .injection import InjectionDetector
from .policy import PolicyEngine
from .proxy import MCPProxy
from .redact import SecretRedactor
from .report import build_report, render_text
from .session import Session
from .validate import PolicyError, load_policy

# The default policy ships inside the package, so `agentguard run` works
# straight after `pip install` rather than only from a clone. It is the
# only policy used implicitly: nothing is picked up from the current
# directory, and --config is the only way to use a different one.
DEFAULT_POLICY = str(Path(__file__).resolve().parent / "policies" / "default.yaml")

# check-policy --probe exit code when the probed call would be denied.
# Distinct from 1 (invalid policy) and 2 (usage error) so scripts can
# tell "your policy is broken" from "your policy said no".
PROBE_DENIED_EXIT = 3
PROBE_ASK_EXIT = 4

# Where 0.1.x looked for the policy when --config was omitted.
LEGACY_DEFAULT_POLICY = os.path.join("policies", "default.yaml")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="Minimal-privilege proxy for MCP tool calls.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the proxy in front of an MCP server")
    run_parser.add_argument("--config", default=None, help="Path to policy YAML file (default: the policy bundled with agentguard)")
    run_parser.add_argument("--audit-log", default="agentguard_audit.log", help="Path to audit log file")
    run_parser.add_argument(
        "server_cmd",
        nargs=argparse.REMAINDER,
        help="MCP server command to wrap, e.g. -- python3 server.py",
    )

    check_parser = subparsers.add_parser(
        "check-policy",
        help="Validate a policy file, print the effective policy, and optionally probe a call against it",
    )
    check_parser.add_argument("--config", default=None, help="Path to policy YAML file (default: the policy bundled with agentguard)")
    check_parser.add_argument(
        "--tools",
        metavar="TOOLS_JSON",
        help="A saved tools/list result (or its `tools` array) so --probe can classify by schema, as the proxy would",
    )
    check_parser.add_argument(
        "--probe",
        nargs=2,
        metavar=("TOOL", "JSON_ARGS"),
        help="Evaluate one call — a tool name and its arguments as JSON — and explain the decision",
    )

    verify_parser = subparsers.add_parser(
        "verify-audit", help="Verify a hash-chained audit log for tampering"
    )
    verify_parser.add_argument("audit_log", help="Path to the audit log file to verify")
    verify_parser.add_argument(
        "--anchor", action="append", default=[], metavar="ANCHOR",
        help='An anchor to check the chain against: "<count> <hash>" as printed by `agentguard anchor`, '
             "or a bare hash. May be repeated.",
    )
    verify_parser.add_argument(
        "--anchor-file", metavar="PATH",
        help="A file of anchors, one per line (the policy's anchor_file, or one you kept elsewhere)",
    )

    anchor_parser = subparsers.add_parser(
        "anchor",
        help="Print the audit chain's current head — <count> <hash> — to keep somewhere the log's attacker can't reach",
    )
    anchor_parser.add_argument("audit_log", help="Path to the audit log file")
    anchor_parser.add_argument("--write", metavar="ANCHOR_FILE", help="Also append it to this anchor file")

    approve_parser = subparsers.add_parser(
        "approve",
        help="Connect to a running proxy's approval socket and answer its `ask` verdicts",
    )
    approve_parser.add_argument("--socket", required=True, help="The approval_socket path from the proxy's policy")

    report_parser = subparsers.add_parser(
        "report",
        help="What did the agent touch? Files, hosts, commands, blocks, redactions — per session, from the audit log",
    )
    report_parser.add_argument("audit_log", help="Path to the audit log file to report on")
    report_parser.add_argument("--session", metavar="ID", help="Only the session whose id starts with ID")
    report_parser.add_argument("--json", action="store_true", help="Machine-readable output")

    subparsers.add_parser(
        "default-policy",
        help="Print the policy bundled with agentguard (the default for --config), to save and edit as your own",
    )

    return parser


def _resolve_config(args: argparse.Namespace, err=None) -> str:
    """`--config` if given, else the bundled policy. 0.1.x read
    `policies/default.yaml` from the working directory when --config was
    omitted; if that file is here, say plainly that it is being ignored
    rather than let an upgrade drop someone's edits without a word."""
    if args.config is not None:
        return args.config
    if os.path.isfile(LEGACY_DEFAULT_POLICY):
        print(
            f"agentguard: using the policy bundled with agentguard ({DEFAULT_POLICY}). "
            f"./{LEGACY_DEFAULT_POLICY} is not read unless you pass --config {LEGACY_DEFAULT_POLICY} "
            "(0.1.x read it implicitly).",
            file=err if err is not None else sys.stderr,
        )
    return DEFAULT_POLICY


def _load_config_or_exit(path: str, parser: argparse.ArgumentParser) -> dict:
    try:
        return load_policy(path)
    except FileNotFoundError:
        parser.error(f"policy config file not found: {path}")
    except yaml.YAMLError as e:
        parser.error(f"failed to parse policy config {path}: {e}")
    except PolicyError as e:
        parser.error(f"policy config {path} is invalid:\n  " + "\n  ".join(e.errors))
    raise AssertionError("unreachable")


def _run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    server_cmd = args.server_cmd
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]
    if not server_cmd:
        parser.error("missing MCP server command; usage: agentguard run --config <policy.yaml> -- <cmd...>")

    args.config = _resolve_config(args)
    raw_config = _load_config_or_exit(args.config, parser)
    policy = PolicyEngine(raw_config)
    redactor = SecretRedactor.from_config(raw_config)
    injection_detector = InjectionDetector.from_config(raw_config)
    audit = AuditLog(
        args.audit_log,
        anchor_file=raw_config.get("anchor_file"),
        anchor_every=int(raw_config.get("anchor_every", 100)),
    )
    session = Session.new(server_cmd, policy.classifier, policy_path=args.config)
    approver = _build_approver(raw_config, session)
    proxy = MCPProxy(
        server_cmd, policy, audit,
        redactor=redactor, injection_detector=injection_detector, session=session,
        approver=approver,
    )
    return proxy.run()


def _build_approver(config: dict, session: Session):
    """The approval channel, if the policy configures one and the
    platform can provide it. Otherwise None — and a line on stderr, so
    "why is every ask denied?" has an answer without reading the log."""
    path = config.get("approval_socket")
    if not path:
        return None
    timeout = float(config.get("approval_timeout", DEFAULT_TIMEOUT_SECONDS))
    if not supports_unix_sockets():
        print(
            f"agentguard: approval_socket is set ({path}) but this platform has no Unix domain "
            "sockets; every `ask` verdict will be denied. (Named-pipe support is planned.)",
            file=sys.stderr,
        )
        return None
    broker = ApprovalBroker(timeout=timeout)
    return ApprovalServer(broker, path, session=session, grants_file=config.get("grants_file"))


def _approve(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if not supports_unix_sockets():
        parser.error("agentguard approve needs Unix domain sockets, which this platform does not provide")
    client = ApprovalClient(args.socket, terminal_prompt, output=sys.stdout)
    try:
        answered = client.run()
    except FileNotFoundError:
        parser.error(f"no proxy is listening at {args.socket} (is `agentguard run` up, with approval_socket set?)")
    except KeyboardInterrupt:
        print()
        return 130
    print(f"proxy went away; {answered} verdict(s) given.")
    return 0


def _file_sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _print_effective_policy(path: str, config: dict, out) -> None:
    print(f"policy: {path}  (sha256 {_file_sha256(path)[:16]}...)", file=out)
    mode = config.get("unclassified_arguments", "allow")
    note = "" if mode == "deny" else "  (deny is the secure setting)"
    print(f"unclassified_arguments: {mode}{note}", file=out)

    for category, kind in (("file_access", "glob"), ("command_exec", "regex"), ("network", "hostname glob")):
        section = config.get(category) or {}
        enabled = section.get("enabled", True)
        deny = section.get("deny_patterns") or []
        allow = section.get("allow_patterns") or []
        default_action = section.get("default_action", "allow")
        status = "enabled" if enabled else "DISABLED"
        summary = f"{len(deny)} deny, {len(allow)} allow ({kind})"
        if allow:
            summary += f", default_action: {default_action}"
        print(f"{category}: {status}, {summary}", file=out)
        for entry in deny:
            if isinstance(entry, dict):
                print(f"  {entry.get('action', 'deny'):<6} {entry['pattern']}", file=out)
            else:
                print(f"  deny   {entry}", file=out)
        for pattern in allow:
            print(f"  allow  {pattern}", file=out)
        if allow and default_action == "allow":
            print("  note: allow_patterns has no effect while default_action is 'allow'", file=out)

    overrides = config.get("tools") or {}
    if overrides:
        print(f"tools: {len(overrides)} override(s)", file=out)
        for tool_name, override in overrides.items():
            override = override or {}
            if override.get("enabled") is False:
                print(f"  {tool_name}: DISABLED", file=out)
                continue
            parts = []
            for key, value in override.items():
                if isinstance(value, dict):
                    parts.extend(f"{key}.{k}={v!r}" for k, v in value.items())
                else:
                    parts.append(f"{key}={value!r}")
            print(f"  {tool_name}: {', '.join(parts)}", file=out)

    budgets = config.get("budgets") or {}
    if budgets:
        print("budgets: " + ", ".join(f"{k}={v}" for k, v in budgets.items()), file=out)

    grants_file = config.get("grants_file")
    if config.get("approval_socket"):
        print(f"approval_socket: {config['approval_socket']}  (timeout {config.get('approval_timeout', DEFAULT_TIMEOUT_SECONDS):g}s)", file=out)
    if grants_file:
        store = GrantStore(grants_file)
        print(f"grants_file: {grants_file}  ({len(store.grants)} persistent grant(s) — operator `always` answers, not policy)", file=out)
        for g in store.grants:
            print(f"  grant  {g.scope}   ({g.granted_at}, session {g.session_id[:12]})", file=out)

    for section_name in ("redaction", "injection_detection"):
        section = config.get(section_name) or {}
        enabled = section.get("enabled", True)
        status = "enabled" if enabled else "DISABLED"
        if "rules" in section:
            names = [r["name"] for r in section.get("rules") or []]
            print(f"{section_name}: {status}, {len(names)} rules: {', '.join(names)}", file=out)
        else:
            print(f"{section_name}: {status}, built-in default rules", file=out)


def _load_tools_json(path: str, parser: argparse.ArgumentParser):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        parser.error(f"could not read --tools file {path}: {e}")
    # Accept a full JSON-RPC response, a bare result, or the tools array.
    if isinstance(data, dict) and "result" in data:
        data = data["result"]
    if isinstance(data, dict) and "tools" in data:
        data = data["tools"]
    if not isinstance(data, list):
        parser.error(f"--tools file {path}: expected a tools/list response, result, or tools array")
    return data


def _check_policy(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    args.config = _resolve_config(args)
    config = _load_config_or_exit(args.config, parser)
    engine = PolicyEngine(config)
    _print_effective_policy(args.config, config, sys.stdout)
    print("OK: policy is valid.")

    if args.tools:
        registered = engine.classifier.register_tools(_load_tools_json(args.tools, parser))
        print(f"tools: {registered} schema(s) loaded from {args.tools}: {', '.join(engine.classifier.known_tools)}")

    if not args.probe:
        return 0

    tool_name, raw_args = args.probe
    try:
        arguments = json.loads(raw_args)
    except json.JSONDecodeError as e:
        parser.error(f"--probe arguments are not valid JSON: {e}")
    if not isinstance(arguments, dict):
        parser.error("--probe arguments must be a JSON object")

    decision = engine.evaluate(tool_name, arguments)
    print()
    print(f"probe: {tool_name} {json.dumps(arguments)}")
    if not decision.arguments:
        print("  (no string arguments to classify)")
    for arg in decision.arguments:
        category = arg.category or "UNCLASSIFIED"
        print(f"  {arg.key} = {arg.value!r}  ->  {category} ({arg.source})")
    verdict = decision.action.upper()
    rule = f"  matched_rule={decision.matched_rule}" if decision.matched_rule else ""
    print(f"decision: {verdict}  category={decision.category}{rule}")
    print(f"reason: {decision.reason}")
    if decision.action == "ask":
        print("note: ASK needs an approval channel at runtime (approval_socket); without one it is denied")
        return PROBE_ASK_EXIT
    return 0 if decision.allowed else PROBE_DENIED_EXIT


def _verify_audit(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    anchors = []
    try:
        anchors.extend(Anchor.parse(text) for text in args.anchor)
        if args.anchor_file:
            anchors.extend(read_anchor_file(args.anchor_file))
    except ValueError as e:
        parser.error(f"bad anchor: {e}")
    except OSError as e:
        parser.error(f"could not read anchor file: {e}")

    result = verify_audit_log(args.audit_log, anchors)
    if result.valid:
        anchored = f", {result.anchors_checked} anchor(s) matched" if anchors else ""
        print(f"OK: {result.entry_count} entries verified, hash chain intact{anchored}.")
        return 0
    print(f"TAMPERED: {result.error} (verified {result.entry_count} entries before the break)")
    return 1


def _anchor(args: argparse.Namespace) -> int:
    result = verify_audit_log(args.audit_log)
    if not result.valid:
        print(f"TAMPERED: {result.error} — refusing to anchor a broken chain")
        return 1
    line = f"{result.entry_count} {result.head_hash}"
    print(line)
    if args.write:
        with open(args.write, "a", encoding="utf-8") as f:
            f.write(f"{time.time():.3f} {line}\n")
    return 0


def _report(args: argparse.Namespace) -> int:
    report = build_report(args.audit_log, args.session)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_text(report))
    return 0 if report["chain"]["valid"] else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return _run(args, parser)
    if args.command == "check-policy":
        return _check_policy(args, parser)
    if args.command == "verify-audit":
        return _verify_audit(args, parser)
    if args.command == "anchor":
        return _anchor(args)
    if args.command == "report":
        return _report(args)
    if args.command == "approve":
        return _approve(args, parser)
    if args.command == "default-policy":
        with open(DEFAULT_POLICY, "r", encoding="utf-8") as f:
            sys.stdout.write(f.read())
        return 0
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
