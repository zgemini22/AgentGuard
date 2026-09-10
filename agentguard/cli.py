"""CLI entry points:

    agentguard run --config policies/default.yaml -- <mcp-server-cmd...>
    agentguard check-policy [--config policies/default.yaml]
                            [--tools tools-list.json]
                            [--probe TOOL '{"arg": "value"}']
    agentguard verify-audit <audit-log-path>
    agentguard report <audit-log-path> [--session ID] [--json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import List, Optional

import yaml

from .audit import AuditLog, verify_audit_log
from .injection import InjectionDetector
from .policy import PolicyEngine
from .proxy import MCPProxy
from .redact import SecretRedactor
from .report import build_report, render_text
from .session import Session
from .validate import PolicyError, load_policy

# check-policy --probe exit code when the probed call would be denied.
# Distinct from 1 (invalid policy) and 2 (usage error) so scripts can
# tell "your policy is broken" from "your policy said no".
PROBE_DENIED_EXIT = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="Minimal-privilege proxy for MCP tool calls.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the proxy in front of an MCP server")
    run_parser.add_argument("--config", default="policies/default.yaml", help="Path to policy YAML file")
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
    check_parser.add_argument("--config", default="policies/default.yaml", help="Path to policy YAML file")
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

    report_parser = subparsers.add_parser(
        "report",
        help="What did the agent touch? Files, hosts, commands, blocks, redactions — per session, from the audit log",
    )
    report_parser.add_argument("audit_log", help="Path to the audit log file to report on")
    report_parser.add_argument("--session", metavar="ID", help="Only the session whose id starts with ID")
    report_parser.add_argument("--json", action="store_true", help="Machine-readable output")

    return parser


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

    raw_config = _load_config_or_exit(args.config, parser)
    policy = PolicyEngine(raw_config)
    redactor = SecretRedactor.from_config(raw_config)
    injection_detector = InjectionDetector.from_config(raw_config)
    audit = AuditLog(args.audit_log)
    session = Session.new(server_cmd, policy.classifier, policy_path=args.config)
    proxy = MCPProxy(
        server_cmd, policy, audit,
        redactor=redactor, injection_detector=injection_detector, session=session,
    )
    return proxy.run()


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
        for pattern in deny:
            print(f"  deny   {pattern}", file=out)
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
    verdict = "ALLOW" if decision.allowed else "DENY"
    rule = f"  matched_rule={decision.matched_rule}" if decision.matched_rule else ""
    print(f"decision: {verdict}  category={decision.category}{rule}")
    print(f"reason: {decision.reason}")
    return 0 if decision.allowed else PROBE_DENIED_EXIT


def _verify_audit(args: argparse.Namespace) -> int:
    result = verify_audit_log(args.audit_log)
    if result.valid:
        print(f"OK: {result.entry_count} entries verified, hash chain intact.")
        return 0
    print(f"TAMPERED: {result.error} (verified {result.entry_count} entries before the break)")
    return 1


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
        return _verify_audit(args)
    if args.command == "report":
        return _report(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
