"""CLI entry points:

    agentguard run --config policies/default.yaml -- <mcp-server-cmd...>
    agentguard verify-audit <audit-log-path>
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

import yaml

from .audit import AuditLog, verify_audit_log
from .injection import InjectionDetector
from .policy import PolicyEngine
from .proxy import MCPProxy
from .redact import SecretRedactor


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

    verify_parser = subparsers.add_parser(
        "verify-audit", help="Verify a hash-chained audit log for tampering"
    )
    verify_parser.add_argument("audit_log", help="Path to the audit log file to verify")

    return parser


def _run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    server_cmd = args.server_cmd
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]
    if not server_cmd:
        parser.error("missing MCP server command; usage: agentguard run --config <policy.yaml> -- <cmd...>")

    with open(args.config, "r") as f:
        raw_config = yaml.safe_load(f) or {}

    policy = PolicyEngine(raw_config)
    redactor = SecretRedactor.from_config(raw_config)
    injection_detector = InjectionDetector.from_config(raw_config)
    audit = AuditLog(args.audit_log)
    proxy = MCPProxy(server_cmd, policy, audit, redactor=redactor, injection_detector=injection_detector)
    return proxy.run()


def _verify_audit(args: argparse.Namespace) -> int:
    result = verify_audit_log(args.audit_log)
    if result.valid:
        print(f"OK: {result.entry_count} entries verified, hash chain intact.")
        return 0
    print(f"TAMPERED: {result.error} (verified {result.entry_count} entries before the break)")
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        return _run(args, parser)
    if args.command == "verify-audit":
        return _verify_audit(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
