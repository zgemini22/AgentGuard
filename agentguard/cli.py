"""CLI entry point: `agentguard run --config policies/default.yaml -- <mcp-server-cmd...>`."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .audit import AuditLog
from .policy import PolicyEngine
from .proxy import MCPProxy


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
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    server_cmd = args.server_cmd
    if server_cmd and server_cmd[0] == "--":
        server_cmd = server_cmd[1:]
    if not server_cmd:
        parser.error("missing MCP server command; usage: agentguard run --config <policy.yaml> -- <cmd...>")

    policy = PolicyEngine.from_yaml(args.config)
    audit = AuditLog(args.audit_log)
    proxy = MCPProxy(server_cmd, policy, audit)
    return proxy.run()


if __name__ == "__main__":
    sys.exit(main())
