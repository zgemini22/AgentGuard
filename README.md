# AgentGuard

A minimal-privilege proxy for AI agent tool calls. AgentGuard sits between
an MCP client (e.g. Claude Code) and an MCP server, and enforces a policy
on every `tools/call` before it reaches the real server.

Status: early Week 1 build — the core interception layer and a v1 policy
engine. Prompt-injection detection, secret redaction, and tamper-evident
audit logging are planned for later and not implemented yet (see
[What's not here yet](#whats-not-here-yet)).

## Architecture

```
agent (MCP client) --stdio--> agentguard proxy --stdio--> real MCP server
                                    |
                                    v
                              policy engine (YAML)
                                    |
                                    v
                              audit log (JSONL)
```

The proxy speaks the MCP stdio transport (newline-delimited JSON-RPC 2.0)
on both sides. Every message that isn't a `tools/call` is passed through
untouched. A `tools/call` request is evaluated against the policy before
it is forwarded:

- **allowed** — forwarded to the real server, response passed back to the agent.
- **denied** — the real server never sees the request; the agent gets a
  JSON-RPC error back immediately.

Either way, the decision is recorded in the audit log.

## Policy engine (v1)

Rules live in a YAML file (see `policies/default.yaml`) with three
independent categories:

- `file_access` — glob deny-patterns matched against path-like arguments
  (`path`, `file`, `filename`, ...). Default policy blocks `~/.ssh/**`,
  `.env` files, AWS credentials, `*.pem`/`*.key`, etc.
- `command_exec` — regex deny-patterns matched against command-like
  arguments (`command`, `cmd`, `script`, `shell`). Default policy blocks
  `rm -rf /`, `curl | bash`-style pipe-to-shell, fork bombs.
- `network` — glob allowlist matched against the hostname of URL-like
  arguments (`url`, `uri`, `host`, `domain`); anything not on the list is
  denied when `default_action: deny`.

Argument matching is by key name, not by a fixed tool allowlist, since
MCP servers don't share one schema — this is a deliberate v1
simplification, see [What's not here yet](#whats-not-here-yet).

## Quickstart

```bash
pip install -e .

# Wrap any MCP server with the proxy:
agentguard run --config policies/default.yaml -- python3 your_mcp_server.py
```

The agent talks to the `agentguard` process exactly as it would to the
wrapped server directly (same stdio transport) — only the policy checks
are new.

## 30-second demo

```bash
./demo/run_demo.sh
```

This spins up `demo/vulnerable_server.py` — an intentionally unrestricted
MCP-style server with one `read_file` tool — and shows:

1. Without AgentGuard, a request for `~/.ssh/id_rsa` just returns the key.
2. With AgentGuard in front of the same server, the same request is
   blocked and logged.
3. A normal file read still goes through unaffected.

## Tests

```bash
pip install -e . pytest
pytest
```

Covers the policy engine's allow/deny decisions per category, and an
end-to-end proxy test asserting a blocked call never reaches the wrapped
server (the secret string never appears in the response) while a normal
call round-trips correctly.

## What's not here yet

Deliberately out of scope for this milestone, per the project plan:

- Prompt-injection detection on tool *output* (rule-based + LLM layer)
- Secret/API-key redaction in tool output
- Tamper-evident (hash-chained) audit log — current log is plain
  append-only JSONL
- Multi-agent/multi-transport support beyond MCP stdio
- Any GUI
