# AgentGuard

A minimal-privilege proxy for AI agent tool calls. AgentGuard sits between
an MCP client (e.g. Claude Code) and an MCP server, and enforces a policy
on every `tools/call` before it reaches the real server.

Status: Week 1-3 build — the core interception layer, a v1 policy engine,
and output-side secret redaction. Prompt-injection detection and
tamper-evident audit logging are planned for later and not implemented
yet (see [What's not here yet](#whats-not-here-yet)).

## Architecture

```
                              policy engine (YAML)         secret redactor
                                    |                             |
                                    v                             v
agent (MCP client) --stdio--> agentguard proxy <---------------------> real MCP server
                                    |
                                    v
                              audit log (JSONL)
```

The proxy speaks the MCP stdio transport (newline-delimited JSON-RPC 2.0)
on both sides.

**Requests** (agent -> server): every message that isn't a `tools/call`
is passed through untouched. A `tools/call` request is evaluated against
the policy before it is forwarded:

- **allowed** — forwarded to the real server.
- **denied** — the real server never sees the request; the agent gets a
  JSON-RPC error back immediately.

**Responses** (server -> agent): the text content of a `tools/call`
result — for a call the policy just allowed — is scanned by the secret
redactor before being forwarded on. A tool call can be legitimate and
still return something (an accidentally-committed `.env`, a token in an
API response) that shouldn't reach the agent's context unmasked; matched
secrets are replaced with `[REDACTED:<rule-name>]` in place.

Every policy decision and every redaction is recorded in the audit log.

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

## Secret redaction (v1)

A separate `redaction` section in the same YAML config (see
`policies/default.yaml`) lists named regex rules — AWS/GitHub/Slack key
formats, PEM private key blocks, JWTs, a generic `key: "..."` pattern.
Omit `rules` to fall back to `agentguard.redact.DEFAULT_RULES`. This is
known-format matching, not entropy-based secret detection — no
statistical guessing until there's real traffic to tune false-positive
rates against.

## Quickstart

```bash
pip install -e .

# Wrap any MCP server with the proxy:
agentguard run --config policies/default.yaml -- python3 your_mcp_server.py
```

The agent talks to the `agentguard` process exactly as it would to the
wrapped server directly (same stdio transport) — only the policy checks
are new.

## Demo

```bash
./demo/run_demo.sh
```

This spins up `demo/vulnerable_server.py` — an intentionally unrestricted
MCP-style server with one `read_file` tool — and shows:

1. Without AgentGuard, a request for `~/.ssh/id_rsa` just returns the key.
2. With AgentGuard in front of the same server, the same request is
   blocked and logged.
3. A normal file read still goes through unaffected.
4. A file that merely *contains* a secret (an AWS key inside some notes)
   isn't blocked — the read is allowed, but the key is redacted from the
   response, and the redaction is logged.

## Tests

```bash
pip install -e . pytest
pytest
```

Covers the policy engine's allow/deny decisions per category, the
redactor's pattern matching, and end-to-end proxy tests asserting: a
blocked call never reaches the wrapped server and its secret never
appears in the response; a normal call round-trips correctly; an
allowed call's output gets a matched secret redacted and logged.

## What's not here yet

Deliberately out of scope for this milestone, per the project plan:

- Prompt-injection detection on tool *output* (rule-based + LLM layer)
- Entropy-based secret detection (current redaction is known-format regex only)
- Tamper-evident (hash-chained) audit log — current log is plain
  append-only JSONL
- Multi-agent/multi-transport support beyond MCP stdio
- Any GUI
