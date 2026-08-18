# Threat model

What AgentGuard defends against, what it explicitly doesn't, and the
assumptions the whole design rests on. Written down on purpose: a
security tool that doesn't say what it's *not* for is a tool nobody can
actually reason about deploying.

## Actors

- **The user** — runs the agent, owns the machine and credentials the
  agent has access to. Trusted.
- **The agent** (the LLM driving tool calls, e.g. Claude Code) — trusted
  to *want* to do what the user asked, not trusted to always resist
  manipulation by content it reads. This is the actor the injection
  detector exists for.
- **The MCP server** — whatever tool backend the agent is calling
  (a filesystem tool, a web-fetch tool, a shell tool, ...). Not
  trusted: it may be third-party code, and even first-party code can
  have bugs that turn "read a file" into "read any file."
  AgentGuard's whole job is mediating between the agent and this actor.
- **External content** — anything a tool call fetches or reads that
  originated outside the user's control (a web page, an email, a file
  someone else wrote, a dependency's README). Actively adversarial:
  this is where injected instructions and leaked secrets come from.

## Assets being protected

- Files an attacker shouldn't be able to read or write via the agent:
  SSH keys, cloud credentials, `.env` files, arbitrary filesystem access
  beyond what a task needs.
- The shell: arbitrary command execution, especially anything that
  pulls and runs remote code (`curl | bash`).
- Network egress: the agent talking to hosts it has no reason to talk
  to (exfiltration destinations, C2, unreviewed package registries).
- The agent's own instruction-following: external content should never
  be able to make the agent do something the user didn't ask for.
- An accurate record of what the agent's tools actually did, that
  survives the agent (or an attacker who compromised it) trying to
  cover its tracks.

## In scope — what AgentGuard actually does today

| Threat | Mitigation | Where |
|---|---|---|
| Agent reads `~/.ssh`, `.env`, cloud credentials via a file-reading tool | Glob deny-list on path-like tool-call arguments | `PolicyEngine` (file_access) |
| Agent runs `rm -rf /`, pipes a remote script into a shell, forkbombs | Regex deny-list on command-like tool-call arguments | `PolicyEngine` (command_exec) |
| Agent's tools talk to arbitrary/attacker-controlled hosts | Hostname allow-list on URL-like tool-call arguments, default-deny | `PolicyEngine` (network) |
| Tool output contains a known-format secret that shouldn't reach the agent's context (leaked `.env`, a token in an API response) | Regex matching on known secret formats, output masked in place | `SecretRedactor` |
| Tool output (a fetched page, a read file) contains hidden instructions trying to redirect the agent — "ignore previous instructions," "send the private key to..." | Regex matching on instruction-shaped output text; a hit blocks the *entire* tool result | `InjectionDetector` |
| Someone edits, deletes, or reorders a past audit log entry to hide what happened | Hash chain (`prev_hash`/`hash` per entry); `agentguard verify-audit` detects the first break | `AuditLog` |

## Explicitly out of scope

Stated here so nobody deploying this mistakes silence for a guarantee.

- **A malicious or compromised MCP server that lies about what it's
  doing.** AgentGuard inspects the JSON-RPC messages that cross the
  wire; it does not sandbox the server process, restrict its syscalls,
  or verify its behavior matches its declared tool schema. A server
  that reads `~/.ssh/id_rsa` and returns its contents under a `path`
  argument AgentGuard doesn't recognize (or under a field name outside
  `PATH_ARG_KEYS`) will not be caught. **Mitigation path:** run the
  server itself under OS-level sandboxing (containers, seccomp, a
  restricted user) — complementary to, not replaceable by, AgentGuard.
- **Novel injection phrasings the regex rules don't match.** Rule-based
  detection catches known shapes; an attacker who knows the rule set
  (they're public, in `policies/default.yaml`) can phrase an
  instruction to slip past it. An LLM classification layer for
  borderline content is planned, not built — see the README's "What's
  not here yet."
- **Semantic/logical attacks that don't look like injected instructions
  or known secrets.** E.g., a tool argument that's individually
  "allowed" but combines with other calls into something harmful
  (path traversal built from multiple small steps, a sequence of
  otherwise-fine network calls that together exfiltrate data
  incrementally). AgentGuard evaluates each `tools/call` independently;
  it has no cross-call state or session-level reasoning.
- **Confidentiality of tool-call arguments in transit.** The proxy runs
  locally over stdio between processes the user already trusts to run;
  it is not a network-facing service and doesn't add its own transport
  security. If the wrapped MCP server itself talks over an insecure
  channel, that's outside AgentGuard's boundary.
- **Tamper-*proofing* the audit log**, as opposed to tamper-*evidence*.
  The hash chain makes a silent edit to an existing log file
  detectable. It does not stop an attacker with full filesystem access
  from deleting the log entirely, or rewriting it from scratch with a
  freshly self-consistent chain — there's no external anchor (a
  separate host, a transparency log) that a local attacker can't also
  reach. See `agentguard/audit.py`'s module docstring for the same
  point in more detail.
- **Denial of service.** AgentGuard doesn't rate-limit, timeout, or
  otherwise protect the wrapped server or the agent from a
  slow/hanging/resource-exhausting tool call.
- **Any tool call outside `tools/call`.** `initialize`, `tools/list`,
  and other MCP protocol messages pass through unmodified — there's no
  policy surface there because there's no dangerous *action* to gate
  (only capability negotiation).
- **Non-MCP agents/transports.** AgentGuard speaks MCP's stdio
  transport specifically. An agent calling tools over HTTP, a different
  protocol, or via a mechanism that doesn't route through this proxy
  is entirely unprotected by it.

## Design assumptions

- The proxy process itself runs with the same privileges and trust
  level as the agent process it's wrapping — it is not a privilege
  boundary in the OS sense, only a policy/inspection point in the
  message stream. If the agent process is compromised at the OS level,
  it can bypass the proxy entirely (e.g. by talking to the MCP server
  directly instead of through AgentGuard).
- The policy YAML file itself is trusted and not attacker-writable. An
  attacker who can edit `policies/default.yaml` doesn't need to bypass
  AgentGuard — they can just turn it off.
- Detection rules (redaction, injection) are matched against *text*
  content in `result.content[].text`. Non-text content types, or
  secrets/instructions encoded to dodge plain-text matching (base64,
  unusual whitespace, homoglyphs), are not normalized or decoded before
  matching in v1.
