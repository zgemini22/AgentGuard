# Threat model

What AgentGuard defends against, what it explicitly doesn't, and the
assumptions the whole design rests on. Written down on purpose: a
security tool that doesn't say what it's *not* for is a tool nobody can
actually reason about deploying.

## Actors

- **The user** — runs the agent, owns the machine and credentials the
  agent has access to. Trusted.
- **The operator** — the human who answers `ask` verdicts through
  `agentguard approve`. Usually the user; trusted to the same degree.
  Their answers are recorded, and "always" is written to a separate
  overlay rather than the policy, so a hasty answer is reviewable and
  revocable.
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
| Agent reads `~/.ssh`, `.env`, cloud credentials via a file-reading tool | Glob deny-list (and optional allow-list) on path-classified tool-call arguments, including `file://` URIs and `resources/read` | `PolicyEngine` (file_access) |
| Agent runs `rm -rf /`, pipes a remote script into a shell, forkbombs | Regex deny-list on command-classified arguments | `PolicyEngine` (command_exec) |
| Agent's tools talk to arbitrary/attacker-controlled hosts | Hostname allow-list on URL-classified arguments, default-deny | `PolicyEngine` (network) |
| A server names its path argument `file_location` (or anything else) so the key-name rules never look at it | Arguments are classified from the tool's declared `inputSchema` (format, name tokens, description) as well as key names; `unclassified_arguments: deny` refuses any call with an argument nothing recognized | `ArgumentClassifier`, `PolicyEngine` |
| One tool needs a narrower policy than the rest | `tools.<name>:` overrides, field-level, over the global rules | `PolicyEngine` |
| "Read one more file, then one more" / a tool returns a 50 MB blob | Session budgets: per-category call ceilings, per-call and total output byte ceilings | `Session`, `PolicyEngine` |
| Two individually-fine calls that together exfiltrate: read `.env`, then POST | Three fixed sequence rules — no network after a sensitive read, no exec after a fetch, a ceiling on distinct directories | `Session`, `PolicyEngine` |
| A strict policy blocks legitimate work and gets loosened to allow-all | The `ask` verdict: an operator decides over a Unix socket (deny / once / session / always), with a timeout that denies | `ApprovalBroker`, `ApprovalServer`, `agentguard approve` |
| Tool output contains a known-format secret that shouldn't reach the agent's context (leaked `.env`, a token in an API response) | Regex matching on known secret formats over *normalized* text, output masked in place at the original spans | `SecretRedactor`, `normalize` |
| Tool output (a fetched page, a read file, a resource, a prompt) contains hidden instructions trying to redirect the agent — "ignore previous instructions," "send the private key to..." | Regex matching on instruction-shaped text over normalized text; a hit withholds the *entire* result | `InjectionDetector`, `normalize` |
| The injected instruction or secret is hidden with zero-width characters, homoglyphs, fullwidth letters, or base64 | Normalization before scanning: NFKC, invisible characters stripped, a fixed homoglyph table folded, base64 runs decoded one level | `normalize` |
| A policy typo silently disables a rule | Strict validation on load: unknown keys, non-compiling regexes and wrong types are startup errors; `check-policy` echoes the effective policy and probes calls | `validate`, `agentguard check-policy` |
| Someone edits, deletes, or reorders a past audit log entry to hide what happened | Hash chain (`prev_hash`/`hash` per entry); `agentguard verify-audit` detects the first break | `AuditLog` |
| Someone rewrites the *whole* log with a fresh, self-consistent chain | Anchoring: `agentguard anchor` / `anchor_file:` record the chain's head; `verify-audit --anchor` checks the chain still passes through it | `AuditLog`, `agentguard anchor` |
| "The agent ran for twenty minutes and I have no record of what it touched" | `agentguard report`: files by directory, hosts, commands, every block/redaction/injection/grant, per session | `report` |

## In scope, with caveats

These were out of scope in 0.1. They're mitigated now, but each has an
edge that the mitigation doesn't reach, and pretending otherwise would
be worse than the old disclaimer.

- **Unrecognized arguments.** Schema-based classification raises the
  bar from "rename one argument" to "lie convincingly in your own
  schema": a server whose `inputSchema` describes a path argument as
  "the color to use" won't be classified. `unclassified_arguments:
  deny` closes that entirely — at the cost of refusing calls to tools
  whose schemas are too thin to classify, which is why it isn't the
  default. `check-policy --probe --tools` exists so you can find out
  before flipping it.
- **Encoded content.** Normalization covers the cheap tricks (invisible
  characters, a fixed table of whole-glyph homoglyphs, NFKC, one level
  of base64). It does not cover leetspeak, nested encodings, encryption,
  an image of text, or novel Unicode confusables outside the table.
  Anything the model can decode that the normalizer can't is still a
  gap.
- **Cross-call state.** Budgets and the three sequence rules answer
  three specific questions, not "is this sequence of calls dangerous"
  in general. A sequence that isn't one of those three shapes is still
  judged one call at a time. The three are a fixed menu on purpose: a
  fourth is a design conversation, not a config key.
- **Tamper-proofing the audit log.** Anchoring makes a from-scratch
  rewrite detectable *if the anchor is somewhere the attacker can't
  also edit*. AgentGuard can't put it there for you. An `anchor_file`
  on the same disk as the log is a convenience; an anchor pasted into
  a message to yourself, or appended on another host, is the real
  thing.
- **Denial of service.** Output-size and call-count budgets bound how
  much a session can consume. There's still no timeout on a hanging
  tool call and no rate limit on a fast-looping one.
- **The `ask` channel on Windows.** It needs Unix domain sockets. On a
  platform without them the proxy says so on stderr at startup and
  every `ask` is denied, recorded as `ask_resolution: no_channel`.
  Named pipes are planned.

## Explicitly out of scope

Stated here so nobody deploying this mistakes silence for a guarantee.

- **A malicious or compromised MCP server that lies about what it's
  doing.** AgentGuard inspects the JSON-RPC messages that cross the
  wire; it does not sandbox the server process, restrict its syscalls,
  or verify its behavior matches its declared tool schema. A server
  that reads `~/.ssh/id_rsa` in response to a call whose arguments
  don't say so — or that mislabels its own schema (see above) — will
  not be caught. **Mitigation path:** run the server itself under
  OS-level sandboxing (containers, seccomp, a restricted user) —
  complementary to, not replaceable by, AgentGuard.
- **Novel injection phrasings the regex rules don't match.** Rule-based
  detection catches known shapes; an attacker who knows the rule set
  (they're public, in `agentguard/policies/default.yaml`) can phrase an
  instruction to slip past it. An LLM classification layer for
  borderline content is planned, not built — deliberately, for now:
  it makes the tool guessier, not more trustworthy, and the fixes in
  0.2 were about making the existing guarantees hold.
- **Confidentiality of tool-call arguments in transit.** The proxy runs
  locally over stdio between processes the user already trusts to run;
  it is not a network-facing service and doesn't add its own transport
  security. If the wrapped MCP server itself talks over an insecure
  channel, that's outside AgentGuard's boundary.
- **MCP protocol messages with no action to gate.** `initialize`,
  `tools/list`, notifications, and the rest pass through unmodified
  (`tools/list` responses are *read* for schemas, never changed). The
  gated methods are `tools/call` and `resources/read` on the way in;
  those plus `prompts/get` on the way out.
- **Non-MCP agents/transports.** AgentGuard speaks MCP's stdio
  transport specifically. An agent calling tools over HTTP, a different
  protocol, or via a mechanism that doesn't route through this proxy
  is entirely unprotected by it. Streamable-HTTP transport is a
  planned, pure-plumbing addition.

## Design assumptions

- The proxy process itself runs with the same privileges and trust
  level as the agent process it's wrapping — it is not a privilege
  boundary in the OS sense, only a policy/inspection point in the
  message stream. If the agent process is compromised at the OS level,
  it can bypass the proxy entirely (e.g. by talking to the MCP server
  directly instead of through AgentGuard).
- The policy YAML file itself is trusted and not attacker-writable. An
  attacker who can edit `agentguard/policies/default.yaml` doesn't need to bypass
  AgentGuard — they can just turn it off. This is also why operator
  grants never write to it: the `grants_file` overlay is the only
  thing AgentGuard writes at runtime besides the audit log, and it can
  only ever turn an `ask` into an allow.
- The approval socket is only as private as its file permissions
  (0600) and the machine's user separation. Anyone who can connect to
  it can approve calls; anyone who can replace the file at that path
  can impersonate the proxy. The proxy refuses to replace a non-socket
  file at the path, but it can't defend the path itself.
- Detection rules (redaction, injection) are matched against the
  *normalized* text of `text` content, embedded resources,
  `structuredContent` strings, `resources/read` contents and
  `prompts/get` messages. Binary content (images, audio, `blob`
  resources) is passed through unscanned and logged as such — the
  audit trail says where the scanners had no visibility rather than
  implying they looked.
