# Changelog

## 0.2.0 — 2026-09-13

From a stateless per-call filter to a least-privilege session runtime.
Built to [`docs/ROADMAP-0.2.md`](docs/ROADMAP-0.2.md); the direction
was "make the guarantees the README already claims actually hold,
then give the proxy a session and a human in the loop" — not the LLM
injection classifier, on purpose.

### Guarantees that now hold

- **Arguments are classified from the tool's declared schema**, not
  only by key name. The proxy reads each `tools/list` response on its
  way past and classifies by JSON-Schema `format`, the v1 key names,
  name tokens (`file_location`, `targetHost`), and description
  keywords. A `tools/call` arriving while a `tools/list` is in flight
  waits for it. Lists and nested objects are walked.
- **`unclassified_arguments: allow | deny | ask`.** `deny` closes the
  rename-the-argument bypass outright. Audit entries for such calls say
  `category: "unclassified"` instead of `"none"`.
- **Output is normalized before scanning**: NFKC, zero-width/bidi
  characters stripped, a fixed homoglyph table folded, base64 runs
  decoded one level. Redaction still edits only the matched spans of
  the original.
- **Every content type is inspected**: `resources/read` and
  `prompts/get` results, embedded `resource` items, `structuredContent`.
  `resources/read` is also policy-gated on the way in; a `file://` URI
  anywhere is judged by the file rules. Images/audio/blobs pass through
  and are logged as `unscannable_content`.
- **Strict policy validation.** Unknown keys (with a did-you-mean
  hint), non-compiling regexes, and wrong types are startup errors,
  all reported at once. `deny_patterns` / `allow_patterns` /
  `default_action` now mean the same thing in every category —
  `network.deny_patterns` and file/command allowlists were previously
  accepted and ignored.
- **`agentguard check-policy [--probe TOOL JSON] [--tools tools.json]`**
  prints the effective policy and explains what the engine would do
  with a call and why (exit 0 allow / 3 deny / 4 ask).

### Session runtime

- **`Session`**: every run has an id stamped on every audit entry,
  bracketed by `session_start` (server command, policy path and
  sha256, versions) and `session_end` (exit code, duration, tools seen).
- **Budgets**: `max_file_calls`, `max_network_calls`,
  `max_command_calls`, `max_output_bytes_per_call`,
  `max_total_output_bytes`. Only forwarded calls and delivered bytes
  count. _(Roadmap said `max_file_reads`; the policy can't tell a read
  from a write, so the key doesn't claim it can.)_ With a total output
  budget set, the proxy waits for outstanding responses before judging
  the next call so a pipelining client can't outrun the counter.
- **Per-tool scoping**: `tools.<name>:` overrides, merged field by
  field over the global rules; `enabled: false` denies a tool outright.
- **Sequence rules** — exactly three: `deny_network_after_sensitive_read`
  (built-in sensitive list when none is given), `max_distinct_directories`,
  `deny_exec_after_fetch`.
- **`agentguard report <log> [--session ID] [--json]`**: files touched
  by directory, hosts, commands, every block / redaction / injection /
  withheld result / grant, budget consumption, timeline — per session,
  after verifying the chain.

### Human in the loop

- **The `ask` verdict.** `Decision.action` is `allow | deny | ask`;
  `allowed` stays a plain field so old callers work. Any deny pattern
  may be `{pattern, action: ask}`; `default_action`,
  `unclassified_arguments`, `budgets.on_exceed` and `sequences.on_trip`
  accept `ask`. Without a channel, `ask` degrades to deny and the audit
  entry says `ask_resolution: no_channel`.
- **Approval channel**: `approval_socket:` (Unix domain socket, mode
  0600) + `approval_timeout:` (default 60s → deny), and
  `agentguard approve --socket <path>` which shows each pending call
  and takes deny / once / session / always. Not available on Windows
  (says so on stderr; every ask denied).
- **Grants**: `session` lives on the Session; `always` is written to
  the `grants_file:` overlay — never the policy file, which is the
  trust root. Grants are narrow scopes (`tool:category:rule`), shown
  separately by `check-policy`, recorded as `grant` audit entries, and
  only ever turn an `ask` into an allow.

### Audit

- **Anchoring**: `agentguard anchor <log>` prints `<count> <hash>`;
  `verify-audit --anchor "<count> <hash>"` / `--anchor-file` checks the
  chain still passes through it, catching a from-scratch rewrite.
  `anchor_file:` + `anchor_every:` make the proxy anchor itself.
- Audit entries gain `argument_categories`, `action`, `ask_resolution`,
  `method`, `session_id`; new events `session_start`, `session_end`,
  `unscannable_content`, `budget_block`, `grant`.

### Docs, demo, CI

- `THREAT_MODEL.md`: unrecognized arguments, encoded content,
  cross-call state and tamper-proofing move from "out of scope" to
  "in scope, with caveats" — the caveats are spelled out.
- Demo server gains `read_document(file_location=…)`, `screenshot`,
  `resources/read` and `prompts/get`; `run_demo.sh` shows the rename
  bypass caught and `agentguard report`. The asciinema recording is
  from 0.1 and needs re-recording.
- CI adds a Windows runner (socket tests skip there; the degrade path
  runs).

### Compatibility

- `PolicyEngine(config)` now raises `PolicyError` on an invalid config
  where it used to load silently. `Decision.category` is
  `"unclassified"` where it used to be `"none"` for calls whose string
  arguments matched nothing. Everything else is additive; the default
  policy's behavior on the 0.1 demo scenarios is unchanged.

## 0.1.1

Initial public release: YAML policy engine (file / command / network
rules matched by argument key name), secret redaction, rule-based
prompt-injection detection, hash-chained audit log, `agentguard run`
and `verify-audit`.
