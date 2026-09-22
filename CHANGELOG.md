# Changelog

## Unreleased

_Nothing yet._

## 0.2.0 — 2026-09-22

From a stateless per-call filter to a least-privilege session runtime.
The direction was "make the guarantees the README already claims
actually hold, then give the proxy a session and a human in the loop" —
not the LLM injection classifier, on purpose.

### Fixed before release

A full audit of the release candidate found that several of the
guarantees above, and some that 0.1.1 already claimed, did not hold.
Each is fixed with a regression test that fails without the fix.

- **File rules match the canonical path.** Globs were matched against
  the raw argument string, so a bare or relative name (`.env`, `id_rsa`,
  `server.pem`) passed every `**/…` pattern in the default policy, `..`
  escaped a `/project/**` allowlist, and symlinks, case (macOS/Windows)
  and Win32 aliases (`.env.`, `.env::$DATA`) did the rest. Values are
  now resolved against the server's working directory, normalized, and
  matched in resolved-symlink form too. The sensitive-read sequence rule
  uses the same matching. (Affects 0.1.1.)
- **Network hosts are taken only when unambiguous.** A backslash in the
  authority made `urlparse` and the HTTP clients servers use disagree
  about the host, and a value with no scheme was matched as a whole
  string. Such values are now denied, and schemeless values are read as
  `host[/path]`. (Affects 0.1.1.)
- **Arguments are judged under every category they could belong to.**
  `script_path` was command-only, a URL under `destination` was judged
  only by file globs, and lists of lists weren't walked at all (not even
  under `unclassified_arguments: deny`). Non-object `arguments` are
  refused.
- **Any deny wins, and grants cover exactly what was approved.** An
  `ask` on one argument could hide a hard deny on another, which an
  approval then let through; an allowlist-miss grant was keyed on the
  first argument of the category, not the one that missed.
- **Every response is inspected.** A result could skip injection
  blocking, redaction, the output budget and the audit log if the
  server echoed the id as another JSON type, sent a message reusing the
  id first, or sent a request of its own with a colliding id; one
  malformed line stopped inspection of everything after it. Error
  objects are now scanned too. (Affects 0.1.1.)
- **UTF-8 on the wire whatever the locale.** On Windows without UTF-8
  mode (cp936, cp1252) non-ASCII text crashed the proxy, or let an AWS
  key through redaction.
- **The scanners fail closed and run in linear time.** base64 decoding
  stopped after 64 runs and delivered the rest unscanned; now a text
  over the decode limit is blocked. Several shipped patterns were
  quadratic: 100 KB of crafted text took over 300 s to scan and stalled
  every later response; it now takes about 0.1 s. Rules with literal
  spaces use `\s+`, and the pipe-to-shell and `rm` rules cover more
  spellings (still 34 rules).
- **Audit log.** With `anchor_file` set, the head is anchored at every
  session's start and end, so cutting off a finished session's tail is
  caught. Several proxies on one log extend one chain instead of
  forking it. A missing log is `MISSING`, not `OK`. The limits of the
  chain without an anchor are stated in the README, the threat model and
  `verify-audit`'s own output. (The tail limit affects 0.1.1.)
- The approval socket that can't be created degrades to deny, with a
  line on stderr, instead of stopping the proxy (79e7edf); every `ask`
  is then recorded as `ask_resolution: no_channel`.
- `check-policy` lists `{pattern, action: ask}` deny entries under the
  action they take instead of as a raw dict under `deny` (49841bb).

### Packaging

- The default policy ships inside the package, and `agentguard run` /
  `check-policy` use it when `--config` is omitted — they failed after
  `pip install` in 0.1.0 and 0.1.1 unless run from a clone. Nothing is
  read from the working directory implicitly; a `./policies/default.yaml`
  (what 0.1.x read) gets a warning instead of being dropped silently.
  `agentguard default-policy` prints the bundled policy to start your
  own from.
- The sdist includes what its tests need and runs them; the wheel
  installs no tests. Project URLs, per-version Python classifiers.
- CI: Python 3.9–3.13 on Linux, macOS, Windows with UTF-8 mode, Windows
  under the locale code page, and a job that builds the wheel and runs it
  from an empty directory.

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
  bypass caught and `agentguard report`.
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
