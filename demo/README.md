# Demo

Two scripts, same underlying attack/defense scenarios, different
purposes:

- **`run_demo.sh`** — fast, no pacing, meant to actually run (locally,
  in CI, to sanity-check a change). This is what the main README's
  Demo section walks through.
- **`record_demo.sh`** — the same scenarios with headers and pacing
  added for a human watching a recording. This is what produced
  `agentguard_demo.cast`.
- **`vulnerable_server.py`** — the intentionally-unrestricted MCP-style
  server both scripts wrap: a `read_file` tool with no path
  restrictions, a `read_document` tool that does the same under an
  argument named `file_location` (the rename bypass 0.1 fell for), a
  `fetch_url` tool returning two fixed, canned pages (a poisoned one, a
  clean one) with no real network access, a `screenshot` tool returning
  an image, and `resources/read` / `prompts/get` handlers so the
  non-`tools/call` inspection paths can be exercised.

## Watching the recording

The recording was made with AgentGuard 0.2.0 and shows all twelve
steps of `record_demo.sh`. Watch it online, no install needed:
**[asciinema.org/a/Wsy4px9o1lnc4FCu](https://asciinema.org/a/Wsy4px9o1lnc4FCu)**

Or play the file in this repo locally — same recording, an
[asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/), a
plain-text terminal-only capture (no video, no audio), ~40 seconds, of
`record_demo.sh` actually running against a real `agentguard` process:

```bash
pip install asciinema
asciinema play demo/agentguard_demo.cast
```

## Re-recording after a change

If the demo scenarios or their output change, re-record rather than
hand-editing the `.cast` file (it's a timestamped event log, not
something to patch by hand):

```bash
asciinema rec --command "bash demo/record_demo.sh" \
  --cols 140 --rows 50 --idle-time-limit 2 \
  --title "AgentGuard <version>: minimal-privilege MCP proxy demo" \
  --overwrite demo/agentguard_demo.cast
```

Uploading (`asciinema upload demo/agentguard_demo.cast`) creates a *new*
recording with a new URL; it never replaces the old one. Update the link
here, in the top-level README, and anywhere else that shows it, then
delete the old recording from the asciinema account — otherwise the old
URL keeps serving the old demo, which is how this link went stale once
already.
