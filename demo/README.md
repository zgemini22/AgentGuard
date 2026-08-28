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
  restrictions, and a `fetch_url` tool returning two fixed, canned
  pages (a poisoned one, a clean one) with no real network access.

## Watching the recording

Watch it online, no install needed:
**[asciinema.org/a/cYpJRwcAOB9mTeSj](https://asciinema.org/a/cYpJRwcAOB9mTeSj)**

Or play the file in this repo locally — same recording, an
[asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/), a
plain-text terminal-only capture (no video, no audio), ~30 seconds, of
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
  --cols 120 --rows 40 --idle-time-limit 2 \
  --title "AgentGuard: minimal-privilege MCP proxy demo" \
  --overwrite demo/agentguard_demo.cast
```

Then re-upload (`asciinema upload demo/agentguard_demo.cast`) — this
mints a **new** URL rather than updating the existing one in place, so
update the link above and in the main README's Demo section to match.
