# Why I put a proxy between my AI agent and my server

A few months ago I let an AI coding agent manage a personal server. It
had shell access, it could read and write anything my user account
could touch, and it could fetch whatever URLs it wanted. It worked
great — until one afternoon I watched it read `~/.ssh/id_rsa` as a
completely incidental step in a task that had nothing to do with SSH
keys. It didn't do anything malicious with it. It didn't need to. The
problem was that it *could*, and I had no record of what it had touched
before I happened to be watching the terminal.

That's the moment this project started. Not "AI agents are dangerous"
in the abstract — I'd read those takes — but a specific, boring
realization: **I had given a process more privilege than the task
required, and I had no way to audit what it had done with it.** That's
not a new problem. It's the same problem `sudo`, SELinux, and every
least-privilege model in security exists to solve. It just hadn't been
solved yet for this specific new kind of process.

## The shape of the problem

An AI agent using tools (reading files, running commands, fetching
URLs) has three failure modes that matter here, and they're different
problems even though they get lumped together as "AI safety":

1. **The agent does something the task didn't require.** Not
   malicious — just overreach, because nothing stopped it. Reading a
   config file two directories over when it only needed one. Running
   `find /` when `ls .` would do.
2. **Something the agent reads tries to redirect it.** A web page, a
   file, an API response can contain text that looks like an
   instruction. If the agent doesn't distinguish "content I'm
   processing" from "instructions I should follow," a poisoned
   document can hijack it. This is the prompt-injection problem, and
   it's structurally different from #1: the agent isn't overreaching,
   it's being *used* by something in its own tool output.
3. **Something legitimate the agent does still leaks something it
   shouldn't.** The agent was allowed to read that file. The file
   happened to contain an API key. Nothing about the *call* was wrong —
   the *content* was sensitive and nobody masked it before it landed in
   a context window that might get logged, screenshotted, or handed to
   another system.

Three different failure modes need three different mechanisms. That's
the core design decision behind AgentGuard: it isn't one filter, it's
three independent layers, because conflating them produces a tool that
does all three badly.

## Where to put the enforcement point

The next decision was *where* this logic should live. A few options,
and why I didn't pick them:

- **Inside the agent's prompt** ("please don't read SSH keys"). This
  is not enforcement, it's a suggestion the model can be talked out of.
  If the security boundary lives in natural language, it isn't a
  boundary.
- **Inside the MCP server itself.** Reasonable for a server you
  control, but it means re-implementing the same policy logic in every
  server you use, and it does nothing for third-party servers you
  don't control the source of.
- **At the OS level** (containers, seccomp, restricted users). This is
  genuinely valuable and complementary — see the threat model's note
  on sandboxing the server process — but it operates on syscalls, not
  on the semantic content of a tool call. It can stop a process from
  opening a file; it has no concept of "this JSON-RPC message is a
  `tools/call` for `read_file` with an argument that looks like a
  path," which is the level where I wanted to reason about policy.

What I landed on: **sit on the wire between the agent and the MCP
server, and inspect every `tools/call` message before it's forwarded,
and every result before it's returned.** MCP already gives you a clean
protocol boundary — newline-delimited JSON-RPC over stdio — so this
doesn't require modifying the agent or the server. You point the agent
at the proxy instead of the server, and the proxy quietly enforces
policy in the middle. The agent and server both continue speaking MCP
exactly as before; neither one knows AgentGuard is there.

## The three layers, briefly

- **Policy engine** (input-side): glob deny-lists for file paths,
  regex deny-lists for shell commands, a hostname allowlist for
  network calls — matched against `tools/call` arguments by key name
  (`path`, `command`, `url`, ...), since MCP servers don't share one
  argument schema. This is failure mode #1: stop the call before it
  happens.
- **Injection detector** (output-side, first pass): scans tool
  *output* for instruction-shaped text. A hit blocks the entire result
  rather than trying to surgically remove the offending sentence —
  more on why in the next post. This is failure mode #2.
- **Secret redactor** (output-side, second pass): masks known secret
  formats in whatever output the injection detector didn't block. This
  is failure mode #3 — the call was fine, the content wasn't.

Every decision from all three layers gets written to an audit log,
which is hash-chained (each entry commits to the previous entry's
hash) so that editing a past entry — someone trying to cover their
tracks after the fact — is detectable by re-walking the chain. That
part exists because "audit log" is a hollow promise if the log itself
isn't trustworthy; a log an attacker can silently edit is not
meaningfully different from no log.

## What I decided not to promise

The full reasoning lives in [`THREAT_MODEL.md`](../../THREAT_MODEL.md)
in the repo, but the short version: I'd rather ship a narrower tool
with an honest boundary than a broader one with an implied guarantee I
can't back up. AgentGuard does not sandbox the MCP server process
itself — a server that lies about what it's doing at the OS level is
outside what a protocol-level proxy can see. It does not catch every
injection phrasing — the rules are public, in the policy YAML, and an
attacker who reads them can phrase around them; an LLM classification
layer for what the rules miss is a real gap, not a hidden one. And the
audit log is tamper-*evident*, not tamper-*proof* — it can prove a
specific edit happened, but it can't stop someone with full filesystem
access from deleting it and starting a fresh, self-consistent chain
from scratch.

None of that is a caveat I'm burying in fine print. It's in the
README, in a dedicated threat model doc, and now in this post, because
the entire point of building a security tool is that people can reason
about what it actually buys them. A tool that quietly overpromises is
worse than no tool — it changes what people don't bother checking
themselves.

The next post goes into the injection detector specifically: why
rule-based detection over an LLM classifier for v1, what a false
positive costs versus a false negative, and a real bug the test suite
caught in the shipped default rules before it shipped further.
