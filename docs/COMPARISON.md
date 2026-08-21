# Prior art and how AgentGuard compares

Written before building further, on purpose: shipping a security tool
without knowing what already exists is how you end up re-solving a
solved problem, or worse, missing a real gap because you assumed one
existed. This survey is honest about both — including the uncomfortable
part, which is that AgentGuard is not filling an empty niche. A small
but real ecosystem of MCP-specific runtime gateways already does
overlapping work, some of it more mature than what's here.

_Based on public descriptions and documentation as of August 2026, not
hands-on testing of every tool listed — sources are linked throughout
so you can verify anything that matters for a real decision._

## Two categories that look similar but solve different problems

**Pre-deployment scanners/red-teamers** test a model or application
*before* it ships, by throwing adversarial prompts at it and scoring
the results. **Runtime gateways/proxies** sit in the live traffic path
and enforce policy on every real call, *while the agent is running*.
AgentGuard is the second kind. Confusing the two matters: a scanner
tells you your agent is vulnerable to injection in the abstract; it
does nothing when a real poisoned page reaches your real agent at 2am.
A runtime gateway is the thing standing there when that happens.

### garak (NVIDIA) — pre-deployment scanner, not comparable

[garak](https://github.com/NVIDIA/garak) is an open-source LLM
vulnerability scanner — "Generative AI Red-teaming & Assessment Kit."
It runs thousands of adversarial prompts against a model (via
Hugging Face, OpenAI's API, REST, GGUF, etc.) and reports where it's
vulnerable to prompt injection, jailbreaks, data leakage, toxicity, and
more ([Help Net Security](https://www.helpnetsecurity.com/2025/09/10/garak-open-source-llm-vulnerability-scanner/),
[garak docs](https://docs.garak.ai/garak)). It's a testing tool you run
against a model, not something that sits in front of a running agent.
Complementary to AgentGuard, not competing with it — you'd use garak to
red-team the *model*, and something like AgentGuard to constrain what
the *agent's tools* can actually do at runtime regardless of what the
model decides.

### promptfoo — pre-deployment eval/red-team framework, not comparable

[promptfoo](https://github.com/promptfoo/promptfoo) is an open-source
CLI for testing, evaluating, and red-teaming LLM applications; its red
team module generates adversarial inputs covering 50+ vulnerability
types (direct/indirect injection, jailbreaks, PII leaks, tool misuse)
against the OWASP LLM Top 10, using an LLM-as-judge to score whether
each attack succeeded (per
[promptfoo review coverage](https://appsecsanta.com/promptfoo),
[aitestingguide.com](https://aitestingguide.com/promptfoo-review/)).
Reportedly used by 350,000+ developers, with OpenAI announcing an
acquisition of promptfoo in March 2026. Like garak, this is pre-
deployment testing, not a runtime enforcement layer — same
complementary relationship as above, not a competitor.

## The actually-comparable category: MCP runtime gateways

This is where AgentGuard needs to be honest about not being alone.

| Project | What it is | Overlap with AgentGuard |
|---|---|---|
| [**mcp-firewall** (ressl)](https://github.com/ressl/mcp-firewall) | Proxies MCP JSON-RPC, YAML allow/deny policy on tools/arguments, scans tool *output* for leaked secrets, compliance-oriented audit logging, a dashboard. AGPL-3.0 with commercial licensing. | Very close. YAML policy, output secret-scanning, and audit logging are the same core idea as AgentGuard's policy engine + redactor + audit log. |
| [**evalops/mcp-firewall**](https://github.com/evalops/mcp-firewall/) | A separate, smaller project (same name, different author): proxies JSON-RPC, enforces allow/deny on tools/resources/prompts/methods. | Same category, narrower scope than the ressl project. |
| [**Lasso MCP Gateway**](https://www.lasso.security/resources/lasso-releases-first-open-source-security-gateway-for-mcp) | Proxy/orchestrator for MCP traffic; policy definition, real-time monitoring, request/response guardrails against sensitive data exposure. Part of a commercial GenAI security platform. | Same category; enterprise-oriented, backed by a security vendor. |
| [**Microsoft MCP Gateway**](https://github.com/microsoft/mcp-gateway) | Reverse proxy and lifecycle/routing management for MCP servers in Kubernetes — session-aware, scalable. | Different center of gravity: this is primarily infrastructure/routing (multi-server orchestration at scale), with governance as one piece, not primarily a security-policy tool. |
| **agent-wall, mcpwall, pipelock**, and others in [awesome-mcp-security](https://github.com/tamish560/awesome-mcp-security) / [awesome-mcp-gateways](https://github.com/e2b-dev/awesome-mcp-gateways) | A growing list of similar MCP-call interceptors — policy enforcement, attack blocking, egress/exfiltration scanning, some with cryptographically-signed audit receipts. | Same category as a whole; varying maturity, several very recent. |

**The honest takeaway:** "an MCP proxy that enforces a YAML policy and
scans output" is not a novel idea in August 2026 — it's converged on
independently by several projects in roughly the same period MCP
itself took off, which is a reasonable signal that it's the right
shape of tool, not that AgentGuard invented it.

## What's actually different about AgentGuard, stated carefully

Not "better" — different in scope and purpose, and it matters to be
precise about which:

- **A hash-chained, independently verifiable audit log is not something
  the public materials for the comparable projects specifically call
  out** (mcp-firewall's docs mention "compliance-ready audit logging,"
  which may or may not include tamper-evidence — that wasn't verifiable
  from the public description alone). AgentGuard's `agentguard
  verify-audit` walks the chain and reports the exact entry where
  tampering happened, with the underlying construction and its limits
  documented in [`THREAT_MODEL.md`](../THREAT_MODEL.md). If this
  specifically matters for a use case, it's worth checking the other
  projects' actual behavior rather than trusting a marketing summary on
  either side — including this one.
- **Minimal footprint, on purpose.** One runtime dependency (PyYAML),
  ~680 lines across five focused modules (`policy.py`, `redact.py`,
  `injection.py`, `audit.py`, `proxy.py` — verifiable with `wc -l`), no
  dashboard, no SaaS component, no account system. Easy to read start
  to finish in one sitting, which several of the more feature-complete
  competitors above are not — that's a real tradeoff, not a
  superiority claim: less capability, more legibility.
- **Built from scratch as a from-the-ground-up exercise**, not a
  wrapper around an existing framework — every layer (policy matching,
  regex-based secret/injection detection, the hash chain) is
  implemented directly rather than delegated to a library, which is
  the point when the goal is demonstrating the underlying security
  engineering, not shipping the fastest path to a working gateway.

## What this means for AgentGuard's roadmap

Given this landscape, positioning AgentGuard as *the* solution to MCP
tool-call security would be inaccurate. The more honest framing: it's a
minimal, from-scratch implementation of the same idea several other
projects are also converging on, built to demonstrate specific security
engineering fundamentals (least privilege, an explicit threat model,
tamper-evident logging) end to end rather than to compete on feature
breadth with tools that already have dashboards, rate limiting, and
commercial backing. Whether it's worth extending toward feature parity
with the more mature options, or staying deliberately small, is a real
open question — not one this survey answers on its own.
