# Blog drafts

Draft technical writeups for the project, kept in-repo rather than
published externally — publishing to an outside platform needs a real
account/credentials this environment doesn't have, so these are ready
for the project owner to post wherever they'd like (a personal blog,
dev.to, Medium, ...).

1. [Why I put a proxy between my AI agent and my server](01-threat-model-and-design.md) —
   the incident that started the project, the three failure modes it's
   designed around, why enforcement lives at the MCP protocol boundary
   instead of in the prompt or the OS, and what the threat model
   deliberately doesn't promise.
2. [Rule-based prompt-injection detection: what it catches, what it costs](02-injection-detection-rules-and-tradeoffs.md) —
   why a detected injection blocks the whole tool result instead of
   just the matched span, why rules instead of an LLM classifier for
   v1, and a real false-negative the default rules shipped with that a
   regression test caught.
