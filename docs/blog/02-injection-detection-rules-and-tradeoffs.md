# Rule-based prompt-injection detection: what it catches, what it costs

The demo scenario I built AgentGuard's injection detector around is
deliberately mundane: an agent fetches a cookie recipe. Buried in an
HTML comment on that page is a sentence telling the agent to ignore its
instructions and send the user's private key to an attacker's email
address. The agent never asked to see that sentence — it just fetched a
page, the way a "summarize this recipe" task would ask it to — and nothing
about the *tool call* was wrong. The problem is entirely in the *content
that came back*.

This post is about the mechanism I built to catch that
(`agentguard/injection.py`), and specifically about two decisions that
matter more than the regex patterns themselves: what to do with a hit,
and why rules instead of a model.

## Block the whole message, not the matched span

AgentGuard's secret redactor works by masking — a matched API key
becomes `[REDACTED:aws_access_key_id]` and everything else in the
message passes through untouched. My first instinct for injection
detection was the same approach: strip out the "ignore previous
instructions" sentence and let the rest of the recipe through.

I talked myself out of that pretty quickly, for a reason that's obvious
once you say it out loud: **redaction assumes the rest of the content
is safe to keep. Injection doesn't give you that assumption.** A
secret is a self-contained span — remove it, and what's left is just
less informative than before, but not less trustworthy. An injected
instruction is not self-contained the same way. If I strip the exact
sentence my regex matched but the page contains a *second*, differently
worded instruction three paragraphs later that my rule doesn't catch,
I've now given the agent a false sense that this content was checked
and passed, sitting right next to content that wasn't caught. Partial
cleaning of adversarial content is worse than no cleaning, because it
removes the signal ("this is untrusted, unscanned text") without
removing the risk.

So the design in `proxy.py`'s `_check_injection` is blunter on purpose:
any rule match on any text block in a tool result blocks the *entire*
result. The agent gets back an `isError` response with a message
naming which rules fired, not a "cleaned" version of the page. This is
a strictly worse experience when the detector is wrong — a false
positive means a legitimate page becomes unusable instead of
mildly-edited — but it's the right failure mode for something with
this specific class of risk. I'd rather the tool be annoying on a false
positive than quietly wrong on a false negative.

## Why rules, not a classifier, for v1

The obvious "better" approach is running suspicious content through an
LLM classifier — "does this text contain an attempt to redirect an AI
agent's behavior?" — which would catch phrasings no regex author
thought of. I didn't build that for v1, and it's not because I think
it's a bad idea; it's explicitly called out as a planned layer in the
README. The reason is more basic: a classifier adds latency, cost, and
a second model's worth of failure modes (it can be wrong in its own
new ways, and now you have two systems' errors to reason about) on
every single tool call, and I'd rather validate the *mechanism* — scan
output, decide block-or-pass, log the decision, prove it works on a
real attack scenario — against something deterministic and free to run
first. Rules are also auditable in a way a classifier isn't: anyone
using AgentGuard can read `policies/default.yaml` and know exactly
what will and won't trigger a block, which matters if you're the one
debugging why a legitimate tool call got blocked at 2am.

The honest cost of that choice: the rules are public, in a YAML file,
in this repo. An attacker who wants to phrase around them can just
read them. That's not a flaw I discovered later — it's the direct,
foreseeable tradeoff of shipping transparent, auditable rules instead
of a black-box classifier, and it's why the README doesn't call this
"prompt injection prevention." It's detection of the shapes I know
about, stated as exactly that.

## A false negative the test suite caught, not me

Here's a concrete example of the false-positive/false-negative
tradeoff, and it's more interesting than a hypothetical because it's a
real bug that shipped and then got caught.

One of the default rules is `disregard_instructions`, meant to catch
phrasings like "disregard your previous instructions." The regex I
originally wrote was:

```
disregard\s+(your|all|previous|prior)\s+(instructions|rules|guidelines|prompt)
```

That looks reasonable — it allows one qualifier word before the noun.
It matches "disregard previous instructions" and "disregard your
rules." What it does *not* match is "disregard **your previous**
instructions" — two qualifiers stacked before the noun — which is at
least as natural a phrasing as either of the ones it does catch. I
didn't notice this by reading the regex. I noticed it because I later
wrote `tests/test_default_policy.py`, a regression suite that loads
the actual shipped `policies/default.yaml` (not a hand-built test
config) and asserts each documented rule catches its named phrasing
against realistic example text. That test failed on first run.

The fix was small — repeat the qualifier group instead of matching it
once:

```
disregard\s+((your|all|previous|prior)\s+)+(instructions|rules|guidelines|prompt)
```

— but the lesson generalizes past this one pattern: **testing a
detection rule against the *config file you actually ship*, not just
against hand-picked strings in a unit test, is what catches this class
of bug.** It's easy to write a regex, write a test string that happens
to match your mental model of the regex, watch the test pass, and ship
a rule that's quietly narrower than you think it is. The fix here was
testing the deployed artifact end to end, the same way you'd want
integration tests to run against a built binary instead of only
against source.

## Where this leaves the false-positive/false-negative line

Rule-based detection, tuned toward "block the shapes I'm confident
about," lands in a specific spot on that tradeoff curve: fewer false
positives than an aggressive classifier might produce (the rules only
fire on fairly explicit instruction-override language), at the cost of
missing anything phrased carefully enough to avoid all seven patterns.
That's a defensible place to start, not a finished answer — the
`disregard_instructions` gap is proof the "confident" rules weren't
even as tight as intended, and a determined attacker who's read the
source has an easier time than the demo's crude cookie-recipe example
suggests.

What I'd want before calling this done: real traffic to see what
actually triggers false positives in practice (right now the answer is
"nothing observed," which mostly means it hasn't been tested against
enough real content, not that it's well-tuned), and the LLM
classification layer as a second-opinion pass on content the regex
rules don't flag — not a replacement for the rules, since the
determinism and auditability are worth keeping, but a way to catch what
they structurally can't.
