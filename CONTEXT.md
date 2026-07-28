# ClaudeGuardIL

A security auditor for vibecoded apps. It computes what can be computed about a codebase, then
grades those observations into a report a non-expert can act on.

## Language

### The analysis pipeline

**Fact**:
Something observed to be true, independent of how dangerous it is. "This variable carries a
public bundler prefix." "This URL returned no CSP header." Facts never carry a severity. A Fact
records which Tier observed it, because a fact about a running system can change tomorrow while
a fact about committed code cannot.
_Avoid_: observation, signal, detection, result

**Tier**:
How a Fact was obtained: reading the code (`static`), a read-only request to a live target
(`passive-live`), or sending attack traffic (`active-dast`). Tiers 2 and 3 require the user to
attest they own the target.
_Avoid_: mode, level, phase

**Finding**:
A graded statement that something is wrong, carrying a severity and a confidence. Produced only
by the grader, never by the engine.
_Avoid_: issue, vulnerability, alert, hit

**Engine**:
The deterministic layer that reads a repo and emits Facts. It has no opinion about severity.
_Avoid_: scanner, analyzer

**Severity**:
How bad the Finding is *if it is real* (P0–P4). It expresses impact only and is never reduced
because we are unsure — uncertainty is Confidence's job, and discounting twice would bury a
catastrophic-but-unproven issue where nobody looks. The headline verdict counts only `confirmed`
Findings, so an unproven P0 never triggers a red badge.
_Avoid_: priority, risk, score, criticality

**Evidence**:
How solidly a Fact is established: `definitive` (the compiler or bundler guarantees it, no
inference needed), `strong` (a direct, single-hop observation), `weak` (inferred through a chain
that could break, such as a re-export barrel), or `judgement` (a reviewer's reading of intent,
which no rule could have enumerated).
_Avoid_: strength, certainty, quality, reliability

**Provenance**:
Which half of the pipeline produced a Finding — a deterministic Rule, or a reviewer walking the
inventory. Provenance is shown to the user, because "a rule proved this" and "a reviewer thinks
this" warrant different responses.
_Avoid_: source, origin, author

**Confidence**:
Belief that a Finding is real. It is a pure function of Evidence, so the same repo always yields
the same Confidence. The verifier may only *refute* a Finding, never raise its Confidence.
_Avoid_: probability, likelihood, trust

**Grader**:
The single component that maps Facts to Findings. It is the only authority on severity, so the
severity policy exists in exactly one place rather than being re-derived inside each rule.
_Avoid_: scorer, ranker, classifier

**Rule**:
A single deterministic mapping owned by the Grader: it takes a set of Facts and decides whether
they constitute a Finding. A Rule that iterates every member of an enumerable set (every table,
every route) is how completeness is achieved — there is no separate "invariant" concept.
_Avoid_: invariant, check, assertion, policy, detector

**Coverage**:
The record of what was examined and what could not be, expressed as a set that must add up:
every enumerated subject is accounted for as passing, failing, undeterminable or allowlisted.
Coverage is what stops a quiet report from being mistaken for a safe one.
_Avoid_: completeness, scope, audit trail

**Undeterminable Fact**:
A Fact whose content is "this could not be established, and here is why" — for example RLS state
in a repo with no migrations. It travels the same path as any other Fact; the Grader decides
whether it is merely Coverage or is itself worth reporting as a Finding.
_Avoid_: unknown, gap, miss, blind spot
