# 0008 — Reviewer findings are capped at judgement→likely and validated before merge

## Status

Accepted — 2026-07-29

## Context

The grader proves its own findings safe with the assertions in `grade()` (ADR 0005). But the domain auditors (web-auditor, ai-auditor, …) are LLMs, and their findings land in the *same* report the badge is computed from. Nothing structurally stopped an auditor from emitting a `confirmed` P0 on a route that does not exist and turning the badge red with no rule behind it. That is the seam on which the whole "safe to let an LLM contribute to a security report" claim rests.

## Decision

All reviewer findings pass through `mergeReviewerFindings()` before entering the report. It enforces on agent output every law the grader enforces on itself:

- **Provenance is set by the channel, not the payload** — everything through this path becomes `provenance: reviewer`. An agent cannot launder its finding into a rule-looking one.
- **Evidence is capped at `judgement`**, whatever the payload claimed, so confidence derives to `likely` (ADR 0003) and can **never** be `confirmed`. If an agent claims stronger evidence, that is a signal the fact belongs in an engine rule; the finding is kept, capped, and the correction recorded in `reviewerNotes`.
- **LAW 3 still holds** — a name-only P0 is rejected.
- **Malformed findings are rejected** with a specific reason (missing required field, invalid severity enum), not silently dropped.
- **Un-enumerated subjects are flagged `unanchored`** — a finding about a subject the engine never saw is either a hallucination or proof the enumeration missed something; either way the user is told, not shown a clean-looking finding.

**The keystone invariant**, asserted at runtime and fuzz-tested: merging reviewer findings can **never** change the confirmed verdict (`level`, `confirmedP0`, `confirmedP1`). `mergeReviewerFindings()` recomputes the summary and throws if the confirmed verdict moved; the test suite throws every severity × evidence combination — including a stray `confirmed` — at it and asserts the badge is unchanged. That invariant is what makes it safe to let an LLM write into the report at all.

## Consequences

Positive:

- An LLM can contribute the judgement-level findings a rule cannot produce (a business-logic flaw on an already-authenticated route) without ever being able to move the badge.
- Every drop and every cap is explained back to the user (`rejected`, `reviewerNotes`), so the validator is auditable rather than a black box.
- The security boundary is one function with one keystone assertion, tested adversarially — a small, checkable surface.

Costs / risks accepted:

- A genuinely definitive fact a reviewer notices cannot reach `confirmed` as a reviewer finding; to move the badge it must be promoted into an engine rule (ADR 0001, ADR 0003). Correctness is deliberately traded for reproducibility: the model would rather under-confirm a real reviewer insight than let an LLM's certainty into the verdict.
- Reviewer findings live permanently at `likely`, so a real one shares a confidence band with a merely plausible one; the `assumption` field is what separates them for the reader.

Note: The plan amendment (same date) lists under "Known open" that "reviewer-produced findings have no validator." That is now stale: `grader.mjs` ships `mergeReviewerFindings()`, and the keystone is asserted at runtime and fuzz-tested (`test/reviewer_validator.test.mjs`), so the code has advanced past the amendment on this point. Where the amendment and the code disagree here, the code is the later and governing state.
