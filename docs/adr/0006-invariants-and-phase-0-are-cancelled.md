# 0006 — invariants.mjs and Phase 0 are cancelled

## Status

Accepted — 2026-07-29

## Context

The plan originally proposed a separate module, `invariants.mjs` (~8 invariants), sitting beside the grader, and a **Phase 0** experiment to run *before* building anything: three arms (source only / source + fact base / source + fact base + invariant results) scored against ground truth, to decide whether invariants were worth their cost.

Two things dissolved this during the domain-modelling pass.

First, **an invariant is a Grader rule.** CONTEXT.md defines a Rule as "a single deterministic mapping owned by the Grader… A Rule that iterates every member of an enumerable set is how completeness is achieved — there is no separate 'invariant' concept." Having both `invariants.mjs` and the grader meant two places could decide severity — the exact duplication ADR 0001 exists to remove.

Second, **Phase 0 was asking a question that no longer had a variable in it.** The experiment was designed to test whether an LLM given invariants beats an LLM given the project model. Once the Grader was settled as *deterministic code* rather than an LLM, the comparison had no live term: an LLM grader forfeits reproducibility by construction, so no measured number could change the decision. Running it would have bought a number, not an answer.

## Decision

Delete the concept of an invariant. There is one abstraction — the Rule — and rules live in `grader.mjs`. Cancel Phase 0; do not run it.

## Consequences

Positive:

- One severity authority, one abstraction, in one file (reinforces ADR 0001). There is no second place a P-level can be decided.
- ~2,000 lines of speculative experiment and a parallel module were never written.
- The public claim sharpened from the unfalsifiable "smarter than a single-pass LLM" to something checkable: complete enumeration + reproducibility + explicit coverage.

Costs / risks accepted:

- We ship without the empirical number Phase 0 would have produced. The bet that a deterministic grader is the right shape is made on argument, not measurement — defensible because reproducibility is a property we *chose* rather than one we needed to discover, but it is still a bet made without the experiment.
- "Invariant" is common security vocabulary; collapsing it into "Rule" means contributors must unlearn a familiar word (CONTEXT.md lists it under _Avoid_).
