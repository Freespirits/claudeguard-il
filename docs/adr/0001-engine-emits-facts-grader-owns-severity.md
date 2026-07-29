# 0001 — Engine emits Facts; a single Grader owns severity

## Status

Accepted — 2026-07-29

## Context

The v1 analysis was Claude reading code: severity, confidence, and prose all came out of one LLM pass. v2 puts a deterministic layer underneath it, and the first question was where the severity policy should live. The tempting answer is "wherever the fact is discovered" — the env probe knows a `NEXT_PUBLIC_` secret is bad, the SQL parser knows a missing `enable row level security` is bad, so let each emit a severity alongside its observation. That is how the engine originally carried a `severityHint`, and how the two live probes each shipped their own P-levels.

The cost of that shape is that the danger policy is re-derived in every place a fact is produced. Two scanner adapters did exactly this — passing a tool's own severity straight through — so the same P0 could be defined three times with three subtly different meanings, and there was no single place to read, test, or change what the tool considers critical.

CONTEXT.md draws the line explicitly: a **Fact** is "something observed to be true, independent of how dangerous it is" and "Facts never carry a severity"; the **Engine** "has no opinion about severity"; the **Grader** is "the only authority on severity, so the severity policy exists in exactly one place rather than being re-derived inside each rule."

## Decision

`project_model.mjs` (the engine) computes Facts only and expresses no opinion about danger. `grader.mjs` is the sole authority that turns Facts into Findings and assigns severity. Concretely:

- `severityHint` was **deleted** from the engine. The engine reports what is true; it never reports how bad it is.
- The two live/DAST probes were changed to emit **tier-tagged observations** (a `kind` plus where it was seen), not graded findings. The kind→severity mapping lives in one table in the grader (`OBSERVATION_POLICY`).
- The external scanner adapters (gitleaks/semgrep/npm-audit) were likewise reduced to observations. Where two of them previously passed a tool's own severity through, the grader now owns the P-level and decides how much to trust each source.

## Consequences

Positive:

- The whole severity model is one readable file. To learn or change what "critical" means, there is exactly one place to look and one place to test.
- Facts are reusable. The same env fact drives a P0 in one repo and a P2 in another (see `gradeNextConfig`, where severity depends on whether the repo has a privileged secret to inline) without the engine knowing anything about it.
- Reproducibility follows for free: deterministic Facts in, deterministic policy applied, identical output every run.

Costs / risks accepted:

- Every new detector is split across two files — a fact in the engine and a rule in the grader — which is more ceremony than a single detector that "just knows" its own severity.
- A fact with no rule in the grader is silent. The engine can observe something the grader never grades; correctness now depends on keeping the two in step. The coverage ledger (ADR 0005) is what surfaces such a gap.

See ADR 0002 for why the grader assigns severity uncapped, and ADR 0006 for why there is no second severity authority (`invariants.mjs`).
