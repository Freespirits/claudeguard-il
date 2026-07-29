# Architecture Decision Records

An Architecture Decision Record (ADR) captures one significant decision — its context, the choice made, and the consequences accepted — as a short, dated, immutable record. These follow the classic Michael Nygard format (Title, Status, Context, Decision, Consequences); each is roughly one page and is superseded rather than edited after acceptance.

These records document the load-bearing decisions of the ClaudeGuardIL v2 analysis pipeline. They read best in order — 0002 and 0004 are a matched pair, and most of the rest reference 0001.

- [0001](0001-engine-emits-facts-grader-owns-severity.md) — Engine emits Facts; a single Grader owns severity
- [0002](0002-severity-is-impact-if-true-and-uncapped.md) — Severity is impact-if-true and uncapped
- [0003](0003-confidence-is-a-pure-function-of-evidence.md) — Confidence is a pure function of Evidence; the verifier may only refute
- [0004](0004-the-verdict-counts-only-confirmed-findings.md) — The verdict counts only confirmed findings
- [0005](0005-the-three-laws-enforced-as-runtime-assertions.md) — The three laws, enforced as runtime assertions
- [0006](0006-invariants-and-phase-0-are-cancelled.md) — invariants.mjs and Phase 0 are cancelled
- [0007](0007-taint-is-cut-generic-dataflow-is-delegated.md) — taint.mjs is cut; generic dataflow is delegated
- [0008](0008-reviewer-findings-are-capped-and-validated.md) — Reviewer findings are capped at judgement→likely and validated before merge
- [0009](0009-clean-requires-coverage-not-merely-the-absence-of-proof.md) — `clean` requires coverage, not merely the absence of proof (amends 0004)
