# 0002 — Severity is impact-if-true and uncapped

## Status

Accepted — 2026-07-29

## Context

The plan's original **Law 3** capped severity by evidence strength: weak evidence could not raise a P0, so a catastrophic-but-unproven issue was printed as a P2. This ADR reverses that.

The intent of the cap was honesty — don't shout "critical" about something you cannot prove. In practice it did two harmful things.

**It double-counted the uncertainty.** The model already has an axis for "how sure are we": Confidence, which is a pure function of Evidence (ADR 0003). Capping severity as well subtracts the same doubt a second time, and the reader has no way to add it back — they see a P2 and cannot recover the fact that its *impact* is total.

**It buried the worst case where nobody looks.** Reports sort by severity. A P0 demoted to P2 for lack of proof sorts below three CSP warnings, and the non-expert this tool is for stops reading long before reaching it. A report that hides its scariest line in order to look rigorous has failed at its only job.

## Decision

Severity expresses **impact if the finding is real**, on the P0–P4 scale, and is **never reduced because we are unsure**. Uncertainty lives entirely in Confidence.

Plainly: **an unproven P0 still prints as a P0.** It carries `needs-review` beside it, it states the assumption that would make it a false positive, and — crucially — it does not turn the badge red (ADR 0004). The worked case is `CG-DB-COVERAGE`: a repo with no migrations has tables of unknown RLS state; impact if RLS is off is total exposure, so severity is P0; evidence is `weak`, so confidence is `needs-review`; it appears at the top of the report as a P0 to settle with one query, and the verdict stays `clean` unless something else was actually confirmed.

The **surviving piece of the old Law 3** is narrower and still enforced: name-only evidence may never justify a P0 (ADR 0005, LAW 3).

## Consequences

Positive:

- The most dangerous possibility is always at the top of the report, where a non-expert will actually see it.
- Severity means one thing — consequence — and can be reasoned about without knowing how it was found.
- No information is destroyed: impact and certainty are both visible and independently recoverable.

Costs / risks accepted:

- The reader must understand that severity and confidence are two different axes; a P0 is no longer a promise that the sky is falling. This is a real cognitive cost.
- That cost is **paid for by the verdict rule** (ADR 0004): because the headline and badge count only `confirmed` findings, an uncapped unproven P0 is loud in the list but cannot trigger a false alarm. Uncapped severity is only safe *because* of that rule — the two decisions are a matched pair.
