# 0009 — `clean` requires coverage, not merely the absence of proof

## Status

Accepted — 2026-07-29. Amends the `clean` row of [ADR 0004](0004-the-verdict-counts-only-confirmed-findings.md); the four graded levels there are unchanged.

## Context

ADR 0004 computed the badge from `confirmed` findings and nothing else, and accepted one risk explicitly: *"`clean` is dangerously easy to misread as 'safe'… A renderer that shows the badge alone silently reintroduces the lie."* The mitigation was left entirely to the renderer.

That risk arrived, and not through a renderer. It was in the model.

A repository with a **fully unauthenticated DELETE endpoint** graded 🟢 `clean`. Every step was individually correct. The route rule raises the finding at P1, because impact-if-true is that an anonymous caller destroys data (ADR 0002). Its evidence is `weak`, because the absence of an auth token in a handler is not proof — the check could live in a helper this pass does not follow (LAW 1). So confidence is `needs-review` (ADR 0003), so it did not count, so the badge was green. The same held for a scan that could read only a third of the repository: nothing confirmed, badge green.

This is a **false all-clear**, and it is the asymmetric failure for this audience. A false positive costs a non-expert an afternoon and some trust. A false all-clear costs them the database, and — unlike a false positive — they have no way to detect it. "Nothing was proven" and "nothing is wrong" were printing the same colour, and `core/methodology/discovery.md` had already written down the answer: *"When discovery is degraded… the honest headline is not 'clean' — it is 'we could not see enough to say'."* The grader was not implementing it.

## Decision

The badge is a function of **coverage × confirmed**, not of confirmed alone. A new level, `unknown` (HE `לא נבדק`), stands for *not proven safe*.

`clean` is emitted only when **all three** hold:

1. zero `confirmed` findings (ADR 0004, unchanged), **and**
2. zero **unproven P0/P1** — no finding at severity P0 or P1 with confidence `likely` or `needs-review` is still open, **and**
3. **discovery coverage at or above its floor** — the discovery ledger is present and reconciles, at least one file was read, and `(filesParsed + configParsed) / (filesParsed + configParsed + oversized + readErrors) ≥ 0.95`.

If (1) holds and (2) or (3) does not, the level is `unknown`. The four graded levels — `critical`, `high`, `medium`, `low` — are computed from `confirmed` findings exactly as ADR 0004 specified and are untouched: **`unknown` only ever replaces what used to be `clean`.**

This is **LAW 4**, and like the other three (ADR 0005) it is a runtime assertion, not a comment: `grade()` throws if it is about to return `clean` with an unproven P0/P1 open or with coverage below the floor. The failure it guards against is silent by nature — a report that reintroduces the false all-clear looks exactly like every other clean report — so it must fail loudly at the source instead of being caught by a reader who, by construction, cannot catch it.

Two boundaries drawn deliberately:

- **P2 and below do not block `clean`.** A missing CSP at `needs-review` is a real weakness and not a reason to withhold a clean bill of health. Folding it in would make `unknown` the permanent answer, and a badge that never varies carries no information.
- **`unsupported` files are excluded from the coverage denominator.** Images and lockfiles are deliberate, accounted-for exclusions. A repository is not under-read for owning a logo, and flipping correct apps to `unknown` for having assets would be the cry-wolf failure wearing a different hat.

## Consequences

Positive:

- The headline can no longer overstate the evidence. The repo whose delete endpoint is open reads `⚪ UNKNOWN — not proven safe`, which is exactly what we know.
- The mitigation ADR 0004 delegated to the renderer is now enforced in the model, where it cannot be forgotten. A renderer that prints the badge alone can still be terse, but it can no longer be *wrong*.
- It makes a deploy gate possible (`--gate`, exit `2` on `unknown`), and gives it a property worth having: a reviewer finding can never reach `confirmed`, and an unsettled reviewer P0/P1 pushes `clean` to `unknown`, so every path an agent's output can take raises the exit code. An agent cannot talk the gate green.

Costs / risks accepted:

- **More repositories will read `unknown` than used to read `clean`.** That is the correction, not a side effect — but `unknown` is a weaker call to action than either a red badge or a green one, and a user who sees it repeatedly may learn to treat it as the default. The mitigation is that `unknown` always prints *why*: the count of open unproven P0/P1s, or the coverage ratio against its floor, each with the one assumption to check.
- **The keystone invariant of ADR 0008 is restated rather than kept verbatim.** Reviewer findings may now move `clean → unknown`; what they may never move is the *confirmed* verdict, which is the axis that made letting an LLM contribute safe in the first place. The permitted transition is one-way and asserted; any other throws.
- **An absent discovery ledger now counts as inadequate coverage.** Hand-built models that omit it grade `unknown`. This is deliberate — if absence counted as adequate, deleting one key from the model would be the cheapest way to buy a green badge — but it means fixtures have to state what they saw.
