# 0004 — The verdict counts only confirmed findings

## Status

Accepted — 2026-07-29

## Context

ADR 0002 made severity uncapped, which means the findings list now contains loud, unproven P0s. Something has to prevent those from firing a false "your app is critically broken" alarm every time the tool cannot read a schema. If the headline badge counted every P0, the tool would cry wolf on most real repos — vibecoded apps routinely have no migrations, so their RLS state is unknowable from source — and users would learn to ignore it, the exact failure the honesty of the model is trying to avoid.

## Decision

The headline verdict and the badge are computed from `confirmed` findings **and nothing else**. Because confidence is a pure function of evidence (ADR 0003), "confirmed" means "backed by definitive evidence — the compiler, bundler, or schema guarantees it."

| Level | Emitted when |
|---|---|
| `critical` | any confirmed P0 |
| `high` | any confirmed P1 (and no confirmed P0) |
| `medium` | any confirmed P2 (and nothing above) |
| `low` | at least one confirmed finding, all P3/P4 |
| `clean` | no confirmed findings at all |

`needs-review` and `likely` findings never touch the verdict; they are rendered in a quieter section below it. The grader emits, in the same object, `confirmedP0`/`confirmedP1` and — deliberately alongside — the counts of what did *not* count (`likely`, `needsReview`).

Critically: **`clean` means "nothing was proven," not "nothing is wrong."** A repo with eleven unproven P0s and no migrations grades `clean`. The report must therefore never show `clean` on its own — it is shown next to the unconfirmed findings and next to Coverage, or it is a lie by omission.

## Consequences

Positive:

- This is **what pays for uncapped severity** (ADR 0002). The scariest possibility can sit at the top of the list without the badge crying wolf, because only proof moves the badge.
- The badge is trustworthy: a `critical` verdict means a rule proved a critical issue, so it is worth interrupting someone for.
- The quiet path preserves the worklist: unconfirmed findings become the honest "here is what a human still has to check."

Costs / risks accepted:

- `clean` is dangerously easy to misread as "safe." The word carries a meaning the model explicitly rejects, and the design leans hard on the renderer to always present `clean` beside Coverage and the unconfirmed list. A renderer that shows the badge alone silently reintroduces the lie.
- A real but only-`likely` problem does not raise the badge, so a user who reads *only* the headline can miss it. The design accepts this in exchange for a badge that never cries wolf, and mitigates it by keeping unproven findings loud in the body.
