# 0003 — Confidence is a pure function of Evidence; the verifier may only refute

## Status

Accepted — 2026-07-29

## Context

Uncapped severity (ADR 0002) puts all of the tool's uncertainty onto one axis: Confidence. For that axis to be trustworthy it cannot be a mood — it must be mechanical, or the same repo grades differently on two runs and the central "reproducible" claim collapses.

There is also a standing temptation, once an LLM is in the loop, to let a persuasive argument raise a finding's confidence: the auditor "is quite sure," so promote `likely` to `confirmed`. That would put a human judgement back into the one place the design guarantees is deterministic.

## Decision

Confidence is derived from Evidence alone, by one fixed mapping and nothing else:

| Evidence | Confidence |
|---|---|
| `definitive` | `confirmed` |
| `strong` | `likely` |
| `weak` | `needs-review` |
| `judgement` | `likely` |

Rules supply Evidence; the grader derives Confidence and asserts the mapping again before returning. No rule, agent, or payload may set confidence directly — `finding()` computes it and ignores any confidence field passed in. `judgement` maps to `likely`, not `needs-review`, on purpose: a reviewer who read the code has done more than a regex that half-matched. It is capped there and can never reach `confirmed`, because no amount of reading is a proof.

**The one asymmetry:** the adversarial verification pass may only **refute** a finding — drop it, or correct the Evidence it rests on — never raise its confidence by argument. If a `likely` finding deserves `confirmed`, the legitimate path is *better Evidence*: a live check (`/cg-live`) that observes the behaviour, or an engine rule that can see the fact definitively. Persuasion is not a path.

## Consequences

Positive:

- The same repo always grades the same way — two runs, two machines, two people, identical confidences and verdict.
- Confidence is auditable: given a finding's evidence strength, its confidence is predictable and checkable.
- The verifier can prune false positives (its highest-value job) without being able to manufacture certainty.

Costs / risks accepted:

- Confidence is only as good as the Evidence taxonomy. If a rule mislabels weak evidence as `strong`, the confidence is wrong in a way no downstream step can catch — the honesty of the whole axis rests on rules labelling evidence correctly.
- A genuinely correct `likely` finding cannot be promoted in place; upgrading it to `confirmed` requires new work (a live observation or a new rule). This can feel like friction when a reviewer is right but has no rule to point to (see ADR 0008).
