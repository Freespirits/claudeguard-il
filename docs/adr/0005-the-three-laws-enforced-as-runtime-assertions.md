# 0005 — The three laws, enforced as runtime assertions

## Status

Accepted — 2026-07-29

## Context

Three properties are load-bearing for everything else in the model, and each is the kind of rule that quietly rots if it lives only in a document. A design doc cannot stop a future rule from printing a checkmark it should not, or from letting a subject fall out of the accounting. So the laws are written into the code that would otherwise be free to break them.

## Decision

Three laws, enforced in code rather than only documented:

**LAW 1 — No subject passes on a token's presence.** Seeing `getUser` in a route file does not prove the handler is gated: the call may be unawaited, its result ignored, its throw swallowed. Such a subject is recorded `undeterminable`, never `pass`. The `undeterminable` rows are precisely the reviewer's work list — the honest short list of "here is what a human still has to open." A `pass` is reserved for structural facts (an env var with no inlining prefix and no client reader cannot reach the browser; a migration that enables RLS with a non-permissive predicate). Enforced two ways: by construction (every legitimate `pass` is structural and lives in a set that reads a fact, not a token), and — for the sets where a token could tempt a pass, `routes` and `llmSites` (`NO_PASS_SETS`) — by a runtime assertion in `grade()` that forbids a `pass` row in those sets outright.

**LAW 2 — `enumerated === pass + fail + undeterminable + allowlisted`, for every subject set.** A subject that silently falls out of the ledger is how "we found nothing" comes to mean "we looked nowhere." Enforced by the `Ledger`: recording the same subject twice throws (two rules disagree about the same thing), and `toJSON()` throws if the four dispositions do not sum to the enumerated count.

**LAW 3 — Name-only evidence never justifies a P0.** `FOO_API_KEY` in a variable name is not proof a privileged credential exists; names like `PUSHER_APP_KEY` are routinely publishable. `finding()` throws if a rule claims P0 from name-only evidence; these are raised at P2 with the assumption stated. `grade()` re-checks it over the whole finding set before returning.

These live in the `Ledger`, in `finding()`, and in the enforcement loop at the end of `grade()` — asserted, not just described, because a law only written down drifts. LAW 1's assertion (the `NO_PASS_SETS` check) sits alongside LAW 2's in `grade()`, right after the coverage ledger is built.

## Consequences

Positive:

- The failure the whole design exists to prevent — a green checkmark over an ungated route — cannot be printed by construction; it becomes an `undeterminable` row instead.
- Coverage cannot silently under-report: a dropped or double-counted subject is a thrown error in tests, not a quiet gap in a report.
- LAW 3 stops the tool from teaching its audience to ignore it by crying P0 over publishable identifiers.

Costs / risks accepted:

- The laws make the tool *quieter and more honest*, which reads as "less impressive": many routes land in `undeterminable` rather than `pass`, and a user who wanted a wall of green checkmarks gets a worklist instead. That is intended, but it is a cost.
- A thrown assertion is a hard failure: a malformed rule crashes grading rather than degrading. That is the right trade for a security tool, but it means rule bugs surface as crashes.

Note: LAW 1's enforcement is not uniform, and it is worth knowing when adding a rule. LAW 2 (the `Ledger` throws) and LAW 3 (`finding()` and `grade()` throw) are asserted for every subject. LAW 1 is asserted only for the token-sensitive sets `routes` and `llmSites` (`NO_PASS_SETS`), where a `pass` could only have come from a token; for every other set it holds by construction, because those rules read a structural fact rather than a token when they elect `pass`. A future rule that invented a *new* token-sensitive set and recorded `pass` on a bare token there would need to be added to `NO_PASS_SETS` to be caught — the assertion covers today's token-sensitive sets, not any conceivable one. Separately, the plan amendment lists the mobile domain as having "no Grader rules or Ledger set at all, so LAW 2 is unenforceable there"; `grader.mjs` has since grown `gradeMobile()` with `mobileArtifacts`/`exportedComponents` ledger sets, so that known-open no longer holds.
