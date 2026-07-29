# Methodology — running the method by hand

The plugin ships Node scripts that compute all of this. On claude.ai there is no interpreter:
**you are the engine, the grader and the ledger.** These files are the same discipline written
out so a model that can only read files can follow it without running anything.

Read this page first (90 seconds), then the file for the phase you are in. Paths below are
relative to the `references/` root.

## The three laws

Everything else on this page is detail. These three are not negotiable, and each exists because
breaking it produced a concrete, embarrassing failure.

> **LAW 1 — A subject is never `pass` because a token appeared in the source.**
> Seeing `getUser` in a route file does not prove the route is gated: the call may be unawaited,
> its result ignored, or its throw swallowed by a `try/catch`. Printing a checkmark there is
> worse than printing nothing, because the user stops looking. The honest disposition is
> `undeterminable`, and those rows become the reviewer's work list.

> **LAW 2 — `enumerated = pass + fail + undeterminable + allowlisted`, for every subject set.**
> A subject that silently falls out of the ledger is how "we found nothing" comes to mean "we
> looked nowhere". If the arithmetic does not add up, you dropped something — find it.

> **LAW 3 — Name-only evidence may never justify a P0.**
> `FOO_API_KEY` in a variable name is not proof that a privileged credential exists.
> `PUSHER_APP_KEY`, `IDEMPOTENCY_KEY` and `NEXT_PUBLIC_GOOGLE_MAPS_KEY` are all publishable.
> A name may open an investigation; it may never close one at P0.

## The pipeline

```
  repo ──► Engine ──► Facts ──► Grader ──► Findings ──┐
                        │                              ├──► Report
       reviewer walks the inventory ──► reviewer Findings ┘
                        │
                        └──────────────► Coverage (the ledger)
```

1. **Engine** (`methodology/enumerate.md`) — read the repo and record what is *there*. Facts
   only: no severity, no opinion. "This var carries a bundler-inlined prefix." "This migration
   never enables RLS on `orders`." Also record what you could **not** establish, as an
   *Undeterminable Fact* — "no migrations exist, so RLS state is unknowable from this repo".
2. **Grader** (`methodology/grade.md`) — the single authority on severity. It maps Facts to
   Findings, and it is the *only* place severity is decided, so the policy exists once instead
   of being re-derived every time you look at a file.
3. **Reviewer findings** — things no rule could enumerate, reached by reading code and forming a
   view. They enter the same report with `provenance: reviewer` and evidence `judgement`.
4. **Coverage** (`methodology/coverage.md`) — the ledger that proves the report is a statement
   about the whole repo and not about the three files you happened to open.
5. **Report** — rendered per `report-template.md`, labels from `i18n/he.md` and `i18n/en.md`.

Before you grade anything, read `methodology/false-positives.md`. It is the highest-value file
here: it is the list of mistakes that already cost this project its credibility once.

## Vocabulary

Authoritative definitions live in `CONTEXT.md` at the repo root. The short form:

| Term | One line |
|------|----------|
| **Fact** | Something observed to be true. Never carries a severity. Records which Tier saw it. |
| **Tier** | How it was obtained: `static` (reading code), `passive-live`, `active-dast`. |
| **Finding** | A graded statement that something is wrong. Has severity *and* confidence. |
| **Severity** | How bad it is **if true** (P0–P4). Impact only. Never reduced for uncertainty. |
| **Evidence** | How solidly the Fact is established: `definitive` / `strong` / `weak` / `judgement`. |
| **Confidence** | Belief the Finding is real. A **pure function** of Evidence. Nothing else sets it. |
| **Provenance** | `rule` (a deterministic mapping proved it) or `reviewer` (someone read it and judged). |
| **Coverage** | The ledger: every enumerated subject accounted for. Stops a quiet report from reading as a safe one. |
| **Undeterminable Fact** | "This could not be established, and here is why." A first-class output, not a gap. |

Two consequences worth memorising:

- **Severity is uncapped, confidence carries the doubt.** An unproven P0 is still reported as a
  P0 — but the headline verdict counts **only `confirmed`** findings, so it does not turn the
  badge red. Discounting twice (once in severity, once in confidence) buries a
  catastrophic-but-unproven issue where nobody looks.
- **Verification may only refute.** Re-reading the code can drop a Finding or lower its
  confidence. It can never raise confidence — that would make the same repo grade differently
  depending on how hard you squinted.

## Why this discipline exists

This project's thesis is one sentence: **a security tool that cries wolf loses its audience.**
The people this is built for are shipping their first app. If the report says "CRITICAL: your
API key is exposed" and it isn't, they rotate keys, tell their users there was a breach, and
then never open the tool again — and the real P0 three lines down goes unfixed. Every rule in
these files is downstream of a specific time that happened.

## File map

| File | Read it when |
|------|--------------|
| `methodology/enumerate.md` | Building the inventory — routes, tables, env vars, LLM call sites — and deciding whether it is complete. |
| `methodology/grade.md` | Turning Facts into Findings: severity, evidence, confidence, the verdict. |
| `methodology/false-positives.md` | **Always, before reporting anything.** The catalogue of wrong readings. |
| `methodology/coverage.md` | Closing the audit: the ledger arithmetic and how to render it. |

Related: `severity-model.md` (the P0–P4 ladder and the finding schema), `checks/*.md` (what to
look for per stack), `guard-recipes/*.md` (the fix to paste).
