# 0007 — taint.mjs is cut; generic dataflow is delegated

## Status

Accepted — 2026-07-29

## Context

The plan's largest proposed component was `taint.mjs`: generic interfile dataflow / taint tracking, whose flagship output was IDOR. It is also, by a wide margin, the most false-positive-prone and most rot-prone code in the design — a resolver that cannot resolve a bare package reads a chain through an unresolved barrel as clean, and generic taint over a large repo produces a stream of maybes that a non-expert cannot triage. Meanwhile, mature tools already do exactly this as maintained products.

## Decision

Do not build `taint.mjs`. Delegate generic dataflow to external scanners:

- **Semgrep OSS** — default, local, no upload.
- **Snyk Code** — opt-in, and **consent-gated because it uploads source to Snyk's cloud.** It is never default-on; it requires an explicit flag *and* a recorded consent flag, because some users audit client code under NDA and code must never leave the machine without an explicit yes.

The scanner adapters follow the existing detect-and-adapt contract and are wired **through the grader**: they emit observations, the grader owns the P-level and decides how much to trust each source (`gradeScanners`), and every scanner result enters the **coverage ledger** as its own subject set. Whether git history was scanned, whether Semgrep ran at all — these become explicit coverage facts rather than silent gaps. What we keep building is the layer the scanners *don't* have: Supabase RLS state, the `NEXT_PUBLIC_` client boundary, LLM / prompt-injection sites, and the route inventory.

## Consequences

Positive:

- We do not own the most brittle, highest-FP code in the design; interfile dataflow is maintained by teams whose whole product it is.
- Scanner output is held to the same severity model and the same coverage accounting as everything else (ADR 0001, ADR 0005) — no tool's own severity leaks through, and a scanner that did not run is a loud `undeterminable`, not a silent hole.
- The local-first default keeps the tool free and offline; the cloud option is available but only with informed consent.

Costs / risks accepted:

- Coverage now depends on tools that may be absent. If Semgrep is not installed and Snyk is not consented, the generic-dataflow surface is `undeterminable` — honest, but it means the tool's dataflow reach varies by environment.
- The best interfile analysis (Snyk Code) sits behind a consent gate and a metered free tier, so many users will run without it and get the local Semgrep tier instead.
- Delegation means we inherit each scanner's own false positives and precision, which the grader can down-weight but not fix.
