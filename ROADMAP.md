# Roadmap

What is built, what is deliberately not, and what comes next. Kept honest on purpose: a security
tool that overstates its own reach is doing the exact thing this project argues against. Where that
happened anyway, the claim is quoted and retracted in [`ERRATA.md`](ERRATA.md) rather than deleted.

Current version: **0.2.0**. See [CHANGELOG](#changelog-since-010) at the bottom.

---

## Where the tool actually stands

| Area | State |
|---|---|
| Static analysis (Tier 0) | **Solid.** 405 tests; the benchmark gate holds **0 regressions across 18 pinned detections and 0 unexpected confirmed findings over 8 clean variants**, deterministic. That is regression protection, not a detection rate — see below. This is the part to rely on. |
| Secrets, RLS, config, CI/CD, IaC, mobile manifests | **Its strongest surface.** Rules, ground truth and cry-wolf fixtures for each. |
| Coverage accounting | **Unusual and load-bearing.** Every subject the engine enumerates is `pass`/`fail`/`undeterminable`/`allowlisted`, asserted arithmetically at runtime. Everything it sees but does not grade gets a declared row. |
| Dataflow / injection (SQLi, XSS, SSRF) | **Delegated, on purpose.** See [ADR 0007](docs/adr/0007-taint-is-cut-generic-dataflow-is-delegated.md). Without semgrep or Snyk installed, this surface depends on reviewer judgement. |
| Business logic | **New, and capped.** Seven of ten taxonomy classes implemented; three declared unsupportable. Every finding is `judgement` → `likely`, never `confirmed`. |
| Vibecoder hygiene | **Four cheap greps, graded, capped.** CG-HYG-001..004: a placeholder credential shipped in source, base64 used as encryption, an auth token in web storage, a TODO left in auth code. None may reach `confirmed` — the engine sees the sink but not whether it matters, so `likely` with a named assumption is the honest ceiling for a regex. Measured at **0 findings on 4 clean reference repos and 0 on this repository's own source**. |
| Active probing (Tier 2) | **Four GET probes.** A smoke test, not a scanner. See below. |
| Parser depth | **Regex plus lightweight parsing, not a type-aware AST.** Dynamic requires, barrel re-exports and unusual routing can escape it. Stated in `limits` on every model. |
| **Compliance pillar (NEW)** | **Accessibility shipped, privacy documented.** A second pillar beside security: legal exposure, not breach. `pillar:'compliance'` findings never touch the security badge. Accessibility (ת"י 5568 / WCAG 2.0 AA): CG-A11Y-001..007 graded, statement + rendered-DOM declared, cry-wolf-tested. Privacy (data-security regs): CG-PRIV-* domain spec written, grader next. See below. |

### The benchmark, stated plainly

The scorecard prints recall 100% / precision 100% / 0 false positives. Every one of those numbers is
real and reproducible, and what they measure is a **golden-file regression gate** — not a detection
rate. `bench/run.mjs` says so in its own header: `expected.json` for each case *records what the
grader actually produces today*, asserted so it stays that way, and the harness ships a `--dump` mode
for authoring it from that output. A vulnerability the grader misses therefore never becomes a label,
so recall cannot fall below 100% except by regression. Which is exactly what the gate is for.

Stated as what it is: **0 regressions across 18 pinned detections in 7 vulnerable scenarios, and 0
unexpected confirmed findings across 8 clean variants — a corpus authored by this project.** That is
excellent regression protection and a genuine cry-wolf gate. **Real-world detection rate: not yet
measured.**

The earlier framing led with the percentages and read as a detection claim; it is retracted as
**ERR-006** in [`ERRATA.md`](ERRATA.md). Growing the corpus with cases we did not write (§5 below) is
the only thing that changes the underlying fact.

---

## The compliance pillar — a lawsuit is not a breach

A vibecoded app gets its owner in trouble two ways, and only one of them is a hacker. The other is a
**regulator or a plaintiff**, and for the Israeli audience it is often the more immediate risk. So
findings now carry a `pillar: 'security' | 'compliance'` tag, and the two are kept rigorously apart:
`summarize()` computes the security badge over security findings **only**, compliance gets its own
`summary.compliance` block, and the benchmark's decision-rate ratchet and false-positive gate are
scoped to the security pillar — a new compliance domain can never lower the security bar or redden the
security badge. Compliance severity is **legal-exposure-if-unfixed** (stated in the statute's terms),
and there is deliberately **no compliance P0**. Full model: [`core/severity-model.md#pillars`](core/severity-model.md).

**Domain 1 — Accessibility (ת"י 5568 חלק 1 / WCAG 2.0 AA). Shipped.** A pure JSX/HTML tokenizer
(`plugin/scripts/lib/a11y_scan.mjs`) feeds `gradeAccessibility`: **CG-A11Y-001** (img no alt),
**-002** (html no lang), **-003** (form control no label), **-004** (icon-only control no name),
**-005** (video no captions), **-006** (positive tabIndex), **-007** (non-keyboard-operable clickable).
Every false-positive trap is encoded as engine data (empty `alt=""` is valid, `{...spread}` abstains,
dynamic values abstain, decorative `role`/`aria-hidden` opt out). The legally-mandatory **accessibility
statement is a *declared* row, not a fired finding** — a static scan cannot tell a real deployed site
from a fresh scaffold, and a red P1 on `create-next-app` output is the cry-wolf failure the whole model
forbids; the report's mandatory-artifacts reminder carries the "you must publish one" instead. The
rendered-DOM half of WCAG (contrast, focus, ARIA-in-practice) is declared. Cry-wolf and detection twins
in `test/accessibility.test.mjs` + `test/a11y_scan.test.mjs`.

**Domain 2 — Privacy / data security (תקנות הגנת הפרטיות (אבטחת מידע) 2017). Documented; grader next.**
[`core/checks/privacy-data-security.md`](core/checks/privacy-data-security.md) maps the regulation as a
second compliance domain: a declared security-level classifier (basic/medium/high), a thin graded slice
(**CG-PRIV-TLS** cleartext transit, **CG-PRIV-COOKIE** session-cookie flags), and ~19 declared
obligation rows (audit logging, pen-testing, outsourcing contracts, breach process…) each tied to its
תקנה. Because the regulation is overwhelmingly process and paperwork invisible to a repo, this domain is
grade-or-declare taken to its limit — the graded checks are few and conservative, and their absence is
never asserted as a violation.

**Future compliance domains** could join under the same mechanism: cookie-consent, terms/privacy-policy
presence, age-gating. Each would be its own statute-denominated severity axis, none ever touching the
security badge.

---

## Why Snyk and not XBOW / NodeZero / Burp / HexStrike / Strix / Kali MCP / CAI

The most common question about the integration list. The tools split into two categories that need
completely different things from us.

**Category one — read-only analysers.** Snyk, semgrep, gitleaks, npm-audit, pip-audit, osv-scanner.
They read code and emit findings. Integrating one is a normalizer plus a coverage row: the adapter
observes, the grader owns severity, and a tool that could not run becomes an `undeterminable` row
naming why. There is no authorization surface, because nothing is sent anywhere. **Snyk went first
because it is in this category**, and because reachability and dataflow are the two things it knows
that a regex cannot.

**Category two — offensive tools.** HexStrike, Strix, XBOW, Horizon3 NodeZero, Burp Suite Pro's
scanner, Kali MCP, CAI. These send attack traffic at live systems. For every one of them the adapter
is the easy half. The hard half is that
[`core/authorization/dynamic-testing-gate.md`](core/authorization/dynamic-testing-gate.md) is right:
**those tools enforce nothing.** No authentication, no target allowlist, no rate limit, no sandbox.
Their safety model is "run it in a VM and supervise."

So the gate came first, on purpose. `plugin/scripts/dynamic_gate.mjs` is finished — three tiers
(`recon` / `active` / `exploit`), per-tool allowlists, deny-by-default, a kill switch, an append-only
audit log, and 66 adversarial tests including every host-matching bypass we could invent. It is
wired to nothing, because no adapter exists yet. That is the sequencing the spec demands:

> *"If we cannot build a gate we trust, we do not ship the integration. A scanner that can be argued
> into attacking the wrong host is worse than no scanner."*

**And the strategic point underneath it.** We are not going to out-scan XBOW or NodeZero; they are
funded products doing autonomous pentesting full-time. What this project can be is *the
deny-by-default boundary an LLM cannot argue past when it drives them* — the seatbelt, not the
arsenal. Each offensive integration also multiplies legal exposure and needs its own tier mapping,
which is why they land one at a time behind an attestation, not as a batch.

---

## Next

Ordered. Each item says what "done" means.

### 1 · Wire up what is already built

This section listed three unwired components. **Two of the three were wired and this file was not
updated** — the entry stayed on the list long after the work landed, which is its own small version
of the dishonesty this document is supposed to prevent. Both were re-verified end to end before
being struck, rather than taken on trust a second time:

- ~~**The Snyk adapter.**~~ **Done.** `/cg-scan` runs `run_snyk.mjs` when `detect_tools.mjs` reports
  Snyk installed *and* authenticated, and passes `--snyk` to the grader. Verified against the
  recorded real payloads in `test/fixtures/snyk/`: 8 findings (CG-SNYK-001 dep-vulns, CG-SNYK-006 IaC
  misconfigurations), **all at `needs-review`** — Snyk is a `JUDGEMENT_SOURCE`, so its output can
  never reach `confirmed` — and all four `scan:snyk-*` coverage rows render, in the ran case *and* in
  the unauthenticated one ("SNYK_TOKEN is not set, so the adapter did not run it"). The consent
  boundary holds: Snyk Code is the only scan that sends source off the machine and stays off until
  the user says yes.
- ~~**The business-logic intent loop.**~~ **Done.** The claim here was the strongest in this file —
  "structurally broken", "cannot be consumed even if a user writes one by hand", "incapable of ever
  reporting `confirmed`" — and it is simply not true of the current code. The grader has `--intent`,
  calls `loadIntent`, and auto-discovers `claudeguard.intent.yml` at the repo root. Verified as the
  full round trip: no file → `assumed`; `--propose-intent` drafts one with `TODO:` markers for the
  rules it refuses to invent; committing it at the root → **`confirmed`**, via auto-discovery and via
  the explicit flag. The ceiling still holds — `CG-BIZ` findings stay capped at `likely` by a
  module-load assertion, because a confirmed intent file does not turn a guess about business rules
  into a proof.
- **`dynamic_gate.mjs`.** Still unwired, and still **deliberately** so — see the section above. It is
  a documented dependency inversion, not an oversight, and the day a HexStrike or Strix adapter lands
  it is the precondition that already exists. This is the only genuine entry left in this section.

### 2 · Close the non-JS blind spot

The engine parses `.js/.jsx/.ts/.tsx/.mjs/.cjs/.svelte/.vue` and nothing else. Mobile got an explicit
declaration path, so Kotlin, Swift, Dart and Gradle produce loud `ungradedSurfaces` rows. **Backend
languages got nothing:** a Python, Go, Ruby or PHP repo renders `routes | 0 | 0 | 0 | 0 | 0` with no
declared row, because `SERVER_FRAMEWORKS` is keyed on npm package names. That is the precise failure
[`grade-or-declare.md`](core/methodology/grade-or-declare.md) exists to eliminate, in the one place it
is not enforced. Done when an unparsed backend is loud instead of invisible.

### 3 · Ship it like a product

- Reconcile the version across every manifest — done in 0.2.0; it had drifted three ways.
- Publish a release artifact so claude.ai users do not need Node and a clone. The skill zip is
  currently gitignored and **built with backslash path separators on Windows**, which the ZIP spec
  forbids; CI runs on Linux and never sees it.
- Keep `README.he.md` in step with `README.md`. The bilingual promise had an unmaintained half.

### 4 · Depth where the check lists are thinnest

Measured against `core/checks/*.md`, which enumerate the intended checks per domain:

| Domain | Documented | With a rule |
|---|---:|---:|
| Electron / desktop | ~16 | **0** |
| iOS | ~13 | ~2 |
| Android | ~15 | ~4 |
| AI / LLM | ~21 | ~6 |
| Supabase / Firebase | ~18 | ~7 |
| Web | ~33 | ~11 |
| Backend / IaC | ~19 | ~13 |
| Supply chain / CI-CD | ~15 | ~8 |

Electron is the standout: sixteen documented checks, zero rules, one declared row. Tauri is not
detected at all.

### 5 · A corpus we did not write

The benchmark's honesty problem is authorship and construction, not size: we wrote the cases, and
`expected.json` is authored from what the grader already outputs (ERR-006). Adding real-world cases —
from public disclosures, from OWASP Benchmark-style suites, from repos we have not seen — is the only
thing that turns "excellent regression protection" into evidence about detection rate. Done when a
number in this file comes from a corpus nobody here authored.

### 6 · Real dynamic testing — the worklist resolver

Not "a scanner." The static engine leaves a route `undeterminable` when it cannot tell whether an
auth call gates the handler; the resolver sends one gated, unauthenticated request and lets the
answer settle it — a 200 is a **confirmed** auth bypass with a live proof, a 401/403 is a pass. A
live proof is the definitive evidence a heuristic can never have, and the only honest route to
`confirmed` for a class the static tier could only suspect.

- **Phase 1 — the loop, one prober, no container. DONE.** `plugin/scripts/dynamic_runner.mjs` reads
  the `undeterminable` route worklist, drives an `authz_probe` through the hardened gate
  (`dynamic_gate.mjs`), and emits observations the grader maps to `CG-DAST-AUTHZ-POC` (definitive →
  confirmed → P0). Dry-run by default; every send gated; the response body is never read, only the
  status. Proven end-to-end in `test/dynamic_runner.test.mjs`.
- **Phase 2 — multi-principal IDOR.** Two attested sessions: log in as A, read A's id, request it as
  B. B receiving A's record is `exploited-idor`, a confirmed P0 — the one thing single-session DAST
  structurally cannot prove. Record proof-of-access, never the record.
- **Phase 3 — the sandbox.** A rootless container with a curated tool (nuclei), behind an
  HTTP-proxy adapter that routes every call through `decide()`. Suspicion-grade tool output caps at
  `likely`; only the purpose-built probers' positives reach `confirmed`.
- **The exploit tier stays refused** for this audience (no sqlmap/hydra/metasploit), and any active
  traffic needs machine-verified target ownership, not a typed boolean.

The old four-GET Tier 2 (`dast_runner.mjs`) remains as the perimeter smoke test, honestly named.

---

## Not planned

- **Becoming a pentest platform.** Burp, ZAP, Nuclei and the autonomous platforms do this better. The
  interesting position is the gate in front of them.
- **A type-aware AST engine.** [ADR 0007](docs/adr/0007-taint-is-cut-generic-dataflow-is-delegated.md)
  delegates generic dataflow to semgrep and Snyk deliberately. Revisit only with evidence that
  delegation is failing.
- **Raising the business-logic ceiling.** Those findings are capped at `likely` by a module-load
  assertion. A confirmed intent file does not make a guess about business rules into a proof.
- **Emitting a finding for missing configuration.** Not configuring the tool is not a vulnerability.
  This was shipped once and removed as a cry-wolf failure.

---

## How to judge this project

Use it as a **first gate**, not a sign-off. It is stronger than an ordinary PR review for security
coverage and completeness, and weaker than an experienced AppSec reviewer on subtle logic. It is not
a pentest. The combination that works: this first, then a security-focused review, then authenticated
testing for anything production-critical.

A clean scan is not proof of safety. It is proof that nothing was proved.

---

## Changelog since 0.1.0

- **Grade or declare.** Five artifact classes the engine discovered and no rule read — GitHub
  Actions workflows, Dockerfiles, compose, Terraform, Firebase rules — are graded, plus 22 new rules.
  Anything still ungraded gets a declared row.
- **The gate was attacked and rebuilt** (ERR-001). Six real bypasses in the shipped Tier-1/Tier-2 gate, all of
  one family: the gate and the scanner parsed the same URL differently. `https://localhost:3000@169.254.169.254`
  — using the default target from our own example scope file — cleared the gate and reached the cloud
  metadata endpoint. Both now derive from one WHATWG parse.
- **A credential leak in the Supabase spot-check** (ERR-003). `--supabase-url` was never gated and the request
  carried the user's anon key, so naming any host sent that key there. Found by external review,
  reproduced, fixed, and pinned with twelve tests.
- **The mobile arm was re-audited.** Twenty proven defects. An untouched `npx react-native init`
  graded `medium`; it now grades `clean`. A `network_security_config.xml` trusting user-installed CAs
  had been passing.
- **Quoted source is no longer source.** Fixture code in template literals was read as live code —
  seven phantom LLM call sites and eighteen phantom dependencies, in this repo alone.
- **Business-logic tier** (facts → intent → audit) and the **Snyk adapter**, both validated against
  real recorded tool output.
- **The Tier-2 overclaim was retracted** (ERR-004, and ERR-005 for the half of it that was announced
  before it was made). "Real attack traffic (injection, IDOR, fuzzing)" was four GET probes.
- Tests **159 → 405**. The benchmark's regression gate stayed green throughout — recall 100% /
  precision 100% / 0 false positives, which is regression protection and not a detection rate
  (ERR-006).
