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
| Active probing (Tier 2) | **Four GET probes.** A smoke test, not a scanner. See below. |
| Parser depth | **Regex plus lightweight parsing, not a type-aware AST.** Dynamic requires, barrel re-exports and unusual routing can escape it. Stated in `limits` on every model. |

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

Three finished components have no invocation path:

- **The Snyk adapter.** `run_snyk.mjs` is complete and the grader already accepts `--snyk`, but no
  skill passes it. Done when `/cg-scan` runs it where available and its four coverage rows render.
- **The business-logic intent loop.** This one is structurally broken, not merely unwired: the grader
  imports `loadIntent` and never calls it, and its CLI has no `--intent` flag, so
  `claudeguard.intent.yml` **cannot be consumed even if a user writes one by hand.** The tier is
  therefore incapable of ever reporting `confirmed`. Done when a user can produce the file through a
  guided pass, the grader discovers it, and the report shows `assumed → confirmed`.
- **`dynamic_gate.mjs`.** Deliberately left unwired — see the section above. It is a documented
  dependency inversion, not an oversight, and the day a HexStrike or Strix adapter lands it is the
  precondition that already exists.

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

### 6 · Real dynamic testing, or none

Tier 2 is four GET probes. The options are to build real crawling, authenticated flows, parameter
discovery and multi-user IDOR testing behind the existing gate, or to keep the smoke test and say so
in the name. **Until one of those happens, the documentation says exactly what it does.**

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
