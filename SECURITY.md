# Security policy

ClaudeGuardIL is a **community project** and is **not an official Anthropic product**.

Claims this project made and later found to be wrong are quoted and retracted in
[`ERRATA.md`](ERRATA.md) rather than deleted.

## Reporting a vulnerability
If you find a security issue in ClaudeGuardIL itself (the plugin, the skill, or the scanner
scripts — for example a way to bypass the Tier 1/2 authorization gate, or a scanner that leaks a
secret it was scanning; both have happened here, and are **ERR-001** and **ERR-003** in
[`ERRATA.md`](ERRATA.md)), please report it privately:

- Open a **GitHub Security Advisory** (repo → **Security** → **Report a vulnerability**), or
- Contact the maintainers via the [community group](https://www.facebook.com/groups/cladue).

Please do **not** open a public issue for a real vulnerability until it has been addressed.

## About the deliberately vulnerable code in this repo

**Three** directories contain **intentionally insecure** code, and they exist so the tool can be
tested against known-bad input:

- `sample-vulnerable-app/` — the demonstration app. Its weaknesses are at the **code** level: an
  exposed Supabase `service_role` key, tables with no RLS, an IDOR API route, prompt injection,
  missing security headers.
- `bench/corpus/**` — the ground-truth benchmark, where each case is a vulnerable/fixed pair used
  to measure precision and recall.
- `bench/wild/*/repo/` — **real third-party source**, vendored at a pinned commit SHA and labelled
  by a reviewer blind to this tool (`bench/wild.mjs`). Not ours, not fixed, and deliberately still
  vulnerable: a case that got patched would stop measuring anything. Each case's `truth.json` names
  its `source_url`. One case (`breakableflask-python`) is Python — its `requirements.txt` and
  `database-requirements.txt` are pip manifests that feed the same dependency graph, and the same
  never-bump rule applies to them.

**Never install or deploy any of them.**

### Why the Security tab shows a fixture-only alert count

Their dependencies are **not** kept current, so Dependabot flags them. Every Dependabot alert on
this repository points at one of those three fixture trees, and none is reachable from anything the
tool ships.

An earlier version of this section named only the first two trees and told you to expect *"a large
alert count"* — while `bench/wild/`, unnamed, was producing most of it (about 122 alerts, from 429
vendored dependency entries). Both the inventory and the resignation are retracted as **ERR-007** in
[`ERRATA.md`](ERRATA.md). 0.3.1 cut the count by roughly an order of magnitude by deleting the
vendored dependencies the engine **cannot read** — `project_model.mjs` consults a closed set of
package names, so anything outside it bought no detection and cost an alert. The wild scorecard is
byte-identical across that change; `test/wild_manifest_hygiene.test.mjs` keeps it that way.

**The remaining count is correct and will not go to zero.** The dependencies the engine *does* read
(`next`, `express`, `firebase`, `electron`, `vite`, `openai`, …) stay at their real upstream pins,
vulnerable versions included, because the pin is what the benchmark is measuring against.

A fixture dependency bump is **noise, not a risk**. No `expected.json` in `bench/corpus` expects
`CG-DEP-001`, and the dependency-scanning arm is exercised in `test/dep_audit_shapes.test.mjs` and
`test/scanners.test.mjs` against **recorded tool output**, never against a fixture's installed
versions. Several fixture bumps have since been merged with the benchmark's regression gate green
throughout. Merge it or ignore it as you prefer, and re-run `node bench/run.mjs` either way.

One exception worth stating: do **not** bump a `bench/wild/*/repo/` manifest. Those are pinned to a
third-party commit and matched against labels written against that commit; changing a version there
falsifies the corpus rather than tidying it.

This section once justified the same conclusion with a reason that was false — that upgrading a
fixture "would delete test coverage" — while `README.md` simultaneously claimed the dependencies
were current. Both are retracted in the open as **ERR-002** in [`ERRATA.md`](ERRATA.md) rather than
quietly rewritten, because they are the mistake this tool exists to catch: a confident statement
nobody had checked.

ClaudeGuardIL itself has **zero runtime dependencies** — CI asserts this on every push, and the
build fails if any are added. Nothing this tool ships depends on the flagged packages, and nothing
in the fixtures is installed when you install the plugin or the skill.

If you see a Dependabot or scanner alert pointing at a fixture, that is expected and intended.

## Scope of the tool
- **Tier 0 (static)** is safe and read-only.
- **Tier 1 (passive live)** and **Tier 2 (active probes)** send network traffic and are hard-gated
  behind a `claudeguard.scope.yml` file in which you attest ownership/authorization of the target.
  Only test systems you own or are authorized in writing to test. You are responsible for your
  scope. Tier 2 is four GET probes — a smoke test, not a scanner; the older "real attack traffic
  (injection, IDOR, fuzzing)" description is retracted as **ERR-004** in [`ERRATA.md`](ERRATA.md).

A clean scan is **not** a proof of safety.
