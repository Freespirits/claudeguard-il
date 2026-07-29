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

Two directories contain **intentionally insecure** code, and they exist so the tool can be tested
against known-bad input:

- `sample-vulnerable-app/` — the demonstration app. Its weaknesses are at the **code** level: an
  exposed Supabase `service_role` key, tables with no RLS, an IDOR API route, prompt injection,
  missing security headers.
- `bench/corpus/**` — the ground-truth benchmark, where each case is a vulnerable/fixed pair used
  to measure precision and recall.

**Never install or deploy either of them.**

### Why the Security tab shows a large alert count

Their dependencies are **not** kept current, so Dependabot flags them. Every Dependabot alert on
this repository points at one of those two fixture trees.

A fixture dependency bump is **noise, not a risk**. No `expected.json` in `bench/corpus` expects
`CG-DEP-001`, and the dependency-scanning arm is exercised in `test/dep_audit_shapes.test.mjs` and
`test/scanners.test.mjs` against **recorded tool output**, never against a fixture's installed
versions. Several fixture bumps have since been merged with the benchmark's regression gate green
throughout. Merge it or ignore it as you prefer, and re-run `node bench/run.mjs` either way.

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
