# Security policy

ClaudeGuardIL is a **community project** and is **not an official Anthropic product**.

## Reporting a vulnerability
If you find a security issue in ClaudeGuardIL itself (the plugin, the skill, or the scanner
scripts — for example a way to bypass the Tier 1/2 authorization gate, or a scanner that leaks a
secret it was scanning), please report it privately:

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

Their dependencies are deliberately **not** kept current. Known-vulnerable packages are what the
dependency-scanning part of the tool is exercised against, so upgrading them would delete test
coverage rather than add safety. Every Dependabot alert on this repository points at one of those
two fixture trees.

ClaudeGuardIL itself has **zero runtime dependencies** — CI asserts this on every push, and the
build fails if any are added. Nothing this tool ships depends on the flagged packages, and nothing
in the fixtures is installed when you install the plugin or the skill.

If you see a Dependabot or scanner alert pointing at a fixture, that is expected and intended.

## Scope of the tool
- **Tier 0 (static)** is safe and read-only.
- **Tier 1 (passive live)** and **Tier 2 (active DAST)** send network traffic and are hard-gated
  behind a `claudeguard.scope.yml` file in which you attest ownership/authorization of the target.
  Only test systems you own or are authorized in writing to test. You are responsible for your
  scope.

A clean scan is **not** a proof of safety.
