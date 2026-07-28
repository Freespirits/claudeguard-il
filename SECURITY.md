# Security policy

ClaudeGuardIL is a **community project** and is **not an official Anthropic product**.

## Reporting a vulnerability
If you find a security issue in ClaudeGuardIL itself (the plugin, the skill, or the scanner
scripts — for example a way to bypass the Tier 1/2 authorization gate, or a scanner that leaks a
secret it was scanning), please report it privately:

- Open a **GitHub Security Advisory** (repo → **Security** → **Report a vulnerability**), or
- Contact the maintainers via the [community group](https://www.facebook.com/groups/cladue).

Please do **not** open a public issue for a real vulnerability until it has been addressed.

## About the "vulnerable app" in this repo
`sample-vulnerable-app/` is **intentionally insecure** and exists only so the tool can be tested
against known-bad code. Its weaknesses are at the **code** level — an exposed Supabase
`service_role` key, tables with no RLS, an IDOR API route, prompt injection, missing security
headers. Its **dependencies are kept current**, so it should not raise Dependabot alerts. Never
install or deploy it.

If you see a Dependabot or scanner alert pointing at `sample-vulnerable-app/`, that is expected —
it is a teaching fixture, not shipped code.

## Scope of the tool
- **Tier 0 (static)** is safe and read-only.
- **Tier 1 (passive live)** and **Tier 2 (active DAST)** send network traffic and are hard-gated
  behind a `claudeguard.scope.yml` file in which you attest ownership/authorization of the target.
  Only test systems you own or are authorized in writing to test. You are responsible for your
  scope.

A clean scan is **not** a proof of safety.
