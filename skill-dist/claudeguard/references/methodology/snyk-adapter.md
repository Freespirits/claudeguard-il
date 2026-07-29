# Snyk adapter — a commercial-grade scanner through the same grader

Snyk is not a new axis; it is a stronger member of the family ClaudeGuardIL already integrates
(gitleaks/semgrep/npm-audit). It slots into the existing observation → grader pattern, and it
happens to fill three gaps the security-team audit reproduced: **IaC is never graded**, there is
**no static dataflow/taint** (SQLi/XSS/SSRF), and **dependency reachability is unknown**. Snyk
addresses all three.

## How it connects

Snyk ships its **own MCP server inside the CLI** — no separate install:

```
snyk mcp -t stdio --experimental      # stdio transport; -t sse also available
SNYK_TOKEN=<personal-access-token>    # auth (SNYK_CFG_ORG=<org> optional)
```

It is a **local** MCP server with local file access. One safety wrinkle to respect: Snyk requires
**trusting a folder** before it scans (`snyk_trust`, or `--disable-trust`). The adapter trusts only
the repo path under scan, never a parent.

## The tools, and what each maps to

| Snyk MCP tool | What it does | ClaudeGuard use |
|---|---|---|
| `snyk_sca_scan` | dependency (open-source) vulns, **with reachability** | replaces/augments `run_dep_audit`; reachability drives confidence |
| `snyk_code_scan` | SAST with **interfile dataflow** | the delegated-taint role (we cut `taint.mjs` for exactly this); fills the "no SQLi/XSS/SSRF detector" gap |
| `snyk_iac_scan` | Dockerfile / Terraform / K8s / compose misconfig | **fills the ungraded-IaC gap** the audit found |
| `snyk_container_scan` | container image vulns | new coverage surface |
| `snyk_sbom_scan` / `snyk_aibom` | SBOM / AI-BOM analysis | inventory, lower priority |
| `snyk_auth` / `snyk_trust` / `snyk_version` | session / trust / version | adapter plumbing, not findings |

## The observation contract

Exactly like the existing scanner adapters: Snyk emits **observations**, the **grader owns severity
and confidence**. The adapter normalizes each Snyk result to:

```
{ tier: 'static', source: 'snyk', kind, subject, at: {file, line}, detail,
  advisorySeverity,          # Snyk's own critical/high/medium/low — an INPUT, never our severity
  reachability,              # 'reachable' | 'not-reachable' | 'unknown'  (SCA only)
  hasDataflow }              # true when snyk_code proved a source→sink path (Code only)
```

New `kind`s (grader owns their P-level): `dep-vuln`, `sast-sqli`, `sast-xss`, `sast-ssrf`,
`sast-path-traversal`, `iac-misconfig`, `container-vuln`.

## The confidence win — reachability and dataflow

This is the reason Snyk is worth more than "another scanner." The two things it knows that a regex
cannot let the grader raise confidence honestly:

- **SCA reachability.** The current `run_dep_audit` adapter must cap every dependency CVE at
  `needs-review` because it cannot tell whether the vulnerable code is reached. Snyk can:
  - `reachable` → **strong** evidence → `likely` (a real, exercised path).
  - `not-reachable` → not a finding; a **coverage** row ("present but unreached").
  - `unknown` → `weak` → `needs-review`, as today.
  This resolves the "unreachable-CVE false positive" the methodology already warns about, with data
  instead of a caveat.
- **Snyk Code dataflow.** A SAST hit with a proven source→sink path is a stronger lead than a
  pattern match. Still an external tool's judgement, so it is capped at `likely` (never `confirmed`
  — only our own deterministic rules or a live PoC reach that), but `hasDataflow: true` justifies
  `strong` over `weak`. A finding without a dataflow path stays `needs-review`.

Severity re-mapping (grader-owned, a starting point the Grader may override by rule):
`critical → P0 · high → P1 · medium → P2 · low → P3`.

## The consent gate — source leaving the machine

`snyk_sca_scan` and `snyk_iac_scan` analyze locally. **`snyk_code_scan` (SAST) can send source to
Snyk's cloud** for analysis. That is a different trust decision than running a local regex, and this
audience (vibecoders, private repos) must opt in explicitly:

- SCA + IaC + container: on by default when a `SNYK_TOKEN` is present (metadata, not source, leaves
  the machine).
- **Code (SAST): OFF unless the user explicitly consents** (a flag / scope-file key), because it
  uploads source. The report states plainly when Code was skipped for consent, as a `scanCoverage`
  row — a skipped scan is never a silent gap.

## Coverage

Snyk unavailable, unauthenticated (no token), or a folder untrusted → a `scanCoverage`
`undeterminable` row naming why, exactly like a missing gitleaks. A commercial tool the user has not
authenticated is a coverage limitation, not a clean result.

## What it is not

Snyk's severities are its opinion, re-mapped and re-graded — never trusted verbatim (the same
discipline applied to semgrep). Its findings overlap with the existing scanners and with the tool's
own rules, so the **differential-comparison/dedup step becomes mandatory**: when Snyk, semgrep, and
a ClaudeGuard rule all flag the same file:line, they are reconciled into one finding, not three.
Snyk is a commercial dependency and a token the vibecoder may not have — so it strengthens the tool
when present and is a named coverage gap when absent, never a requirement.
