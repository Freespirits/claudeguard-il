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
the repo path under scan, never a parent — a trust grant covers every subdirectory, so trusting a
home directory silently authorises every future scan of every sibling project on the machine.

### What the MCP transport actually returns — verified, and not what the table below implies

The server does **not** proxy the CLI's JSON, and building on the assumption that it does is the
single most expensive mistake available here: the adapter would answer `null` to every call, for
ever, with nothing throwing to explain it. Confirmed against `snyk` 1.1306.2:

- `snyk_sca_scan` and `snyk_code_scan` run the CLI, **discard its output**, and return Snyk's own
  summary: `{success, issueCount, issues: [{id, title, severity, cwes[], cves[], packageName,
  version, ecosystem, fixedIn[], filePath, line, column, message, dataflow[], isIgnored, …}]}`.
  Snyk Code's dataflow survives that mapping; **SCA reachability does not appear in it at all**, so
  the reachability win is a CLI-path capability.
- `snyk_iac_scan` and `snyk_container_scan` expose **no `json` parameter and no output mapper** —
  over MCP they answer in human-readable text. There is nothing to normalise, so those two are a
  declared coverage gap on the MCP path and the CLI is the only structured route.
- Every result arrives as `{content: [{type: 'text', text: '<json-encoded string>'}]}`, so the
  payload needs parsing a second time.

### The failure modes, which are the part that actually has to be right

Recorded from a real unauthenticated run:

```
snyk test --json           → {"ok": false, "error": "Use `snyk auth` to authenticate.", "path": "…"}
snyk code test --json      → the same envelope
snyk container test --json → the same envelope
snyk iac test --json       → NOT JSON. A bare stack trace: FailedToGetIacOrgSettingsError: …
snyk_sca_scan (MCP)        → "Error: folder '…' is not trusted. Please run 'snyk_trust' first"
```

Three things follow. **Trust is checked before auth**, so an untrusted repo must not be reported as
an authentication problem or the user fixes the wrong thing. **Not every failure is JSON**, so
"could not parse" has to be a first-class branch that still names the cause. And an auth failure can
arrive wearing another name — `FailedToGetIacOrgSettingsError` says nothing about tokens and means
exactly "no token".

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

## As implemented

`plugin/scripts/run_snyk.mjs` (adapter) and `gradeSnyk` in `plugin/scripts/grader.mjs` (policy).
Four decisions the design above left open, settled here so a reader running the method by hand
grades the same way the script does:

**The normaliser contract, inherited verbatim from `run_dep_audit.mjs`.** `[]` means the payload was
recognised and holds zero results; `null` means it was not recognised. Unauthenticated,
untrusted-folder and unknown-shape payloads are all `null`, which becomes an `undeterminable`
coverage row naming why. Collapsing the two is how a scan that never ran gets reported as clean, and
a shape adapter fails silently by nature — nothing throws, the output just goes quiet — so each
normaliser is exported and unit-tested over recorded Snyk output rather than living inside a CLI.

**Severity: the map, and its ceiling.** `critical → P0 · high → P1 · medium → P2 · low → P3` is the
starting point; the per-kind ceiling is the override the Grader owns. `dep-vuln` and
`container-vuln` are capped at **P1**, matching the ladder `npm audit` findings already use — one
critical upstream advisory graded P1 by one tool and P0 by another would mean the badge depends on
which scanner the user happens to have installed. The SAST kinds are capped at **P1**, matching
`CG-DAST-SQLI` and `CG-DAST-XSS`. `iac-misconfig` is **uncapped**: a public bucket or an `0.0.0.0/0`
rule on a database port really is total exposure, and severity is impact-if-true.

**Confidence, stated as evidence — because confidence is a pure function of evidence and nothing
may write one directly:**

| Fact | Evidence | Confidence |
|---|---|---|
| SCA `reachability: reachable` | `strong` | `likely` |
| SCA `reachability: not-reachable` | — | **no finding**; a `pass` row, "present but unreached" |
| SCA `reachability: unknown` | `weak` | `needs-review` |
| Snyk Code `hasDataflow: true` | `strong` | `likely` |
| Snyk Code `hasDataflow: false` | `weak` | `needs-review` |
| IaC / container | `weak` | `needs-review` |

Snyk has **three overlapping vocabularies** for reachability and they do not agree: the CLI's own
enum (`function`, `package`, `not-reachable`, `no-info`), the values that appear in real output
(`reachable`, `no-path-found`), and the `--reachability-filter` flag
(`reachable | no-info | not-applicable`). Everything that is not a firm yes or a firm no collapses
to `unknown` **on purpose**, and that includes `no-info` — the CLI's help text calls it the
"non-reachable" filter, while the CLI's own enum lists it as a *different* value from
`not-reachable`. With the tool contradicting itself the tie goes to the reading that cannot hurt
anyone: a `not-reachable` result becomes a `pass`, and a `pass` is an instruction to stop looking.

Reachability also needs `--reachability=true` (Snyk Preview, CLI ≥ 1.1301.0) and warns that it
"returns a new findings schema" in which "some legacy fields may not be available" — so this is the
first mapping to re-check against a real authenticated run.

**`confirmed` is unreachable for Snyk, and it is asserted, not merely intended.** `confirmed` drives
the headline verdict and the auto-fix gate; Snyk's answer is a judgement about code this grader
never read. The grader throws if a Snyk finding ever resolves to `confirmed`.

**The `not-reachable` pass, and its limit.** It is a real `pass` — the honest disposition for
"Snyk followed the call graph and found no path" — and the row states what could still break it: a
dynamic `require` or reflection. A pass with a named limit is not a checkmark; recording these as
`undeterminable` instead would move the noise rather than remove it, which is the whole reason
reachability is worth paying for (`false-positives.md` FP-16).

## What it is not

Snyk's severities are its opinion, re-mapped and re-graded — never trusted verbatim (the same
discipline applied to semgrep). Its findings overlap with the existing scanners and with the tool's
own rules, so the **differential-comparison/dedup step becomes mandatory**: when Snyk, semgrep, and
a ClaudeGuard rule all flag the same file:line, they are reconciled into one finding, not three.
Snyk is a commercial dependency and a token the vibecoder may not have — so it strengthens the tool
when present and is a named coverage gap when absent, never a requirement.
