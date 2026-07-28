# Severity model & finding schema

Single source of truth for how ClaudeGuardIL ranks findings and what a finding must contain.
Both the plugin and the claude.ai skill render findings from this schema.

## Severity levels (P0–P4)

Rate by **impact × exploitability**, biased toward the reality of a vibecoded app that is
already (or about to be) public.

| Level | Label (EN / HE) | Meaning | Typical examples |
|-------|-----------------|---------|------------------|
| **P0** | Critical / קריטי | Full compromise or total data exposure reachable by an anonymous attacker, no special conditions. Fix before anyone else sees the URL. | `service_role` key shipped to the browser; Supabase table with RLS off and public read/write; admin API route with no auth; live private API key in client bundle. |
| **P1** | High / גבוה | Serious breach that needs one easy step or a known-common condition. | IDOR on `/api/orders/:id`; missing server-side authz; SQL/NoSQL injection; secret in git history still valid; prompt injection that reaches a destructive tool. |
| **P2** | Medium / בינוני | Real weakness that raises risk or eases another attack. | Missing/weak CSP; no rate limit on auth/LLM endpoints; permissive CORS; cookies without `HttpOnly`/`SameSite`; verbose stack traces in prod. |
| **P3** | Low / נמוך | Hygiene gap, defense-in-depth, or hard-to-exploit issue. | Source maps in prod; outdated-but-unreached dependency; missing security headers of secondary value. |
| **P4** | Info / מידע | Not a vulnerability; worth noting or confirming. | "RLS is on and looks correct"; "no secrets found in bundle"; a deprecated pattern to watch. |

**Escalation rule:** any secret that is (a) currently valid and (b) grants privileged access is
**P0**, regardless of where it lives. When in doubt between two levels, pick the higher one only
if you can name a concrete attacker action; otherwise pick the lower and say why.

## Confidence

Every finding carries a confidence, set **after** the adversarial verification pass:

- `confirmed` — reproduced against the actual code/config; evidence is exact (`file:line`).
- `likely` — strong signal, one assumption not verified (e.g. can't confirm the key is live).
- `needs-review` — heuristic match that a human must judge; never auto-fixed.

Only `confirmed` findings are eligible for `/cg-fix`. P0/P1 must be `confirmed` or clearly
labelled `likely` with the missing assumption stated.

## Finding schema (every finding has all fields)

```yaml
id:            CG-<DOMAIN>-<NNN>        # e.g. CG-WEB-014, CG-LLM-003
title_en:      Short imperative title
title_he:      כותרת קצרה
severity:      P0 | P1 | P2 | P3 | P4
confidence:    confirmed | likely | needs-review
domain:        web | ai-llm | supabase-firebase | android | ios | desktop | backend-iac | ci-cd
cwe:           CWE-<id>                 # when applicable
owasp:         "A01:2021" | "LLM01" | "M1" ...   # web / LLM / mobile top-10 tag
evidence:                              # what proves it — required
  - file: path/to/file.ts
    line: 42
    snippet: "const admin = createClient(url, SERVICE_ROLE_KEY)"
exploit:       One concrete sentence: attacker does X, gets Y.
impact:        Business consequence: data/accounts/money/compliance.
guard:         guard-recipes/<name>.md#<anchor>   # the fix to paste
autofixable:   true | false
tier:          static | passive-live | active-dast   # how it was found
```

## Report ordering

Sort by severity (P0→P4), then confidence (`confirmed` first), then domain. Lead every report
with a one-line **risk verdict** and a P0/P1 count so a non-expert instantly knows how bad it is.

## Scoring notes (CVSS-lite, no false precision)

Do **not** compute a numeric CVSS vector — it reads as false rigor to this audience. Use the
P0–P4 label plus the `exploit` + `impact` sentences. If a user asks for CVSS, map: P0≈9.0–10,
P1≈7.0–8.9, P2≈4.0–6.9, P3≈0.1–3.9, P4=N/A, and state it's an approximation.
