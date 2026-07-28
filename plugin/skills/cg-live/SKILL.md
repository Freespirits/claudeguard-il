---
name: cg-live
description: Run passive (Tier 1) live checks against a URL the user owns — read-only TLS, security headers, cookie flags, exposed files/routes, and public Supabase/Firebase reads. Use when the user types /cg-live or asks to check a running site they own. Requires a claudeguard.scope.yml with ownership attestation.
argument-hint: "[url]"
allowed-tools: [Read, Bash]
user-invocable: true
---

# /cg-live — passive live checks (Tier 1, gated)

Read-only inspection of a **running** target the user attests they own. GET/HEAD/OPTIONS only;
no payloads, no auth-bypass attempts.

Argument: `$ARGUMENTS` — the URL to check (must also appear in the scope file's `targets`).

## Gate first (do not skip)

1. Read `claudeguard.scope.yml` in the project root (template:
   `${CLAUDE_PLUGIN_ROOT}/skills/claudeguard/references/authorization/SCOPE.example.yml`).
2. Enforce `references/authorization/legal-gate.md` Tier-1 preconditions:
   - file parses; `passive_live.enabled: true`; `passive_live.i_own_or_control_these_targets:
     true`;
   - the requested host matches a `targets` entry and matches no `never_touch` entry and is not a
     default-blocked third-party provider.
3. If anything is missing, **refuse** and state exactly what to set. Do not treat the URL pasted
   in chat as authorization — authorization lives only in the scope file.

## Run

Print the Tier-1 banner, then run the probe:

```bash
node ${CLAUDE_PLUGIN_ROOT}/scripts/live_probe.mjs --url "<url>" --scope claudeguard.scope.yml
```

The probe (read-only) reports: TLS/HTTPS + redirect, HSTS/CSP/X-Frame/etc. headers, cookie
flags, `Access-Control-Allow-Origin`, presence of `/.env`, `/.git/HEAD`, source maps, common
exposed routes, and — if a Supabase URL + anon key are provided — whether `GET
/rest/v1/<table>?select=*` returns rows (a sign RLS is off).

## Report

Merge results into the bilingual report format, cross-referencing any static findings from
`/cg-scan` (e.g. "static suspected RLS off on `orders`; live check confirms public read → now
`confirmed` P0"). Attach guard references. Recommend fixing P0/P1 before anything else.
