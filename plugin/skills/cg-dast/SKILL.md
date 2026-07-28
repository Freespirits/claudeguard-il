---
name: cg-dast
description: Run active (Tier 2) DAST against a target the user owns and is authorized in writing to test — real attack traffic (injection, auth/IDOR, fuzzing), rate-limited and dry-run by default. Use when the user types /cg-dast. Requires a claudeguard.scope.yml with written-authorization and ownership attestations. High-risk; hard-gated.
argument-hint: "[url] [--i-am-authorized]"
allowed-tools: [Read, Bash]
user-invocable: true
---

# /cg-dast — active DAST (Tier 2, hard-gated)

Sends **real attack traffic**. This is penetration testing. Only for a target the user **owns**
and is **authorized in writing** to test.

Argument: `$ARGUMENTS` — the URL (must be in scope `targets`) and, for a live run, the literal
`--i-am-authorized` flag.

## Gate first (do not skip — refuse on any failure)

1. Read `claudeguard.scope.yml` and enforce `references/authorization/legal-gate.md` Tier-2
   preconditions, which include all Tier-1 checks **plus**: `active_dast.enabled: true`,
   `i_am_authorized_in_writing: true`, `i_own_or_control_these_targets: true`.
2. `dry_run` is honored. While `dry_run: true` (the default), the runner only **plans** requests
   and sends nothing. A real run additionally requires the `--i-am-authorized` flag in
   `$ARGUMENTS`.
3. Rate is capped at ≤ 2 req/s regardless of the file. `avoid_destructive: true` skips any
   payload that could delete/modify data or send mail/money.
4. The host must be in `targets`, not in `never_touch`, and not a default-blocked third-party
   provider. If not, refuse. Never treat a chat-pasted URL as authorization.

If any precondition is unmet, print exactly what is missing (e.g. "set
`active_dast.i_am_authorized_in_writing: true`") and stop.

## Run

Print the loud Tier-2 banner and a one-line summary of what will be sent, then:

```bash
# dry run (default): plan only, sends nothing
node ${CLAUDE_PLUGIN_ROOT}/scripts/dast_runner.mjs --url "<url>" --scope claudeguard.scope.yml

# real run: only after the gate passes AND the user included --i-am-authorized
node ${CLAUDE_PLUGIN_ROOT}/scripts/dast_runner.mjs --url "<url>" --scope claudeguard.scope.yml --execute
```

Probes (bounded, non-destructive by default): reflected/stored XSS markers, error-based SQL/NoSQL
injection signals, IDOR by swapping owned-object ids, missing-authz on known routes, open
redirect, and security-header confirmation.

## Report

Fold results into the bilingual report; upgrade matching static/live findings to `confirmed`
with the observed response as evidence. Remind the user they are responsible for the scope, and
that fixes belong in the codebase (`/cg-harden`, `/cg-fix`), not in the live target.
