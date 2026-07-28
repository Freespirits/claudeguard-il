# Authorization gate — rules the live/DAST tiers enforce

These rules are enforced by `scripts/live_probe.mjs` (Tier 1) and `scripts/dast_runner.mjs`
(Tier 2), and repeated in the `cg-live` / `cg-dast` skills so the model refuses at the reasoning
layer too. **Both layers must pass.** If any check fails, stop and explain — never "try anyway."

## Hard preconditions

### Tier 1 — passive live (read-only)
1. A `claudeguard.scope.yml` exists and parses.
2. `passive_live.enabled: true` **and** `passive_live.i_own_or_control_these_targets: true`.
3. The requested host matches an entry in `targets` and matches no `never_touch` entry and is
   not a default-blocked third-party provider.
4. Only safe methods (GET/HEAD/OPTIONS). No request bodies, no auth-bypass attempts, no payloads.
Print the warning banner, then proceed.

### Tier 2 — active DAST (attack traffic)
All of Tier 1, plus:
5. `active_dast.enabled: true` **and** `i_am_authorized_in_writing: true` **and**
   `i_own_or_control_these_targets: true`.
6. `dry_run` is honored: while true, the runner only *plans* requests and sends nothing.
7. Rate limit ≤ the hard cap (default 2 req/s) regardless of the file's value.
8. `avoid_destructive: true` skips any payload that could delete/modify data or send
   mail/money.
9. The interactive `--i-am-authorized` flag was passed for a non-dry-run execution.
Print the loud warning banner and a one-line summary of what will be sent, then proceed.

## Refusal behavior
If a precondition is missing, respond with exactly what is missing and how to fix it
(e.g. "set `active_dast.i_am_authorized_in_writing: true` in claudeguard.scope.yml"). Do **not**:
- probe a host that isn't in `targets`,
- probe a `never_touch` / third-party provider host,
- exceed the rate cap,
- run destructive payloads when `avoid_destructive` is true,
- treat a URL pasted in chat as authorization — authorization lives only in the scope file.

## Scope for this community
Most real findings here are **static** (Tier 0) — leaked keys, missing RLS, exposed LLM keys.
Encourage users to fix those first. Tiers 1–2 are for confirming issues on infrastructure the
user owns, not for testing other people's sites. The tool is for **authorized** security testing.

## Banners

Tier 1:
```
⚠️  Passive live check — read-only, targets you attested to owning. No payloads sent.
```
Tier 2:
```
🚨  ACTIVE DAST — real attack traffic to a target you attested you OWN and are AUTHORIZED to test.
    Rate-limited, dry-run unless you passed --i-am-authorized. You are responsible for this scope.
```
