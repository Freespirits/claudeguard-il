---
name: cg-harden
description: Generate paste-ready hardening code (guards) for ClaudeGuardIL findings without modifying files. Use when the user types /cg-harden or asks for the fix, the guard, RLS policy, validation, headers, or middleware for a finding.
argument-hint: "[finding-id | domain | all]"
allowed-tools: [Read, Glob, Grep]
user-invocable: true
---

# /cg-harden — generate guards (no file changes)

Produce the concrete fix for one or more findings, tailored to the user's actual code. This
**does not edit anything** — it outputs code to paste. To apply automatically, use `/cg-fix`.

Argument: `$ARGUMENTS` — a finding id (`CG-SB-001`), a domain (`web`), or `all` (default: the
findings from the most recent scan).

## Steps

1. Resolve the target findings. If none are in context, run the `/cg-scan` workflow first.
2. For each finding, open the referenced recipe in
   `${CLAUDE_PLUGIN_ROOT}/skills/claudeguard/references/guard-recipes/` and **adapt** the snippet
   to the user's real files: their table/column names, route paths, framework, env var names.
   Read the relevant source with Read/Grep so the guard drops in cleanly.
3. Output per finding:
   - a one-line HE + EN summary of the fix,
   - the exact code to paste and **where** it goes (`file:line` / new file path),
   - any follow-up steps that aren't code (rotate a key, run a migration, set a server env var),
   - a verification line ("re-run `/cg-scan`; for RLS also `/cg-live`").
4. Order by severity (P0 first). Group multi-file fixes clearly.

Prefer reusing the project's existing utilities (its Supabase client, its validation lib, its
middleware) over introducing new dependencies. If a fix needs a new package, say so explicitly.
