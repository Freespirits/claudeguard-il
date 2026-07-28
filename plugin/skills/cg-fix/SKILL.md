---
name: cg-fix
description: Apply ClaudeGuardIL guards to the codebase (opt-in auto-fix), dry-run diff first and review before writing. Use when the user types /cg-fix or asks to automatically fix, patch, or apply the security fixes. Only touches the codebase, never a live target.
argument-hint: "[finding-id | all] [--apply]"
allowed-tools: [Read, Glob, Grep, Edit, Write, Bash]
user-invocable: true
---

# /cg-fix — apply guards (opt-in, dry-run first)

Apply the hardening code to the codebase. **Safety-first and non-destructive by default:** show a
diff, get confirmation, then write. Never touches a live target — only source files.

Argument: `$ARGUMENTS` — a finding id or `all` (default: all `confirmed`, `autofixable` findings
from the latest scan), plus optional `--apply` to write after review.

## Rules

- **Only `confidence: confirmed` and `autofixable: true` findings** are eligible. Skip
  `likely`/`needs-review` and explain why (they need a human).
- **Never auto-do the irreversible-but-not-code parts.** Rotating a leaked key, running a
  production migration, or changing hosting env vars are listed as manual steps, not performed.
- **Dry-run by default.** Without `--apply`, produce the full diff and stop.

## Steps

1. Resolve eligible findings (run `/cg-scan` first if none in context).
2. For each, build the patch by adapting the recipe from
   `${CLAUDE_PLUGIN_ROOT}/skills/claudeguard/references/guard-recipes/` to the real files.
3. **Present a unified diff** per file, grouped by finding, with the severity and id. Summarize
   in HE + EN.
4. If the user did not pass `--apply`, stop here and ask them to review. If they confirm (or
   passed `--apply`), write the changes with Edit/Write.
5. After applying: list the remaining **manual** steps (key rotation, migrations, env changes),
   then run the `/cg-scan` workflow again to confirm the findings are resolved and nothing new
   was introduced. Report the before/after P0–P4 counts.

Prefer minimal, idiomatic diffs that match the surrounding code. If a fix is risky or ambiguous,
downgrade it to a `/cg-harden` suggestion rather than writing it.
