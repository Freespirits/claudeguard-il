---
name: cg-scan
description: Run a static (Tier 0) ClaudeGuardIL security scan of the current project. Use when the user types /cg-scan or asks to scan, audit, or security-check the codebase without touching a live server.
argument-hint: "[path] [--domain web|ai-llm|supabase-firebase|android|ios|desktop|backend-iac|ci-cd]"
allowed-tools: [Read, Glob, Grep, Bash]
user-invocable: true
---

# /cg-scan — static security scan (Tier 0)

Run a safe, read-only static audit. No network, no credentials. This is the default entry point.

Arguments: `$ARGUMENTS` — optional path to scan (default: repo root) and an optional
`--domain` filter to limit to one catalog.

## Steps

1. **Load the knowledge.** Follow the `claudeguard` skill workflow and its
   `references/checks/*` catalogs. If a `--domain` is given, scan only that catalog; otherwise
   detect the stack and run every relevant one.

2. **Detect the stack.** Use Glob/Grep to find `package.json`, `next.config.*`,
   `AndroidManifest.xml`, `Info.plist`, Electron `webPreferences`, `Dockerfile`, `*.tf`,
   `.github/workflows/*`, LLM SDK imports, and `@supabase`/`firebase` usage.

3. **Prefer real scanners when present.** Run
   `node ${CLAUDE_PLUGIN_ROOT}/scripts/detect_tools.mjs` and, for any tool it reports as
   available, use the matching adapter:
   - secrets → `run_gitleaks.mjs` (falls back to a regex/entropy read)
   - SAST → `run_semgrep.mjs`
   - deps → `run_dep_audit.mjs`
   When a tool is missing, read the code directly instead. Do **not** install anything; you may
   offer the install command.

4. **Dispatch domain auditors.** In Claude Code, launch the relevant auditor subagents in
   parallel (`web-auditor`, `ai-auditor`, `mobile-auditor`, `infra-auditor`) so each works with
   focused context, then collect their candidate findings.

5. **Verify.** Run the `finding-verifier` agent (or do the pass yourself) to drop false
   positives — especially the Supabase anon key / Firebase apiKey "leak" false positive and
   unreachable dependency CVEs. Assign `confidence`.

6. **Report.** Render with `references/report-template.md` (bilingual HE/EN), lead with the risk
   verdict + P0/P1 count, and attach the guard recipe reference for each finding.

7. **Offer next steps:** `/cg-harden` to generate the fixes, `/cg-fix` to apply them (dry-run),
   or `/cg-live` to confirm suspected issues on a target you own.

Keep every finding evidence-backed (`file:line`). If nothing is found, say so honestly and note
that a clean static scan is not a proof of safety.
