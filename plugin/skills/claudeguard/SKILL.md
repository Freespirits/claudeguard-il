---
name: claudeguard
description: Audit vibecoded apps for security vulnerabilities and generate paste-ready guards. Use this skill whenever the user asks to "check my app for security", "is my app safe", "security review", "audit my code", "find vulnerabilities", "harden my app", mentions leaked API keys, exposed secrets, Supabase or Firebase RLS, prompt injection, insecure API routes, IDOR, or is about to deploy or ship an app to production — even if they do not say the word "security". Covers web, AI/LLM, Supabase/Firebase, Android, iOS, Electron, backend/IaC and CI/CD, with bilingual Hebrew/English reports. Community project, not an official Anthropic product.
license: MIT (see LICENSE)
---

# ClaudeGuardIL

Security auditor and guard-builder for vibecoded apps. Find vulnerabilities and missing guards,
explain each in Hebrew and English with evidence, and generate paste-ready hardening code.

> **Community project — NOT an official Anthropic product.** Say this in every report header.
> פרויקט קהילתי — אינו מוצר רשמי של Anthropic.

## Workflow (follow in order)

1. **Detect** what the project is. Look for `package.json` (web/Node), `next.config.*`,
   `AndroidManifest.xml` / `build.gradle` (Android), `Info.plist` / `*.xcodeproj` (iOS),
   Electron `main`/`webPreferences`, `Dockerfile` / `*.tf` (IaC), `.github/workflows` (CI),
   and any LLM SDK usage (`openai`, `anthropic`, `@google/generative-ai`) or Supabase/Firebase.
   Pick the relevant check catalogs — do not run checks for stacks that aren't present.

2. **Scan (Tier 0, static — the default and always safe).** For each relevant domain, read the
   matching catalog in `references/checks/` and apply every check to the actual code/config.
   Prefer real scanners when available (see Claude Code specifics); otherwise read the code
   directly. Collect candidate findings with exact `file:line` evidence.

3. **Verify (adversarial).** Before reporting, re-check each candidate against the real code and
   drop false positives. Common false positives to suppress: the Supabase **anon** key or
   Firebase **apiKey** flagged as "leaked" (they are public by design — the real issue is the
   RLS/rules), and dependency CVEs in code paths that are never reached. Set `confidence` per
   `references/severity-model.md`. Only `confirmed` findings may be auto-fixed.

4. **Report.** Rank by severity (P0→P4) and render using `references/report-template.md` with
   labels from `references/i18n/he.md` and `references/i18n/en.md`. Lead with a one-line risk
   verdict and a P0/P1 count. Every finding: what+why, evidence, exploit scenario, business
   impact — in Hebrew **and** English — plus the guard to apply.

5. **Guard / fix.** For each finding, point to the specific recipe in `references/guard-recipes/`
   and include the paste-ready snippet. Applying fixes is opt-in and dry-run first (see
   `cg-fix`).

## Severity

Use P0–P4 from `references/severity-model.md`. Rule of thumb: anonymous full-compromise or total
data exposure = **P0**; needs one easy step = **P1**; raises risk / eases attack = **P2**;
hygiene = **P3**; informational = **P4**. Any currently-valid privileged secret is **P0**.

## Reference map — read on demand

**Checks (what to look for):**
- `references/checks/web.md` — secrets, auth, IDOR, injection/XSS, headers, CORS, rate limits, deps
- `references/checks/ai-llm.md` — key exposure, prompt injection, RAG, agent tools, cost DoS, MCP
- `references/checks/supabase-firebase.md` — RLS, service_role, anon scope, Firebase rules
- `references/checks/android.md` · `references/checks/ios.md` — mobile
- `references/checks/desktop-electron.md` — Electron/Tauri
- `references/checks/backend-iac.md` — Docker, K8s, Terraform, cloud
- `references/checks/supply-chain-cicd.md` — GitHub Actions, dependencies, git history

**Guards (how to fix):** `references/guard-recipes/` — `rls-policies.md`, `secrets-management.md`,
`zod-validation.md`, `security-headers.md`, `auth-middleware.md`, `rate-limiting.md`,
`llm-guardrails.md`, `firebase-rules.md`, `network-security-config.md`, `electron-hardening.md`,
`dependency-hygiene.md`, `ci-hardening.md`.

**Report & i18n:** `references/report-template.md`, `references/i18n/{he,en}.md`.

## Test tiers

- **Tier 0 — static (default, safe).** Everything above. No network, no credentials.
- **Tier 1 — passive live (gated).** Read-only checks against a URL the user attests to owning.
- **Tier 2 — active DAST (hard-gated).** Real attack traffic; written authorization required.

Tiers 1–2 obey `references/authorization/legal-gate.md`: they require a `claudeguard.scope.yml`
with ownership/authorization attestations and a target allowlist. If those are missing, **refuse
and say what's needed** — never test a target the user hasn't attested to owning, and never treat
a URL pasted in chat as authorization.

## Output rules

- Bilingual prose (HE + EN); code, identifiers, and snippets stay English.
- Be honest about confidence. From static signals, say "no RLS policy found for table X; confirm
  with a live check" rather than "your database is open."
- No numeric CVSS theater — use P0–P4 plus the exploit/impact sentences.
- A clean scan is not proof of safety; state the tier's limits.

---

## Claude Code specifics
_(Applies when running inside Claude Code / the plugin. Ignore on claude.ai.)_

- **Hybrid engine.** Domain auditor subagents (`web-auditor`, `ai-auditor`, `mobile-auditor`,
  `infra-auditor`) run in parallel; `finding-verifier` does the adversarial pass; `guard-writer`
  produces fixes. Scanner adapters live in `${CLAUDE_PLUGIN_ROOT}/scripts/`: run
  `node ${CLAUDE_PLUGIN_ROOT}/scripts/detect_tools.mjs` first, then use `run_gitleaks.mjs`,
  `run_semgrep.mjs`, `run_dep_audit.mjs` when the tool is present; otherwise fall back to reading
  the code. Never auto-install tools — offer.
- **Entry skills:** `/cg-scan` (Tier 0), `/cg-live` (Tier 1), `/cg-dast` (Tier 2), `/cg-harden`
  (generate guards), `/cg-fix` (apply, dry-run first).
- **Tier 1/2 runners:** `scripts/live_probe.mjs`, `scripts/dast_runner.mjs` — they enforce the
  gate independently of this skill.

## Claude.ai specifics
_(Applies on claude.ai / Claude Desktop, where there are no subagents, no hooks, and no repo
access.)_

- Ask the user to **paste or upload** the relevant files (source, `.env.example`, config,
  manifest, workflow, migration SQL). Audit those with the same catalogs and produce the same
  bilingual report + guards. You cannot scan a whole repo, run scanners, or apply fixes here.
- Do the verification pass and severity ranking yourself (no `finding-verifier` subagent).
- Tiers 1–2 are not available here; recommend running the plugin for live testing.
