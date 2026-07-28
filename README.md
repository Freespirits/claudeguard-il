# 🛡️ ClaudeGuardIL

**Security auditor & guard-builder for vibecoded apps.** Point it at your project, get a ranked
report of real vulnerabilities with evidence, and paste-ready hardening code — for web, AI/LLM,
Supabase/Firebase, Android, iOS, Electron, backend/IaC and CI/CD.

> **Community project — NOT an official Anthropic product.**
> פרויקט קהילתי — אינו מוצר רשמי של Anthropic. Built for the
> [Claude Israeli community](https://www.facebook.com/groups/cladue).

---

## עברית (בקצרה)

כלי אבטחה שבודק אפליקציות שנבנו ב-vibecoding ומייצר קוד הגנה מוכן להדבקה. מריצים אותו על הפרויקט
ומקבלים דוח דו-לשוני (עברית ואנגלית) עם ממצאים מדורגים (P0–P4), ראיות (`file:line`), תרחיש תקיפה,
והתיקון המומלץ. שלוש רמות בדיקה: סטטית (ברירת מחדל, בטוחה), live פסיבית, ו-DAST אקטיבית — שתי
האחרונות דורשות בעלות על היעד ואישור מפורש.

---

## Two ways to use it

### 1) Claude Code plugin (full engine)
Scans your whole repo, runs scanners, and can generate & apply fixes.

```
/plugin marketplace add Freespirits/claudeguard-il
/plugin install claudeguard-il@claudeguard-il
```
Then, in your project:
```
/cg-scan            # static audit (Tier 0) — safe, read-only, the default
/cg-harden          # generate paste-ready guards for the findings
/cg-fix             # apply guards (dry-run diff first, you confirm)
/cg-live  <url>     # Tier 1 passive live checks (target you own)
/cg-dast  <url>     # Tier 2 active DAST (target you own + authorized)
```

Local test without installing:
```
claude --plugin-dir ./plugin
```

### 2) claude.ai / Claude Desktop skill (knowledge + report)
For people who don't use the terminal. Build the skill zip, then upload it in claude.ai
(Settings → Capabilities → Skills) or Claude Desktop.

```
node scripts/build.mjs          # produces claudeguard-skill.zip (SKILL.md at the root)
```
Then paste or upload your code/config and ask: *"בדוק את האבטחה של האפליקציה"* / *"check my app's
security"*. Same knowledge and bilingual report; no repo scanning, subagents, or auto-fix here.

---

## The three test tiers

| Tier | What | Safety |
|------|------|--------|
| **0 · Static** | Reads source, config, deps, `.env`, RLS, manifests, git history. | Default. No network, no credentials. |
| **1 · Passive live** | Read-only checks on a running URL (TLS, headers, cookies, exposed files, public reads). | Requires `claudeguard.scope.yml` with ownership attestation. GET/HEAD only. |
| **2 · Active DAST** | Real attack traffic (injection, IDOR, fuzzing). | Requires written-authorization + ownership attestation, target allowlist, rate limit; dry-run by default. |

Copy `core/authorization/SCOPE.example.yml` to `claudeguard.scope.yml` and fill it in to enable
Tiers 1–2. **Only test systems you own or are authorized in writing to test.**

---

## What it looks for

Secrets in the client/repo · Supabase RLS & `service_role` exposure · Firebase rules ·
auth/authorization & IDOR · input validation & mass assignment · SQL/XSS/SSRF injection ·
security headers/CORS/cookies · rate limiting · **LLM risks** (key exposure, prompt injection,
agent-tool abuse, cost DoS) · Android/iOS manifest & storage · Electron isolation & IPC ·
Docker/K8s/Terraform · GitHub Actions & dependency/supply-chain. Full catalog in `core/checks/`.

## How it's built

`core/` is the single source of truth (plain markdown). `scripts/build.mjs` copies it into both
wrappers, so one edit updates the plugin and the claude.ai skill together. The scan engine is
**hybrid**: it uses `gitleaks` / `semgrep` / `npm audit` when installed and falls back to Claude
reading the code when they aren't — it never force-installs anything.

## Repo layout
```
core/          shared knowledge (checks, guard-recipes, severity, i18n, authorization)
plugin/        the Claude Code plugin (skills, agents, hooks, scanner scripts)
skill-dist/    the claude.ai skill (assembled by build.mjs)
scripts/       build.mjs
sample-vulnerable-app/  a deliberately-insecure app to test against
```

## Why is there a "vulnerable app" in this repo?
`sample-vulnerable-app/` is an **intentional test fixture** — it exists only so the tool can be
run against known-bad code. Its problems are at the **code** level (exposed `service_role` key,
no RLS, IDOR, prompt injection, missing headers); its **dependencies are kept current**, so it
shouldn't trip Dependabot. Never deploy it. See [`SECURITY.md`](SECURITY.md).

## Disclaimer
Provided as-is, no warranty. A clean scan is **not** proof of safety. You are responsible for
what you scan and for the scope of any live/DAST testing. Not affiliated with Anthropic.

MIT licensed — see `LICENSE`.
