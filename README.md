# 🛡️ ClaudeGuardIL

![ClaudeGuardIL — security for vibecoded apps](assets/banner.png)

<div align="center">

### קלוד — הקהילה הישראלית · Claude — the Israeli Community

</div>

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

## Built for non-experts (plain Hebrew)

The audience is people who built a real app with an AI tool and never learned security. So every
finding opens with a **"בפשטות / In plain words"** line — jargon-free, before any technical prose:
what is actually exposed, why it matters, and the one thing to do. There is also a standalone
beginner's guide, [`core/plain-language/concepts.he.md`](core/plain-language/concepts.he.md), that
teaches the underlying ideas once in plain Hebrew — the browser-vs-server model, `service_role` vs
the anon key, RLS, IDOR, prompt injection, denial-of-wallet — independent of any scan. The
per-finding text lives in [`core/plain-language/findings.md`](core/plain-language/findings.md),
keyed by finding id, and ships to both the plugin and the claude.ai skill.

## How it works

Most AI security review reads files one at a time and forms an impression. That misses things for
a boring reason: a model looking at `orders/route.ts` cannot know whether the `orders` table has
RLS, because the answer is in a different file — or in no file at all. ClaudeGuardIL puts a
deterministic layer underneath the model so it reasons over computed facts instead.

**Engine → Facts → Grader → Findings → Reviewers → Report.**

- The **engine** (`plugin/scripts/project_model.mjs`) builds the import graph, classifies the
  client/server boundary, traces env-var flow, and inventories every route, table, LLM call site
  and Supabase client. It emits **Facts** and has no opinion about how dangerous anything is.
- The **grader** (`plugin/scripts/grader.mjs`) is the single authority on severity. Every rule
  walks an enumerable set and decides each member, so nothing the engine discovered is left ungraded.
- **Reviewers** (the subagents) then work the list of things the rules could not decide — business
  logic, workflow flaws, authorization that is present but wrong. Their findings are marked as
  judgement and can never be reported as proven.

What that buys you, stated so you can check it rather than take our word for it:

| Claim | How to verify |
|---|---|
| **Complete accounting of what it found** — every route, table and env var the engine *discovered* is graded | The report's analysis-coverage section: `pass + fail + undeterminable + allowlisted` equals the number enumerated. Asserted at runtime. |
| **Honest about what it might have missed** — it reports what it could not *see*, not just how it graded what it saw | A separate discovery-coverage section: files parsed vs skipped (with reasons), routes it could only partially model, unresolved imports. |
| **Reproducible** — the same repo always yields the same severities | Severity is deterministic code, and confidence is a pure function of evidence. Run it twice. |
| **Explicit about what it could not check** — a quiet report is not a safe one | Anything unverifiable is listed as `undeterminable` with the reason, not silently dropped. |

**The honest caveat, stated plainly:** the engine is regex plus lightweight parsing, not a
type-aware AST. So it can prove it accounted for every subject it *discovered* — not that it
discovered every subject. Dynamic imports, metaprogramming, and unusual framework constructs can
escape enumeration. That gap is precisely what the **discovery-coverage** axis exists to surface: a
report tells you what it parsed, what it skipped, and where it could only partially model something,
so a partial scan can never quietly pass for a complete one. A clean report is not proof of safety —
it is a record of what was checked.

Three rules keep it honest, and each exists because breaking it produced a real, embarrassing bug:

1. **Nothing passes because a keyword was present.** A route containing `getUser()` is reported as
   *unverified*, never as safe — from a regex, a correct check is indistinguishable from one whose
   result is ignored. Those rows become the reviewer's work list.
2. **Everything enumerated is accounted for.** A subject that quietly falls out of the ledger is
   how "we found nothing" comes to mean "we looked nowhere".
3. **A variable name is not a credential.** `FOO_API_KEY` in a name never justifies a P0 on its own.

Severity says how bad a finding is *if it is real*, and is never discounted because we are unsure —
that is what confidence is for. The headline verdict counts only **confirmed** findings, so an
unproven P0 is still shown to you but does not turn the badge red.

The regression suite includes a deliberately **correct** app — t3-env, user-scoped Supabase
clients, RLS with `auth.uid()` policies, middleware auth — and asserts it produces **zero**
findings. A security tool that cries wolf at correct code teaches people to ignore it, so that
test is treated as seriously as the ones that catch real bugs.

## How it's built

`core/` is the single source of truth (plain markdown). `scripts/build.mjs` copies it into both
wrappers, so one edit updates the plugin and the claude.ai skill together. Scanning is **hybrid**:
it uses `gitleaks` / `semgrep` / `npm audit` when installed and falls back to Claude reading the
code when they aren't — it never force-installs anything. The engine and grader have **zero**
runtime dependencies, which CI enforces; you can run them with nothing but Node.

## Repo layout
```
core/          shared knowledge (checks, guard-recipes, methodology, severity, i18n, authorization)
plugin/        the Claude Code plugin (skills, agents, hooks, engine + grader scripts)
skill-dist/    the claude.ai skill (assembled by build.mjs)
scripts/       build.mjs
test/          the regression suite, including the "correct app must stay quiet" fixture
sample-vulnerable-app/  a deliberately-insecure app to test against
CONTEXT.md     the domain model — the vocabulary this codebase is written in
```

## Why is there a "vulnerable app" in this repo?
`sample-vulnerable-app/` is an **intentional test fixture** — it exists only so the tool can be
run against known-bad code. Its problems are at the **code** level (exposed `service_role` key,
no RLS, IDOR, prompt injection, missing headers). Its **dependencies are not kept current**, so it
does trip Dependabot — every alert on this repository points at a fixture, and none of them is
reachable from anything the tool ships. Never deploy it. See [`SECURITY.md`](SECURITY.md).

## Disclaimer
Provided as-is, no warranty. A clean scan is **not** proof of safety. You are responsible for
what you scan and for the scope of any live/DAST testing. Not affiliated with Anthropic.

MIT licensed — see `LICENSE`.
