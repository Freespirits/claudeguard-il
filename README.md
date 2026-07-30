# 🛡️ ClaudeGuardIL

![ClaudeGuardIL — security for vibecoded apps](assets/banner.png)

<div align="center">

### קלוד — הקהילה הישראלית · Claude — the Israeli Community

**v0.3.2** · zero runtime dependencies · 629 tests · bilingual HE/EN

</div>

**A security auditor & guard-builder for vibecoded apps.** Point it at your project, get a ranked
report of real vulnerabilities — with evidence (`file:line`), an attack scenario, and paste-ready
hardening code — for web, AI/LLM, Supabase/Firebase, Android, iOS, Electron, backend/IaC and CI/CD.
It computes what can be computed about a codebase, then grades those observations into a report a
non-expert can act on.

> **Community project — NOT an official Anthropic product.**
> פרויקט קהילתי — אינו מוצר רשמי של Anthropic. Built for the
> [Claude Israeli community](https://www.facebook.com/groups/cladue). MIT licensed.

**Also on GitLab:** [gitlab.com/FreeSpirity/claudeguard-il](https://gitlab.com/FreeSpirity/claudeguard-il)
— GitHub stays primary; `main` and tags are pushed there by
[`.github/workflows/mirror-to-gitlab.yml`](.github/workflows/mirror-to-gitlab.yml) once its token is set.

---

## What the numbers mean, before anyone quotes them

This project measures itself two ways, and keeps them strictly apart — because conflating them is
exactly the overclaim it exists to prevent.

- **The regression gate** (`bench/run.mjs`, a corpus this project wrote) stands at **0 regressions
  across 19 pinned detections, and 0 unexpected confirmed findings across 9 clean variants**,
  deterministic. That is genuine regression protection and a cry-wolf gate — but its recall is 100%
  *by construction*, so it is **not** a detection rate. The earlier "recall 100% / precision 100%"
  framing read as one and is retracted as **ERR-006** in [`ERRATA.md`](ERRATA.md).
- **The wild benchmark** (`bench/wild.mjs`) is the honest answer: **11 real repos at pinned commit
  SHAs, labelled by a reviewer blind to this tool**, in a neutral CWE vocabulary. Measured numbers,
  and **both denominators, because a lone percentage is what gets quoted**:
  - **10/16 (63%)** over the categories this tool has a rule for — 83% on the target profile
    (Next.js/Supabase/Firebase/AI), **0 candidate false positives**.
  - **10/28 (36%)** over *every* label the blind reviewer wrote. The difference is scope, not
    detection: 3 labels are in categories with no rule and no delegate, and **9 are delegated to
    semgrep by [ADR 0007](docs/adr/0007-taint-is-cut-generic-dataflow-is-delegated.md) and are
    currently UNMEASURED** — run `node bench/wild.mjs --sast` on a host that can reach semgrep.dev to
    put a number on them.

  Until then, that arm is unmeasured and this README will not imply otherwise. The harness used to
  print those 9 as *"no rule for this category"* and report only the 63% — both retracted as
  **ERR-008** in [`ERRATA.md`](ERRATA.md). It also caught four real cry-wolf bugs on reference code,
  all fixed. This is a measurement, not a gate — and every repo added tightens it.

**A clean scan is not proof of safety. It is proof that nothing was proved.**

---

## עברית (בקצרה)

כלי אבטחה שבודק אפליקציות שנבנו ב-vibecoding ומייצר קוד הגנה מוכן להדבקה. מריצים אותו על הפרויקט
ומקבלים דוח דו-לשוני (עברית ואנגלית) עם ממצאים מדורגים (P0–P4), ראיות (`file:line`), תרחיש תקיפה,
והתיקון המומלץ. שלוש רמות בדיקה: סטטית (ברירת מחדל, בטוחה), live פסיבית, ובדיקות אקטיביות (בדיקת
עשן, לא סורק) — שתי האחרונות דורשות בעלות על היעד ואישור מפורש.

**שני צירים, לא אחד.** מלבד ממצאי אבטחה (פריצה), הכלי מדרג כעת גם ממצאי **תאימות** (חשיפה משפטית) —
נגישות לפי ת"י 5568 / WCAG 2.0 AA, ופרטיות לפי תקנות הגנת הפרטיות (אבטחת מידע). ממצא תאימות לעולם
אינו משפיע על ציון האבטחה.

---

## Two pillars — a lawsuit is not a breach

A vibecoded app gets its owner in trouble two ways, and only one of them is a hacker. The other is a
**regulator or a plaintiff** — often the more immediate risk. So every finding carries a
`pillar: 'security' | 'compliance'`, and the two are held rigorously apart.

| Pillar | What it is | Severity means | Touches the security badge? |
|---|---|---|---|
| **security** | a breach path (exposed key, open RLS, IDOR, prompt injection) | impact **if the finding is real** (P0–P4) | yes — the headline verdict |
| **compliance** | a legal exposure (accessibility, privacy) | **legal-exposure-if-unfixed**, in the statute's terms | **never** — its own axis, no compliance P0 |

The security badge is computed over security findings **only**; the benchmark's decision-rate ratchet
and false-positive gate are scoped to security — so a new compliance domain can never lower the
security bar or redden the security badge.

- **Compliance · Domain 1 — Accessibility (ת"י 5568 חלק 1 / WCAG 2.0 AA). Shipped.** A pure JSX/HTML
  scan grades **CG-A11Y-001..007** (img alt, `html lang`, form labels, icon-button names, video
  captions, positive `tabIndex`, keyboard-operable clickables). Every false-positive trap is engine
  data — an empty `alt=""` is valid, a `{...spread}` abstains, decorative `aria-hidden` opts out —
  and the legally-mandatory accessibility statement is a *declared* row, never a cry-wolf P1 on a
  fresh scaffold.
- **Compliance · Domain 2 — Privacy / data security (תקנות הגנת הפרטיות 2017). Documented.** A thin
  graded slice (cleartext transit, session-cookie flags) plus declared obligation rows tied to each
  תקנה — grade-or-declare taken to its limit, because most of the regulation is paperwork invisible
  to a repo.

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
/cg-scan            # static audit (Tier 0) — safe, read-only, the default.
                    #   Grades security AND compliance (accessibility) in one pass.
/cg-intent          # build/correct claudeguard.intent.yml in a few plain questions — turns the
                    #   business-logic audit from a guess (assumed) into a review (confirmed)
/cg-harden          # generate paste-ready guards for the findings
/cg-fix             # apply guards (dry-run diff first, you confirm)
/cg-live  <url>     # Tier 1 passive live checks (target you own)
/cg-dast  <url>     # Tier 2 active probes — a smoke test (target you own + authorized)
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
| **2 · Active probes** | Four GET probes against a running URL: a reflected-markup check, a single quote in an `id` parameter, an open-redirect check, and a CSP header check. **This is a smoke test, not a scanner** — no crawling, no authenticated flows, no parameter discovery, no IDOR, no fuzzing. Use Burp, ZAP or Nuclei for real DAST. | Requires written-authorization + ownership attestation, target allowlist, rate limit; dry-run by default. |

> **On Tier 2's name.** An earlier version of this table said Tier 2 sent "real attack traffic
> (injection, IDOR, fuzzing)". It never did — it sends the four probes above, and there is no IDOR
> probe at all. Named and retracted rather than quietly deleted: **ERR-004** in
> [`ERRATA.md`](ERRATA.md). See [`ROADMAP.md`](ROADMAP.md) for what real dynamic testing would
> require and why it is gated behind work that is deliberately unfinished.

> **The gate came before the arsenal, on purpose.** `plugin/scripts/dynamic_gate.mjs` — three tiers,
> per-tool allowlists, deny-by-default, a kill switch, an append-only audit log, and 66 adversarial
> tests including every host-matching bypass we could invent — is finished and wired to nothing,
> because no offensive adapter exists yet. *"A scanner that can be argued into attacking the wrong
> host is worse than no scanner."* Copy `core/authorization/SCOPE.example.yml` to
> `claudeguard.scope.yml` to enable Tiers 1–2. **Only test systems you own or are authorized in
> writing to test.**

---

## What it looks for

**Security.** Secrets in the client/repo · Supabase RLS & `service_role` exposure · Firebase rules ·
auth/authorization & IDOR · input validation & mass assignment · SQL/XSS/SSRF injection (delegated to
semgrep/Snyk, [ADR 0007](docs/adr/0007-taint-is-cut-generic-dataflow-is-delegated.md)) · security
headers/CORS/cookies · rate limiting · **LLM risks** (key exposure, prompt injection, agent-tool
abuse, cost DoS) · Android/iOS manifest & storage · Electron isolation & IPC · Docker/K8s/Terraform ·
GitHub Actions & dependency/supply-chain.

**Vibecoder hygiene** — four cheap, high-signal greps, each capped at `likely` because a regex sees
the sink but not whether it matters: **CG-HYG-001** placeholder credential shipped in source
(`admin123`, `sk-xxxx`), **-002** base64 used *as* encryption on a secret, **-003** an auth token in
`localStorage`, **-004** a TODO left inside auth code. Measured at **0 findings on four clean
reference repos and 0 on this repo's own source.**

**Compliance** — accessibility (ת"י 5568 / WCAG 2.0 AA) and privacy (data-security regs); see the
two-pillar section above. Full catalog in `core/checks/`.

---

## Built for non-experts (plain Hebrew)

The audience is people who built a real app with an AI tool and never learned security. So every
finding opens with a **"בפשטות / In plain words"** line — jargon-free, before any technical prose:
what is actually exposed, why it matters, and the one thing to do. There is also a standalone
beginner's guide, [`core/plain-language/concepts.he.md`](core/plain-language/concepts.he.md), that
teaches the underlying ideas once in plain Hebrew — the browser-vs-server model, `service_role` vs
the anon key, RLS, IDOR, prompt injection, denial-of-wallet — independent of any scan. The
per-finding text lives in [`core/plain-language/findings.md`](core/plain-language/findings.md), keyed
by finding id, and ships to both the plugin and the claude.ai skill.

---

## How it works

Most AI security review reads files one at a time and forms an impression. That misses things for a
boring reason: a model looking at `orders/route.ts` cannot know whether the `orders` table has RLS,
because the answer is in a different file — or in no file at all. ClaudeGuardIL puts a deterministic
layer underneath the model so it reasons over computed facts instead.

**Engine → Facts → Grader → Findings → Reviewers → Report.**

- The **engine** (`plugin/scripts/project_model.mjs`) builds the import graph, classifies the
  client/server boundary, traces env-var flow, and inventories every route, table, LLM call site and
  Supabase client. It emits **Facts** and has no opinion about how dangerous anything is.
- The **grader** (`plugin/scripts/grader.mjs`) is the single authority on severity. Every rule walks
  an enumerable set and decides each member, so nothing the engine discovered is left ungraded.
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

**The honest caveat, stated plainly:** the engine is regex plus lightweight parsing, not a type-aware
AST. So it can prove it accounted for every subject it *discovered* — not that it discovered every
subject. Dynamic imports, metaprogramming, and unusual framework constructs can escape enumeration.
That gap is precisely what the **discovery-coverage** axis exists to surface: a report tells you what
it parsed, what it skipped, and where it could only partially model something, so a partial scan can
never quietly pass for a complete one.

### Three laws keep it honest
Each exists because breaking it produced a real, embarrassing bug:

1. **Nothing passes because a keyword was present.** A route containing `getUser()` is reported as
   *unverified*, never as safe — from a regex, a correct check is indistinguishable from one whose
   result is ignored. Those rows become the reviewer's work list.
2. **Everything enumerated is accounted for.** A subject that quietly falls out of the ledger is how
   "we found nothing" comes to mean "we looked nowhere".
3. **A variable name is not a credential.** `FOO_API_KEY` in a name never justifies a P0 on its own.

Severity says how bad a finding is *if it is real*, and is never discounted because we are unsure —
that is what confidence is for. The headline verdict counts only **confirmed** findings, so an
unproven P0 is still shown to you but does not turn the badge red. And a `clean` verdict is only
emitted when nothing confirmed *and* nothing unproven-but-catastrophic is open *and* discovery
coverage cleared its floor — otherwise the level is `unknown` ("not proven safe"), never `clean`.

The regression suite includes a deliberately **correct** app — t3-env, user-scoped Supabase clients,
RLS with `auth.uid()` policies, middleware auth — and asserts it produces **zero** findings. A
security tool that cries wolf at correct code teaches people to ignore it, so that test is treated as
seriously as the ones that catch real bugs.

---

## How it's built

`core/` is the single source of truth (plain markdown). `scripts/build.mjs` copies it into both
wrappers, so one edit updates the plugin and the claude.ai skill together, and CI fails the build if
the generated copies drift. Scanning is **hybrid**: it uses `gitleaks` / `semgrep` / `npm audit` /
**Snyk** (reachability + dataflow) when installed, and falls back to Claude reading the code when they
aren't — it never force-installs anything, and a tool that could not run becomes a declared
`undeterminable` coverage row, never a silent pass. Findings also render to **SARIF 2.1.0** for GitHub
Code Scanning. The engine and grader have **zero** runtime dependencies, which CI enforces; you can
run them with nothing but Node ≥ 20.

---

## Repo layout
```
core/          shared knowledge (checks, guard-recipes, methodology, severity, i18n, authorization)
plugin/        the Claude Code plugin (skills, agents, hooks, engine + grader scripts)
skill-dist/    the claude.ai skill (assembled by build.mjs)
bench/         run.mjs — the regression gate;  wild/ — 11 real repos, blind-labelled, real numbers
scripts/       build.mjs
test/          the 629-test suite, including the "correct app must stay quiet" fixture
sample-vulnerable-app/  a deliberately-insecure app to test against
CONTEXT.md     the domain model — the vocabulary this codebase is written in
ROADMAP.md · ERRATA.md   what's next, and every claim we made and later found wrong
```

## Why is there vulnerable code in this repo, and why does the Security tab have alerts?
Three trees are **intentional test fixtures**, and none of them is installed, built or shipped:

- `sample-vulnerable-app/` — the demo app. Its problems are at the **code** level (exposed
  `service_role` key, no RLS, IDOR, prompt injection, missing headers).
- `bench/corpus/**` — the vulnerable/fixed pairs behind the regression gate.
- `bench/wild/*/repo/` — **real third-party source** at a pinned commit SHA, still vulnerable on
  purpose: a case that got patched would stop measuring anything.

Their dependencies are not kept current, so Dependabot flags them. **Every alert on this repository
points at one of those three trees, and none is reachable from anything the tool ships** — the engine
and grader have zero runtime dependencies, which CI enforces.

That count does not go to zero, and shouldn't. The dependencies the engine actually reads (`next`,
`express`, `firebase`, `electron`, `openai`, …) stay pinned to the real upstream versions, vulnerable
ones included, because the pin is what the wild benchmark measures against. What 0.3.1 did remove
were the **429** vendored dependencies the engine *cannot* read — `project_model.mjs` consults a
closed set of package names, so those bought no detection and cost an alert each. Roughly an order of
magnitude fewer alerts, wild scorecard byte-identical.

Never deploy any of it. See [`SECURITY.md`](SECURITY.md); **ERR-002** in [`ERRATA.md`](ERRATA.md) for
the contradictory claims this README used to make about fixture dependencies, and **ERR-007** for the
fixture tree these documents forgot to name while it produced most of the alerts.

## Errata

Claims this project made and later found wrong are retracted in the open, numbered, and kept:
[`ERRATA.md`](ERRATA.md). It currently holds eight — a gate of ours that checked one host and opened
another (ERR-001), the fixture-dependency claims (ERR-002), a credential leak in our own live probe
found by external review (ERR-003), the Tier-2 overclaim (ERR-004), the half of that retraction that
was announced before it was made (ERR-005), the benchmark headline (ERR-006), an account of our own
Dependabot alerts that named two fixture trees while a third produced most of them (ERR-007), and a
delegated half of the engine that scored zero by construction while the benchmark called it "no rule"
(ERR-008).

The ledger exists because the failure this tool is built to catch — a confident statement nobody
checked — is one we keep making too. Nothing is quietly deleted; each entry quotes the old claim.

## How to judge this project

Use it as a **first gate**, not a sign-off. It is stronger than an ordinary PR review for security
coverage and completeness, and weaker than an experienced AppSec reviewer on subtle logic. It is not
a pentest. The combination that works: this first, then a security-focused review, then authenticated
testing for anything production-critical.

## Disclaimer
Provided as-is, no warranty. A clean scan is **not** proof of safety. You are responsible for what you
scan and for the scope of any live/DAST testing. Not affiliated with Anthropic.

MIT licensed — see `LICENSE`.
