# Cross-model poll — regrouped synthesis

Eight models were shown the coverage-expansion memo (AI/LLM depth vs Electron vs DNS, the top-5 LLM
checks, the "vibecoder blind spots"). This file regroups their replies into consensus, divergence,
genuinely-new checks, and a mapping onto what ClaudeGuardIL already does — so the signal is in one
place instead of eight.

## What each file actually is

| File | Kind | Weight |
|------|------|--------|
| `fable5.md` | Review — sharpest; catches an FP-firehose in the env-var check and reframes it exactly as CG already works | **Highest** |
| `GLM5.2.md` | Review — research-backed (arXiv Deng 2026, Escape.tech, CVEs); reorders around access-control | **High** |
| `deepseekv4pro.md` | Review — concrete regex/suppressor detail, two-pass architecture | **High** |
| `openai.md` | Review — broad; adds SSRF, LLM-decides-authz, unvalidated tool args, agent-loop safety | **High** |
| `minimaxm3.md` | Review — env-var "ship first", god-tool "flag all", supply-chain typosquat | Medium |
| `nemotron-3-super.md` | Restatement of the memo in a table — little new | Low |
| `Gemma4.31B.md` | Restatement of the memo in a table — little new | Low |
| `kimi.md` | NOT a review — a sample CG report on a vulnerable app ("formatted by Lyra"). An output-format demo. | (reference) |

## Consensus (all six reviewers agree)

1. **AI/LLM depth is the highest-value direction. DNS is zero. Electron is low.** Unanimous, and
   GLM5.2 backs it empirically: 94.5% of vibe-coded apps are web (arXiv Deng 2026), <1% desktop.
2. **The real #1 is access control, not anything LLM-specific.** GLM5.2: Broken Access Control = 36%
   of all findings, 75.5% of repos. The memo's "blind spots" (unprotected destructive routes,
   client-only admin guards, secret-in-client) are where the value actually is. **CG already grades
   this** (`gradeRoutes`, `NEXT_PUBLIC_` inlining, client/server boundary) — the reviewers are
   validating the existing core, not asking for something new.
3. **Two output tiers.** fable5 names it best: **`violation`** (zero-FP, CI-blocking) vs **`nudge`**
   (heuristic, surfaced, non-blocking). This is *exactly* CG's `confirmed` (drives the badge) vs
   `likely`/`needs-review` (printed, never reddens the badge) — the reviewers independently
   reinvented the confidence model. No change needed; it's a naming confirmation.
4. **Sink-to-source, not taint analysis.** With no AST and a zero-FP mandate, anchor on the dangerous
   sink and check the immediate source. Everyone agrees this is the right compromise.

## The env-var check — the sharpest correction (fable5), and CG is already right

deepseekv4pro/minimax called "non-`NEXT_PUBLIC_` `process.env` in a component" the single
highest-value check. **fable5 shows it's an FP firehose**: in the App Router, server components are
the default, so `process.env.DATABASE_URL` in `app/dashboard/page.tsx` is correct, idiomatic code.
And a non-prefixed var in client code isn't a *leak* — it's `undefined` in the browser. The real leak
vector is a **secret under a public prefix** (`NEXT_PUBLIC_STRIPE_SECRET_KEY`,
`VITE_SUPABASE_SERVICE_ROLE_KEY`). The right discriminator is the **`'use client'` boundary** plus the
public prefix.

**This is precisely what CG already does** — `PUBLIC_PREFIXES` × `classifySecretName` × client
reachability, with `PUBLIC_BY_DESIGN` guarding the anon-key false positive fable5 warns about. The
poll's strongest correction lands on a check CG shipped long ago. Worth a regression test named after
the failure mode; not a new rule.

## Genuinely new, worth building (ranked by consensus × fit)

| # | Check | Backers | CG status |
|---|-------|---------|-----------|
| 1 | **LLM output → dangerous sink**: `dangerouslySetInnerHTML`/`innerHTML`/`v-html`, `eval`/`Function()`/`vm.*`/`child_process`, `$queryRaw`/`rpc()`, and **`fetch(llmUrl)` (SSRF)** | all six | **new** — extends `gradeLlmSites`; task #22 |
| 2 | **Unvalidated tool arguments**: a tool handler uses `args.*` with no zod/joi/valibot/JSON-schema | openai, GLM5.2 | new — task #22 |
| 3 | **LLM decides authorization**: `if (completion.includes('approved')) deleteUser()` | openai, GLM5.2 | new — task #22 |
| 4 | **Placeholder secret shipped**: `changeme`, `sk-xxx`, `your-api-key-here`, `ghp_xxxx…` outside `.env.example`/docs | deepseek, fable5 | new — cheap, near-zero FP |
| 5 | **God-tool** (destructive tool, no human-in-loop): flag destructive tool *names*; check the **whole file/imports** for `confirm`/`approve`/`requires_approval`, not one function | all six (minimax/fable: flag-all beats string-match) | new — task #22 |
| 6 | **Agent-loop safety**: `while(true){ llm(); runTool() }` with no max-iterations/timeout/budget | openai | new |
| 7 | **`btoa()` as "encryption"** + **OAuth/session token in `localStorage`** ("demo-oriented design", 84% Crit/High) | GLM5.2 | new — cheap |
| 8 | **TODO/FIXME within ~5 lines of auth/password/session** ("forgotten obligations", 89% Crit/High) | GLM5.2 | new — cheap |
| 9 | **MCP tool descriptions** carrying injection instructions | GLM5.2, openai | new — task #22 (`mcpServers` fact) |
| 10 | **Prompt/secret exfil sinks** beyond `console.log`: `console.error`, `pino`/`winston`, **`Sentry.captureException(..,{prompt})`**; suppress on `NODE_ENV !== 'production'` | deepseek, fable5 | new |

**Suppressors that keep these zero-FP** (fable5/deepseek): require a sanitizer *call*
(`DOMPurify.sanitize`, `sanitize-html`, `escapeHtml`) between source and sink — not just a hopeful
variable name; webhook routes are signature-verified by design (`stripe.webhooks.constructEvent`,
`svix`, `x-hub-signature`, `timingSafeEqual`) → never flag as unauth; middleware-scoped auth
(`middleware.ts` matcher, `clerkMiddleware`, tRPC `protectedProcedure`) → downgrade route findings.
CG already models the middleware case.

## Divergence — the one real disagreement: RAG

- **openai / GLM5.2**: keep it, but only fire when the retrieved data is **not user-owned**
  (`public_*`, `documents`, `comments`) AND the LLM has tool/output reach ("lethal trifecta").
- **deepseek / fable5**: rescope to **request-derived** sources (`req.query|body|params`,
  `searchParams`) — but fable5 notes this makes it *reflected* injection, not RAG; the canonical RAG
  attack (poisoned retrieved document) lives exactly in the DB-sourced data being dropped.
- **minimax**: drop retrieval-detection entirely; look for missing instruction/data separation.

**Resolution for CG:** RAG/indirect-injection is a **declared** row (grade-or-declare), not a graded
rule — every reviewer's zero-FP version either misses the real attack or needs flow analysis CG
doesn't have. Declaring it honestly beats a rule that fires on every RAG app. Matches the plan.

## Architecture notes the reviewers converged on

- **Pass 0 — project fingerprint** (fable5): framework, App-vs-Pages router, `middleware.ts`,
  auth/payment libs from `package.json`. **CG already has this** (`framework`, `middleware`,
  boundary seeds) — its rules are already parameterised on the stack.
- **Two-pass** (deepseek): per-file, then cross-file correlation. CG's engine (whole-repo model) →
  grader (reasons over the model) already is this shape.
- **SARIF 2.1.0 output** (fable5): for GitHub Code Scanning — `level` maps to violation/nudge,
  `relatedLocations` carries cross-file pairs, `partialFingerprints` gives "fail on new only"
  baselining. **This is a genuinely new, high-value deliverable** CG does not yet emit — a SARIF
  renderer over the existing findings. Worth a task.
- **Skip**: Electron (all), supply-chain as a scanner (deepseek — "Snyk/Socket own it"; but minimax
  wants the cheap typosquat/new-package check, which CG's supply-chain-hygiene task already scopes).

## Net effect on the roadmap

Nothing here overturns the plan; it sharpens it.
- **Validates** the compliance pillar's sibling (security) core: access-control and the public-prefix
  secret check are the reviewers' #1, and CG already ships both.
- **Feeds task #22 (AI/LLM depth)** a concrete, consensus-ranked check list (table above) with the
  suppressors that keep them zero-FP.
- **Adds two new backlog items**: a **SARIF renderer** (fable5, high value) and the cheap
  **placeholder-secret / btoa / localStorage-token / TODO-in-auth** grep checks.
- **Confirms** RAG stays declared, Electron stays low, DNS stays out.
