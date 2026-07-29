I've now conducted extensive research across academic papers, industry reports, and existing tools. Here's a comprehensive analysis of your specification, validated against the current state of the art.

---

## Comprehensive Review of Your LLM Security Scanner Specification

### Overall Assessment

Your specification is **well-targeted and architecturally sound**. The decision to prioritize AI/LLM depth over Electron or DNS hygiene aligns perfectly with the empirical research landscape. The "sink-to-source" anchor approach is the right compromise given a zero-AST, zero-FP mandate. However, the research reveals several gaps and opportunities that warrant attention.

---

### 1. Ranking of Expansion Directions — Validated and Reinforced

Your ranking is correct, and the research strongly supports it:

**AI/LLM Depth (Highest Value):** The arXiv study "Understanding the (In)Security of Vibe-Coded Applications" (Deng et al., 2026) analyzed 200 deployed vibe-coded web apps and found **1,471 vulnerabilities across 90% of repositories**, with 76.7% rated Critical or High. The top three OWASP categories — Broken Access Control (36%), Cryptographic Failures (20.7%), and Injection (17.7%) — account for 74.4% of all vulnerabilities. The SusVibes benchmark (Zhao et al., 2025) found that **82.8% of functionally correct AI-generated solutions contain security vulnerabilities**. The Escape.tech report found **34,232 vulnerabilities across 5,600 vibe-coded apps**, with 400+ leaked secrets and 98 critical issues. Your instinct to focus here is correct.

**Desktop/Electron (Skip):** The arXiv study confirms that **94.5% of vibe-coded applications are web applications**, with TypeScript, React, Tailwind CSS, and Vite as the dominant stack. Desktop apps account for less than 1%. Your reasoning about the "vibecoder" persona being web-first SaaS is empirically validated.

**Perimeter/DNS (Zero Value):** Correct. This is a different product entirely.

**One addition to consider:** The Escape report and the arXiv study both identify **Supabase RLS misconfiguration** (CVE-2025-48757) as the single most prevalent vulnerability class in vibe-coded apps. This is neither pure "AI/LLM depth" nor traditional web security — it's a **platform-specific configuration vulnerability** that AI code generators systematically fail to handle. This might warrant a dedicated check category.

---

### 2. Deep Dive: AI/LLM Depth — Critical Analysis of Your Top 5 Checks

#### Check 1: LLM → HTML (XSS) — **Strong, but needs expansion**

Your heuristic is correct. The Auth0 article on OWASP LLM05 (Improper Output Handling) confirms this is the most common LLM-specific vulnerability. The DeepSeek CVE-2025-26210 is a real-world example where LLM output rendered as raw HTML led to full account takeover via `localStorage` token theft.

**FP Trap Analysis:** Your `dompurify` suppression heuristic is necessary but insufficient. The research (VibeWrench.dev) identifies the broader pattern: `dangerouslySetInnerHTML`, `.innerHTML`, `v-html`, and unsanitized markdown renderers (`marked`, `remark`, `markdown-it`). Consider expanding the sink list beyond React's `dangerouslySetInnerHTML`.

**Missing pattern:** The Escape report found that **60% of analyzed apps had `localStorage` token storage** combined with unsanitized LLM output rendering. You should consider a **composite check**: "LLM output → innerHTML" AND "session tokens in localStorage" = critical severity upgrade. This is the "deadly duo" pattern that leads to account takeover.

#### Check 2: LLM → Exec (RCE) — **Strong, well-validated**

The Vanna.AI CVE-2024-5565 is the canonical example: user input → LLM generates Plotly code → `exec()` → full RCE. The Promptfoo scanner and JFrog SAST both detect this pattern. Your heuristic of matching `eval()`, `child_process.exec()`, and `vm.runInContext()` with LLM-derived arguments is correct.

**FP Trap Analysis:** Your whitelist/regex validation suppression is the right call. However, the Promptfoo blog emphasizes that the real challenge is **tracing** — you need to trace not just "is this variable from an LLM call" but "was the LLM call's input itself user-controlled?" This is the "lethal trifecta" (Simon Willison's framework): access to private data + exposure to untrusted content + ability to communicate externally. Without AST-level analysis, you can only catch the direct sink-to-source pattern, which is still valuable but will miss multi-hop flows.

**Consider adding:** `new Function()` as a sink. AI-generated code frequently uses `new Function(llmOutput)` as a "safe" alternative to `eval()`, which it is not.

#### Check 3: RAG Injection (Untrusted → Prompt) — **Partially correct, needs refinement**

Your heuristic of matching Supabase/Firebase queries interpolated into LLM prompt templates is a good start, but the research reveals this is more nuanced.

**The real vulnerability pattern:** The Promptfoo blog identifies that the critical question is not just "is untrusted data in the prompt" but "does the LLM have the lethal trifecta?" Untrusted data in a prompt is only dangerous if the LLM can also take privileged actions or communicate externally. Your check will fire on every RAG app that retrieves user data and passes it to an LLM, which is... every RAG app. This creates a **massive FP problem** that violates your zero-FP mandate.

**Recommendation:** Instead of flagging all untrusted→prompt flows, flag only those where:
1. The untrusted data source is **not user-owned** (e.g., `supabase.from('public_documents')` vs `supabase.from('user_notes')`)
2. AND the LLM has tool access or output rendering that could lead to harm

This is harder to detect with regex alone, but you could use heuristics like: if the query is to a table named `public_*`, `documents`, `articles`, `comments`, or any table that suggests shared/multi-tenant data, flag it. If it's `user_*`, `profile_*`, `settings_*`, suppress.

#### Check 4: Unprotected "God-Tool" — **Excellent, but the FP trap is worse than you think**

This is one of your highest-value checks. The research on tool-calling attacks (ToolCommander, STAC, Attractive Metadata Attack) shows that **destructive tools without human-in-the-loop are the #1 agentic vulnerability**. The OWASP LLM06 (Excessive Agency) directly maps to this.

However, your FP trap analysis is incomplete. The research shows that human-in-the-loop can be implemented in ways that are invisible to a source code scanner:

1. **UI-level confirmation** (your current FP trap) — correct
2. **Middleware-level interception** — the approval happens in a separate middleware file
3. **Framework-level tool wrapping** — LangChain's `Tool` class can have `return_direct=False` which triggers confirmation
4. **Runtime configuration** — the tool is conditionally registered based on environment variables

**Recommendation:** Instead of looking for `confirm` or `approve` in the same function, look for it in the **entire file** or **imported modules**. This broadens the net while still avoiding cross-file FPs. Also, consider checking for the presence of `human_approval: true` or `requires_approval: true` in tool definitions, which is the emerging standard pattern.

**Missing pattern from STAC research:** The STAC (Sequential Tool Attack Chaining) paper shows that individually benign tools can form dangerous chains. While you can't detect multi-step chains without data flow analysis, you CAN flag when a tool definition includes keywords like `delete` AND the same file also defines tools with `create` or `upload` — this indicates a tool ecosystem where chaining attacks are possible.

#### Check 5: Prompt Leakage (System Prompt) — **Lowest value of the five, consider replacing**

The research suggests prompt leakage is a lower-severity issue compared to the others. The OWASP LLM07 ranking has dropped in the 2025 list. The FP trap you identify (`NODE_ENV === 'development'` guard) is common and will suppress most findings.

**Consider replacing with a higher-value check:** Based on the research, a better Check 5 would be:

**Check 5 (Revised): LLM → SQL/Database Query Execution**

Match `db.query()`, `supabase.rpc()`, or `prisma.$queryRaw()` where the argument is derived from an LLM completion. This maps directly to CVE-2024-7042 (LangChain Cypher injection) and CVE-2024-23751 (LlamaIndex text-to-SQL). The FP trap: the LLM output is parsed as structured JSON and only parameter values are used (not raw SQL). This is a much higher-value check than prompt leakage.

---

### 3. The Blind Spots — Strong Additions, but Need Calibration

#### Blind Spot 1: Client-Side "Admin" Guards — **Critical, but the heuristic needs work**

The arXiv study found that **Broken Access Control is the #1 vulnerability** (36% of all findings, affecting 75.5% of repositories). This is the single most important check in your entire specification. However, your heuristic ("Admin check in frontend AND absent in backend") is hard to implement without cross-file analysis.

**Practical implementation:** Instead of cross-referencing frontend and backend (which requires understanding the API contract), flag any `if (user.role === 'admin')` or `if (user.isAdmin)` check in a `.tsx`/`.jsx` file that wraps a UI element rendering sensitive data or actions. The heuristic is: "Admin role check in client component file" = warning. This is a simpler, more reliable signal.

**Even simpler and higher-value:** Flag any `api/` route (Next.js) or serverless function that performs a destructive operation (`DELETE`, `UPDATE`, `DROP`) without calling `getServerSession()`, `auth.getUser()`, `supabase.auth.getUser()`, or similar auth functions. This is Check 2 from your blind spots, and it's the highest-value check in the entire spec based on the research.

#### Blind Spot 2: The "Hidden" API Route — **Highest value-per-line-of-code**

The arXiv study's "Hidden Security Rules" failure mode (49.9% of all vulnerabilities) directly maps to this check. The specific pattern they found repeatedly: API routes that perform mutations without authentication checks. The "Incomplete Change Propagation" failure mode (12.6%) is also relevant — a new route gets auth middleware but old routes don't.

**Implementation detail:** Look for files in `app/api/` or `pages/api/` that:
1. Export `POST`, `PUT`, `DELETE`, or `PATCH` handlers
2. Do NOT contain `auth`, `session`, `getUser`, `getServerSession`, `verifyToken`, or `requireAuth` anywhere in the function body
3. DO contain database operations (`supabase.from()`, `prisma.`, `db.query`, `mongo`)

This three-factor AND is the zero-FP version. It will only fire on routes that mutate data without any auth signal.

#### Blind Spot 3: Client-Side Env Var Misuse — **Good, but rare**

This is a valid check but the research suggests it's lower frequency. The Escape report found exposed secrets primarily in **frontend JavaScript bundles** (hardcoded keys, not env var misuse). The arXiv study found "User-dependent security" accounted for only 4.6% of vulnerabilities.

**Consider adding instead:** Hardcoded secrets in frontend code. The Escape report found 400+ leaked secrets including 6 GitHub tokens, 7 OpenAI API keys, and 2 admin payment API keys. A simple regex for `sk-`, `pk_`, `SUPABASE_SERVICE_ROLE_KEY=`, `OPENAI_API_KEY=` in `.tsx`/`.jsx`/`.js` files outside of `api/` or `server/` directories would catch the most common pattern.

---

### 4. Not Worth Building — Agreed, with One Caveat

Your reasoning for skipping Electron/Tauri is sound and empirically validated. However, the research reveals one adjacent area worth considering:

**MCP (Model Context Protocol) tool definitions** — The TIP exploitation paper (Xie et al., 2025) demonstrates that MCP tool descriptions are a critical attack surface. The "Attractive Metadata Attack" (Mo et al., 2025) achieves 81-95% attack success rates by manipulating tool metadata. If your users are defining MCP tools in their codebase, checking for malicious tool descriptions (containing injection instructions) would be high-value. However, this may be outside your current scope.

---

### 5. Additional Recommendations from the Research

Based on the comprehensive research, here are checks you should consider adding:

#### A. Supabase RLS Misconfiguration (NEW — High Value)

The Escape report identifies this as **the #1 issue in vibe-coded apps**. The pattern: `supabase.from('table').select()` in client-side code without corresponding RLS policies in the database. While you can't check the database directly, you CAN flag:
- Client-side Supabase queries that include `service_role` key
- Supabase client initialization with `service_role` key in a `.tsx`/`.jsx` file
- Any file that contains both `createClient` and `service_role`

#### B. TODO/FIXME in Auth Logic (NEW — Medium Value)

The arXiv study's "Forgotten Obligations" failure mode (6.9%, but 89.2% Critical/High severity) specifically identifies `TODO` comments in authentication code that ship to production. Flag `TODO`, `FIXME`, or `HACK` within 5 lines of `auth`, `login`, `password`, `session`, or `token` references.

#### C. Hardcoded Credentials in "Demo" Logic (NEW — Medium Value)

The arXiv study's "Demo-Oriented Design" failure mode (16.1%, 84% Critical/High) finds AI-generated code that includes `btoa()` for "encryption", hardcoded demo passwords, and `localStorage` for OAuth tokens. Flag:
- `btoa(` used for "encryption" or "encoding" secrets
- `localStorage.setItem` with keys containing `token`, `auth`, `session`, `password`
- Hardcoded credential strings in conditional blocks like `if (email === 'demo@...')`

---

### 6. Competitive Landscape Awareness

Your tool occupies a specific niche. Key competitors:

- **Promptfoo** (code scanning for LLM apps) — Uses AI agents for tracing, not regex. Higher accuracy but requires LLM API calls. Your zero-LLM approach is faster and cheaper but less accurate on multi-hop flows.
- **VibeWrench** — Targets vibe-coded apps specifically with 18 scan categories. Closest direct competitor.
- **Sentinel AI** — Runtime guardrails, not static analysis. Complementary, not competing.
- **Agent-Aegis** — Python-focused, maps to OWASP Agentic Top 10. Different language ecosystem.

Your differentiation: **zero-FP, zero-LLM, regex-based, JavaScript/TypeScript-first**. This is a valid and underserved niche. The key risk is that Promptfoo's AI-powered tracing will catch vulnerabilities your regex approach misses. Your advantage is speed, cost, and deterministic behavior.

---

### Summary: Revised Priority Ranking

Based on the research, here's my recommended priority order for implementation:

| Priority | Check | Rationale | Expected FP Rate |
|:---|:---|:---|:---|
| 1 | Unauthenticated destructive API routes | #1 vulnerability in research (36% of all findings) | Very Low |
| 2 | LLM → HTML (XSS) | Most common LLM-specific vuln, clear sink pattern | Low |
| 3 | LLM → Exec (RCE) | Highest severity, clear CVE precedents | Low |
| 4 | Client-side env var / secret exposure | 400+ leaked secrets in research data | Very Low |
| 5 | Supabase service_role key in frontend | CVE-2025-48757, #1 issue in vibe-coded apps | Very Low |
| 6 | Unprotected "God-Tool" | OWASP LLM06, tool-calling attack research | Medium |
| 7 | LLM → SQL execution | CVE-2024-7042, CVE-2024-23751 | Low |
| 8 | RAG Injection (refined) | Only with non-user-owned data sources | Medium |
| 9 | TODO/FIXME in auth logic | "Forgotten Obligations" pattern | Low |
| 10 | Demo-oriented credential storage | "Demo-Oriented Design" pattern | Low |

Your original spec is a strong foundation. The research validates your core instincts while revealing that **access control failures** (not LLM-specific issues) are actually the dominant vulnerability class in vibe-coded apps. Your "Blind Spots" section is where the highest-value checks live.