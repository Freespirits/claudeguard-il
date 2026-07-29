# ClaudeGuard-IL Scan Findings — Sample Vulnerable App

**Scan target:** `sample-vulnerable-app`  
**Tool:** ClaudeGuard-IL (Tier 0 static audit)  
**Date:** 2026-07-29  
**Verdict:** `critical`  
**Total findings:** 11  
**Confirmed:** 5 | **Needs-review:** 6

---

## Severity Summary

| Severity | Count | Confidence |
|----------|-------|------------|
| P0 (critical) | 4 | 3 confirmed, 1 needs-review |
| P1 (high) | 2 | 0 confirmed, 2 needs-review |
| P2 (medium) | 3 | 1 confirmed, 2 needs-review |
| P3 (low) | 2 | 1 confirmed, 1 needs-review |
| P4 (info) | 0 | — |

---

## Finding 1 — P0 Confirmed

- **ID:** `CG-DB-001`
- **Subject:** `table:orders`
- **Title:** Table "orders" has row level security disabled
- ** Hebrew:** לטבלה "orders" אין הגנת RLS
- **Evidence:** `supabase/migrations/001_init.sql:5`
- **Why:** The migration creates the table but never runs `alter table ... enable row level security`.
- **Exploit:** Anyone with the anon key (shipped in every browser client) can read and write the whole table.
- **Impact:** Total exposure and modification of all rows in `orders`.
- **CWE:** CWE-284
- **OWASP:** A01:2021
- **Autofixable:** Yes
- **Guard recipe:** `guard-recipes/rls-policies.md#enable-rls`

---

## Finding 2 — P0 Confirmed

- **ID:** `CG-DB-001`
- **Subject:** `table:profiles`
- **Title:** Table "profiles" has row level security disabled
- ** Hebrew:** לטבלה "profiles" אין הגנת RLS
- **Evidence:** `supabase/migrations/001_init.sql:15`
- **Why:** Same as Finding 1 — migration creates the table without enabling RLS.
- **Exploit:** Anyone with the anon key reads/writes all profile rows.
- **Impact:** Total data exposure of the `profiles` table.
- **CWE:** CWE-284
- **OWASP:** A01:2021
- **Autofixable:** Yes
- **Guard recipe:** `guard-recipes/rls-policies.md#enable-rls`

---

## Finding 3 — P0 Confirmed

- **ID:** `CG-ENV-001`
- **Subject:** `env:NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`
- **Title:** Privileged secret `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` is compiled into the browser bundle
- ** Hebrew:** הסוד `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` נכלל בבנדל של הדפדפן
- **Evidence:** `.env:6`
- **Why:** `NEXT_PUBLIC_` is a bundler-inlined prefix, so the value ships verbatim to the client.
- **Exploit:** Open DevTools, read the value from the JS bundle, use it directly.
- **Impact:** Full access to whatever the service-role key grants. Rotate immediately.
- **CWE:** CWE-200
- **OWASP:** A01:2021
- **Autofixable:** Yes
- **Guard recipe:** `guard-recipes/secrets-management.md#public-prefixes`

---

## Finding 4 — P0 Needs-review

- **ID:** `CG-WEB-001`
- **Subject:** `route:pages/api/orders/[id].ts`
- **Title:** Route `/api/orders/[id]` has no visible authentication
- ** Hebrew:** לנתיב `/api/orders/[id]` אין אימות גלוי
- **Evidence:** `pages/api/orders/[id].ts`
- **Why:** No recognizable auth in the handler or covering middleware.
- **Exploit:** Anyone sends requests to `/api/orders/[id]` without logging in.
- **Impact:** Handler uses the service-role key (RLS bypass), so anonymous callers act as database owner.
- **CWE:** CWE-306
- **OWASP:** A01:2021
- **Autofixable:** No
- **Guard recipe:** `guard-recipes/auth-middleware.md`
- **Assumption:** Auth might be performed in an imported helper this pass does not follow.

---

## Finding 5 — P1 Needs-review

- **ID:** `CG-WEB-001`
- **Subject:** `route:pages/api/chat.ts`
- **Title:** Route `/api/chat` has no visible authentication
- ** Hebrew:** לנתיב `/api/chat` אין אימות גלוי
- **Evidence:** `pages/api/chat.ts`
- **Why:** No recognizable auth in the handler or covering middleware.
- **Exploit:** Anyone sends requests to `/api/chat` without logging in.
- **Impact:** Anonymous callers change data through an endpoint intended for signed-in users.
- **CWE:** CWE-306
- **OWASP:** A01:2021
- **Autofixable:** No
- **Guard recipe:** `guard-recipes/auth-middleware.md`
- **Assumption:** Auth might be performed in an imported helper this pass does not follow.

---

## Finding 6 — P1 Needs-review

- **ID:** `CG-WEB-004`
- **Subject:** `route:pages/api/orders/[id].ts`
- **Title:** Route `/api/orders/[id]` looks up a record by id with no ownership check
- ** Hebrew:** הנתיב `/api/orders/[id]` מאחזר רשומה לפי מזהה ללא בדיקת בעלות
- **Evidence:** `pages/api/orders/[id].ts`
- **Why:** Reads `id` from request, holds service-role client (RLS bypass), no ownership column compared.
- **Exploit:** Signed-in user changes the URL id to read or edit another user's record.
- **Impact:** Every record reachable through this route is readable by anyone who can guess an id.
- **CWE:** CWE-639
- **OWASP:** A01:2021
- **Autofixable:** No
- **Guard recipe:** `guard-recipes/auth-middleware.md`
- **Assumption:** Ownership check might be performed in a helper this pass does not follow.

---

## Finding 7 — P2 Confirmed

- **ID:** `CG-WEB-010`
- **Subject:** `next-config:next.config.js:headers`
- **Title:** No security headers configured in `next.config`
- ** Hebrew:** לא הוגדרו כותרות אבטחה ב-next.config
- **Evidence:** `next.config.js`
- **Why:** `next.config` declares no `headers()` function, so CSP, HSTS, or frame protections are absent at the framework level.
- **Exploit:** Clickjacking and injected-script attacks that CSP would block.
- **Impact:** Removes browser-side defenses that limit damage from other bugs.
- **CWE:** CWE-693
- **Autofixable:** Yes
- **Guard recipe:** `guard-recipes/security-headers.md`

---

## Finding 8 — P2 Needs-review

- **ID:** `CG-LLM-002`
- **Subject:** `llm:pages/api/chat.ts`
- **Title:** LLM call site has no rate limit
- ** Hebrew:** לנקודת הקריאה למודל אין הגבלת קצב
- **Evidence:** `pages/api/chat.ts`
- **Why:** No rate-limiting call appears in this file.
- **Exploit:** Someone loops the endpoint; every call is billed to you.
- **Impact:** Denial of wallet — overnight bill with no breach.
- **OWASP:** LLM10
- **Autofixable:** No
- **Guard recipe:** `guard-recipes/rate-limiting.md#llm-endpoints`
- **Assumption:** Rate limiting might be applied at the edge or in middleware this pass does not follow.

---

## Finding 9 — P2 Needs-review

- **ID:** `CG-WEB-002`
- **Subject:** `route:pages/api/chat.ts`
- **Title:** Route `/api/chat` does not validate its request body
- ** Hebrew:** הנתיב `/api/chat` אינו מאמת את גוף הבקשה
- **Evidence:** `pages/api/chat.ts`
- **Why:** No schema validation call appears in the handler.
- **Exploit:** Caller sends unexpected fields that flow into the database or downstream calls.
- **Impact:** Mass-assignment and type-confusion bugs; larger attack surface.
- **CWE:** CWE-20
- **Autofixable:** No
- **Guard recipe:** `guard-recipes/zod-validation.md`
- **Assumption:** Validation might be performed by a helper or framework layer this pass does not follow.

---

## Finding 10 — P3 Confirmed

- **ID:** `CG-WEB-022`
- **Subject:** `next-config:next.config.js:productionBrowserSourceMaps`
- **Title:** Production source maps are published
- ** Hebrew:** מפות מקור מפורסמות בסביבת הייצור
- **Evidence:** `next.config.js:4` — `productionBrowserSourceMaps: true`
- **Why:** Source maps published to production.
- **Exploit:** Attacker reads original source, including comments and internal route names.
- **Impact:** Makes every other weakness easier to find. Not a breach on its own.
- **Autofixable:** No
- **Guard recipe:** `guard-recipes/ci-hardening.md#source-maps`

---

## Finding 11 — P3 Needs-review

- **ID:** `CG-LLM-004`
- **Subject:** `llm:pages/api/chat.ts`
- **Title:** LLM call has no token ceiling
- ** Hebrew:** לקריאה למודל אין תקרת טוקנים
- **Evidence:** `pages/api/chat.ts`
- **Why:** No `max_tokens`, `maxTokens`, or `maxOutputTokens` appears at this call site.
- **Exploit:** Caller crafts input that makes the model generate until provider limit on every request.
- **Impact:** Each request costs far more than intended. Combined with missing rate limit, this creates overnight bills.
- **OWASP:** LLM10
- **Autofixable:** No
- **Guard recipe:** `guard-recipes/llm-guardrails.md`
- **Assumption:** Token ceiling might be set on a shared client defined elsewhere.

---

## Discovery Coverage

| Metric | Value |
|--------|-------|
| Files intended | 6 |
| Files read | 6 |
| Coverage ratio | 1.0 (≥ 0.95 floor) |
| Adequate | Yes |

## Business Logic Status

- **Status:** `assumed`
- **Reason:** No `claudeguard.intent.yml` was provided. Ownership models were guessed from column names.
- **Note:** Every business-logic conclusion in the report rests on the intent file being correct. Use `/cg-intent` to build one.

---

## Tool Limits

- Heuristic parsing (regex + import resolution), not a type-aware AST.
- May miss dynamic requires, re-exports through barrels, and monorepo aliases.
- Client/server classification is decisive for `NEXT_PUBLIC_` checks.
- Database model reflects migrations in the repo, not the live database.

---

*Generated by ClaudeGuard-IL, formatted by Lyra.*
