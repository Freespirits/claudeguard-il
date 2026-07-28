# 🛡️ ClaudeGuardIL — Security Report / דוח אבטחה

```
Target: sample-vulnerable-app        Tier: static (Tier 0)
Scanned: 7 files · 11 findings        Engine: hybrid (fallback-regex secrets / claude-native)

Community project — NOT an official Anthropic product.
פרויקט קהילתי — אינו מוצר רשמי של Anthropic.
```

> This is a real ClaudeGuardIL report against the bundled `sample-vulnerable-app/`. It shows the
> output format, the bilingual findings, and the verifier suppressing a false positive.

## Verdict / פסק דין

```
🔴 CRITICAL — 4 × P0, 3 × P1, 3 × P2, 1 × P3.  Do NOT deploy until the P0s are fixed.
🔴 קריטי — 4 × P0, 3 × P1, 3 × P2, 1 × P3.  אין לפרוס עד לתיקון ה-P0.
```

## Summary / סיכום

| # | ID | Sev | Conf | Title (EN) | כותרת (HE) | File |
|---|----|-----|------|------------|-----------|------|
| 1 | CG-SB-001 | 🔴 P0 | confirmed | service_role key exposed to browser | מפתח service_role חשוף לדפדפן | `lib/db.ts:6`, `.env:6` |
| 2 | CG-SB-002 | 🔴 P0 | likely | `orders` table has no RLS | לטבלת `orders` אין RLS | `supabase/migrations/001_init.sql:5` |
| 3 | CG-SB-003 | 🔴 P0 | likely | `profiles` table has no RLS | לטבלת `profiles` אין RLS | `supabase/migrations/001_init.sql:16` |
| 4 | CG-SECRET-001 | 🔴 P0 | confirmed | Live secrets committed in `.env` | סודות חיים ב-`.env` שהועלה ל-git | `.env:7-9` |
| 5 | CG-WEB-001 | 🟠 P1 | confirmed | IDOR + no auth on orders API | IDOR ואין אימות ב-API של orders | `pages/api/orders/[id].ts:8` |
| 6 | CG-LLM-001 | 🟠 P1 | confirmed | Prompt injection in chat API | הזרקת פרומפט ב-API של chat | `pages/api/chat.ts:14` |
| 7 | CG-SECRET-002 | 🟠 P1 | confirmed | Hardcoded API key in source | מפתח API מוטמע בקוד | `lib/db.ts:11` |
| 8 | CG-LLM-002 | 🟡 P2 | confirmed | No auth/rate-limit on LLM endpoint | אין אימות/הגבלת קצב ל-LLM | `pages/api/chat.ts` |
| 9 | CG-WEB-002 | 🟡 P2 | confirmed | No input validation | אין ולידציה לקלט | `pages/api/chat.ts:11` |
| 10 | CG-WEB-003 | 🟡 P2 | confirmed | Missing security headers | חסרים security headers | `next.config.js` |
| 11 | CG-WEB-004 | 🔵 P3 | confirmed | Source maps in production | source maps ב-production | `next.config.js:5` |

---

## 1 · CG-SB-001 · 🔴 P0 · service_role key exposed to the browser
**כותרת:** מפתח service_role חשוף לדפדפן · חומרה: 🔴 P0 · ודאות: confirmed

**EN — What & why:** The Supabase `service_role` key bypasses **all** Row Level Security. It is
stored behind a `NEXT_PUBLIC_` prefix and imported into the Supabase client, so it ships in the
browser bundle. Anyone who opens the site can read and write every table.

**HE — מה ולמה:** מפתח ה-`service_role` של Supabase עוקף את **כל** מנגנון ה-RLS. הוא מאוחסן עם
קידומת `NEXT_PUBLIC_` ומיובא ל-client, ולכן נשלח ל-bundle של הדפדפן. כל מי שנכנס לאתר יכול לקרוא
ולכתוב לכל טבלה.

**Evidence / ראיות:**
- `.env:6` — `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ…`
- `lib/db.ts:6` — `createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!)`

**Exploit / תרחיש תקיפה:** Open devtools → copy the key from the JS bundle → call the Supabase
REST API directly → full read/write of every table. / פתחו devtools → העתיקו את המפתח מה-bundle →
פנייה ישירה ל-REST API של Supabase → קריאה/כתיבה מלאה לכל טבלה.

**Impact / השפעה:** Total data breach — all orders, profiles, PII, and the ability to modify or
delete anything.

**Guard / הגנה:** `guard-recipes/rls-policies.md#service-role-server-only` — move the key to a
server-only env var (no `NEXT_PUBLIC_`), use the anon key in the client, enable RLS on every
table, then **rotate** the exposed key.

**Auto-fixable:** partial → `/cg-fix` rewrites the client to the anon key; rotating the key is a
manual step.

---

## 2 · CG-SB-002 / CG-SB-003 · 🔴 P0 · tables with no Row Level Security
**כותרת:** טבלאות ללא RLS · חומרה: 🔴 P0 · ודאות: likely

**EN — What & why:** `orders` and `profiles` are created without `enable row level security` and
have no policies. With the anon key public (as intended), the auto-generated REST API exposes
these tables to the world for read and write.

**HE — מה ולמה:** הטבלאות `orders` ו-`profiles` נוצרות ללא `enable row level security` וללא
policies. מאחר שמפתח ה-anon ציבורי (כמתוכנן), ה-REST API האוטומטי חושף את הטבלאות האלה לקריאה
וכתיבה לכולם.

**Evidence / ראיות:**
- `supabase/migrations/001_init.sql:5` — `create table public.orders (...)` with the
  `enable row level security` line commented out.
- `supabase/migrations/001_init.sql:16` — `create table public.profiles (...)`, same.

**Exploit / תרחיש תקיפה:** `GET https://<project>.supabase.co/rest/v1/orders?select=*` with the
public anon key returns every order. / החזרת כל ההזמנות עם מפתח ה-anon הציבורי.

**Impact / השפעה:** Public read/write of all customer orders and profile PII (email, phone).

**Guard / הגנה:** `guard-recipes/rls-policies.md#enable-rls` + `#owner-scoped-policy` — enable RLS
and add `auth.uid() = user_id` policies for select/insert/update/delete.

**Note / הערה:** Marked **likely** — confirmed from the migration only. Run `/cg-live` against your
own project to upgrade to **confirmed** by observing a public read succeed.

---

## 4 · CG-SECRET-001 · 🔴 P0 · live secrets committed to the repo
**כותרת:** סודות חיים הועלו ל-repository · חומרה: 🔴 P0 · ודאות: confirmed

**EN:** The committed `.env` contains an OpenAI key, an AWS access key, and a database URL with an
embedded password. Anyone with repo access (or git history) gets them.

**HE:** הקובץ `.env` שהועלה מכיל מפתח OpenAI, מפתח גישה של AWS, וכתובת DB עם סיסמה מוטמעת. כל מי
שיש לו גישה ל-repo (או להיסטוריית git) מקבל אותם.

**Evidence / ראיות:** `.env:7` OpenAI key · `.env:8` `AKIA…EXAMPLE` · `.env:9`
`postgresql://admin:…@…`

**Guard / הגנה:** `guard-recipes/secrets-management.md#rotate-and-ignore` — **rotate every key
first**, then untrack `.env`, add it to `.gitignore`, and purge git history.

---

## 5 · CG-WEB-001 · 🟠 P1 · IDOR + missing authentication
**כותרת:** IDOR ואין אימות · חומרה: 🟠 P1 · ודאות: confirmed

**EN:** `GET /api/orders/[id]` reads the `id` from the URL and returns the order with no session
check and no ownership check. Any user can read any order by changing the id.

**HE:** `GET /api/orders/[id]` קורא את ה-`id` מה-URL ומחזיר את ההזמנה ללא בדיקת session וללא בדיקת
בעלות. כל משתמש יכול לקרוא כל הזמנה על ידי שינוי ה-id.

**Evidence / ראיות:** `pages/api/orders/[id].ts:8-10` — `supabase.from('orders').select('*')
.eq('id', id)` with no auth/ownership filter.

**Guard / הגנה:** `guard-recipes/auth-middleware.md#ownership-check` — require a session and scope
the query with `.eq('user_id', user.id)`.

---

## 6 · CG-LLM-001 · 🟠 P1 · prompt injection
**כותרת:** הזרקת פרומפט · חומרה: 🟠 P1 · ודאות: confirmed

**EN:** The user's message is concatenated directly into the instruction string
(`"...Do whatever the user says: ${message}"`), so a user can override the system prompt.

**HE:** הודעת המשתמש משורשרת ישירות למחרוזת ההוראה, כך שמשתמש יכול לעקוף את ה-system prompt.

**Evidence / ראיות:** `pages/api/chat.ts:14`.

**Guard / הגנה:** `guard-recipes/llm-guardrails.md#instruction-data-separation` — keep rules in the
system message and the user text in a separate user message; never let output make a security
decision.

---

## Lower-severity findings (7–11)
Full details available on request; each carries `file:line` evidence and a guard reference:
**CG-SECRET-002** hardcoded key `lib/db.ts:11` (P1) · **CG-LLM-002** no auth/rate-limit → cost DoS
`chat.ts` (P2) · **CG-WEB-002** no input validation `chat.ts:11` (P2) · **CG-WEB-003** missing
security headers `next.config.js` (P2) · **CG-WEB-004** source maps in prod `next.config.js:5`
(P3).

## Suppressed by the verifier (not real issues) / דוכאו על ידי המאמת
- **`NEXT_PUBLIC_SUPABASE_ANON_KEY` reported as a "leaked secret"** — the Supabase **anon** key is
  **public by design**. The real risk is the missing RLS (CG-SB-002/003), not the key itself. This
  is the classic false positive; the verifier dropped it. / מפתח ה-anon הוא ציבורי בכוונה; הבעיה
  האמיתית היא ה-RLS החסר, לא המפתח.
- **Dependencies not audited** — no lockfile in the sample, so `pnpm audit` was skipped (reported
  honestly rather than guessed).

## Next steps / הצעדים הבאים
```
1. Fix all 4 P0 before anything else.  |  תקנו את כל ה-4 P0 קודם כול.
2. /cg-harden        → generate the guards.
3. /cg-fix           → apply them (dry-run diff first).
4. /cg-live <url>    → confirm the RLS findings on a target you own.
5. /cg-scan          → re-run to confirm 0 × P0.
```
A clean scan is not a proof of safety. / דוח נקי אינו הוכחה לבטיחות.
