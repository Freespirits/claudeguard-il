# 🛡️ ClaudeGuardIL — Security Report / דוח אבטחה

```
Target: sample-vulnerable-app          Tier: static (Tier 0)
Scanned: 7 code files · 16 findings     Engine: hybrid (fallback-regex secrets / claude-native)

Community project — NOT an official Anthropic product.
פרויקט קהילתי — אינו מוצר רשמי של Anthropic.
```

> A real ClaudeGuardIL **v2** report against the bundled `sample-vulnerable-app/`, produced by
> `project_model.mjs → grader.mjs` (with the secret scanner). It shows the v2 shape: a verdict that
> counts **only confirmed** findings, a quieter section for what could not be proven, and a coverage
> ledger that makes what we *couldn't* settle as visible as what we could.

## Verdict / פסק דין

```
🔴 CRITICAL — 7 confirmed P0, 0 confirmed P1. Do not go public until the P0 issues are fixed.
🔴 קריטי — 7 ממצאי P0 מאומתים, 0 ממצאי P1 מאומתים. אין לעלות לאוויר עד לתיקון בעיות ה-P0.

Not counted in the verdict: 0 likely · 7 needs-review — read them below.
לא נספרו בפסק הדין: 0 ממצאים סבירים · 7 דורשים בדיקה — קראו אותם בהמשך.
```

The verdict is built from `confirmed` findings and nothing else. Severity is uncapped, so a P0 we
could not prove is still printed as a P0 — but below, in the quieter section, where it does not turn
the badge red.

## Summary — confirmed findings only / סיכום — ממצאים מאומתים בלבד

Only `confirmed` rows are here; this table is what the badge is made of.

| # | ID | Severity | Title (EN) | כותרת (HE) | File |
|---|----|----------|------------|-----------|------|
| 1 | CG-DB-001 | 🔴 P0 | Table `orders` has RLS disabled | לטבלה `orders` אין הגנת RLS | `supabase/migrations/001_init.sql:5` |
| 2 | CG-DB-001 | 🔴 P0 | Table `profiles` has RLS disabled | לטבלה `profiles` אין הגנת RLS | `supabase/migrations/001_init.sql:15` |
| 3 | CG-ENV-001 | 🔴 P0 | `service_role` key compiled into the browser bundle | מפתח `service_role` נכלל בבנדל של הדפדפן | `.env:6` |
| 4 | CG-SEC-001 | 🔴 P0 | `openai-key` committed in `.env` | מפתח openai הועלה ל-`.env` | `.env:7` |
| 5 | CG-SEC-001 | 🔴 P0 | `aws-access-key` committed in `.env` | מפתח aws הועלה ל-`.env` | `.env:8` |
| 6 | CG-SEC-001 | 🔴 P0 | `db-url-with-password` committed in `.env` | מחרוזת חיבור עם סיסמה ב-`.env` | `.env:9` |
| 7 | CG-SEC-001 | 🔴 P0 | `openai-key` committed in source | מפתח openai בקוד המקור | `lib/db.ts:11` |
| 8 | CG-WEB-010 | 🟡 P2 | No security headers in `next.config` | לא הוגדרו כותרות אבטחה ב-`next.config` | `next.config.js` |
| 9 | CG-WEB-022 | 🔵 P3 | Production source maps are published | מפות מקור מתפרסמות בייצור | `next.config.js:4` |

---

### 3 · CG-ENV-001 · 🔴 P0 · service_role key compiled into the browser bundle
**כותרת:** מפתח `service_role` נכלל בבנדל של הדפדפן · חומרה: 🔴 P0 · ודאות: מאומת
Evidence: definitive · found by: rule · tier: static
ראיה: חד-משמעית · נמצא על ידי: כלל · שכבה: static

**בפשטות:** המפתח הכי חזק של מסד הנתונים שלך — כזה שנותן שליטה מלאה — נשלח לדפדפן של כל מי שנכנס
לאתר. כל אחד יכול ללחוץ F12, למצוא אותו, ולקרוא או למחוק את כל המידע, כולל של המשתמשים שלך. זו לא
"אולי" בעיה — זו דלת פתוחה לרווחה. מה עושים: מחליפים את המפתח עכשיו (הישן כבר נחשף), ומעבירים אותו
לצד השרת שבו רק הקוד שלך רואה אותו.
**In plain words:** The most powerful key to your database is being sent to every visitor's browser.
Anyone can press F12, find it, and read or delete all your data. Rotate it now (the old one is
already burned) and move it to the server side.

**EN — What & why:** `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` carries a `NEXT_PUBLIC_` prefix, which
the bundler substitutes into client output verbatim. The `service_role` key bypasses every Row
Level Security policy, and it now ships in the browser bundle for anyone to read.

**HE — מה ולמה:** המשתנה `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` נושא את הקידומת `NEXT_PUBLIC_`,
שה-bundler מטמיע את ערכה כפי שהיא בפלט צד-הלקוח. מפתח ה-`service_role` עוקף כל מדיניות RLS, וכעת
הוא נשלח ל-bundle של הדפדפן וגלוי לכל.

**Evidence / ראיות:**
- `.env:6` — `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ…`

**Exploit / תרחיש תקיפה:** Open DevTools → read the key from the JS bundle → query any table via the
REST API → full read/write. / פתחו DevTools → קראו את המפתח מה-bundle → שאילתה לכל טבלה דרך ה-REST
API → קריאה/כתיבה מלאה.

**Impact / השפעה:** Total data breach — every record, and the ability to modify all of it.

**Guard / הגנה:** `guard-recipes/secrets-management.md#public-prefixes`. Move the key to a
server-only variable; use the anon key in the client and rely on RLS.

**Auto-fixable:** yes → `/cg-fix CG-ENV-001` (dry-run diff first). / כן (בכפוף להרצת dry-run).

---

### 4–7 · CG-SEC-001 · 🔴 P0 · Live credentials committed to the repo
**כותרת:** נמצאו סודות חיים שהועלו ל-git · חומרה: 🔴 P0 · ודאות: מאומת
Evidence: definitive · found by: rule · tier: static
ראיה: חד-משמעית · נמצא על ידי: כלל · שכבה: static

**בפשטות:** ייתכן שסוד (מפתח, סיסמה או אסימון גישה) נשמר בטעות בתוך קוד המקור שהעליתם ל-git. כל מי
שיש לו גישה למאגר — או להיסטוריה שלו — יכול להעתיק את הערך ולהשתמש בו. חשוב לזכור: גם אם תמחקו את
השורה עכשיו, הערך נשאר בהיסטוריה של git ונחשב "שרוף". מה עושים: אם זה סוד שנותן גישה אמיתית —
החליפו אותו מיד; אם זה מזהה ציבורי שנועד להיחשף, סמנו אותו ברשימת ההיתרים כדי שלא יופיע שוב.
**In plain words:** A secret (a key, password, or access token) may have been accidentally saved in
source code you pushed to git. Anyone with access to the repo or its history can copy and use it.
Even if you delete the line now, the value stays in history and must be treated as burned — rotate
it if it grants real access; allowlist it if it is a public identifier.

**EN — What & why:** Four privileged credentials are committed as real values — an OpenAI key, an
AWS access key, and a Postgres URL with an embedded password in `.env`, plus a second OpenAI key
hardcoded in `lib/db.ts`. A committed secret is compromised even if the line is later deleted,
because it lives on in git history.

**HE — מה ולמה:** ארבעה מפתחות מורשים הועלו כערכים אמיתיים — מפתח OpenAI, מפתח גישה של AWS, ומחרוזת
חיבור ל-Postgres עם סיסמה מוטמעת בקובץ `.env`, ובנוסף מפתח OpenAI שני מקודד בתוך `lib/db.ts`. סוד
שהועלה ל-git נחשב חשוף גם אם השורה נמחקת מאוחר יותר, מפני שהוא נשמר בהיסטוריית ה-git.

**Evidence / ראיות:**
- `.env:7` — `openai-key` (`sk-…`)
- `.env:8` — `aws-access-key` (`AKIA…`)
- `.env:9` — `db-url-with-password` (`postgres://…:…@…`)
- `lib/db.ts:11` — `openai-key` (`sk-…`)

**Exploit / תרחיש תקיפה:** Anyone who reads the repository or its history copies each value and uses
it directly. / כל מי שקורא את המאגר או ההיסטוריה שלו מעתיק כל ערך ומשתמש בו ישירות.

**Impact / השפעה:** Billing fraud on the API keys, full account access on the AWS key, and direct
database access via the connection string.

**Guard / הגנה:** `guard-recipes/secrets-management.md#public-prefixes`. **Rotate all four now** —
deletion is not enough — then move them to server-only variables and add `.env` to `.gitignore`.

**Assumption / הנחה:** That the keys are still active. Rotate regardless — a value in git history is
already compromised. / שהמפתחות עדיין פעילים. החליפו אותם בכל מקרה — ערך בהיסטוריית git כבר נחשף.

**Auto-fixable:** no — rotation is a human step. / לא — החלפת מפתח היא פעולה אנושית.

_(Findings 1–2, CG-DB-001, and 8–9 follow the same block format; omitted here for length.)_

---

## Not confirmed — worth reading, but they did not set the verdict / לא אומתו — כדאי לקרוא, אך אינם קובעים את פסק הדין

Severity here is the impact **if** the finding is real — it is not discounted for our uncertainty,
so a P0 in this list is a P0 we could not prove. Each names the assumption that would make it a
false positive; checking it usually takes seconds.

החומרה כאן היא ההשפעה בהנחה שהממצא אמיתי — היא אינה מופחתת בשל אי-הוודאות שלנו. לכל ממצא מצוינת
ההנחה שהייתה הופכת אותו להתרעת שווא; בדרך כלל אפשר לבדוק אותה בשניות.

| # | ID | Severity | Confidence / ודאות | Title (EN) | כותרת (HE) | File |
|---|----|----------|--------------------|------------|-----------|------|
| 10 | CG-WEB-001 | 🟠 P1 | needs-review / דורש בדיקה | Route `/api/chat` has no visible authentication | לנתיב `/api/chat` אין אימות גלוי | `pages/api/chat.ts` |
| 11 | CG-WEB-001 | 🟠 P1 | needs-review / דורש בדיקה | Route `/api/orders/[id]` has no visible authentication | לנתיב `/api/orders/[id]` אין אימות גלוי | `pages/api/orders/[id].ts` |
| 12 | CG-LLM-002 | 🟡 P2 | needs-review / דורש בדיקה | LLM call site has no rate limit | לנקודת הקריאה למודל אין הגבלת קצב | `pages/api/chat.ts` |
| 13 | CG-WEB-002 | 🟡 P2 | needs-review / דורש בדיקה | Route `/api/chat` does not validate its body | הנתיב `/api/chat` אינו מאמת את גוף הבקשה | `pages/api/chat.ts` |
| 14 | CG-SEC-001 | 🟡 P2 | needs-review / דורש בדיקה | Possible `jwt` committed in `.env` | ייתכן `jwt` שהועלה ל-`.env` | `.env:4` |
| 15 | CG-SEC-001 | 🟡 P2 | needs-review / דורש בדיקה | Possible `jwt` in `.env` (the service-role value) | ייתכן `jwt` ב-`.env` (ערך ה-service-role) | `.env:6` |
| 16 | CG-SEC-001 | 🟡 P2 | needs-review / דורש בדיקה | Possible `public-prefixed-secret` in `.env` | ייתכן סוד עם קידומת ציבורית ב-`.env` | `.env:6` |

Example block (note the **Assumption** line, which a confirmed block may omit):

### 10 · CG-WEB-001 · 🟠 P1 · Route `/api/orders/[id]` has no visible authentication
**כותרת:** לנתיב `/api/orders/[id]` אין אימות גלוי · חומרה: 🟠 P1 · ודאות: דורש בדיקה
Evidence: weak · found by: rule · tier: static
ראיה: חלשה · נמצא על ידי: כלל · שכבה: static

**בפשטות:** לנקודת הקצה (endpoint — כתובת שהשרת שלך חושף) הזו לא נמצא אימות גלוי, כלומר לא ראינו קוד
שבודק שהמשתמש מחובר. ייתכן שהבדיקה קיימת בקובץ אחר שהקוד הזה משתמש בו, ולכן כדאי לבדוק. אם באמת אין
אימות, כל אחד באינטרנט יכול לקרוא לנקודה הזו בלי להתחבר. ודאו שיש כאן בדיקת התחברות לפני שהפעולה
מתבצעת.
**In plain words:** This endpoint has no visible auth — we saw no code checking the user is logged
in. The check may live in another file this code imports, so it is worth verifying. If there really
is none, anyone on the internet can call it without logging in. Make sure a login check runs first.

**EN — What & why:** Neither the handler nor a middleware matcher covering this path contains any
recognisable authentication call.

**HE — מה ולמה:** לא ב-handler ולא ב-matcher של ה-middleware המכסה את הנתיב נמצאת קריאת אימות מזוהה.

**Assumption / הנחה:** A false positive if authentication happens inside a helper this handler
imports — a path this pass does not follow. Open the file and check. / התרעת שווא אם האימות מתבצע
בתוך פונקציית עזר שה-handler מייבא — מסלול שאינו נעקב כאן. פתחו את הקובץ ובדקו.

**Guard / הגנה:** `guard-recipes/auth-middleware.md`.

**Auto-fixable:** no — confirm it first. / לא — יש לאמת תחילה.

> **Note on findings 15–16.** Line `.env:6` is the `service_role` key, already reported as a
> **confirmed P0** (finding 3). The secret scanner independently flags the same line because the
> key's value is a JWT and it sits behind a public prefix. Those two rows are corroboration, not new
> problems — fixing finding 3 clears them.

---

## Coverage / כיסוי

This is what we examined, and what we could not settle from the source alone. A findings list looks
the same whether we examined everything and found little or examined almost nothing — this section
is what tells the two apart.

זהו מה שנבדק, ומה שלא ניתן היה להכריע מהקוד בלבד.

| Subject set / קבוצה | Enumerated | ✅ Pass | ❌ Fail | ❓ Undeterminable | ⚪ Allowlisted |
|---------------------|-----------|--------|--------|------------------|---------------|
| routes | 2 | 0 | 2 | 0 | 0 |
| tables | 2 | 0 | 2 | 0 | 0 |
| envVars | 6 | 3 | 1 | 0 | 2 |
| llmSites | 1 | 0 | 0 | 1 | 0 |
| supabaseClients | 1 | 0 | 0 | 1 | 0 |
| nextConfigKeys | 2 | 0 | 2 | 0 | 0 |
| secrets | 7 | 0 | 7 | 0 | 0 |
| scanCoverage | 2 | 1 | 0 | 1 | 0 |

Every set adds up: `pass + fail + undeterminable + allowlisted = enumerated`. The grader asserts
this at runtime; printing it is how you can see it.

**Could not be settled from the source / לא ניתן היה להכריע מהקוד:**
- `llm:pages/api/chat.ts` — a server-side LLM call site; whether it is gated and bounded is not
  verified from source.
- `supabase-client:lib/db.ts:6` — a `createClient()` call whose key this pass could not identify.
- `scan:secrets` — a **fallback regex** scan ran; **git history was not read**, so a secret removed
  from the working tree but alive in a past commit would be missed. Install `gitleaks` for full
  coverage.

A subject is never marked ✅ just because a token like `getUser` appears: a call without `await`, a
result nobody checked, and a throw swallowed by `try/catch` all look identical from here. So these
rows say "unknown", not "fine" — and they are the reviewer's work list.

נושא אינו מסומן ✅ רק משום שמופיע אזכור כמו `getUser`: קריאה ללא `await`, תוצאה שאיש לא בדק, וחריגה
שנבלעה ב-`try/catch` — כולן נראות זהות מכאן. לכן השורות האלה אומרות "לא ידוע", ולא "תקין".

The schema was readable here (migrations exist), so no `verifyQuery` is needed. When it is not,
this section prints the exact SQL to run in the Supabase SQL editor to settle every RLS row.

---

## Next steps / הצעדים הבאים

```
1. Fix every confirmed P0 first.  |  תקנו קודם כול כל P0 מאומת.
2. Settle the "not confirmed" list — each finding names the assumption to check.
   הכריעו את רשימת "לא אומתו" — לכל ממצא מצוינת ההנחה שיש לבדוק.
3. Run /cg-harden to generate guards, or /cg-fix to apply them (dry-run, confirmed only).
4. Re-run /cg-scan to confirm.

A clean verdict means nothing was proven — not that nothing is wrong. Read the Coverage section.
פסק דין נקי אומר שדבר לא הוכח — לא שאין בעיות. קראו את מקטע הכיסוי.

Tiers 1–2 (live / DAST) require you to own the target and confirm authorization.
בדיקות live/DAST דורשות בעלות על היעד ואישור מפורש.
```
