# Report template (bilingual HE / EN)

How ClaudeGuardIL presents an audit. Render Hebrew and English for prose; keep code, file paths,
identifiers, and guard snippets in English only. String labels come from `i18n/he.md` and
`i18n/en.md` — do not hardcode translations here.

RTL note: Hebrew blocks are right-to-left; keep each finding's code block in its own fenced
section so mixed-direction text does not scramble.

---

## Header (every report)

```
🛡️  ClaudeGuardIL — Security Report / דוח אבטחה
Target: <repo name or path>        Tier: static | passive-live | active-dast
Scanned: <n> files · <n> findings  Engine: hybrid (<tools used> / claude-native)

Community project — NOT an official Anthropic product.
פרויקט קהילתי — אינו מוצר רשמי של Anthropic.
```

## Risk verdict (one line, both languages)

```
Verdict: 🔴 CRITICAL — 2 × P0, 3 × P1. Do not go public until P0s are fixed.
פסק דין: 🔴 קריטי — 2 × P0, 3 × P1. אין לעלות לאוויר עד לתיקון ה-P0.
```

Verdict colour: 🔴 if any P0/P1, 🟠 if any P2, 🟢 if only P3/P4.

## Summary table

| # | ID | Severity | Confidence | Title (EN) | כותרת (HE) | File |
|---|----|----------|-----------|------------|-----------|------|
| 1 | CG-SB-001 | P0 | confirmed | service_role key in client | מפתח service_role בצד לקוח | lib/db.ts:3 |

## Per-finding block

Render each finding twice-headed (EN then HE) but share one evidence/guard block:

```markdown
### 1 · CG-SB-001 · 🔴 P0 · service_role key exposed to the browser
**כותרת:** מפתח service_role חשוף לדפדפן · חומרה: 🔴 P0 · ודאות: confirmed

**EN — What & why:** The Supabase `service_role` key bypasses all Row Level Security. It is
imported into client code, so it ships in the browser bundle. Anyone can read/write every table.

**HE — מה ולמה:** מפתח ה-`service_role` של Supabase עוקף את כל מנגנון ה-RLS. הוא מיובא לקוד
צד-לקוח ולכן נשלח ל-bundle בדפדפן. כל אחד יכול לקרוא ולכתוב לכל הטבלאות.

**Evidence / ראיות:**
- `lib/db.ts:3` — `createClient(url, process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY)`

**Exploit / תרחיש תקיפה:** Open devtools → copy the key from the bundle → query any table via
the REST API → full DB read/write. / פתחו devtools → העתיקו את המפתח → שאילתה לכל טבלה דרך
ה-REST API → קריאה/כתיבה מלאה.

**Impact / השפעה:** Total data breach: all user records, PII, and the ability to modify data.

**Guard / הגנה:** See `guard-recipes/rls-policies.md#service-role-server-only`. Move the key to a
server-only env var, use the anon key in the client, and enable RLS on every table.

**Auto-fixable:** yes → `/cg-fix CG-SB-001` (dry-run diff first).
```

## Footer

```
Next steps / הצעדים הבאים:
1. Fix all P0 before deploying.  |  תקנו כל P0 לפני פריסה.
2. Run /cg-harden to generate guards, or /cg-fix to apply them (dry-run).
3. Re-run /cg-scan to confirm.

Tiers 1–2 (live / DAST) require you to own the target and confirm authorization.
בדיקות live/DAST דורשות בעלות על היעד ואישור מפורש.
```
