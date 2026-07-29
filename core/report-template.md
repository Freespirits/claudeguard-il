# Report template (bilingual HE / EN)

How ClaudeGuardIL presents an audit. Render Hebrew and English for prose; keep code, file paths,
identifiers, and guard snippets in English only.

**Labels are i18n keys — `i18n/en.md` and `i18n/he.md` are the single source of truth.** The
worked examples below are shown *fully rendered in both languages* so you can match the structure
and tone of a real report. But every recurring **label** in them — the badge words, the bold field
names, the section headings, the coverage disposition names, and the footer boilerplate — is an
i18n key of the same concept. Resolve the actual text from the i18n files at render time. **If an
example here ever disagrees with i18n, i18n wins** — the examples are illustration, not the string
table. Per-finding prose (titles, what-and-why, exploit/impact) is not a label; it comes from the
grader and the reviewer at render time.

Label → key map (pull the EN/HE text for each from the i18n files):

| Where | Keys |
|-------|------|
| Header | `report_title`, `not_official` |
| Verdict / badge | `verdict`, `critical` `high` `medium` `low` `clean`, `verdict_counts`, `do_not_deploy`, `clean_line`, `clean_meaning`, `not_counted`, `not_counted_line` |
| Summary + section headings | `summary`, `confirmed_section`, `not_confirmed_section`, `coverage`, `no_confirmed` |
| Per-finding labels | `title`, `severity`, `confidence` (+ `confirmed`/`likely`/`needs-review`), `evidence_strength` (+ `definitive`/`strong`/`weak`/`judgement`), `found_by` (+ `rule`/`reviewer`), `tier` (+ `static`/`passive-live`/`active-dast`), `what_why`, `evidence`, `exploit`, `impact`, `guard`, `assumption` (+ `assumption_note`), `autofix` (+ `autofix_yes`/`autofix_no`) |
| Not-confirmed section | `not_confirmed_note` |
| Coverage | `coverage_intro`, `subject_set`, `enumerated`, `pass`/`fail`/`undeterminable`/`allowlisted`, `unsettled_heading`, `pass_not_a_token`, `verify_query_intro` |
| Footer | `next_steps`, `next_fix_confirmed`, `next_settle_unconfirmed`, `clean_meaning`, `own_target` |

Placeholders like `{p0}`, `{likely}`, `{n}`, `{total}`, `{set}` in a key are filled at render time.

RTL note: Hebrew blocks are right-to-left; keep each finding's code block in its own fenced
section so mixed-direction text does not scramble.

**The one rule this template exists to enforce:** the headline verdict and the badge count only
`confirmed` findings. Severity is uncapped (see `severity-model.md`), so an unproven P0 is printed
as a P0 — but it is printed *below* the confirmed section and it never turns the badge red. The
order of sections here is not cosmetic; it is the model.

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

The verdict is computed from `confirmed` findings and nothing else. The second pair of lines shows
what was deliberately **not** counted, so a quiet verdict can never be misread as a clean bill of
health.

```
Verdict: 🔴 CRITICAL — 2 confirmed P0, 3 confirmed P1. Do not go public until the P0 issues are fixed.
פסק דין: 🔴 קריטי — 2 ממצאי P0 מאומתים, 3 ממצאי P1 מאומתים. אין לעלות לאוויר עד לתיקון בעיות ה-P0.

Not counted in the verdict: 4 likely · 9 needs-review — read them below.
לא נספרו בפסק הדין: 4 ממצאים סבירים · 9 דורשים בדיקה — קראו אותם בהמשך.
```

Badge, taken straight from the grader's `verdict.level`:

| `verdict.level` | Badge | EN | HE | Emitted when |
|-----------------|-------|----|----|--------------|
| `critical` | 🔴 | CRITICAL | קריטי | any **confirmed** P0 |
| `high` | 🟠 | HIGH | גבוה | any confirmed P1, no confirmed P0 |
| `medium` | 🟡 | MEDIUM | בינוני | any confirmed P2, nothing above |
| `low` | 🔵 | LOW | נמוך | at least one confirmed finding, all P3/P4 |
| `clean` | 🟢 | CLEAN | נקי | **no confirmed findings at all** |

`clean` means "nothing was proven", not "nothing is wrong". Never render it alone — always with the
unconfirmed count and a pointer to Coverage:

```
Verdict: 🟢 CLEAN — No confirmed findings. This is not a proof of safety.
פסק דין: 🟢 נקי — לא אומת אף ממצא. אין בכך הוכחה לבטיחות.

Not counted in the verdict: 1 likely · 11 needs-review, three of them P0 — read them below.
לא נספרו בפסק הדין: ממצא סביר אחד · 11 דורשים בדיקה, שלושה מהם P0 — קראו אותם בהמשך.
Coverage: 8 of 12 routes could not be settled from the source.
כיסוי: לא ניתן היה להכריע מהקוד 8 מתוך 12 נתיבים.
```

## Summary table — confirmed findings only

Only `confirmed` rows belong here; this table is what the badge is made of. Sort by severity
(P0→P4), then `id`.

| # | ID | Severity | Title (EN) | כותרת (HE) | File |
|---|----|----------|------------|-----------|------|
| 1 | CG-SB-001 | 🔴 P0 | service_role key in client | מפתח service_role בצד לקוח | lib/db.ts:3 |

If there are none, say so in both languages rather than leaving an empty table:

```
No confirmed findings. / אין ממצאים מאומתים.
```

## Per-finding block (confirmed findings)

Render each finding twice-headed (EN then HE) but share one evidence/guard block. Print the
`at` locations verbatim — they exist so the user can check our work in their own editor.

**Every finding opens with a plain-words line, before the technical prose.** This audience is
non-expert, so the first thing they read must be jargon-free. Look the finding's `id` up in
`plain-language/findings.md` and print its `HE` and `EN` text as the `בפשטות / In plain words`
line. If an id has no entry there, fall back to a one-sentence plain paraphrase — never leave it
out. The concepts behind the findings are taught once in `plain-language/concepts.he.md`; link the
reader there in the footer.

```markdown
### 1 · CG-SB-001 · 🔴 P0 · service_role key exposed to the browser
**כותרת:** מפתח service_role חשוף לדפדפן · חומרה: 🔴 P0 · ודאות: מאומת
Evidence: definitive · found by: rule · tier: static
ראיה: חד-משמעית · נמצא על ידי: כלל · שכבה: static

**בפשטות:** המפתח הכי חזק של מסד הנתונים שלכם נשלח לדפדפן של כל מי שנכנס לאתר. כל אחד יכול למצוא
אותו ולמחוק את כל המידע. החליפו אותו עכשיו והעבירו אותו לצד השרת.
**In plain words:** The most powerful key to your database is being sent to every visitor's
browser. Anyone can find it and delete all your data. Rotate it now and move it to the server.

**EN — What & why:** The Supabase `service_role` key bypasses all Row Level Security. It sits
behind a `NEXT_PUBLIC_` prefix, which the bundler substitutes into client output verbatim, so it
ships in the browser bundle. Anyone can read and write every table.

**HE — מה ולמה:** מפתח ה-`service_role` של Supabase עוקף את כל מנגנון ה-RLS. הוא מוגדר עם קידומת
`NEXT_PUBLIC_`, שה-bundler מטמיע את ערכה כפי שהיא בפלט צד-הלקוח, ולכן הוא נשלח ל-bundle בדפדפן.
כל אחד יכול לקרוא ולכתוב לכל הטבלאות.

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

---

## Not confirmed — worth reading, but they did not set the verdict / לא אומתו — כדאי לקרוא, אך אינם קובעים את פסק הדין

Everything with confidence `likely` or `needs-review` goes here, **below** the confirmed section,
in the same order (severity → confidence → id). Quieter, not hidden: same fields, same evidence,
no badge.

Open the section with this note, in both languages:

```
Severity here is the impact IF the finding is real — it is not discounted for our uncertainty, so
a P0 in this list is a P0 we could not prove. Each one names the assumption that would make it a
false positive; checking that assumption usually takes seconds.
החומרה כאן היא ההשפעה בהנחה שהממצא אמיתי — היא אינה מופחתת בשל אי-הוודאות שלנו, ולכן ממצא P0
ברשימה הזו הוא P0 שלא הצלחנו להוכיח. לכל ממצא מצוינת ההנחה שהייתה הופכת אותו להתרעת שווא; בדרך
כלל אפשר לבדוק אותה בשניות.
```

| # | ID | Severity | Confidence / ודאות | Title (EN) | כותרת (HE) | File |
|---|----|----------|--------------------|------------|-----------|------|
| 6 | CG-DB-COVERAGE | 🔴 P0 | needs-review / דורש בדיקה | RLS state could not be determined for 5 tables | לא ניתן לקבוע את מצב ה-RLS עבור 5 טבלאות | — |
| 7 | CG-WEB-001 | 🟠 P1 | needs-review / דורש בדיקה | Route /api/orders has no visible authentication | לנתיב /api/orders אין אימות גלוי | app/api/orders/route.ts |

Each block here carries one line that a confirmed block may omit — the assumption:

```markdown
### 7 · CG-WEB-001 · 🟠 P1 · Route /api/orders has no visible authentication
**כותרת:** לנתיב /api/orders אין אימות גלוי · חומרה: 🟠 P1 · ודאות: דורש בדיקה
Evidence: weak · found by: rule · tier: static
ראיה: חלשה · נמצא על ידי: כלל · שכבה: static

**EN — What & why:** Neither the handler nor a middleware matcher covering this path contains any
recognisable authentication.

**HE — מה ולמה:** לא ב-handler ולא ב-matcher של ה-middleware שמכסה את הנתיב הזה נמצא אימות מזוהה.

**Assumption / הנחה:** This is a false positive if authentication happens inside a helper this
handler imports — a path this pass does not follow. Open the file and check.
זו התרעת שווא אם האימות מתבצע בתוך פונקציית עזר שה-handler מייבא — מסלול שהמעבר הזה אינו עוקב
אחריו. פתחו את הקובץ ובדקו.

**Guard / הגנה:** `guard-recipes/auth-middleware.md`.

**Auto-fixable:** no — confirm it first. / לא — יש לאמת תחילה.
```

Never offer `/cg-fix` on a finding in this section. Only `confirmed` findings are auto-fixable.

---

## Discovery coverage / כיסוי גילוי

**A report has two coverage axes, and they answer different questions.** *Discovery* coverage (this
section) asks **what did the engine manage to see?** — how many files it parsed, how many it
skipped and why, and which subjects it could only partially model. *Analysis* coverage (the next
section) asks **of what it saw, what did it grade?** Accounting for every subject you enumerated
means nothing if the engine silently never opened half the repo — so discovery is printed first,
from the grader's `discovery` block.

```
Files discovered:            170     קבצים שנמצאו
  parsed (code):              26       נותחו
  unsupported (not code):    144       לא נתמכים
  oversized / read errors:     0       גדולים מדי / שגיאת קריאה
Directories not entered:       4  (build/vendor and dotfile dirs — listed with reasons)
Routes found on disk:          2 · fully modeled: 0 · methods unread: 2
Routes from framework calls:   3  (Express/Fastify/Hono/Koa/Nest) · framework gaps: 0
Unresolved imports:            0 · dynamic table refs: 0
Schema sources: migrations   → RLS state IS verifiable from the repo
```

List every `notableSkip` (a file we wanted to parse but could not) and every route with unread
methods, each with its reason — this is the honest short list of what the engine could not fully
model. If `discovery.reconciles` is false, say so loudly: the ledger did not add up, and the counts
cannot be trusted until it does.

Call-declared routes (`discovery.routes.fromFrameworkCalls`) are found by reading
`app.get(...)`-style calls, not by listing files, so there is no filesystem count to check them
against. That is what `discovery.routes.frameworkGaps` exists for: a server framework in
`package.json` with **zero** routes enumerated is a coverage hole, not a fact. Print each gap with
its reason — the grader also files it as an `undeterminable` row under `ungradedSurfaces`, so it
cannot fall out of the analysis table.

The single most consequential line for a Supabase app is `schema.rlsVerifiable`. When it is false,
there are no migrations in the repo, so **every RLS pass or fail is really "unknown"** — print the
`verifyQuery` and treat the RLS rows accordingly.

---

## Analysis coverage / כיסוי ניתוח

**Coverage is what stops a quiet report from being mistaken for a safe one.** A findings list looks
identical whether we examined everything and found little, or examined almost nothing. This section
is the only thing that tells the two apart. Print it in every report — especially a clean one.

Say that in the report itself:

```
This is what we examined, and what we could not settle from the source alone.
זהו מה שנבדק, ומה שלא ניתן היה להכריע מהקוד בלבד.
```

One row per subject set. The four counts must add up to `enumerated` — the grader enforces it, and
printing them is how the user can see it:

| Subject set / קבוצה | Enumerated | ✅ Pass | ❌ Fail | ❓ Undeterminable | ⚪ Allowlisted |
|---------------------|-----------|--------|--------|------------------|---------------|
| routes | 12 | 0 | 3 | 8 | 1 |
| tables | 5 | 2 | 1 | 2 | 0 |
| envVars | 14 | 9 | 1 | 0 | 4 |
| supabaseClients | 3 | 2 | 1 | 0 | 0 |
| ciWorkflows | 2 | 1 | 1 | 0 | 0 |
| ungradedSurfaces | 1 | 0 | 0 | 1 | 0 |

`ungradedSurfaces` is the grade-or-declare net (`methodology/grade-or-declare.md`): artifact
classes the engine discovered and no rule grades — an Electron main file, a Kubernetes manifest, a
framework whose routes could not be enumerated. Its rows are `undeterminable` by construction;
render them like every other undeterminable row — seen, not settled, with the reason — never trim
them as noise.

Then list every `undeterminable` row with its reason. These are not filler — **this is the
reviewer's work list**, the short honest list of what a human still has to open:

```
Could not be settled from the source / לא ניתן היה להכריע מהקוד:
- `route:app/api/orders/route.ts` — an authentication call is present, but whether it gates the
  handler is not verified.
- `table:profiles` — discovered from generated types; no migration proves its RLS state.
- `dynamic-table:lib/crud.ts:22` — `.from(name)` is computed at runtime, so the tables it reaches
  cannot be enumerated.

A subject is never marked ✅ just because a token like `getUser` appears in the file: a call without
await, a result nobody checked, and a throw swallowed by try/catch all look identical from here. So
these rows say "unknown", not "fine".
נושא אינו מסומן ✅ רק משום שמופיע בקובץ אזכור כמו `getUser`: קריאה ללא await, תוצאה שאיש לא בדק,
וחריגה שנבלעה ב-try/catch — כולן נראות זהות מנקודת המבט הזו. לכן השורות האלה אומרות "לא ידוע", ולא
"תקין".
```

When the database schema could not be read, print `verifyQuery` verbatim with the instruction in
both languages. It answers in ten seconds the question the repo cannot:

````
Run this in the Supabase SQL editor and paste the result back — it settles every RLS row above.
הריצו את השאילתה הזו ב-SQL editor של Supabase והדביקו את התוצאה — היא מכריעה כל שורת RLS שלמעלה.

```sql
select c.relname,
       c.relrowsecurity as rls_enabled,
       (select count(*) from pg_policy p where p.polrelid = c.oid) as policies
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r'
order by 1;
```
````

Also print whatever the engine reported in `limits`, plus the tier's own blind spots: a static scan
cannot see runtime configuration, and a passive scan cannot see what only attack traffic reveals.

---

## Footer

```
Next steps / הצעדים הבאים:
1. Fix every confirmed P0 first.  |  תקנו קודם כול כל P0 מאומת.
2. Settle the "not confirmed" list — each finding names the assumption to check.
   הכריעו את רשימת "לא אומתו" — לכל ממצא מצוינת ההנחה שיש לבדוק.
3. Run /cg-harden to generate guards, or /cg-fix to apply them (dry-run, confirmed only).
4. Re-run /cg-scan to confirm.

A clean verdict means nothing was proven — not that nothing is wrong. Read the Coverage section.
פסק דין נקי אומר שדבר לא הוכח — לא שאין בעיות. קראו את מקטע הכיסוי.

New to this? Read plain-language/concepts.he.md — it explains RLS, service_role, secrets and the
rest in plain Hebrew, once, with no jargon.
חדשים בתחום? קראו את plain-language/concepts.he.md — הוא מסביר RLS, service_role, סודות והשאר
בעברית פשוטה, פעם אחת, בלי ז'רגון.

Tiers 1–2 (live / DAST) require you to own the target and confirm authorization.
בדיקות live/DAST דורשות בעלות על היעד ואישור מפורש.
```
