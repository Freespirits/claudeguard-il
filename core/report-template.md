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
| Verdict / badge | `verdict`, `critical` `high` `medium` `low` `unknown` `clean`, `verdict_counts`, `do_not_deploy`, `unknown_line`, `unknown_meaning`, `clean_line`, `clean_meaning`, `not_counted`, `not_counted_line` |
| Summary + section headings | `summary`, `confirmed_section`, `not_confirmed_section`, `coverage`, `no_confirmed` |
| Per-finding labels | `title`, `severity`, `confidence` (+ `confirmed`/`likely`/`needs-review`), `evidence_strength` (+ `definitive`/`strong`/`weak`/`judgement`), `found_by` (+ `rule`/`reviewer`), `tier` (+ `static`/`passive-live`/`active-dast`), `what_why`, `evidence`, `exploit`, `impact`, `guard`, `assumption` (+ `assumption_note`), `autofix` (+ `autofix_yes`/`autofix_no`) |
| Not-confirmed section | `not_confirmed_note` |
| Coverage | `coverage_intro`, `subject_set`, `enumerated`, `pass`/`fail`/`undeterminable`/`allowlisted`, `unsettled_heading`, `pass_not_a_token`, `verify_query_intro` |
| Footer | `next_steps`, `next_fix_confirmed`, `next_settle_unconfirmed`, `clean_meaning`, `own_target` |

Placeholders like `{p0}`, `{likely}`, `{n}`, `{total}`, `{set}` in a key are filled at render time.

RTL note: Hebrew blocks are right-to-left; keep each finding's code block in its own fenced
section so mixed-direction text does not scramble.

**The two rules this template exists to enforce:**

1. **Only `confirmed` findings can produce a graded badge.** Severity is uncapped (see
   `severity-model.md`), so an unproven P0 is printed as a P0 — but it is printed *below* the
   confirmed section and it never turns the badge red. The order of sections here is not cosmetic;
   it is the model.
2. **Not red is not green.** When nothing is confirmed but something unproven and catastrophic is
   still open — or the engine could not read enough of the repo — the badge is `unknown` /
   `לא נבדק`, never `clean`. See LAW 4 in `severity-model.md`. Rendering an `unknown` result with a
   green badge or the word "clean" is the one thing this template forbids outright.

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
| `unknown` | ⚪ | UNKNOWN | לא נבדק | nothing confirmed, but an unproven P0/P1 is still open **or** discovery coverage is below its floor |
| `clean` | 🟢 | CLEAN | נקי | nothing confirmed, nothing unproven-and-catastrophic open, coverage above the floor |

**This badge is the *security* pillar only.** Compliance findings (`pillar: "compliance"` — the
accessibility checks) have their own headline and their own section, below, and they **never** move
this badge. A green security badge sitting next to an open accessibility exposure is not a
contradiction — see [the Compliance pillar section](#compliance-pillar) and `severity-model.md#pillars`.

<a id="unknown-badge"></a>
### `unknown` / `לא נבדק` — not proven safe

**Never render `unknown` in green, and never call it clean.** It is not a mild version of `clean`;
it is the absence of a claim. The grader emits it when nothing was confirmed and *either* a P0/P1 it
could not prove is still open, *or* it could not read enough of the repository to say. Both are
states in which a green badge would be a lie, and the reader — a non-expert who cannot audit us —
has no other way to find that out.

Print the reason. `verdict.discoveryCoverage.reasons` says why coverage failed, and
`verdict.unprovenP0` / `unprovenP1` say how many unproven catastrophes are open:

```
Verdict: ⚪ UNKNOWN — Not proven safe. Nothing was confirmed, and 1 unproven P0 and 2 unproven P1
findings are still open. This is NOT a clean result.
פסק דין: ⚪ לא נבדק — לא הוכח שהמערכת בטוחה. לא אומת אף ממצא, ואולם נותרו פתוחים ממצא P0 אחד
ושני ממצאי P1 שלא הצלחנו להוכיח. זו אינה תוצאה נקייה.

Why: coverage or confidence is too low to say. Settle the findings below — each names the one
assumption to check — and re-run.
למה: הכיסוי או רמת הוודאות נמוכים מכדי להכריע. הכריעו את הממצאים שלמטה — לכל אחד מצוינת ההנחה
היחידה שיש לבדוק — והריצו שוב.

Not counted in the verdict: 1 likely · 11 needs-review, three of them P0 — read them below.
לא נספרו בפסק הדין: ממצא סביר אחד · 11 דורשים בדיקה, שלושה מהם P0 — קראו אותם בהמשך.
```

When it is coverage rather than confidence that fell short, say *that*, in both languages, and print
the discovery block immediately after:

```
Verdict: ⚪ UNKNOWN — Not proven safe: we could only read 41 of the 78 files we needed.
פסק דין: ⚪ לא נבדק — לא הוכח שהמערכת בטוחה: הצלחנו לקרוא רק 41 מתוך 78 הקבצים הנדרשים.
```

### `clean` / `נקי`

`clean` means "nothing was proven", not "nothing is wrong" — LAW 4 narrows that gap, it does not
close it. Never render it alone; always with the unconfirmed count and a pointer to Coverage:

```
Verdict: 🟢 CLEAN — No confirmed findings. This is not a proof of safety.
פסק דין: 🟢 נקי — לא אומת אף ממצא. אין בכך הוכחה לבטיחות.

Not counted in the verdict: 1 likely · 4 needs-review, none of them P0 or P1 — read them below.
לא נספרו בפסק הדין: ממצא סביר אחד · 4 דורשים בדיקה, אף אחד מהם אינו P0 או P1 — קראו אותם בהמשך.
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

<a id="compliance-pillar"></a>
## Compliance pillar — accessibility (ת"י 5568 / WCAG 2.0 AA) · a legal exposure, not a breach

**This section is rendered from `summary.compliance` and the `pillar: "compliance"` findings, and it
is kept entirely separate from the security badge above.** A compliance violation is real and
provable, but it is a *lawsuit*, not a *breach* — so it has its own headline, its own findings list,
and its own coverage rows, and it never reddens, greens, or otherwise touches the security verdict.
See `severity-model.md#pillars`. **Omit this whole section only when `summary.compliance.total` is 0
*and* no accessibility surface was discovered** — if a11y checks ran and everything passed, still
print the headline (so a clean compliance result is visible), and always print the declared
rendered-DOM row, because static checks are only half of ת"י 5568.

### The compliance headline (its own badge, next to but never mixed with security)

Drive it from `summary.compliance`: `violations` (confirmed) is the count that carries legal weight;
`needsReview` is the honestly-uncertain rest. State the exposure in the statute's own terms — the ₪
ranges are the point, because they are what makes this legible to a non-lawyer owner.

```
נגישות (ת"י 5568 חלק 1 / WCAG 2.0 AA): {violations} הפרות מאומתות · {needsReview} דורשות בדיקה.
חשיפה משפטית: תביעה אזרחית עד ₪50,000 ללא הוכחת נזק, וצו נגישות של ₪7,500 ליום עד לתיקון.
Accessibility (IS 5568 pt.1 / WCAG 2.0 AA): {violations} confirmed violations · {needsReview} to review.
Legal exposure: civil suit up to ₪50,000 with no proof of harm required, plus a ₪7,500/day order.
```

When `violations` is 0 but static checks ran, say so honestly — it is not a clean bill, because the
rendered-DOM half was not checked:

```
נגישות: לא נמצאו הפרות בבדיקות הסטטיות · אך זו אינה הצהרת התאמה מלאה (ראו למטה).
Accessibility: no violations in the static checks · this is NOT a full conformance statement (see below).
```

### Compliance findings

Same twice-headed (EN then HE) per-finding block as the security findings, with the same fields —
**but the `severity` line reads in legal terms, not attacker terms.** A `confirmed` compliance finding
is a *violation* (הפרה); a `needs-review` one is *to check* (לבדיקה). Sort P1→P4, then confidence,
then `id`. Look each `CG-A11Y-*` id up in `plain-language/findings.md` for the בפשטות / In plain words
line exactly as for security.

| # | ID | Severity | Confidence / ודאות | Title (EN) | כותרת (HE) | File |
|---|----|----------|--------------------|------------|-----------|------|
| 1 | CG-A11Y-001 | 🟠 P1 | confirmed / מאומת | `<img>` has no `alt` | לתמונה אין `alt` | components/Hero.tsx:14 |
| 2 | CG-A11Y-003 | 🟠 P1 | needs-review / דורש בדיקה | Form control has no accessible label | לפקד הטופס אין תווית נגישה | components/Login.tsx:8 |
| 3 | CG-A11Y-006 | 🟡 P2 | confirmed / מאומת | Positive tabIndex breaks focus order | tabIndex חיובי שובר את סדר המוקד | components/Nav.tsx:3 |

**The accessibility statement is NOT in this table — it is a coverage row, not a finding.** Its
absence is reported as an `undeterminable` row in the `a11yStatement` set (a static scan cannot tell a
real deployed site with no statement from a fresh scaffold, so firing a red finding there would be
cry-wolf), and the "you must publish one" message is carried by the mandatory-artifacts reminder
below. When a statement page/link IS detected, that row is a `pass`.

The `severity` line in each block, in legal register:

```
חומרה: 🟠 P1 · חשיפה משפטית אם לא יתוקן · ודאות: מאומת (הפרה)
Severity: 🟠 P1 · legal exposure if unfixed · confidence: confirmed (violation)
```

### The declared rendered-DOM row (grade-or-declare — always printed)

Static analysis can only reach part of ת"י 5568. Print this row in every compliance section, so a
reader never mistakes "passed the static checks" for "accessible":

```
נבדק סטטית: {n} בדיקות (alt, lang, תוויות, מוקד מקלדת, הצהרת נגישות).
לא נבדק — דורש DOM מרונדר ובדיקה ידנית: ניגודיות צבע (1.4.3), סדר וניראות מוקד (2.4.3/2.4.7),
התנהגות ARIA בפועל, והכרזת תוכן דינמי. להתאמה מלאה נדרשת גם בדיקת DOM (מסוג axe-core) ובדיקה
ידנית — וממונה נגישות (רכז נגישות) אם הארגון מעל סף הגודל.
Statically checked: {n} checks (alt, lang, labels, keyboard, accessibility statement).
NOT checked — needs a rendered DOM + manual testing: colour contrast (1.4.3), focus order/visible
(2.4.3/2.4.7), ARIA-in-practice, dynamic-content announcements. Full conformance also needs a
rendered-DOM audit (axe-core-class) and manual testing — and a named accessibility coordinator
(רכז נגישות) if you are over the size threshold.
```

### The two mandatory artifacts (always remind)

Both are legally required in their own right, independent of any single markup finding:

```
מסמכים שהחוק מחייב, גם אם כל השאר תקין:
1. הצהרת נגישות מפורסמת ונגישה (למשל /accessibility או /נגישות).
2. ממונה נגישות (רכז נגישות) בעל שם, אם הארגון מעל סף הגודל.
Legally required regardless of the findings above:
1. A published, reachable accessibility statement (e.g. /accessibility or /נגישות).
2. A named accessibility coordinator, if the organisation is over the size threshold.
```

The compliance subject sets (`a11yImages`, `a11yForms`, …) appear in the **Analysis coverage** table
below like any other set, satisfying LAW 2 — accessibility is graded-or-declared, not sampled.

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

**This section is also where the badge comes from when it says `unknown`.** The grader publishes its
own assessment at `verdict.discoveryCoverage` — `{ adequate, ratio, floor, filesRead, filesIntended,
reasons }`. Print the ratio against the floor whenever the verdict is `unknown`, and print every
reason verbatim. The floor is over the files the engine *set out to read*, not over everything it
found: images and lockfiles are deliberate exclusions and do not count against coverage. See
`severity-model.md` for the exact rule.

```
Discovery coverage: 41 of 78 files we needed (52.6%) — below the 95% floor.
כיסוי גילוי: 41 מתוך 78 הקבצים הנדרשים (52.6%) — מתחת לסף של 95%.
```

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

Print the **decision rate** under the table, from the grader's `decisionRate` block. It is
`(pass + fail) / enumerated` — how much of what we enumerated we actually *decided*, as opposed to
abstained on. A coverage table that adds up perfectly and is almost entirely `undeterminable` is a
complete accounting of nothing, and this one number is what makes that legible at a glance:

```
Decided: 41 of 181 enumerated subjects (22.7%). The rest could not be settled from the source.
הוכרעו: 41 מתוך 181 נושאים שנמנו (22.7%). את השאר לא ניתן היה להכריע מהקוד.
```

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

### The scanner-coverage rows

External scanners (gitleaks, semgrep, npm-audit, Snyk) each add a `scan:<tool>` row to
`coverage.scanCoverage`. **Print each one by name — a scan that did not run is a fact the reader
must see, never an absence.** In particular the four Snyk rows — `scan:snyk-sca`, `scan:snyk-iac`,
`scan:snyk-container`, `scan:snyk-code` — carry the runner's own reason when they are
`undeterminable`. The one that matters most:

```
Snyk Code (deep dataflow analysis) was NOT run, because it uploads your source code to Snyk's
cloud and you did not consent. Everything else ran locally.
בדיקת Snyk Code (ניתוח מעמיק) לא רצה, כי היא מעלה את קוד המקור שלכם לענן של Snyk ולא אישרתם.
כל שאר הבדיקות רצו מקומית.
```

"Skipped for consent" is a different fact from "not installed" or "no token" — render the reason the
row carries, don't collapse them.

## Business-logic model / מודל הלוגיקה העסקית

This section renders `result.businessLogic`. It is the one place a **confident silence is most
dangerous**, because business-logic bugs are the ones a scanner is expected to miss — so an
`assumed` model is never rendered as if it were clean.

**`status: "confirmed"`** — the audit ran against rules the author stated in `businessLogic.intentPath`.
Name the file, and print `rulesChecked / rulesTotal` per resource from `businessLogic.resources`:

```
Business logic: checked against your confirmed claudeguard.intent.yml.
  orders   — 6/10 rules checked   ·   profiles — 4/10 rules checked
לוגיקה עסקית: נבדקה מול claudeguard.intent.yml שאישרתם.
```

**`status: "assumed"`** (no intent file) or **`"error"`** (file unreadable, so it was ignored
entirely) — say so plainly in both languages, then print `businessLogic.proposedIntent` verbatim in
a fenced `yaml` block under a save-correct-commit-re-run instruction, and point at `/cg-intent`:

````
Every ownership rule below was GUESSED from column names, not confirmed by you. A guess that
happens to match the code produces a clean-looking section that means nothing. Run /cg-intent to
turn it into a real review, or save this draft as claudeguard.intent.yml, correct it, and re-scan.
כל כלל בעלות למטה נוחש משמות העמודות, לא אושר על ידכם. הריצו /cg-intent כדי להפוך את זה לסקירה
אמיתית, או שמרו את הטיוטה כ-claudeguard.intent.yml, תקנו, וסרקו מחדש.

```yaml
# ...businessLogic.proposedIntent verbatim...
```
````

Whichever the status, also print the `businessLogic.assumptions` list — every rule that was taken on
trust rather than established. A business-logic section with no coverage line is the same false
all-clear the rest of this tool exists to prevent.

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
An UNKNOWN verdict means we could not prove it safe — coverage or confidence was too low.
פסק דין "לא נבדק" אומר שלא הצלחנו להוכיח שהמערכת בטוחה — הכיסוי או רמת הוודאות היו נמוכים מדי.

New to this? Read plain-language/concepts.he.md — it explains RLS, service_role, secrets and the
rest in plain Hebrew, once, with no jargon.
חדשים בתחום? קראו את plain-language/concepts.he.md — הוא מסביר RLS, service_role, סודות והשאר
בעברית פשוטה, פעם אחת, בלי ז'רגון.

Tiers 1–2 (live / DAST) require you to own the target and confirm authorization.
בדיקות live/DAST דורשות בעלות על היעד ואישור מפורש.
```

### Machine-readable footer: the run record and the gate

Two blocks belong at the very bottom, and both are about reproducibility rather than about safety.

**Run record** (`result.runRecord`) — print it verbatim. It says which tool version, which commit
and which model produced this verdict, so a report pasted into an issue three weeks later can still
be traced to the code that made it. **It attests what was run; it is never a statement that the
repository is secure**, and its own `note` says so. Do not dress it up as a certificate, a seal, or a
pass mark.

```
Run record / רשומת הרצה:
  tool 0.2.0 · commit 41e7c0b · model sha256:5749af6b… · ledgers reconcile: yes
  verdict: unknown · confirmed P0: 0 · confirmed P1: 0 · generated: (caller did not supply a clock)

This records WHAT WAS RUN. It is not a statement that this repository is secure.
זוהי רשומה של מה שהורץ. אין בה קביעה שהמאגר הזה מאובטח.
```

**Gate mode.** For CI or an agent's pre-deploy hook, `node grader.mjs <path> --gate` sets the process
exit code from the verdict — `1` on any confirmed P0/P1, `2` on `unknown` (not proven safe), `0`
otherwise — and writes one summary line to stderr while the full report still goes to stdout. Say so
in the footer when a report was produced in gate mode, and print that line. Because a reviewer
finding can never reach `confirmed` and an unsettled reviewer P0/P1 pushes `clean` to `unknown`,
every path an agent's output can take raises the exit code and none lowers it: **an agent cannot talk
this gate green.** See `severity-model.md`.
