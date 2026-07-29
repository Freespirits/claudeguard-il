# Accessibility checks — ת"י 5568 חלק 1 ≈ WCAG 2.0 AA, under חוק שוויון זכויות לאנשים עם מוגבלות + תקנות הנגישות (התאמות נגישות לשירות), התשע"ג-2013

Israeli law requires the websites of businesses that serve the public to conform to **ת"י 5568 חלק 1**
— the Israeli standard that adopts **WCAG 2.0 level AA** — under **חוק שוויון זכויות לאנשים עם מוגבלות,
התשנ"ח-1998** and the **תקנות שוויון זכויות לאנשים עם מוגבלות (התאמות נגישות לשירות), התשע"ג-2013**. The
teeth are unusual and worth stating plainly, because they change the risk calculus for a vibecoded app:

- A civil suit for an accessibility barrier needs **no proof of harm** — a plaintiff who never tried to
  buy anything can be awarded **statutory damages up to ₪50,000 per suit** (סעיף 19נג) just for the
  barrier existing. There is an organised plaintiff bar that files these.
- The accessibility commissioner (נציבות שוויון) can issue an **accessibility order** carrying a penalty
  on the order of **₪7,500 per day** until the barrier is fixed.
- It applies to **any site serving an Israeli audience — even one hosted abroad**. "We're on Vercel in
  the US" is not a defence.

No security scanner checks any of this, and the owner this tool serves has almost certainly never heard
of ת"י 5568. This is a **compliance domain**, the sibling of privacy/data-security
([`privacy-data-security.md`](privacy-data-security.md)), and it uses the exact `pillar: "compliance"`
mechanism defined in [`../severity-model.md#pillars`](../severity-model.md#pillars):

- An accessibility gap is a **legal exposure**, not a breach. It is a *plaintiff*, not an *attacker*.
  Severity is stated as **legal exposure if unfixed** — the statute, the ₪ range — never "an attacker
  gets X".
- Every finding here carries `pillar: "compliance"`, lands in the `summary.compliance` block, and
  **never reddens, greens, or otherwise touches the security badge**. A green security badge next to an
  open accessibility lawsuit is not a contradiction; it is the honest picture.
- **No compliance P0** (the pillar rule). A missing `alt` is serious and expensive, but it is not the
  drop-everything-before-anyone-sees-the-URL emergency that a live data breach is. Inflating it to P0
  would be the cry-wolf failure in a new costume.
- Confidence is derived from evidence exactly as for security (a pure function of `evidence.strength`),
  and **LAW 1-3 bind these rules the same way**: a token in the source is never a `pass`, a name is
  never a P0, and every enumerated subject satisfies LAW 2 arithmetic.

Contents: [What a static pass can and cannot see](#pillar) · [Graded static checks](#graded) ·
[Declared rows (grade-or-declare)](#declared) · [The two mandatory artifacts](#artifacts) ·
[Web-only gate](#web-gate) · [Coverage subject sets](#coverage) · [Severity register](#severity) ·
[Cry-wolf discipline](#cry-wolf) · [The report line](#report-line) · [How to verify](#verify)

<a id="pillar"></a>
## What a static pass can and cannot see — grade-or-declare, drawn where the source signal ends

Accessibility is the mirror image of the privacy regulation. Privacy is mostly *process and paperwork*,
so almost all of it is declared; **a large slice of WCAG is structural markup**, so most of what this
domain reports it can actually **grade**. A missing `alt`, a missing `lang`, a positive `tabIndex` are
sitting in the JSX/HTML as definitive facts — no rendered DOM required. So `../methodology/grade-or-declare.md`
here splits cleanly:

- **Graded (static):** the seven checks below. Each reads a structural property of an element and either
  raises a finding or records a coverage disposition. The engine (`lib/a11y_scan.mjs`) has already
  encoded every false-positive trap **as data** — an empty `alt=""` still carries the `alt` token, a
  `{...spread}` sets a flag that forces an abstention, a dynamic `lang={expr}` is marked dynamic — so the
  grader only turns that data into findings and dispositions. It never guesses.
- **Declared (needs a rendered DOM or a human):** colour contrast (1.4.3), focus order and
  focus-visible (2.4.3 / 2.4.7), ARIA-in-practice, and dynamic-content announcements. These cannot be
  read from source without running the page, so they are named in **one honest `undeterminable` row** —
  never silently dropped, never guessed at.
- **Declared (organisational):** the published **הצהרת נגישות** (accessibility statement) and the named
  **רכז נגישות** (accessibility coordinator). Their absence is *legally* a problem, but a static scan
  cannot prove absence — see [§ declared](#declared) and [§ artifacts](#artifacts).

The line is drawn exactly where the source signal ends. Silence is the one output forbidden: a report
that omits contrast entirely reads, to a non-expert, identically to a report on a perfectly-contrasted
site.

<a id="graded"></a>
## Graded static checks — the seven a scan can verify

Each check names its `CG-A11Y-*` id, the WCAG success criterion, the heuristic, the false-positive trap
that must **not** fire, the severity in legal register, and the guard. Findings are `pillar: "compliance"`.
Confidence follows evidence: `definitive → confirmed`, `strong → likely`, `weak → needs-review`.

<a id="img-alt"></a>
### CG-A11Y-001 · image with no `alt` · WCAG 1.1.1 · P1 · definitive → confirmed

**Heuristic.** An `<img>` / `<Image>` with **no `alt` attribute at all**. The scheme is right there in
the markup, so evidence is `definitive` and this reaches a **confirmed violation** — the single most
litigated accessibility barrier there is.

**False-positive traps — must NOT fire on:**
- **An empty `alt=""`.** This is *valid* for a decorative image, and the element still carries the `alt`
  token → **pass**. Firing here would be the classic cry-wolf: telling someone their correct decorative
  markup is illegal.
- **`role="presentation"` / `role="none"` / `aria-hidden`.** The author has explicitly opted the image
  out of the accessibility tree → **allowlisted** (decorative), no finding.
- **A `{...spread}`.** A spread may supply `alt` from a variable this pass cannot read → **undeterminable**,
  abstain (LAW 1: we cannot see it, so we do not assert it).

**Severity: P1** — a content image with no text alternative is the spine of the known lawsuit template; a
plaintiff screenshots it in seconds. Legal register: statutory damages up to ₪50,000 with no proof of
harm, plus a ₪7,500/day accessibility order. **Autofixable.** Guard: [`guard-recipes/accessibility.md#img-alt`](../guard-recipes/accessibility.md#img-alt).

<a id="html-lang"></a>
### CG-A11Y-002 · document root with no `lang` · WCAG 3.1.1 · P2 · definitive → confirmed

**Heuristic.** The document root `<html>` / `<Html>` (Next's `next/document`) with **no `lang`
attribute**. Definitive from source → **confirmed**.

**False-positive traps — must NOT fire on:**
- **A dynamic `lang={expr}`.** The value is set from an expression this pass cannot resolve to a code →
  **undeterminable** (verify it yields a valid BCP-47 tag), not a fail.
- **A `{...spread}`** on the root → **undeterminable**.

**Severity: P2** — the whole page is announced with the wrong pronunciation rules; a real barrier that
needs a screen-reader user to bite, so it sits below the P1 content barriers. Note: a Hebrew site expects
**`lang="he" dir="rtl"`** — the guard shows it. **Autofixable.** Guard:
[`#html-lang`](../guard-recipes/accessibility.md#html-lang).

<a id="form-labels"></a>
### CG-A11Y-003 · form control with no accessible label · WCAG 1.3.1 / 4.1.2 · P1 · weak → needs-review

**Heuristic.** An `<input>` / `<select>` / `<textarea>` with **no way to derive an accessible name**. This
is `weak` — a `<label htmlFor>` in another part of the tree could name it, and this static pass does not
resolve that association — so it is `needs-review`, **declared with its assumption written down, never
asserted as confirmed**. Impact-if-true is still P1; the uncertainty lives in confidence, not severity.

**False-positive traps — must NOT fire on:**
- **Input types `hidden` / `submit` / `button` / `reset` / `image`.** These get their name from a value
  or elsewhere, not from a text label → **pass**.
- **`aria-label` / `aria-labelledby` / `title` present** → **pass** (it has an accessible name).
- **An `id` present** → **undeterminable**: a `<label htmlFor="thatId">` may target it, which the static
  pass does not follow. Abstain, do not fail.
- **A dynamic input type**, or a **`{...spread}`** → **undeterminable**.
- **A `placeholder` is NOT a label.** Do not credit it as one — it vanishes on input and is invisible to
  many assistive setups.

**Severity: P1** — an unlabelled field is a field a screen-reader user cannot fill; a core barrier a
plaintiff can demonstrate. Legal register as CG-A11Y-001. Guard:
[`#form-labels`](../guard-recipes/accessibility.md#form-labels).

<a id="accessible-name"></a>
### CG-A11Y-004 · icon-only control with no accessible name · WCAG 4.1.2 · P1 · strong → likely / weak → needs-review

**Heuristic.** An icon-only `<button>` / `<a>` with **nothing that gives it an accessible name**. A name
counts if the element has: a **static text child**, an **`aria-label` / `aria-labelledby` / `title`**, a
**nested `<img>` with `alt`**, or **nested aria**. Two confidence tiers, deliberately:
- **Clear icon-only** (no text, no aria, no nested named image — nothing) → evidence `strong` → **likely**.
- **Only child is a dynamic `{expression}`** → evidence `weak` → **needs-review**: that expression *might*
  render visible text, so the barrier is not proven — the assumption is written down.

**False-positive traps — must NOT fire on:**
- **A `{...spread}`, or children this pass could not read** → **undeterminable**, abstain.
- **A `{child expression}`** does not become a confirmed finding — at most `needs-review`, because it may
  render a name.

**Severity: P1** — an interactive control a screen-reader user hears only as "button" with no purpose; a
common, provable barrier. Guard: [`#accessible-name`](../guard-recipes/accessibility.md#accessible-name).

<a id="captions"></a>
### CG-A11Y-005 · `<video>` with no captions track · WCAG 1.2.2 · P2 · strong → likely

**Heuristic.** A `<video>` element with **no `<track kind="captions">`** (or `subtitles`) child. Evidence
`strong` → **likely**, with the assumption stated (a player component may inject captions at runtime,
which this pass does not follow).

**False-positive traps — must NOT fire on:**
- **`<audio>` is NOT flagged here.** Audio needs a *transcript* (WCAG 1.2.1), which lives off-page and is
  not gradable from markup → **declared undeterminable**, not a video-captions finding.
- **A dynamic `kind={expr}`** on the track → **undeterminable** (cannot confirm it is captions).
- **A `{...spread}`, or unreadable children** → **undeterminable**.

**Severity: P2** — a deaf or hard-of-hearing user loses the spoken content; a partial failure that bites a
particular user, so it sits below the P1 barriers. Captions are **mandatory for public bodies and larger
businesses** under ת"י 5568. Guard: [`#captions`](../guard-recipes/accessibility.md#captions).

<a id="tabindex"></a>
### CG-A11Y-006 · positive `tabIndex` · WCAG 2.4.3 · P2 · definitive → confirmed

**Heuristic.** A **positive `tabIndex` (`> 0`)** on **any element**. This is cross-cutting — it is checked
on every enumerated element, not just one kind — because a positive tab index yanks that element ahead of
the natural DOM order for every keyboard user. Definitive from source → **confirmed**.

**False-positive traps — must NOT fire on:**
- **`tabIndex={-1}`** (programmatically focusable, out of the tab sequence — fine) and **`tabIndex={0}`**
  (natural order — fine). Only a value strictly greater than 0 is a barrier.

**Severity: P2** — a documented, screenshot-able focus-order barrier; needs a keyboard/screen-reader user
to bite. Guard: [`#tabindex`](../guard-recipes/accessibility.md#tabindex).

<a id="clickable-div"></a>
### CG-A11Y-007 · clickable `<div>`/`<span>` not keyboard-operable · WCAG 2.1.1 · P2 · weak → needs-review

**Heuristic.** A `<div>` / `<span>` with an **`onClick`** that is **missing `role` and/or `tabIndex`
and/or a key handler** (`onKeyDown` / `onKeyPress` / `onKeyUp`). A non-interactive element wired as a
control has no keyboard path. Evidence `weak` → **needs-review** (the action may also be available through
a real control nearby — the assumption is stated).

**False-positive traps — must NOT fire on:**
- **All three present** (`role` + `tabIndex` + a key handler) → **pass**. The element has been made
  operable, so it is not flagged.
- **A `{...spread}`** may add any of the three → **undeterminable**, abstain.

**Severity: P2** — a keyboard-only user cannot focus or activate the control at all; a real barrier that
needs that user to bite. Guard: [`#clickable-div`](../guard-recipes/accessibility.md#clickable-div).

<a id="declared"></a>
## Declared rows — grade-or-declare, never a red finding from absence

Two things are legal duties this scan **cannot fire on**, because firing would be crying wolf. Each is a
`grade-or-declare` coverage row, not a finding.

### The accessibility statement — a DECLARED coverage row, not a fireable finding

A published **הצהרת נגישות** is legally mandatory. But its **absence is not a red finding**:

- A page or link at **`/accessibility` or `/נגישות`** (in the source or a route) is a `pass`.
- Its absence is **`undeterminable`** — *"we cannot confirm from static source that you publish one; it is
  legally mandatory, verify it"* — **never a red P1**.

Why declare rather than fire? Because a static scan **cannot tell a real deployed site with no statement
from a fresh `create-next-app` scaffold that simply has not written one yet**. Firing a red P1 on scaffold
output is exactly the cry-wolf failure this tool forbids — a false positive is worse than a miss for this
audience. The **"you must publish one"** message is carried by the report's mandatory-artifacts reminder
([§ artifacts](#artifacts)), not by a fabricated violation. If an accessibility **widget** is detected,
the row notes it *may* provide a statement — a signal of intent, still `undeterminable`, because a widget
is not a conformant statement.

> Contrast with privacy: there the *missing document* is declared too. Accessibility differs only in that
> the statement's **location is statically checkable** (a `/accessibility` route either exists in the
> source or does not) — so presence earns a real `pass`; absence still only earns `undeterminable`.

### The rendered-DOM audit — DECLARED undeterminable

Colour contrast (1.4.3), focus order and focus-visible (2.4.3 / 2.4.7), ARIA-in-practice, and
dynamic-content announcements need a **rendered DOM and manual testing**. They are not gradable statically
and are declared in a single honest `a11yRenderedDom` row — together with the reminder that a **named
רכז נגישות (accessibility coordinator)** is required over the size threshold. "Passed the static checks"
must never be read as "accessible"; this row is what keeps that honest.

<a id="artifacts"></a>
## The two mandatory artifacts

Independent of the seven graded checks, ת"י 5568 / the 2013 regulations require two artifacts a codebase
usually cannot prove exist. The report **reminds**, it does not fabricate a violation:

1. **הצהרת נגישות — a published accessibility statement.** What is accessible, the standard applied
   (ת"י 5568), a contact route for the רכז נגישות, and the date. A copy-pasteable template lives at
   [`guard-recipes/accessibility.md#statement`](../guard-recipes/accessibility.md#statement).
2. **רכז נגישות — a named accessibility coordinator**, mandatory for a business over the size threshold.
   A person and a contact channel, named in the statement.

Both are `undeterminable` in coverage (the statement can reach `pass` when a page/link is found; the
coordinator is organisational and off-code). Neither is ever asserted as a violation from absence.

<a id="web-gate"></a>
## Web-only gate

The statement and rendered-DOM rows apply **only to a web surface** (Next / Vue / Svelte / Vite, or any
project that actually emitted a11y elements). A **React Native / Capacitor shell or a pure backend has no
website to make accessible**, so asking it for a הצהרת נגישות would be a false positive — those two sets
stay `enumerated: 0`. The seven element-level checks still run wherever a11y elements are found.

<a id="coverage"></a>
## Coverage subject sets

Every graded element and every declared duty lands in exactly one of these enumerable sets, and each
satisfies LAW 2 (`enumerated === pass + fail + undeterminable + allowlisted`):

| Set | What it enumerates | Fed by |
|-----|--------------------|--------|
| `a11yImages` | `<img>` / `<Image>` elements | CG-A11Y-001 |
| `a11yFormControls` | `<input>` / `<select>` / `<textarea>` | CG-A11Y-003 |
| `a11yInteractive` | icon-capable `<button>` / `<a>` | CG-A11Y-004 |
| `a11yMedia` | `<video>` / `<audio>` | CG-A11Y-005 |
| `a11yClickable` | `<div>` / `<span>` with `onClick` | CG-A11Y-007 |
| `a11yDocument` | the document root `<html>` | CG-A11Y-002 |
| `a11yStatement` | the published הצהרת נגישות (web-only) | declared |
| `a11yRenderedDom` | the rendered-DOM / manual-test audit (web-only) | declared |

`CG-A11Y-006` (positive `tabIndex`) is cross-cutting: it is raised against whichever set the offending
element already belongs to, not a set of its own.

<a id="severity"></a>
## Severity register — the accessibility compliance pillar

Same P-labels as everywhere (one scale keeps ordering and rendering uniform), but the axis is **legal
exposure if unfixed**, stated in the statute's own terms — the ₪50,000 no-proof-of-harm civil suit, the
₪7,500/day accessibility order. **No P0** (pillar rule).

| Level | Accessibility legal-exposure meaning | This domain's examples |
|-------|--------------------------------------|------------------------|
| **P1** | A core, provable barrier a plaintiff screenshots in seconds — the spine of the known lawsuit template. Exposure: a civil suit **up to ₪50,000 with no proof of harm**, plus a ₪7,500/day order. | `CG-A11Y-001` (image, no alt), `CG-A11Y-003` (form control, no label), `CG-A11Y-004` (icon-only control, no name). |
| **P2** | A real barrier that needs a particular user or assistive tech to bite, or a partial failure. Exposure: the same statute, reached once that user hits it. | `CG-A11Y-002` (no `lang`), `CG-A11Y-005` (no captions), `CG-A11Y-006` (positive `tabIndex`), `CG-A11Y-007` (clickable `<div>`). |
| **P3** | Hygiene / robustness — correct-but-fragile. | A `lang` set from a variable we could not resolve; an accessibility widget present (not a substitute for conformance). |
| **P4** | Informational — not itself a violation. | An accessibility toolbar detected: it signals intent; its *absence* is not a finding, because the law wants real conformance, not a widget. |
| ~~P0~~ | **Deliberately unused.** An accessibility barrier draws a suit and an order — it is not the live-breach emergency P0 marks. | — |

The statement and rendered-DOM rows carry **no severity**: they are `undeterminable` coverage rows, not
findings. Confidence per check is a pure function of evidence — `CG-A11Y-001/002/006` are `definitive →
confirmed` violations; `CG-A11Y-004/005` are `strong → likely`; `CG-A11Y-003/007` and the dynamic-child
`CG-A11Y-004` are `weak → needs-review`, declared with the assumption written down.

<a id="cry-wolf"></a>
## Cry-wolf discipline (restated, because it is the whole point)

For this non-expert audience a **false positive is worse than a miss** — telling an owner their correct
decorative image "breaks the accessibility law" costs them a day of panic and then their trust, and the
real barrier three lines down never gets read. See `../methodology/false-positives.md`. Concretely:

- **An empty `alt=""` is valid** for a decorative image and must `pass`. Never flag it.
- **A `{...spread}` abstains** everywhere — it could supply alt, a label, a name, a track, `lang`,
  role/tabIndex — so the disposition is `undeterminable`, never a fail (LAW 1).
- **Dynamic values abstain** — a `lang={expr}`, a `kind={expr}`, a dynamic input type, an icon whose only
  child is a `{expression}` are all `undeterminable` or at most `needs-review`, never `confirmed`.
- **The statement's absence is `undeterminable`, never a red finding** — a scaffold and a real site look
  identical to a static pass.
- **A name is never a P0** (there is no compliance P0 anyway); **every subject set adds up** (LAW 2); **a
  token is never a `pass`** (LAW 1).

When a signal is ambiguous, ask "what would make this a real barrier, and can I see that from here?" — if
no, it is `undeterminable` with a WCAG reference and an instruction, never a finding tuned to look
impressive.

<a id="report-line"></a>
## The report line (HE + EN)

Rendered in the `summary.compliance` block, kept entirely separate from the security badge (see
`../report-template.md#compliance-pillar`). State the confirmed-violation count, the count of
`needs-review` barriers, and the declared rows; state exposure in the statute's terms, **with the ₪
figures** (unlike privacy, this statute's teeth are a fixed statutory-damages number).

When violations exist:

```
נגישות (ת"י 5568 חלק 1 ≈ WCAG 2.0 AA, לפי חוק שוויון זכויות ותקנות הנגישות התשע"ג-2013): {v} הפרות מאומתות ·
{r} חסמים לבדיקה · הצהרת נגישות: <pass/לא אושרה> · ביקורת DOM מרונדר ורכז נגישות: להצהרה. חשיפה משפטית:
תביעה אזרחית עד ₪50,000 ללא הוכחת נזק, בתוספת צו נגישות של כ-₪7,500 ליום — חל על כל אתר הפונה לקהל
ישראלי, גם אם הוא מאוחסן בחו"ל.
Accessibility (ת"י 5568 part 1 ≈ WCAG 2.0 AA, under the Equal Rights Law + the 2013 accessibility
regulations): {v} confirmed violations · {r} barriers to review · accessibility statement: <pass/unconfirmed> ·
rendered-DOM audit and coordinator: declared. Legal exposure: a civil suit of up to ₪50,000 with no proof
of harm, plus an accessibility order around ₪7,500/day — applies to any site serving an Israeli audience,
even one hosted abroad.
```

When the static slice is clean — honest, because it is only a slice:

```
נגישות: לא נמצאו הפרות בבדיקות הסטטיות (alt לתמונות, lang למסמך, תוויות לטפסים, שמות נגישים, כתוביות,
tabIndex, אלמנטים לחיצים) · אך זו אינה הצהרת התאמה: ניגודיות צבע, סדר וניראות פוקוס, ARIA בפועל, הכרזות
תוכן דינמי — כולם דורשים DOM מרונדר ובדיקה ידנית, והצהרת נגישות ורכז נגישות הם חובות ארגוניים שאינם נראים
בקוד. יש לאשרם.
Accessibility: no violations in the static checks (image alt, document lang, form labels, accessible
names, captions, tabIndex, clickable elements) · but this is NOT a conformance statement: colour
contrast, focus order/visibility, ARIA-in-practice, and dynamic-content announcements all need a rendered
DOM and manual testing, and a published statement and a named coordinator are organisational duties
invisible to a code scan. Confirm them.
```

<a id="verify"></a>
## How to verify (kept honest)

- **The graded checks** reach `confirmed` only on a `definitive` static fact — a missing `alt`, a missing
  `lang`, a positive `tabIndex`. The label, icon-name, captions and clickable-`div` checks stay `likely`
  or `needs-review`; a live pass (`/cg-live`) that observes the rendered accessibility tree is what
  upgrades them.
- **The statement** is settled by the owner confirming a published הצהרת נגישות exists at `/נגישות` (or
  the tool finding the page/link in source). The tool never claims it is missing.
- **The rendered-DOM half** (contrast, focus, ARIA-in-practice) and the **רכז נגישות** are settled by a
  rendered-DOM audit and by the owner — the report hands over the list, tied to each WCAG criterion, and
  never claims to have checked them. That is the honest edge of what a source scan can say about ת"י 5568.
