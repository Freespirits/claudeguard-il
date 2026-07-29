# Guard: accessibility (ת"י 5568 חלק 1 ≈ WCAG 2.0 AA)

Copy-pasteable fixes for the accessibility barriers this tool flags, under **ת"י 5568 חלק 1** (the
Israeli adoption of **WCAG 2.0 level AA**), required by **חוק שוויון זכויות לאנשים עם מוגבלות** and the
**2013 accessibility regulations**. These are legal exposures, not breaches: a barrier can draw a civil
suit **up to ₪50,000 with no proof of harm**, plus an accessibility order around **₪7,500/day**, for any
site serving an Israeli audience — even one hosted abroad.

Each section below is a barrier and its fix, in React/JSX and in plain HTML. The last section is a
template for the **הצהרת נגישות** (accessibility statement) the law requires you to publish.

<a id="img-alt"></a>
## Image alt text (CG-A11Y-001 · WCAG 1.1.1)

**Why.** A screen-reader user hears nothing where an image with no `alt` sits — the content is simply
missing for them. Every `<img>` needs *some* `alt`: descriptive text for a content image, or an **empty
`alt=""`** for a purely decorative one (which tells assistive tech to skip it — that is correct, not a bug).

```jsx
// ❌ no alt at all — the barrier
<img src="/team/dana.jpg" />
<Image src={logo} />

// ✅ content image: describe what it conveys, not "image of"
<img src="/team/dana.jpg" alt="דנה כהן, מנהלת הפיתוח" />
<Image src={logo} alt="לוגו האתר" />

// ✅ decorative image: empty alt is VALID and correct — it opts the image out
<img src="/divider.svg" alt="" />
// or opt it out of the accessibility tree entirely:
<img src="/divider.svg" role="presentation" />
<img src="/divider.svg" aria-hidden="true" />
```

```html
<!-- plain HTML -->
<img src="/team/dana.jpg" alt="דנה כהן, מנהלת הפיתוח" />
<img src="/divider.svg" alt="" />
```

**Guidance / הנחיה.** Describe the image's *purpose*. A photo that is a link to a profile is labelled by
where it goes. Text baked into an image (a banner, a price) must be repeated in the `alt`. Do **not** write
"תמונה של…" / "image of…" — the screen reader already announces it as an image. אל תשאירו תמונת תוכן ללא
`alt`; לתמונה דקורטיבית השתמשו ב-`alt=""`.

<a id="html-lang"></a>
## Document language — `lang="he" dir="rtl"` (CG-A11Y-002 · WCAG 3.1.1)

**Why.** Without a `lang` on the document root, a screen reader announces the whole page with the wrong
pronunciation rules — Hebrew read as if it were English. A Hebrew site must also set `dir="rtl"` so the
page lays out right-to-left.

```jsx
// ❌ no lang
<html>

// ✅ Hebrew site
<html lang="he" dir="rtl">
```

Next.js App Router (`app/layout.tsx`):

```jsx
export default function RootLayout({ children }) {
  return (
    <html lang="he" dir="rtl">
      <body>{children}</body>
    </html>
  )
}
```

Next.js Pages Router (`pages/_document.tsx`):

```jsx
import { Html, Head, Main, NextScript } from 'next/document'
export default function Document() {
  return (
    <Html lang="he" dir="rtl">
      <Head />
      <body><Main /><NextScript /></body>
    </Html>
  )
}
```

```html
<!-- plain HTML -->
<!doctype html>
<html lang="he" dir="rtl">
```

**Guidance / הנחיה.** For a mixed or multilingual page, set the root `lang` to the primary language and
mark spans in another language inline (`<span lang="en">…</span>`). If `lang` is computed from a variable,
make sure it resolves to a valid BCP-47 code (`he`, `en`, `ar`) — a dynamic value is why the scan reports
`undeterminable` rather than a pass.

<a id="form-labels"></a>
## Form labels (CG-A11Y-003 · WCAG 1.3.1 / 4.1.2)

**Why.** A screen-reader user who reaches an unlabelled field cannot tell what to type. A **placeholder is
not a label** — it disappears on input and is invisible to many assistive setups. Every control needs a
programmatically associated name.

```jsx
// ❌ placeholder only — not a label
<input type="email" placeholder="אימייל" />

// ✅ best: a real <label> tied to the control by id
<label htmlFor="email">אימייל</label>
<input id="email" type="email" />

// ✅ label wrapping the control (no id needed)
<label>
  אימייל
  <input type="email" />
</label>

// ✅ when there is no visible label, name it explicitly
<input type="search" aria-label="חיפוש באתר" />
```

```html
<!-- plain HTML: htmlFor is written `for` -->
<label for="email">אימייל</label>
<input id="email" type="email" />
```

**Guidance / הנחיה.** Prefer a **visible** `<label>` — it helps everyone, not only screen-reader users. Use
`aria-label` only when a visible label genuinely does not fit (an icon search box). `aria-labelledby="id"`
points at another element's text as the name. Inputs of type `hidden` / `submit` / `button` / `reset` /
`image` do not need a text label. השתמשו ב-`<label>` גלוי המקושר לשדה; placeholder אינו תווית.

<a id="accessible-name"></a>
## Accessible names for icon-only controls (CG-A11Y-004 · WCAG 4.1.2)

**Why.** A button or link whose only content is an icon has no accessible name — a screen-reader user hears
only "button" or "link", with no idea what it does. Give it a name with `aria-label`, or with visually
hidden text, or by giving a nested image a real `alt`.

```jsx
// ❌ icon-only button: no name
<button onClick={close}><XIcon /></button>
<a href="/cart"><CartIcon /></a>

// ✅ aria-label carries the name
<button onClick={close} aria-label="סגירה"><XIcon /></button>
<a href="/cart" aria-label="עגלת קניות"><CartIcon /></a>

// ✅ or visually-hidden text (also gives sighted keyboard users a tooltip target)
<button onClick={close}>
  <XIcon aria-hidden="true" />
  <span className="sr-only">סגירה</span>
</button>

// ✅ or a nested image with a real alt names the control
<button><img src="/icons/trash.svg" alt="מחיקה" /></button>
```

```css
/* the standard "visually hidden but readable by screen readers" utility */
.sr-only {
  position: absolute; width: 1px; height: 1px;
  padding: 0; margin: -1px; overflow: hidden;
  clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
```

**Guidance / הנחיה.** Mark the decorative icon itself `aria-hidden="true"` so its name is not read twice.
If the button's only child is a dynamic `{expression}`, make sure that expression renders visible text or
add an explicit `aria-label` — the scan reports `needs-review` there because it cannot see what the
expression becomes. תנו שם נגיש (`aria-label` או טקסט מוסתר-ויזואלית) לכל כפתור או קישור מבוסס-אייקון.

<a id="captions"></a>
## Video captions (CG-A11Y-005 · WCAG 1.2.2)

**Why.** A deaf or hard-of-hearing user gets nothing from the spoken track of a video with no captions.
Add a `<track kind="captions">` pointing at a WebVTT file.

```jsx
// ❌ no captions track
<video src="/promo.mp4" controls />

// ✅ captions track (WebVTT), marked as the Hebrew captions
<video src="/promo.mp4" controls>
  <track kind="captions" src="/promo.he.vtt" srcLang="he" label="עברית" default />
</video>
```

```html
<!-- plain HTML -->
<video src="/promo.mp4" controls>
  <track kind="captions" src="/promo.he.vtt" srclang="he" label="עברית" default />
</video>
```

```
WEBVTT

00:00:00.000 --> 00:00:03.000
שלום, וברוכים הבאים לאתר שלנו.

00:00:03.000 --> 00:00:06.500
היום נראה לכם איך מתחילים.
```

**Guidance / הנחיה.** `kind="captions"` includes speaker and sound cues (for a deaf viewer); `subtitles`
translate dialogue for someone who can hear. Prefer `captions`. **`<audio>` is different** — it needs a
**text transcript** on the page (WCAG 1.2.1), not a captions track. If a video-player component injects
captions at runtime, the scan cannot see that and reports `likely` — verify a real track is served.
לווידאו הוסיפו רצועת כתוביות (`<track kind="captions">`); לאודיו ספקו תמליל טקסט בעמוד.

<a id="tabindex"></a>
## tabIndex — never positive (CG-A11Y-006 · WCAG 2.4.3)

**Why.** A positive `tabIndex` (`1`, `2`, …) pulls an element ahead of every other in the keyboard tab
order, producing a jumbled sequence where content is reached out of order or skipped. The DOM order should
*be* the tab order.

```jsx
// ❌ positive values force an unnatural order
<input tabIndex={1} />
<button tabIndex={2}>שליחה</button>

// ✅ let the natural DOM order drive focus — remove the attribute
<input />
<button>שליחה</button>

// ✅ tabIndex={0} (focusable, in natural order) and tabIndex={-1}
//    (focusable only via script, out of the tab order) are both fine
<div tabIndex={0} role="button" onClick={…} onKeyDown={…}>…</div>
<div tabIndex={-1} ref={focusMeProgrammatically}>…</div>
```

**Guidance / הנחיה.** If the tab order is wrong, fix the **order of the elements in the markup**, not with
positive `tabIndex`. The only correct values are `0` and `-1`. אל תשתמשו ב-`tabIndex` חיובי; תקנו את סדר
האלמנטים ב-DOM.

<a id="clickable-div"></a>
## Clickable `<div>` → a real control (CG-A11Y-007 · WCAG 2.1.1)

**Why.** A `<div>` or `<span>` with an `onClick` is invisible to the keyboard: it cannot be focused, and
`Enter` / `Space` do nothing. A keyboard-only user cannot use it at all.

```jsx
// ❌ a div pretending to be a button
<div onClick={save}>שמירה</div>

// ✅ BEST: use the real element — you get focus, Enter/Space, and the role for free
<button onClick={save}>שמירה</button>

// ✅ if it truly must stay a div, add all three: role + tabIndex + a key handler
<div
  role="button"
  tabIndex={0}
  onClick={save}
  onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); save() } }}
>
  שמירה
</div>
```

```html
<!-- plain HTML: the native button is the whole fix -->
<button type="button" onclick="save()">שמירה</button>
```

**Guidance / הנחיה.** Reach for the native element first — `<button>` for an action, `<a href>` for
navigation. They are keyboard-operable, focusable and announced with the right role, with no extra code.
The `role` + `tabIndex={0}` + key-handler trio is the fallback only when you cannot change the tag.
העדיפו `<button>` או `<a>` אמיתיים; אם חייבים `div`, הוסיפו את שלושתם: `role`, `tabIndex`, ומטפל מקלדת.

<a id="statement"></a>
## הצהרת נגישות — accessibility statement template (mandatory)

**Why.** The law requires you to **publish an accessibility statement** (הצהרת נגישות), reachable at a
stable path such as **`/accessibility` or `/נגישות`** and linked from the footer of every page. Its absence
is a legal gap; the scan cannot fire on it (a fresh scaffold looks identical to a real site with none), so
it *reminds* you here. The statement must state **what is accessible, the standard applied (ת"י 5568),
a contact for the רכז נגישות (accessibility coordinator), and the date** it was written/updated.

Publish something like this (adapt the bracketed parts) at `/נגישות`:

```text
הצהרת נגישות

[שם העסק / האתר] רואה חשיבות רבה בהנגשת שירותיו לכלל הציבור, לרבות אנשים עם מוגבלות.
אנו פועלים כדי לאפשר לכל אדם לגלוש באתר באופן עצמאי, נוח ובטוח.

רמת הנגישות
אתר זה הונגש בהתאם לתקן הישראלי ת"י 5568 ברמת AA, המבוסס על הנחיות WCAG 2.0 של ארגון W3C,
ובהתאם לתקנות שוויון זכויות לאנשים עם מוגבלות (התאמות נגישות לשירות), התשע"ג-2013.

מה נגיש באתר
- ניווט מלא באמצעות מקלדת.
- תאימות לתוכנות הקראת מסך.
- טקסט חלופי לתמונות, תוויות לשדות טפסים, וכתוביות לסרטונים.
- מבנה כותרות ושפת מסמך (עברית) מוגדרים כראוי.

הסתייגויות
ייתכן שחלקים מסוימים באתר טרם הונגשו במלואם. אנו פועלים לתקנם. אם נתקלתם בבעיית נגישות,
נשמח שתעדכנו אותנו ונטפל בכך בהקדם.

רכז הנגישות
שם: [שם רכז/ת הנגישות]
דוא"ל: [כתובת אימייל]
טלפון: [מספר טלפון]

תאריך עדכון ההצהרה: [DD/MM/YYYY]
```

Wire it up so the scan (and your users) can find it:

```jsx
// a route at /נגישות (or /accessibility), linked from the site footer on every page
<footer>
  <a href="/נגישות">הצהרת נגישות</a>
</footer>
```

**Guidance / הנחיה.** Name a **real רכז נגישות** with a working contact channel — required over the size
threshold, and the statement is where you publish who they are. Keep the **date** current whenever you
change the site. An accessibility **widget/toolbar** is not a substitute: it signals intent, but the law
wants real conformance plus this published statement. פרסמו הצהרת נגישות בכתובת קבועה (למשל `/נגישות`),
קשרו אליה מהפוטר, וכתבו בה מה נגיש, את התקן ת"י 5568, פרטי רכז נגישות ותאריך.
