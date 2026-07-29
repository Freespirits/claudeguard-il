# Privacy / data-security checks — תקנות הגנת הפרטיות (אבטחת מידע), התשע"ז-2017

The **Israeli Privacy Protection (Data Security) Regulations 2017** — made under **חוק הגנת הפרטיות**
(the Privacy Protection Law) — bind **any business that holds a database of personal data about
Israelis**: customers, users, patients, employees. A vibecoded app with a `users`, `profiles`,
`orders` or `patients` table is such a database, and its owner carries these obligations whether or
not they have ever heard of the regulation. No security scanner checks them, and the owner this tool
serves has almost certainly never read them.

This is the **second compliance domain**, alongside accessibility (`ת"י 5568`). It uses the exact
`pillar: "compliance"` mechanism defined in [`../severity-model.md#pillars`](../severity-model.md#pillars):

- A privacy-regulation gap is a **legal exposure**, not a breach. It is a *regulator*, not an
  *attacker*. Severity is stated as **legal exposure if unfixed** — the regulation, the תקנה, the
  Authority's powers — never "an attacker gets X".
- Every finding here carries `pillar: "compliance"`, lands in the `summary.compliance` block, and
  **never reddens, greens, or otherwise touches the security badge**. A green security badge next to
  an open privacy-compliance gap is not a contradiction; it is the honest picture.
- **No compliance P0** (the pillar rule). A data-security-regulation gap is serious and can draw an
  enforcement order, but it is not the drop-everything-before-anyone-sees-the-URL emergency that a
  live breach is. Inflating it to P0 would be the cry-wolf failure in a new costume.
- Confidence is derived from evidence exactly as for security (a pure function of `evidence.strength`),
  and **LAW 1–3 bind these rules the same way**: a token in the source is never a `pass`, a name is
  never a P0, and every enumerated subject satisfies LAW 2 arithmetic.

Contents: [The pillar](#pillar) · [Security-level classifier (declared)](#classifier) ·
[Graded static checks](#graded) · [Declared obligations (grade-or-declare)](#declared) ·
[Severity register](#severity) · [Cry-wolf discipline](#cry-wolf) · [The report line](#report-line) ·
[How to verify](#verify)

<a id="pillar"></a>
## Why almost all of this regulation is *declared*, not graded

The regulation is overwhelmingly about **process, people and paperwork** — a written security policy,
a roles list, staff vetting, a 24-month audit, breach-notification procedures, a periodic risk
survey. **None of that is visible in source code.** A source-and-config scan can verify only a thin
slice: a handful of transport- and session-security controls that happen to leave a static signal.

So this domain is **grade-or-declare taken to its limit** (`../methodology/grade-or-declare.md`). The
checkable slice is graded with the cry-wolf discipline the rest of the tool uses. **Everything else is
declared** — named, tied to its תקנה, given a one-line "what to confirm", and filed as an
`undeterminable` coverage row. Silence is the one output forbidden: a report that simply omits תקנה 10
(audit logging) reads, to a non-expert, identically to a report on an app that logs perfectly. The
declared rows are the owner's compliance work-list, not noise.

One sharp consequence, and it is deliberate: the regulation's mandatory **documents** — the database
definition document (תקנה 2), the security policy (תקנה 4) — are legally required, and their *absence*
is itself a violation. But they are organisational artifacts that **do not appear in a repository**, so
this tool can never prove the absence. Unlike the accessibility statement (a missing `/accessibility`
route is statically checkable and graded P1), these are **declared `undeterminable`, never asserted as
violations**. Claiming "you have no security policy" from a codebase would be exactly the false
positive this tool exists to avoid.

<a id="classifier"></a>
## The security-level classifier — declared, never inferred

The regulation scales every obligation to the database's **security level** (רמת אבטחה). The level
decides which תקנות apply, so it is the first thing the report must establish — and it is **declared**,
because the two facts that set it (how many people are records, how many people are users) are **not
knowable from source**.

| Level | HE | How a database lands here |
|-------|----|---------------------------|
| **Basic** | בסיסית | The default. Any database not meeting the medium/high criteria — e.g. a single operator, or fewer than 10 authorised users. |
| **Medium** | בינונית | Per **תוספת ראשונה**: holds **sensitive data** (medical, biometric, financial, communication metadata, political/religious beliefs, criminal history, genetic, personal behavioural data), **or** data collected for **commercial transmission** (direct mail), **or** it is a **public-sector** database. Exception back to Basic: only employee/supplier data used for business administration, or fewer than 10 authorised users. |
| **High** | גבוהה | Per **תוספת שנייה**: a **medium-level** database that also has **≥ 100,000 data subjects (records)** **or** **> 100 authorised users**. |

**CG cannot read record counts or authorised-user counts from a repository.** It can sometimes *see*
that sensitive-looking columns exist (`national_id`/`ת"ז`, `health_*`, `diagnosis`, `iban`,
`card_*`, `biometric_*`), which is a hint toward Medium — but a hint is not a classification, and the
back-to-Basic exceptions are invisible too. So the tool runs a **short declared questionnaire** and
asks the user to confirm the level (and may persist the answer, the way the business-logic intent file
is persisted), then lists that level's obligations:

1. Does the database hold any **sensitive category** above, **or** is data collected for
   **commercial transmission** (direct mail), **or** is it a **public-sector** database?
   → at least **Medium** (unless the small-scale exception applies).
2. Does it hold **≥ 100,000 data subjects**? → **High**.
3. Are there **> 100 authorised users**? → **High**.
4. Small-scale exception: is it **only** employee/supplier data for business administration, **or**
   fewer than **10 authorised users**? → back to **Basic**.

Until the user answers, the level is `undeterminable` and the report **declares the union of
obligations conservatively at Medium**, saying so — under-claiming the level would silently drop the
תקנות that matter most. This is `CG-PRIV-LEVEL` (below).

<a id="graded"></a>
## Graded static checks — the slice a scan can verify

Each check names its `CG-PRIV-*` id, the heuristic, the false-positive trap that must **not** fire,
the severity in legal register, and the guard. Findings are `pillar: "compliance"`.

<a id="tls"></a>
### CG-PRIV-TLS · data in transit must be encrypted · תקנה 14(ב)

**Statute.** תקנה 14(ב) requires personal data transmitted over a network to be protected with
**standard encryption** (הצפנה מקובלת). Sending it in cleartext is a direct, provable violation.

**Heuristic (two signals, one id — both are "unencrypted in transit").**
- A `fetch` / `axios` / XHR call, a webhook target, or an API **base URL** using **`http://`** to a
  **non-local host** — especially one that carries user data (login, form POST, an API that reads or
  writes a personal-data table). The scheme is right there in the source: when it is a string literal
  to a real host, evidence is `definitive`/`strong` → this can reach a **violation**.
- A **database / backend connection string that explicitly disables TLS** to a non-local host —
  `sslmode=disable`, `ssl=false`, `ssl: false` in a client config. Personal data then travels
  app↔DB in cleartext. Evidence is `weak` here (the managed provider may enforce TLS server-side
  regardless), so this is `needs-review`, not a confirmed violation — impact-if-true is the same P1,
  the uncertainty lives in confidence, not severity.

**False-positive trap — must NOT fire on:**
- `http://localhost`, `http://127.0.0.1`, `http://0.0.0.0`, `*.local`, `*.internal`, container
  hostnames, and any dev-only / test URL. Local traffic never leaves the machine.
- **`http://` inside a comment, a string that is not a request target, or a test/fixture file** —
  the FP-09 discipline: blank comments and non-target strings before matching, preserving line
  numbers.
- **`http://` as a namespace or identifier, not a network target** — `xmlns="http://www.w3.org/..."`,
  SVG/XML namespaces, a JSON-LD `@context`, an XSD/DTD URL, `http://schema.org`. These are names,
  never fetched. This is the single largest source of cleartext-detector false positives; suppress
  it explicitly.
- A platform that **terminates TLS and redirects** (Vercel, Netlify, Cloudflare Pages). A plain
  `http://` link there is usually upgraded before it leaves the browser; a real finding on those
  almost always means a custom domain whose certificate has not finished provisioning — say "check
  the domain settings" rather than "you transmit in cleartext".
- `sslmode=disable` / `ssl: false` pointing at **localhost**, or living only in `.env.example`.

**Severity: P1** — a provable transmission of personal data without encryption violates a core
security regulation. Legal register: exposes the owner to a **binding enforcement order from the
Privacy Protection Authority**, and — if personal data is actually intercepted — a **reportable
security event** for a medium/high database.

**Guard:** `guard-recipes/security-headers.md#tls` (serve everything over HTTPS) +
`security-headers.md#hsts`. For mobile targets, `network-security-config.md#cleartext` (Android) and
`ios-ats.md#arbitrary-loads` (iOS ATS).

<a id="cookie"></a>
### CG-PRIV-COOKIE · session cookies must carry secure flags · supports תקנה 9(ב) / 14

**Statute.** תקנה 9(ב) governs authentication controls (for medium/high databases) and תקנה 14 network
security. A session cookie that can be read by injected script, or sent over plain HTTP, undermines
both. This is the one slice of session security a static scan can see.

**Heuristic.** An **authentication / session** cookie set **without `Secure` and `HttpOnly`** — an
`httpOnly: false` or a missing `secure` on a cookie whose name or role is session-bearing
(`session`, `sid`, `auth`, `token`, `access_token`, `refresh_token`, a framework session cookie).
Note `SameSite` too (`Lax`/`Strict`) as a CSRF-adjacent flag, but its absence alone is a weaker
signal than a missing `Secure`/`HttpOnly`.

**False-positive trap — must NOT fire on:**
- **Non-session cookies** — theme, locale, `cookie-consent`, an analytics id, a feature flag. They
  carry no credential and are out of scope. Scope this check to session/auth cookies only.
- A **cookie library or framework that sets `Secure` by default in production** — `next-auth`,
  Supabase auth cookies (HttpOnly by default), `express-session` behind `trust proxy` with
  `cookie.secure: true`, `@fastify/secure-session`. Presence of the library is not a violation;
  credit it.
- **`secure` set conditionally on environment** — `secure: process.env.NODE_ENV === 'production'`
  is the correct pattern; the literal `false` seen on the dev branch of that ternary must not fire.
  If the flags are set inside a helper this pass cannot follow, the cookie is `undeterminable`, not
  a fail (LAW 1).

**Severity: P2** — a real weakness in the authentication controls the regulation requires, but it
needs a particular condition (an XSS foothold, or a plain-HTTP hop) to bite. Legal register: a gap in
the תקנה 9(ב)/14 control set that an Authority audit or a post-breach review would flag.

**Guard:** `guard-recipes/security-headers.md#cookies`.

<a id="plaintext"></a>
### CG-PRIV-PLAINTEXT-TRANSFER · sensitive data written without encryption · תקנה 12 / 14(ב) — conservative, mostly declared

**Statute.** תקנה 12 requires portable-media restriction and **standard encryption when exporting**
data from the database; the level's encryption duties extend to sensitive data leaving the trust
boundary. A source scan can only *suspect* this, so it is kept deliberately conservative.

**Heuristic (narrow).** A **sensitive field** (national id / `ת"ז`, health, biometric, financial —
identified by name) written **out of the application in the clear**: serialised into a CSV/Excel
**export**, an unencrypted email/attachment, a third-party sink, or a **plaintext log line** — where
the declared level requires encryption for that data.

**False-positive trap — must NOT fire on:**
- **Storage-layer or provider-side encryption**, which is invisible to source: Postgres/Supabase
  at-rest encryption, S3 SSE, an ORM column-encryption plugin, disk encryption. Absence of visible
  encryption in code is **not** evidence of absence of encryption.
- **Password hashing** — `bcrypt`/`argon2`/`scrypt` on a credential is correct handling, never a
  "plaintext" finding.
- A field that merely *looks* sensitive by name without a real sink — LAW 3: a name is not a fact.

**Severity: P3**, and **most instances are declared `undeterminable`**, not graded. Emit a P3
compliance finding only when there is a concrete sink for a concretely-sensitive field and no visible
encryption on the path; otherwise declare it under תקנה 12 (below) and let the owner confirm.
Impact register: a hygiene/robustness gap against the export-encryption duty — cheap to close, and
the kind of thing a 24-month audit (תקנה 16) is expected to catch.

**Guard:** `guard-recipes/secrets-management.md#server-only` for keeping sensitive values off client
and log paths; the at-rest/export encryption itself is confirmed by the owner (declared).

<a id="level"></a>
### CG-PRIV-LEVEL · the security-level classification prompt · תוספת ראשונה / שנייה — informational

**Not a violation.** This is the declared classifier of [§ classifier](#classifier), rendered so the
report always states which level's obligations it is measuring against. **Severity: P4** —
informational; it carries the questionnaire and, when the user has not answered, the honest note that
the level is `undeterminable` and obligations are being listed conservatively at Medium. It is the
grade-or-declare hook for the whole regulation: the level is declared, and every obligation below
hangs off it.

<a id="declared"></a>
## Declared obligations — grade-or-declare (process/org evidence, out of static reach)

Everything the tool **cannot** verify from code. Each is a real legal duty; each gets a stable
`CG-PRIV-*` id, its תקנה, and a one-line "what to confirm", and each is filed as an **`undeterminable`**
row in the `privacyObligations` coverage set (never a violation — see the pillar note above). They are
**grouped by level** so the owner sees only what applies once they have answered `CG-PRIV-LEVEL`.

### All levels (Basic, Medium, High)

| id | תקנה | Obligation | What to confirm |
|----|------|------------|-----------------|
| `CG-PRIV-DEF-DOC` | 2 | Database definition document (מסמך הגדרות מאגר) | A maintained document describing the database's purpose, data types, data flows and risks exists. |
| `CG-PRIV-VETTING` | 7 | Personnel vetting / screening | Anyone with access was screened before being granted it. |
| `CG-PRIV-ACCESS-LIST` | 8 | Least-privilege access control + a maintained roles/permissions list | A current list ties each authorised person to the minimum permissions their role needs. |
| `CG-PRIV-ACCESS-VERIFY` | 9(א) | Practical verification of authorised-only access | Access is technically restricted to authorised users, and this is actually tested — not just intended. |
| `CG-PRIV-PHYSICAL` | 6 | Physical security | Servers/devices holding the data sit in access-controlled physical locations. |
| `CG-PRIV-PORTABLE` | 12 | Portable-media restriction + standard encryption on export | Use of removable media is restricted, and any data exported/carried off is encrypted with standard encryption. |

### Medium and High (in addition to all of the above)

| id | תקנה | Obligation | What to confirm |
|----|------|------------|-----------------|
| `CG-PRIV-POLICY` | 4 | Written security policy (נוהל אבטחה) | A written, maintained security procedure exists and is followed. |
| `CG-PRIV-AUTHN` | 9(ב) | Authentication procedures | Password strength rules, a failed-attempt lockout, rotation ≤ 6 months, auto-logout on inactivity, immediate credential revocation on termination, reset of shared credentials, and a preference for physical/exclusive-control means. (`CG-PRIV-COOKIE` covers only the cookie-flag slice; the rest is declared.) |
| `CG-PRIV-AUDIT-LOG` | 10 | Access logging & audit trail | Automatic, tamper-resistant logging of user + timestamp + component + action + data scope + allow/deny, retained ≥ 24 months and reviewed routinely. |
| `CG-PRIV-NET` | 14 | Network security | 14(א) no internet connection without intrusion/malware defences; 14(ב) encryption in transit (the graded `CG-PRIV-TLS` slice); 14(ג) strong authentication for remote access. The 14(א)/(ג) parts are declared. |
| `CG-PRIV-SEPARATION` | 13(ב), 13(ג) | System isolation + patching | Systems holding personal data are separated/isolated as required, and are patched — **no unsupported/end-of-life versions**. (The dependency slice overlaps the security pillar's `dependency-hygiene` checks; 13(ג) makes patching a *legal* duty, not only hygiene — cross-reference, don't double-count.) |
| `CG-PRIV-OUTSOURCING` | 15 | Outsourcing / third-party contracts | Contracts with processors define permitted data & purposes, accessible systems, return/destruction on termination, subcontractor confidentiality, and annual compliance + breach reporting. |
| `CG-PRIV-BREACH` | 11 | Breach documentation & notification | A serious breach is documented and reported to the Authority (הרשות להגנת הפרטיות) immediately; a process exists to do so. |
| `CG-PRIV-AUDIT-24MO` | 16 | Periodic independent audit | An independent, qualified assessor audits data security at least every 24 months. |
| `CG-PRIV-BACKUP` | 18 | Backup procedures | Backup procedures exist and are exercised. |

### High only (in addition to all of the above)

| id | תקנה | Obligation | What to confirm |
|----|------|------------|-----------------|
| `CG-PRIV-RISK-SURVEY` | 5(ג) | Risk survey (סקר סיכונים) every 18 months | A risk survey is performed at least every 18 months and its findings acted on. |
| `CG-PRIV-PENTEST` | 5(ד) | Penetration testing (מבדקי חדירות) every 18 months | Penetration testing is performed at least every 18 months. |
| `CG-PRIV-ARCH-INVENTORY` | 5(א) | Current system-architecture inventory | An up-to-date inventory of the systems and their architecture is maintained. |
| `CG-PRIV-BACKUP-COPY` | 18 | Maintained backup copy with integrity/recovery | A maintained backup copy exists with verified integrity and a tested recovery path. |

<a id="severity"></a>
## Severity register — the privacy compliance pillar

Same P-labels as everywhere (one scale keeps ordering and rendering uniform), but the axis is **legal
exposure if unfixed**, stated in the regulation's own terms — Authority enforcement order, reportable
security event, civil/criminal liability under חוק הגנת הפרטיות. **No ₪ figures**: unlike the
accessibility statute, this regulation's teeth are *orders + breach-reporting + Authority
enforcement*, not a fixed fine — so no fine is invented. **No P0** (pillar rule).

| Level | Privacy legal-exposure meaning | This domain's examples |
|-------|--------------------------------|------------------------|
| **P1** | A provable transmission/config violation of a **core** security regulation. Exposure: a binding **enforcement order** from the Privacy Protection Authority, and reportable-**breach** risk if personal data is actually exposed. | `CG-PRIV-TLS` (personal data over `http://` to a real host). |
| **P2** | A real weakness in a required control that needs a particular condition to bite. Exposure: a gap an Authority audit or a post-breach review flags. | `CG-PRIV-COOKIE` (session cookie missing `Secure`/`HttpOnly`). |
| **P3** | Hygiene / robustness against a data-protection duty — cheap to close, the kind of thing the 24-month audit is meant to catch. | `CG-PRIV-PLAINTEXT-TRANSFER` (conservative, mostly declared). |
| **P4** | Informational — not itself a violation. The level-classification prompt, and reminders of declared obligations. | `CG-PRIV-LEVEL`. |
| ~~P0~~ | **Deliberately unused.** A data-security-regulation gap draws an order and a duty to report — it is not the live-breach emergency P0 marks. | — |

Declared obligations (`CG-PRIV-DEF-DOC` … `CG-PRIV-BACKUP-COPY`) carry **no severity**: they are
`undeterminable` coverage rows, not findings. One becomes a P1/P2/P3 finding **only** when a static
signal proves a specific violation of it — never from absence-of-evidence.

<a id="cry-wolf"></a>
## Cry-wolf discipline (restated, because it is the whole point)

For this non-expert audience a **false positive is worse than a miss** — telling an owner they are
"breaking the privacy law" when they are not costs them a day of panic and then their trust, and the
real finding three lines down never gets read. See `../methodology/false-positives.md`. Concretely,
in this domain:

- **Never assert a process/paperwork violation from a repository.** No "you have no security policy",
  no "you don't log access", no "you never ran a pen-test". These are `undeterminable`, always — the
  evidence simply is not in the code.
- **The classifier is declared, not guessed.** A sensitive-looking column is a hint toward Medium, not
  a classification; record counts and user counts are unknowable from source.
- **The transport checks respect their traps** — localhost, namespaces (`xmlns`), comments/strings,
  TLS-terminating platforms, and env-conditional `secure` flags do not fire.
- **A token is never a `pass`** (LAW 1); **a name is never a P0** (LAW 3, and there is no compliance
  P0 anyway); **every subject set adds up** (LAW 2).

When a signal is ambiguous, ask "what would have to be true for this to be a real violation, and can I
see that from here?" — if no, it is `undeterminable` with a תקנה and an instruction, never a finding
tuned to look impressive.

<a id="report-line"></a>
## The report line (HE + EN)

Rendered in the `summary.compliance` block, kept entirely separate from the security badge (see
`../report-template.md#compliance-pillar`). State the declared level, the static-findings count, and
the count of declared obligations; state exposure in the regulation's terms, **no ₪ figure**.

When static findings exist:

```
אבטחת מידע (תקנות הגנת הפרטיות (אבטחת מידע), התשע"ז-2017): רמת המאגר: <declared> · {n} ממצאים סטטיים ·
{m} חובות להצהרה ואישור. חשיפה משפטית: צו אכיפה של הרשות להגנת הפרטיות, ואירוע אבטחה בר-דיווח אם מידע
אישי נחשף בפועל — עד כדי אחריות אזרחית ופלילית לפי חוק הגנת הפרטיות.
Data security (Privacy Protection (Data Security) Regulations 2017): database level: <declared> ·
{n} static findings · {m} obligations to confirm. Legal exposure: an enforcement order from the
Privacy Protection Authority, plus a reportable security event if personal data is actually exposed —
up to civil and criminal liability under the Privacy Protection Law.
```

When the static slice is clean — honest, because it is only a slice:

```
אבטחת מידע: לא נמצאו הפרות בבדיקות הסטטיות (הצפנת תעבורה, דגלי עוגיית התחברות) · אך זו אינה הצהרת
התאמה: {m} חובות (מסמך הגדרות, נוהל אבטחה, תיעוד גישה, סקר סיכונים ומבדקי חדירות, ביקורת 24 חודשים ועוד)
הן ארגוניות ואינן נראות בקוד — יש לאשרן. רמת המאגר: <declared>.
Data security: no violations in the static checks (transport encryption, session-cookie flags) · but
this is NOT a conformance statement: {m} obligations (definition document, security policy, access
logging, risk survey & penetration testing, the 24-month audit, and more) are organisational and
invisible to a code scan — confirm them. Database level: <declared>.
```

When the level is still `undeterminable`, say obligations are listed conservatively at Medium and
prompt the questionnaire (`CG-PRIV-LEVEL`), in both languages.

<a id="verify"></a>
## How to verify (kept honest)

- **The static checks** (`CG-PRIV-TLS`, `CG-PRIV-COOKIE`) reach `confirmed` only on a `definitive`/
  `strong` static fact — a literal `http://` request target to a real host, a session cookie with
  `httpOnly:false`/no `secure`. The DB-TLS and export signals stay `needs-review`; a live pass
  (`/cg-live`) that observes the actual scheme/flags on the wire is what upgrades them.
- **The level** is settled by the user answering the questionnaire — the tool asks, it does not
  assume. Everything downstream is scoped to that answer.
- **The declared obligations** are settled by the owner (or their DPO / legal advisor) confirming the
  organisational facts. The report hands them the list, grouped by level, with the תקנה on each row —
  it never claims to have checked them, and never claims they are missing. That is the honest edge of
  what a source scan can say about this regulation.
