# Severity model & finding schema

Single source of truth for how ClaudeGuardIL grades findings and what a finding must contain.
The grader (`plugin/scripts/grader.mjs`) is the only component allowed to apply this model; the
plugin and the claude.ai skill both render what it emits. `CONTEXT.md` defines the vocabulary —
this file is the policy written in that vocabulary.

## The whole model in four sentences

1. **Severity** says how bad it would be *if the finding is real*. It is never lowered because we
   are unsure.
2. **Confidence** says how sure we are, and it is computed from **Evidence** alone — nothing else
   may set it.
3. The **graded verdict counts only `confirmed` findings**. That is where the uncertainty gets paid
   for, which is what makes rule 1 safe.
4. **`clean` is not the default.** Not turning the badge red is not the same as turning it green:
   `clean` also requires that nothing unproven-but-catastrophic is still open and that discovery
   coverage cleared its floor. Otherwise the level is **`unknown`**.

Everything below is an elaboration of those four.

---

## Severity — impact if true (P0–P4)

Rate by **impact × exploitability**, biased toward the reality of a vibecoded app that is already
(or about to be) public. Severity is a property of the *consequence*, not of how well we proved it.

| Level | Label (EN / HE) | Meaning | Typical examples |
|-------|-----------------|---------|------------------|
| **P0** | Critical / קריטי | Full compromise or total data exposure reachable by an anonymous attacker, with no special conditions. Fix before anyone else sees the URL. | `service_role` key behind a `NEXT_PUBLIC_` prefix, so it is compiled into the browser bundle; a Supabase table created without `enable row level security`; a `SECURITY DEFINER` function with no `auth.uid()` check, callable by anyone through `supabase.rpc()`; `dangerouslyAllowBrowser: true` on an LLM SDK; an unauthenticated API route that holds the service-role key. |
| **P1** | High / גבוה | Serious breach that needs one easy step or one common condition. | A mutating `/api/...` route with no visible authentication; a `SECURITY DEFINER` function that never pins `search_path`; user input interpolated into a prompt at a call site that also defines tools the model may invoke; injected markup reflected back unescaped; a sensitive path readable over the open internet. |
| **P2** | Medium / בינוני | A real weakness that raises risk or makes another attack easier. | No `headers()` in `next.config`, so nothing sets a CSP; no rate limit on an LLM endpoint (denial of wallet — a real overnight bill with no breach involved); CORS that allows any origin together with credentials; a cookie without `HttpOnly`; a mutating route that never validates its request body; `remotePatterns` that allows any image host. |
| **P3** | Low / נמוך | Hygiene, defence-in-depth, or something genuinely hard to exploit. | Production source maps published; `ignoreBuildErrors` / `ignoreDuringBuilds` switched on; a server variable read from client code that will simply be `undefined` in the browser (a correctness bug that people "fix" by adding a public prefix — which *would* be a breach); missing `Referrer-Policy` or `nosniff`. |
| **P4** | Info / מידע | Not a vulnerability. Worth knowing or worth confirming. | RLS enabled with zero policies — deny-all, safe but the feature is probably broken; a `.env.example` that pairs a public prefix with a credential-shaped name, teaching the next person to ship a secret. |

**Escalation rule.** Any secret that is (a) currently valid and (b) grants privileged access is
**P0**, wherever it lives. When torn between two levels, pick the higher one only if you can name
a concrete attacker action; otherwise pick the lower one and say why.

### Severity is uncapped — and this reverses the old rule

An earlier version of this model capped severity by evidence strength: weak evidence could not
produce a P0, so an unproven catastrophe was printed as a P2. **That rule is gone.** Severity is
now impact-if-true and nothing discounts it.

Two reasons:

- **It double-counted the uncertainty.** Confidence already carries "how sure are we". Capping
  severity subtracts the same doubt a second time, and the reader has no way to add it back.
- **It buried the worst case where nobody looks.** A P0 demoted to P2 for lack of proof sorts
  below three CSP warnings. The non-expert reading the report stops long before reaching it. A
  report that hides its scariest line to look rigorous has failed at the only job it has.

So, plainly: **an unproven P0 is still printed as a P0.** It carries `needs-review` beside it, it
states the assumption that would make it a false positive, and it does *not* turn the badge red.

Worked example — `CG-DB-COVERAGE`. A repo with no migrations: the tables are visible in generated
types, but nothing in the repo says whether RLS is on. Impact if RLS is off is total exposure, so
severity is **P0**. Evidence is `weak`, so confidence is **needs-review**. It appears at the top of
the report as a P0 the user must settle with one query — the badge does not go red, because nothing
was confirmed, and it does not go green either, because an unproven P0 is open: the level is
**`unknown`**. See [LAW 4](#law-4).

**The one hard ceiling (LAW 3).** Name-only evidence may never justify a P0. `FOO_API_KEY` in a
variable name is not proof that a privileged credential exists. The grader throws if a rule tries.
In practice these are raised at P2, with the assumption stated: "that this key actually grants
privileged access rather than being a public identifier."

---

## Evidence — how solidly the fact is established

Evidence is about the *fact*, not about the danger. Four values, no others:

| Evidence | HE | What it means | Example |
|----------|----|---------------|---------|
| `definitive` | חד-משמעית | The compiler, bundler or schema guarantees it. No inference, nothing in the chain that could break. | A `NEXT_PUBLIC_` prefix means the bundler substitutes the value into client output verbatim. The migrations create a table and never enable RLS. |
| `strong` | חזקה | A direct, single-hop observation. | A module is imported directly by a client entrypoint and constructs a service-role client. |
| `weak` | חלשה | Inferred through a chain that could break. | The module is reachable only through a re-export barrel, where tree-shaking may drop it. No auth token appears in a handler — but the check could live in a helper it imports. |
| `judgement` | שיקול דעת | A reviewer read the code and formed a view that no rule could have enumerated. | "This admin action is gated by a flag the user controls." |

`evidence.nameOnly` is a separate boolean: `true` when the **only** thing establishing the finding
is an identifier's name. It is what LAW 3 keys on.

**Name-only evidence may never justify a P0.** Names like `PUSHER_APP_KEY` or `IDEMPOTENCY_KEY`
are routinely publishable. Reporting one as a leaked credential is how a security tool teaches its
audience to ignore it.

---

## Confidence — a pure function of Evidence

| Evidence | → Confidence | HE |
|----------|--------------|-----|
| `definitive` | `confirmed` | מאומת |
| `strong` | `likely` | סביר |
| `weak` | `needs-review` | דורש בדיקה |
| `judgement` | `likely` | סביר |

**Nothing may set confidence directly.** Rules supply Evidence; the grader derives Confidence and
asserts the mapping again before returning. `judgement` maps to `likely` rather than
`needs-review` on purpose: a reviewer who read the code has done more work than a regex that
half-matched. It is capped there and can never reach `confirmed`, because no amount of reading is
a proof.

**What this buys you:** the same repo always grades the same way. Two runs, two machines, two
different people — same findings, same confidences, same verdict. Confidence is not a mood.

**The one asymmetry.** The adversarial verification pass may only **refute** a finding — drop it,
with a one-line reason so it is not re-raised. It may never raise a finding's confidence. Raising
confidence would put a human judgement back into the one place the model guarantees is mechanical.
If a `likely` finding deserves `confirmed`, the way to get there is stronger Evidence: a live check
(`/cg-live`) that observes the behaviour, or a rule that can see the fact definitively.

Only `confirmed` findings are eligible for `/cg-fix`.

---

## The verdict — only `confirmed` findings can grade it, and `clean` has to be earned

This is the rule that pays for uncapped severity. The **graded** levels are computed from
`confirmed` findings **and nothing else**:

| Level | HE | Emitted when |
|-------|----|--------------|
| `critical` | קריטי | any confirmed P0 |
| `high` | גבוה | any confirmed P1 (and no confirmed P0) |
| `medium` | בינוני | any confirmed P2 (and nothing above) |
| `low` | נמוך | at least one confirmed finding, all P3/P4 |
| `unknown` | לא נבדק | nothing confirmed, but the repo was **not proven safe** — see LAW 4 |
| `clean` | נקי | nothing confirmed, nothing unproven-and-catastrophic open, coverage above floor |

The grader emits, alongside the level, `confirmedP0`, `confirmedP1`, `confirmedLevel` (the level the
confirmed findings alone produce, `null` when there are none), the counts of everything that did
*not* count (`likely`, `needsReview`, `unprovenP0`, `unprovenP1`), and the `discoveryCoverage`
assessment the floor was applied to.

<a id="law-4"></a>
### LAW 4 — the `clean` verdict must not lie

**The defect.** For as long as the verdict counted `confirmed` findings alone, a repository with a
**fully unauthenticated DELETE endpoint graded 🟢 `clean`**. Every step was individually correct: the
route rule raises a P1, and its evidence is `weak` because the absence of an auth token is not proof
(the check could live in a helper this pass does not follow — LAW 1), so the confidence is
`needs-review`, so it did not count, so the badge was green. The same held for a scan that could
only read a third of the repo: nothing confirmed, badge green.

That is a **false all-clear**, and it is the one failure mode this audience cannot detect for
itself. A false positive costs a non-expert an afternoon. A false all-clear costs them the database.
"Nothing was proven" and "nothing is wrong" were printing the same colour.

**The rule.** The badge is a function of **coverage × confirmed**. `clean` requires all three:

1. **zero `confirmed` findings** (unchanged), **and**
2. **zero unproven P0/P1** — no finding whose severity is P0 or P1 at confidence `likely` or
   `needs-review` is still open. (Allowlisted and refuted subjects raise no finding at all, so
   anything left in the list is by definition unsettled.) **And**
3. **discovery coverage at or above the floor** (below).

If (1) holds but (2) or (3) does not, the level is **`unknown` / `לא נבדק`** — *not proven safe*. It
is never rendered green. A repository **with** confirmed findings is unaffected: it keeps
`critical` / `high` / `medium` / `low` exactly as before. `unknown` only ever replaces what used to
be `clean`, so this can never make a report louder about any specific finding — the cry-wolf thesis
is intact. One thing changed: a badge that used to claim more than the evidence supports now says so.

Asserted at runtime at the end of `grade()`, beside the LAW 1/2/3 checks: a result whose level is
`clean` while an unproven P0/P1 is open, or while coverage is below the floor, **throws**. A renderer
or a future refactor cannot silently reintroduce the false all-clear, because the failure it would
produce looks exactly like every other clean report.

<a id="coverage-floor"></a>
### The discovery-coverage floor, exactly

Discovery coverage (`methodology/discovery.md`) asks *what did the engine manage to see* — a
different axis from the pass/fail ledger's *of what it saw, what did it grade*. The floor reads
`model.discovery` and is adequate only when **all** of the following hold:

| Condition | Why |
|---|---|
| `discovery.counts` is present | An absent ledger is **not** neutral. A model that never says what it saw has not earned `clean`, and treating absence as adequate would make deleting one key the cheapest way to buy a green badge. |
| `discovery.reconciles === true` | `filesParsed + configParsed + unsupported + oversized + readErrors === filesDiscovered`. A ledger that does not add up cannot support any verdict built on it. |
| `filesDiscovered > 0` and at least one file was read | Pointing the tool at an empty or entirely unreadable directory used to grade `clean`. There was nothing behind that verdict. |
| **read ratio ≥ 0.95** | `(filesParsed + configParsed) / (filesParsed + configParsed + oversized + readErrors)`. |

Note what the denominator is **not**: it excludes `unsupported`. Images, lockfiles and binaries are
deliberate, accounted-for exclusions — a repo is not under-read for owning a logo, and putting those
in the denominator would flip correct apps to `unknown` for having assets, which is the cry-wolf
failure wearing a different hat. What belongs in the denominator is only the files we *wanted* and
failed to get: oversized ones and read errors. The threshold is **0.95** because more than one file
in twenty that we meant to read and could not is a hole big enough to hide the finding, and at that
point "we could not see enough to say" is the honest headline.

Every `false` carries its reasons in `verdict.discoveryCoverage.reasons`, and the report prints
them: a floor that fails without saying why is just another opaque verdict.

**What LAW 4 does not do.** It does not consider unproven **P2 and below**. A missing CSP at
`needs-review` is a real weakness and not a reason to withhold a clean bill of health; folding it in
would make `unknown` the permanent answer, and a badge that never varies carries no information.

**`clean` still means "nothing was proven", not "nothing is wrong."** LAW 4 narrows the gap; it does
not close it. The report must never present `clean` on its own — it is shown next to the unconfirmed
findings and next to Coverage, or it is a lie by omission. See `report-template.md`.

---

<a id="gate-mode"></a>
## Gate mode — the exit code *is* the verdict

`node grader.mjs <path> --gate` prints the report to stdout as usual, writes one human line to
stderr, and sets the **process exit code** from the verdict:

| Exit | When | Meaning |
|------|------|---------|
| `1` | any **confirmed** P0 or P1 | Proven bad. The thing this tool exists to stop. |
| `2` | level is `unknown` | **Not proven safe** — an open unproven P0/P1, or discovery below the floor. |
| `0` | `clean`, or only confirmed P2/P3/P4 | Nothing blocking. |

It drops into a CI step or an agent's pre-deploy hook. Confirmed P2 and below deliberately do not
block: a gate that fires on a missing `Referrer-Policy` is a gate somebody switches off, and then it
protects nothing at all.

**The agent-deploy property.** An agent cannot talk this gate green. A reviewer finding is capped at
`judgement → likely` and can never reach `confirmed`, so no amount of agent output can lower the
confirmed counts a `0` depends on; and an unsettled reviewer P0/P1 pushes a `clean` repo to
`unknown`, i.e. from `0` to `2`. Every path more agent output can take raises the exit code, never
lowers it. The only way to a `0` is better evidence in the repository.

---

<a id="run-record"></a>
## The run record — what was run, not what is safe

Every result carries a `runRecord`: `toolVersion`, `commit`, `generatedAt`, `modelHash`,
`ledgerReconciles`, `confirmedP0`, `confirmedP1`, `verdict`. It exists so two people can establish
that they are looking at the same run before they argue about a finding, and so a report pasted into
an issue three weeks later can still be traced to the code that produced it.

It attests **what was run**. It is never a statement that the repository is secure, and it carries a
`note` saying so, because a signed-looking block at the bottom of a security report is exactly the
thing a reader will over-trust.

**It is deterministic by construction.** Two runs on the same model produce an identical record —
including `modelHash`, which is a SHA-256 over the model serialised with every object key sorted, so
the same facts hash the same however the JSON was assembled. `generatedAt` is `null` unless the
**caller** supplies a clock (`opts.now`); the grader never reads one. A grader that reaches for
`Date.now()` cannot be diffed against itself, and "re-run after the fix and trust the diff" is the
only workflow this tool offers.

---

## Finding schema

What `grader.mjs` emits for every finding. Renderers may rely on every field being present.

```yaml
id:           CG-<DOMAIN>-<NNN>       # stable and unique per rule; the prefix carries the domain
                                      # (ENV, WEB, DB, LLM, LIVE, DAST). A few config rules key the
                                      # suffix to the config key instead, e.g. CG-WEB-env.
subject:      route:app/api/orders/route.ts   # the exact thing graded — the join key to Coverage
title_en:     Short imperative title
title_he:     כותרת קצרה
severity:     P0 | P1 | P2 | P3 | P4  # impact if true; never reduced for uncertainty
confidence:   confirmed | likely | needs-review   # DERIVED from evidence.strength — never written
provenance:   rule | reviewer         # a deterministic rule, or a reviewer walking the inventory
source:       null | gitleaks | semgrep | snyk | npm …   # which external tool established it;
                                      # null when one of our own rules did
tier:         static | passive-live | active-dast # how the underlying fact was obtained
evidence:
  strength:   definitive | strong | weak | judgement
  nameOnly:   false                   # true when only an identifier's name establishes this
  why:        One sentence on what makes the fact true at this strength.
  at:                                 # where to look — rendered verbatim so the user can check us
    - file:    lib/db.ts
      line:    3
      snippet: "const admin = createClient(url, SERVICE_ROLE_KEY)"
exploit:      One concrete sentence: attacker does X, gets Y.
impact:       Business consequence: data / accounts / money / compliance.
assumption:   What would have to be true for this to be a FALSE POSITIVE. null when there is none.
guard:        guard-recipes/<name>.md#<anchor>    # the fix to paste
cwe:          CWE-<id>                # when applicable, else null
owasp:        "A01:2021" | "LLM01" | "M1"         # web / LLM / mobile top-ten tag, else null
autofixable:  true | false
corroboration: []                     # other tools that independently reported the SAME weakness
                                      # at the same file:line, each with its own severity. Usually
                                      # empty; non-empty is a reason to look sooner.
```

### `source` and `corroboration` — one defect, one finding

Several tools now look at the same repository, and they overlap: Snyk's SAST covers ground semgrep
covers, and both touch files this grader already has rules for. Printed straight through, one
missing `USER` directive arrives three times with three severities, and the reader cannot tell that
from three separate problems. **Volume is what destroys trust — not any single finding.**

So the grader reconciles them. Findings that name the **same weakness class at the same
`file:line`** are one defect, and it prints once:

- **Only across sources.** Two findings from the *same* producer at one line are that producer's
  enumeration, and it meant both (a compose file really can mount the Docker socket *and* run
  privileged). Reconciliation is about the same fact seen twice.
- **A native rule outranks any external tool.** This grader is the single severity authority and its
  own rules read the file directly, so a commercial scanner's opinion about the same `file:line`
  does not overwrite a grade we derived ourselves. Among external tools, the strongest evidence
  wins.
- **A weakness class we cannot name is never merged.** Two genuinely different defects can share a
  line; collapsing those would hide one, and a hidden finding is worse than a visible duplicate.

The absorbed findings are not deleted — they move to the survivor's `corroboration`, carrying their
own severity and reason, and their coverage row is rewritten to point at the survivor so the
"every `fail` row has a finding" cross-check still holds.

### The external-analysis ceiling

`source` also carries a cap. **Snyk and semgrep may never produce a `confirmed` finding**, and the
grader throws if one does. Both report an *analysis* — a judgement about code this grader did not
read for itself — and `confirmed` is what drives the headline verdict and the auto-fix gate. Snyk's
reachability and dataflow are excellent and still are not a proof.

gitleaks is deliberately **not** capped: it reports a credential's **value** at a `file:line`, which
is precisely the evidence LAW 3 allows to close a P0, and which the user can check by opening the
file.

### What changed, and why

- **`evidence` is now an object, not a list of locations.** The old schema used the word "evidence"
  for the file/line list. `CONTEXT.md` defines Evidence as *how solidly the fact is established*,
  which is a different thing entirely — so the locations moved under `evidence.at`, and
  `evidence.strength` took the name. Any renderer that iterated `finding.evidence` must now iterate
  `finding.evidence.at`.
- **`confidence` is no longer a field anyone writes.** It is derived from `evidence.strength`.
- **`subject` is new.** It names the exact thing graded — one table, one route, one env var — and it
  is the key that ties a finding to its row in Coverage and to the user's allowlist.
- **`provenance` is new.** `rule` means a deterministic rule proved it; `reviewer` means a person
  walking the inventory thinks so. The two deserve different responses from the reader, so the
  report shows which it is instead of flattening them into one voice.
- **`assumption` is new.** It names what would have to be true for the finding to be a **false
  positive** — "that authentication is not performed inside a helper this handler imports", "that
  RLS was not enabled from the Supabase dashboard". A `likely` with no stated assumption is just
  hedging: it transfers doubt to the reader without telling them what to check. With the assumption
  written down, a five-second look settles it.
- **`domain` is gone as a field.** The domain lives in the `id` prefix.

---

## Coverage — what was actually examined

A findings list alone cannot be trusted, because it looks identical whether we checked everything
and found little, or checked almost nothing. Coverage is the ledger that tells the two apart.

Every rule iterates one enumerable set — every table, every route, every env var — and records
**exactly one** disposition for **every** member:

| Disposition | HE | Meaning |
|-------------|----|---------|
| `pass` | עבר | A structural property of the code shows the control is present. |
| `fail` | נכשל | The rule concluded the control is absent or broken here, and raised a finding. |
| `undeterminable` | לא ניתן לקבוע | Could not be settled from the repo. A reason is always attached. |
| `allowlisted` | ברשימת ההיתרים | The user accepted it, or it is public by design (an anon/publishable identifier), or the control does not apply (a Prisma/Drizzle schema has no RLS layer to be missing). |

A `pass` is not a promise of silence: a subject can pass and still carry an informational finding.
RLS enabled with zero policies passes (deny-all is the safe direction) and still raises a P4,
because the feature is probably broken and the usual "fix" is a permissive policy.

**LAW 2 — the four must add up.** For every subject set,
`enumerated === pass + fail + undeterminable + allowlisted`. This is asserted at runtime, not just
written here. A subject that silently falls out of the ledger is how "we found nothing" comes to
mean "we looked nowhere".

### What `pass` does not mean

**A subject is never marked `pass` because a token appeared in the source.** That is LAW 1, and it
is enforced in the grader.

Seeing the string `getUser` in a route file does not prove the handler is gated. The call may be
unawaited. Its result may be ignored. Its throw may be swallowed by a `try/catch` three lines down.
All of those look identical to a static read — so a route with an auth call in it lands in
**`undeterminable`**, never in `pass`. The same applies to a `headers()` function that exists but
whose contents we cannot verify, and to a `SECURITY DEFINER` function whose body mentions
`auth.uid()` without our knowing whether the check gates anything.

This is deliberate, and it is the point of the whole design. Printing a checkmark there would be
worse than printing nothing, because the user stops looking. **The `undeterminable` rows are the
reviewer's work list** — the short, honest list of "here is what a human still has to open".

A `pass` is reserved for structural facts: an env var with no inlining prefix and no client reader
*cannot* reach the browser; a table whose migration enables RLS with a non-permissive policy has
its predicate in the migration, not inferred from a token.

### Shape

Coverage is emitted per subject set, alongside `verifyQuery` — the SQL handed to the user verbatim
when the schema could not be read, so they can answer in ten seconds the question we could not.

```yaml
coverage:
  routes:
    enumerated: 12
    counts: { pass: 0, fail: 3, undeterminable: 8, allowlisted: 1 }
    # All four arrays are present, one per disposition; each row is {subject, disposition, note}.
    undeterminable:
      - subject: route:app/api/orders/route.ts
        disposition: undeterminable
        note: an authentication call is present, but whether it gates the handler is not verified
verifyQuery: "select c.relname, c.relrowsecurity as rls_enabled ..."   # null when not needed
```

Subject sets currently enumerated: `envVars`, `nextConfigKeys`, `tables`, `dynamicTableRefs`,
`sqlFunctions`, `routes`, `llmSites`, `supabaseClients`, `liveObservations`.

<a id="decision-rate"></a>
### Decision rate — the counter-pressure against a cheap `undeterminable`

LAW 1 makes `undeterminable` the honest answer whenever a token is all the evidence there is. That
is right, and it is also **the cheapest exit in this architecture**: a rule that abstains on every
subject satisfies LAW 2, prints a complete coverage table, and has decided nothing. Nothing in the
ledger distinguishes "we looked hard and could not settle it" from "we never tried".

So the grader publishes, per subject set and overall, alongside `coverage`:

```yaml
decisionRate:
  overall: { enumerated: 181, decided: 41, abstained: 128, allowlisted: 12, rate: 0.2265 }
  bySet:
    routes: { enumerated: 10, decided: 3, abstained: 7, allowlisted: 0, rate: 0.3 }
```

`decided` is `pass + fail`. `allowlisted` is reported but **not** counted as decided — the user
decided it, we did not. `bench/run.mjs` prints the corpus-wide figure and gates on it: **it may not
decrease.** Every other release gate protects against the tool getting louder or wronger; this one
protects against it getting quieter. The floor is the value measured on the corpus, and it exists to
be ratcheted upward by better evidence — never argued downward.

---

## Report ordering

Sort by severity (P0→P4), then confidence (`confirmed` → `likely` → `needs-review`), then `id`.
Because the `id` prefix carries the domain, equal-ranked findings group by domain for free.

Only `confirmed` findings can produce a graded (red/orange/yellow/blue) badge — see the verdict rule
above, and LAW 4 for why a quiet report is `unknown` rather than green when something unproven and
catastrophic is still open. `report-template.md` covers how the unconfirmed findings are rendered
without driving the badge.

---

## Scoring notes (CVSS-lite, no false precision)

Do **not** compute a numeric CVSS vector — it reads as false rigor to this audience. Use the P0–P4
label plus the `exploit` and `impact` sentences, which say the same thing in words a non-expert can
act on. If a user explicitly asks for CVSS, map: P0 ≈ 9.0–10, P1 ≈ 7.0–8.9, P2 ≈ 4.0–6.9,
P3 ≈ 0.1–3.9, P4 = N/A — and say plainly that it is an approximation, not a computed vector.
