# Coverage — the discipline of accounting

Coverage is the ledger that turns a report from *"here are some things I noticed"* into
*"here is what I examined, and here is what I could not."*

Without it, a report with no findings is indistinguishable from a report where nothing was
examined. The user reads the same green badge either way, ships, and gets breached through the
table you never enumerated. **Coverage is what stops a quiet report from being mistaken for a
safe one.**

---

## The rule

> **LAW 2 — Every enumerated subject gets exactly one of `pass` / `fail` / `undeterminable` /
> `allowlisted`, and the four must add up to the enumerated count.**

For every subject set:

```
enumerated == pass + fail + undeterminable + allowlisted
```

No exceptions, no "misc", no subject that appears in two buckets, no subject quietly dropped
because it was boring. A subject that silently falls out of the ledger is how *"we found
nothing"* comes to mean *"we looked nowhere"*.

The subject sets, at minimum: `envVars`, `routes`, `tables`, `dynamicTableRefs`, `sqlFunctions`,
`llmSites`, `supabaseClients`, `nextConfigKeys`. Declare each set even when it is empty —
`enumerated: 0` is a real and useful statement ("this project has no SQL functions"), and it is
different from not having looked.

---

## The four dispositions

**`pass`** — a **structural** reason this subject is not a problem. The reason must be something
the code *guarantees*, not something a token suggests.

Legitimate passes look like: *"RLS enabled with uid-scoped policies"* (the predicate is in the
migration), *"server-only — no inlining prefix, no client reader"* (structurally cannot reach
the browser), *"security invoker — RLS still applies to the caller"*, *"user-scoped client, RLS
is the control"*, *"placeholder only — no value and no reader"*.

**`fail`** — a Finding was emitted for this subject. Every `fail` row has a finding id; every
finding has a subject in some set. If those two lists disagree, one of them is wrong.

**`undeterminable`** — the honest answer. Cannot be established from what you could read, and
here is why. **This is the work list**, not an apology.

**`allowlisted`** — deliberately out of scope: a user allowlist entry, or a structural exclusion
like *"public by design (anon / publishable identifier)"* or *"ORM-managed schema — RLS is not
the control here"*. Always record the reason; an unexplained allowlist is indistinguishable
from a bug in your reasoning.

---

## The rule that does the most work

> **LAW 1 — A subject is NEVER marked `pass` because a token such as `getUser` appeared.**

Seeing `getUser` in a route handler does not prove the route is gated. The call may be
unawaited, its result never compared, its throw swallowed by a `try/catch`. All three are
textually identical to the correct version.

The disposition is **`undeterminable`**, with a note that says exactly what is unverified:

```
route:app/api/orders/route.ts   undeterminable
  an authentication call is present, but whether it gates the handler is not verified
```

The same applies to a `SECURITY DEFINER` function whose body *mentions* `auth.uid()`, to a
`headers()` function that *exists* in `next.config` without your having read what it sets, and
to a server-side service-role client whose own authorization you did not follow.

**Why this matters more than it sounds:** a checkmark is an instruction to stop looking.
Printing one you have not earned is worse than printing nothing, because "nothing" leaves the
user's attention available and a false checkmark spends it. The `undeterminable` rows are where
a human's time is actually worth spending — they are the deliverable, not the residue.

---

## Checking your own arithmetic

Do this explicitly before rendering. It takes a minute and it catches the failure mode that
matters.

**Per set:**

1. Write down `enumerated` — the number of members you listed during enumeration. Do this
   **from the inventory**, not by counting the ledger rows, or the check is circular.
2. Count rows in each of the four buckets.
3. Add the four. Compare to `enumerated`.
4. Check that no subject id appears twice, in the same bucket or across buckets.

**If the sum is short**, you dropped a subject — find it by diffing your inventory against your
ledger rows. Do not "fix" it by lowering `enumerated`.

**If the sum is over**, the same subject was dispositioned twice. That means **two rules
disagree about the same thing**, and whichever you wrote last would silently win. Resolve the
overlap — decide which rule owns that subject — rather than papering over it. (The scripted
grader treats a double-record as a hard error for exactly this reason.)

**Cross-check against findings:** every emitted finding's subject must appear as a `fail` row
(or, for coverage-style findings like *"RLS state could not be determined for N tables"*, must
correspond to the `undeterminable` rows it summarises). A finding whose subject is in no set is
a finding about something you never enumerated — which means the set is not closed.

---

## Rendering it

Coverage goes **in the report body**, near the verdict — not in an appendix and not omitted when
it is boring. Prose is bilingual (HE + EN) per `report-template.md`; identifiers, paths, SQL and
file names stay English.

```
Coverage / כיסוי

| Set              | Enumerated | Pass | Fail | Undeterminable | Allowlisted |
|------------------|-----------:|-----:|-----:|---------------:|------------:|
| envVars          |         14 |   10 |    1 |              0 |           3 |
| routes           |         23 |    0 |    4 |             19 |           0 |
| tables           |          7 |    0 |    0 |              7 |           0 |
| llmSites         |          2 |    0 |    1 |              1 |           0 |
| supabaseClients  |          5 |    4 |    0 |              1 |           0 |
```

Then the part that is actually actionable — **the work list**, ordered by how much a wrong
answer would cost:

```
Needs a human / דורש בדיקה אנושית

1. tables (7) — no migrations in this repo, so RLS state is unknowable from source.
   Run the verify query below against your database. Ten seconds, settles all seven.
2. routes (19) — an auth call is present but not proven to gate the handler.
   Open each and confirm the result is awaited and acted on. Start with the 4 mutating ones.
3. supabase-client:lib/db.ts:12 — createClient() with a key this pass could not identify.
```

Every undeterminable row needs **an instruction for settling it**: a query to run, a file to
open, a command to try. A row without one is an apology; with one it is often the most useful
line in the report.

And state the tier's limits alongside: static analysis cannot tell you whether a header is
actually sent or whether the anon key actually returns rows. Say which questions require
`/cg-live`.

---

## Why a quiet report without coverage is dangerous

The person reading this is about to make a deployment decision. They will read the verdict, and
if it is green they will ship.

- A report that says **"no findings"** answers *"did this tool find anything?"*
- A report that says **"no findings; 7 of 7 tables undeterminable because there are no
  migrations"** answers *"is my app safe?"* — with an honest **"unknown, and here is the query
  that will tell you."*

The second is less impressive and far more useful. It is also the only version that survives
being wrong: if the app is later breached through a table with RLS off, the report that listed
that table as undeterminable was **correct**, and the one that said "no findings" was a lie the
user acted on.

Two habits follow:

- **Never let a `clean` verdict stand alone.** Print it next to the coverage table and the count
  of `likely` / `needs-review` findings. `clean` means *nothing was proved*, not *nothing is
  wrong* — per `i18n/en.md`: *"No issues found at this tier. This is not a proof of safety."*
- **Be proud of the undeterminable rows.** They are the honest measure of the audit. A tool that
  reports twenty `undeterminable` routes and four real findings has told the truth; a tool that
  reports twenty-four passes has told a story.
