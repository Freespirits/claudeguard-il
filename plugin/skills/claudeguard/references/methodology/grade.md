# Grade — severity and confidence policy

Grading is the **only** place severity is decided. Not while reading a file, not while writing
the report. One authority, one policy, applied to the inventory from `methodology/enumerate.md`.

If severity is re-derived in every place you notice something, the same repo grades differently
on Tuesday, and every argument about a finding turns into an argument about the whole model.

The P0–P4 ladder itself lives in `severity-model.md`. This file is the *policy* for applying it.

---

## The two axes, and why they must stay separate

**Severity = impact if the finding is true.** Nothing else. Not how sure you are. Not how likely
exploitation is in practice. Just: if this is real, how bad?

**Confidence = belief that it is real.** Derived from evidence, and from nothing else.

> **Severity is never reduced because you are unsure.** Uncertainty is Confidence's job.
> Discounting twice — once by softening P0 to P2, once by marking it needs-review — buries a
> catastrophic-but-unproven issue where nobody looks. A user scanning for red never sees it.

The system pays for uncapped severity in exactly one place: **the headline verdict counts only
`confirmed` findings.** An unproven P0 is printed as a P0, sorted to the top, and does *not*
turn the badge red. That is the whole trade, and it only works if you hold both halves.

---

## Evidence — the four strengths

Evidence is how solidly the underlying Fact is established. Pick the level by asking: *what
would have to be true for this to be wrong?*

### `definitive` — the compiler, the bundler, or the file itself guarantees it. No inference.

Nothing can break the chain. There is no assumption to name.

- `NEXT_PUBLIC_STRIPE_SECRET_KEY` exists. The prefix means the bundler **textually substitutes**
  the value into client output. Whether anyone imports it correctly is irrelevant.
- A migration runs `create table public.orders` and no migration ever runs
  `alter table public.orders enable row level security`. Within the static tier, the migration
  set *is* the schema.
- `dangerouslyAllowBrowser: true` appears in an OpenAI client construction. The SDK's own guard
  against shipping a key to the browser has been explicitly switched off.
- `next.config` contains a `publicRuntimeConfig:` block. The block is right there.
- A live probe fetched the URL and there was no `Content-Security-Policy` response header.

### `strong` — a direct, single-hop observation. One thing could be true that makes it wrong.

- A module that constructs a service-role Supabase client is imported **directly** by a
  `'use client'` file — one hop, no barrel. *Wrong only if* the bundler drops it, which at one
  hop it will not.
- A `SECURITY DEFINER` function's body never mentions `auth.uid()` or `auth.jwt()`.
  *Wrong only if* authorization is enforced by something the body calls.
- A variable with no public prefix is read in a module reachable from a client entrypoint —
  strong evidence of a **runtime-undefined bug**, which is what it actually is (FP-01).
- `next.config` sets `env:` and the repo also contains a privileged secret. The block is
  definitive; *which* variables are inside it is not, so the finding is strong, and the
  assumption "that a privileged value is among the ones listed" gets named.

### `weak` — inferred through a chain that could break.

- A route handler contains no recognisable auth token. **The check could live in a helper the
  route imports**, which this pass does not follow.
- A module is client-reachable **only through a re-export barrel**, where tree-shaking may drop
  it entirely.
- A table appears in generated types but in no migration, so nothing in the repo states its RLS
  state.
- No rate-limiting call appears in an LLM handler — but limiting may be applied at the edge or
  in middleware.

### `judgement` — a reviewer read the code and formed a view no rule could have enumerated.

- "This handler checks `session.user.id` but then queries by `body.userId`, so the check gates
  nothing." No pattern enumerates that; someone had to read it.
- "This admin route is only linked from the admin UI, but nothing server-side enforces role."
- "The ownership filter is applied to the wrong table in the join."

Findings with `judgement` evidence carry `provenance: reviewer`, and the report says so, because
"a rule proved this" and "a reviewer thinks this" warrant different responses from the user.

---

## Confidence — a pure function of evidence

| Evidence | Confidence | |
|---|---|---|
| `definitive` | **`confirmed`** | The only level eligible for the headline verdict and for auto-fix. |
| `strong` | **`likely`** | |
| `weak` | **`needs-review`** | |
| `judgement` | **`likely`** | Capped here. See below. |

Nothing else may set confidence. Not how important the finding feels, not how much you want the
user to act on it.

**Why `judgement` → `likely` and not `needs-review`:** a reviewer who read the code and formed a
view has done strictly more work than a regex that half-matched. But it is **capped** there and
can never reach `confirmed`, because no amount of reading is a proof.

**Verification may only refute.** After grading, re-check each finding adversarially against the
real code. That pass has exactly two legal outcomes: **drop** the finding, or **correct the
evidence** it rests on — for example, showing that a chain believed to be direct actually runs
through a re-export barrel, which is `weak`, not `strong`. Confidence is then re-derived from the
corrected evidence by the table above; the verifier never writes a confidence value itself.

It may never raise confidence, by either route. Confidence is a function of evidence, so if the
evidence is unchanged the confidence cannot change — and if an argument alone could move it, the
same repo would grade differently depending on how hard someone squinted. The legitimate way to
reach `confirmed` is to go get **better evidence** (run `/cg-live` and observe the live system),
not to argue more persuasively.

---

## LAW 3 — name-only evidence never justifies a P0

If the **only** thing establishing a finding is an identifier's name, mark it `nameOnly` and cap
it below P0. No exceptions.

`FOO_API_KEY` is not a credential. `PUSHER_APP_KEY`, `IDEMPOTENCY_KEY`, `CACHE_KEY` and
`NEXT_PUBLIC_GOOGLE_MAPS_KEY` are all publishable by design. The correct shape for a
credential-shaped name behind a public prefix is:

> **P2**, evidence `weak`, confidence `needs-review`, `nameOnly: true`, with the assumption
> stated: *"that this key actually grants privileged access rather than being a public
> identifier."*

The name may open the investigation. Only a value, a definitive exposure, or a name from the
small `high` set (see `enumerate.md` §3b) may close it at P0.

---

## Choosing the severity

Read `severity-model.md` for the ladder. The recurring judgement calls, decided once here:

| Situation | Severity | Why |
|---|---|---|
| Privileged secret behind a bundler-inlined public prefix | **P0** | It is in the bundle. Anyone opens DevTools. |
| Service-role Supabase client in client-reachable code | **P0** | The key bypasses RLS entirely for any visitor who reads it. |
| Table with RLS off (proved by migrations) | **P0** | The anon key ships in every browser client; the table is world read/write. |
| RLS on, but a policy uses `using (true)` | **P0** | Protection reads as present in the dashboard while granting everything. |
| `SECURITY DEFINER` function with no auth check in the body | **P0** | Callable by anon via `rpc()`, runs as owner, bypasses every policy you wrote. |
| LLM SDK with `dangerouslyAllowBrowser: true` | **P0** | Billable key in the bundle. Unbounded spend. |
| Unauthenticated route that **uses the service-role key** | **P0** | Anonymous caller acts as database owner. |
| Unauthenticated **mutating** route | **P1** | Anonymous caller changes data. |
| Unauthenticated **read** route | **P2** | Anonymous caller reads data. |
| `SECURITY DEFINER` without a pinned `search_path` | **P1** | Privilege escalation to the function owner. |
| User input reaches a prompt at a site that defines tools | **P1** | Injection with a reachable consequence. |
| Missing security headers / no body validation / no rate limit | **P2** | Raises risk, eases other attacks. |
| No LLM rate limit | **P2** | Denial of wallet — real money, first night, no breach required. |
| Source maps in prod, build errors suppressed, ESLint suppressed | **P3** | Removes a safety net; not a breach. |
| A non-prefixed var read in client code (undefined at runtime) | **P3** | A correctness bug — and the "fix" people reach for **would** be a breach. |
| `.env.example` pairs a public prefix with a credential-shaped name | **P4** | Nothing leaks yet. A future P0 with a written invitation. |
| RLS on with zero policies (deny-all) | **P4** | Safe. Report it because the app is probably broken and the panic fix is `using (true)`. |

Note the pattern: **severity tracks what the attacker gets, not how visible the mistake is.**

---

## What every finding must carry

Per `severity-model.md`'s schema. Three fields deserve special emphasis:

- **`at`** — file:line, shown to the user verbatim so they can check your work in their own
  editor. A finding with no location is an opinion.
- **`why`** — the mechanism, in one sentence: *"`NEXT_PUBLIC_` is a bundler-inlined prefix, so
  this value is present in client output verbatim."* Not the category name.
- **`assumption`** — **what would have to be true for this to be a false positive.** Required
  for anything below `confirmed`. A `likely` finding with no named assumption is just hedging,
  and it gives the user nothing to check.

`exploit` is one concrete sentence — *attacker does X, gets Y*. `impact` is the business
consequence — data, accounts, money. `guard` points at the exact recipe in `guard-recipes/`.

**Bilingual requirement:** `title_en` **and** `title_he` are both mandatory, and every prose
field rendered to the user (what & why, exploit, impact, next steps) appears in Hebrew and
English per `report-template.md`, with labels from `i18n/he.md` and `i18n/en.md`. Code, file
paths, identifiers, SQL and guard snippets stay English only.

---

## The verdict

```
verdict counts ONLY findings whose confidence is `confirmed`
  any confirmed P0 → critical
  else any confirmed P1 → high
  else any confirmed P2 → medium
  else any confirmed at all → low
  else → clean
```

Report alongside it the count of `likely` and `needs-review` findings, so "clean" never reads as
"nothing to look at". `clean` means *nothing was proved*, not *nothing is wrong* — and the
coverage block (`methodology/coverage.md`) is what makes that difference legible.

**Ordering:** severity first (P0→P4), then confidence (`confirmed` → `likely` → `needs-review`),
then id. The thing to fix now goes at the top.

---

## Before you print: the checklist

1. Is any P0 resting on a name alone? → LAW 3 violation. Cap it and mark `nameOnly`.
2. Does every confidence match its evidence per the table above? No hand-adjustments.
3. Does every finding below `confirmed` name its assumption?
4. Did you read `methodology/false-positives.md` and check each finding against it?
5. Does every enumerated subject have exactly one disposition, and does the arithmetic add up?
   → `methodology/coverage.md`.
6. Did severity get lowered anywhere "because we're not sure"? Put it back and lower the
   confidence instead.
