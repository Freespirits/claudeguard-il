# False positives — the catalogue

**Read this before reporting anything.**

Every entry below is a mistake that an earlier version of this tool actually made, or that the
engine has explicit code to prevent. They are not hypothetical. One of them fired **five
confident P0s at a correctly-built repo** — a repo that was correct *because* it used the exact
library designed to prevent that class of bug.

The cost is not embarrassment. A user who is told their API key is exposed will rotate keys,
tell their users there was a breach, and lose a day. Then they will stop opening the tool, and
the real P0 three lines down never gets fixed. **Volume is what destroys trust — not any single
finding.**

Each entry is: **signal → the naive reading → why it is wrong → what to do instead.**

---

## FP-01 · A non-prefixed `process.env.SECRET` in a client-imported module

**Signal.** `lib/stripe.ts` contains `process.env.STRIPE_SECRET_KEY`, and `lib/stripe.ts` is
reachable from a `'use client'` component.

**The naive reading.** "A secret is referenced in client code — it ships to the browser. P0."

**Why it is wrong.** Bundlers statically replace **only allowlisted prefixes**: `NEXT_PUBLIC_`,
`VITE_`, `PUBLIC_`, `EXPO_PUBLIC_`, `REACT_APP_`, `GATSBY_`, `NUXT_PUBLIC_`. Everything else is
simply **absent** from client output and evaluates to `undefined` in the browser. There is no
value in the bundle to steal. This is a *correctness* bug, not a breach.

This reading produced **five confident P0s against a correct repo that uses t3-env** — the
textbook guard *against* this very mistake. t3-env's `createEnv({ server, client, runtimeEnv })`
block necessarily **names every server variable in one file**, so the repo doing the right thing
looks maximally guilty to a naive scan. Reporting a best-practice pattern as a critical
vulnerability is precisely how a security tool loses its audience.

**What to do instead.**

- Exposure `referenced-in-client-module` → disposition **`pass`**, note: *"not inlined by the
  bundler — absent from client output."*
- If the reachability is **strong** and the name is credential-ish, emit a **P3**, evidence
  `strong`: *"`X` is read from client code and will be `undefined` in the browser."* Impact:
  *"a correctness bug that often gets 'fixed' by adding a public prefix — which **would** be a
  breach. Move the read to the server instead."*
- If you see `createEnv(` anywhere, record it and say the project is using an env guard. Credit
  it; never punish it.

---

## FP-02 · `SUPABASE_ANON_KEY` and friends reported as a leaked secret

**Signal.** `NEXT_PUBLIC_SUPABASE_ANON_KEY` is in `.env`, in the bundle, in the README.

**The naive reading.** "A key with `KEY` in the name is public. P0 credential exposure."

**Why it is wrong.** The anon key is **public by design**. It is meant to ship in every browser
client; that is its entire job. RLS is what protects the data behind it. The same is true of
`SUPABASE_URL`, `FIREBASE_API_KEY` and every other Firebase web config value, `SENTRY_DSN`,
`POSTHOG_KEY`, `STRIPE_PUBLISHABLE_KEY`, `MAPBOX_*`, `GOOGLE_MAPS_*`, `RECAPTCHA_SITE_KEY`,
`PUSHER_APP_KEY`, `ALGOLIA_SEARCH_KEY`, `VAPID_PUBLIC`.

This is the single most important false-positive guard in the tool for this audience, because
this exact finding is the one every naive scanner emits first, and every Supabase user has
already been told it is wrong. Emitting it identifies you as a tool that does not know Supabase.

**What to do instead.** Disposition **`allowlisted`**, note: *"public by design (anon /
publishable identifier)"*. Then go look at the thing that actually matters: **RLS on the tables
that key can reach.** If the anon key is exposed and RLS is off, the finding is *"table X has no
RLS"* — not *"the anon key leaked"*.

---

## FP-03 · `.eq('id', id)` on a `@supabase/ssr` client called an IDOR

**Signal.** `createServerClient(url, ANON_KEY, { cookies })`, then
`supabase.from('orders').select().eq('id', params.id)` with no visible ownership check.

**The naive reading.** "Reads an id from the request and queries without checking ownership.
Classic IDOR. P1."

**Why it is wrong.** `@supabase/ssr`'s `createServerClient` with the **anon key plus the user's
cookies** produces a **user-scoped** client. Every query it makes runs as that user, and RLS
with `auth.uid()` is the correct and sufficient control. The database refuses rows the user does
not own; the application code does not need a second check. This is the **officially
recommended** pattern.

Flag it and you flood every idiomatic Supabase app with false P1s — one per query — which is the
volume failure that destroys trust faster than any single wrong finding.

**What to do instead.**

- `createServerClient`, `createBrowserClient`, `createRouteHandlerClient`,
  `createServerComponentClient`, `createClientComponentClient`, `createMiddlewareClient`,
  `createPagesBrowserClient`, `createPagesServerClient` → identity **anon / user-scoped**,
  disposition **`pass`**, note: *"user-scoped, RLS is the control"*. IDOR must never be
  `confirmed` here.
- The IDOR question is real **only** where RLS is not the control: a **service-role** client, a
  Prisma/Drizzle connection, a raw `pg` pool. There, check ownership in application code and
  report it if missing.
- A plain `createClient(url, KEY)` whose key you cannot identify → **`undeterminable`**, not a
  guess in either direction.

---

## FP-04 · A variable that exists only in `.env.example`

**Signal.** `.env.example` contains `STRIPE_SECRET_KEY=`. Nothing else in the repo mentions it.

**The naive reading.** "A secret is declared in a committed file. P0/P1."

**Why it is wrong.** The name has **no value**, appears only in a template, and is **never read
by any code**. It describes a variable that does not exist yet. There is nothing to leak.
Reporting it manufactures a P0 out of documentation — and `.env.example` is the file the *good*
projects have.

**What to do instead.** Disposition **`pass`**, note: *"placeholder only — no value and no
reader"*.

The one exception worth a line: if the template pairs a **public prefix** with a
**credential-shaped name** (`NEXT_PUBLIC_STRIPE_SECRET_KEY=`), emit **P4**, evidence
`definitive` — *"the template teaches an unsafe pattern; whoever fills this in ships a secret to
the browser."* A future P0 with a written invitation, and cheap to fix now.

Note the different question: is the `.env` file itself **committed and holding real values**?
That is a genuine P0/P1 — but it is about `.env`, not `.env.example`, and it is about a *value*,
not a name.

---

## FP-05 · Reachability through a re-export barrel treated as proof

**Signal.** A `'use client'` component does `import { cn } from '@/lib'`. `lib/index.ts` is
`export * from './utils'; export * from './db'`. And `lib/db.ts` builds a service-role client.

**The naive reading.** "A client component imports a module that transitively imports the
service-role client. The key is in the bundle. P0."

**Why it is wrong.** A barrel is a pure re-export hub, and **tree-shaking drops unused
re-exports**. Importing `cn` does not mean the bundler ships `lib/db.ts`. Treating a
barrel-mediated chain as strong evidence fabricates a P0 on a correct app — and a wrong P0 makes
people rotate production keys and announce a breach that never happened.

**What to do instead.** Classify reachability strength while you walk the graph:

- **strong** — the file *is* a client entrypoint, or is imported **directly** by one, one hop,
  not through a barrel.
- **weak** — transitive, or through a barrel (≥ ~60% of its non-blank lines are `export … from`).

Keep the severity (a service-role key in the bundle is a P0 **if true**), but set evidence
`weak` → confidence `needs-review`, and name the assumption: *"that tree-shaking does not drop
this module from the client bundle."* Then tell the user how to settle it: build and grep the
output for the key shape.

---

## FP-06 · A chain through a module that does `import 'server-only'`

**Signal.** A client component's import chain passes through `lib/session.ts`, which starts with
`import 'server-only'`.

**The naive reading.** "The graph says it is reachable from the client. Report it."

**Why it is wrong.** `server-only` exists to make exactly this a **build error**. If a client
component could reach that module, the app would not compile. The chain **cannot exist** in an
app that ships.

**What to do instead.** Stop the client-reachability walk at any module containing
`import 'server-only'`. Do not propagate through it, and do not report anything downstream of it
as client-exposed. Record the module in the server-only list — it is a signal that this project
knows what it is doing.

---

## FP-07 · RLS enabled with zero policies read as "unprotected"

**Signal.** `alter table public.audit_log enable row level security;` and no `create policy` for
that table anywhere.

**The naive reading.** "RLS is on but there are no policies protecting it. Something is missing.
P1."

**Why it is wrong.** RLS with no policies is **deny-all**. Every anon and authenticated query
returns nothing. It is the *safe* direction — strictly safer than a table with a policy.

**What to do instead.** Disposition **`pass`**, note: *"RLS enabled with no policies —
deny-all"*. Emit a **P4** advisory anyway, because the app is probably broken in a way the user
has not noticed, and the fix people reach for under time pressure is `using (true)` — which
*is* a P0. Point at the scoped-policy recipe, not at "add a policy".

Related, same family: **RLS on with non-permissive policies is a structural `pass`**, because
the predicate is in the migration, not inferred from a token in application code. Only a policy
whose predicate is literally `true` (`using (true)` / `with check (true)`) is a P0.

---

## FP-08 · Demanding RLS from a Prisma or Drizzle project

**Signal.** `schema.prisma` defines twelve models. No `.sql` file enables RLS on anything.

**The naive reading.** "Twelve tables with no row level security. Twelve P0s."

**Why it is wrong.** Prisma and Drizzle projects talk to Postgres as a **privileged application
user** and enforce authorization in application code. There is no RLS layer to be missing. The
anon-key threat model does not apply, because there is no anon key: nothing in the browser talks
to the database directly.

Demanding a control the project never adopted floods a correctly-built app with findings about
an architecture it does not use.

**What to do instead.** A table known only from `prisma` or `drizzle` (and not from migrations)
→ disposition **`allowlisted`**, note: *"ORM-managed schema — RLS is not the control here"*.
Then ask the question that *is* right for this architecture: does each query filter by the
session user, and is authorization enforced server-side? That is a reviewer question, graded as
`judgement`.

(If the project has *both* — Drizzle plus Supabase migrations that enable RLS — grade the
migrations normally. The migration is proof; the ORM is not.)

---

## FP-09 · Matching raw SQL, comments and all

**Signal.** A migration file contains:

```sql
-- alter table public.orders enable row level security;
```

**The naive reading.** "RLS is enabled on `orders`. Pass."

**Why it is wrong.** This is the catalogue's one **false negative**, and it is here because it
is worse than any false positive in the file: it prints a **checkmark over a P0**. The same trap
catches `create policy` inside a comment block, and `enable row level security` inside a string
literal in a seed script.

**What to do instead.** Before matching anything in a `.sql` file, blank out `--` line comments,
`/* */` blocks, and string literals — while preserving line numbers, so your `file:line`
evidence stays exact. Read dollar-quoted function bodies (`$$ … $$`) separately rather than
discarding them: that is where `SECURITY DEFINER` logic lives, and dropping it would trade one
blind spot for a worse one.

The same rule applies to `next.config.*` and to JS/TS: a commented-out `publicRuntimeConfig` is
not config.

---

## FP-10 · A credential-shaped name treated as a credential

**Signal.** `NEXT_PUBLIC_PUSHER_APP_KEY`, `NEXT_PUBLIC_GOOGLE_MAPS_KEY`, `IDEMPOTENCY_KEY`,
`CACHE_KEY`, `PUBLIC_TURNSTILE_SITE_KEY`.

**The naive reading.** "`KEY` behind a public prefix. Secret in the bundle. P0."

**Why it is wrong.** These are publishable identifiers. `_KEY` in a name means almost nothing:
half the ecosystem's public identifiers are called `KEY`. This is LAW 3's whole reason for
existing — it is the anon-key catastrophe (FP-02) wearing a variable name you have not seen
before.

**What to do instead.** Split names into tiers before grading (see `enumerate.md` §3b):

- **`high`** (`SERVICE_ROLE`, `*_SECRET`, `PRIVATE_KEY`, `PASSWORD`, `DATABASE_URL`, named
  provider keys like `OPENAI_API_KEY`/`STRIPE_SECRET_KEY`…) behind a public prefix → **P0**,
  evidence `definitive`.
- **`weak`** (everything else matching `API_KEY|TOKEN|CREDENTIAL|_KEY$|AUTH`) behind a public
  prefix → **P2**, evidence `weak`, `nameOnly: true`, confidence `needs-review`, with the
  assumption stated: *"that this key actually grants privileged access rather than being a
  public identifier."* Title it as a question — *"`X` is public — confirm it is meant to be"* —
  not as an accusation.
- **`none`** behind a public prefix → **`pass`**. A public prefix on a non-credential is what
  the prefix is *for*.

---

## FP-11 · `getUser` in the file read as "this route is authenticated"

**Signal.** `app/api/orders/route.ts` contains the string `getUser`.

**The naive reading.** "Auth is present. Mark the route `pass`, move on."

**Why it is wrong.** This is **LAW 1 in its purest form**. From a text match you cannot tell an
awaited, checked `getUser()` from one that is unawaited, one whose result is never compared, or
one whose throw is swallowed by a `try/catch`. All three look identical. Marking it `pass` is
precisely the failure this whole design exists to prevent — the user sees a checkmark and stops
looking.

The inverse is FP-12: the *absence* of the token is not proof either.

**What to do instead.** Disposition **`undeterminable`**, note: *"an authentication call is
present, but whether it gates the handler is not verified."* That row goes on the reviewer's
work list — and a reviewer who reads the handler and concludes the check is decorative writes a
finding with evidence `judgement`, confidence `likely`, provenance `reviewer`.

Same rule for `SECURITY DEFINER` functions whose body mentions `auth.uid()`: mentioning it is
not gating on it. `undeterminable`.

---

## FP-12 · "No auth in this file" reported as an unauthenticated route

**Signal.** A route handler contains none of the auth tokens.

**The naive reading.** "No authentication. Confirmed P1."

**Why it is wrong.** Two ways it can be wrong, and both are common:

1. **The check lives in a helper the route imports** — `withAuth(handler)`, `requireSession()`
   in `lib/auth.ts`. A single-file read does not follow that.
2. **Middleware covers the path.** `middleware.ts` with an auth call and a `matcher` that
   matches this URL protects the route centrally. Reporting it produces one false finding per
   route — twenty at once on a correctly-built app.

**What to do instead.** Read `middleware.ts` first and check whether a matcher covers the route's
URL path. If it does, the route is **`undeterminable`** (*"middleware auth covers `/api/orders`,
but whether it rejects unauthenticated callers is not verified"*), not a fail. If nothing covers
it, report it — but with evidence **`weak`** → `needs-review`, severity uncapped by
consequence (service-role → P0, mutating → P1, read → P2), and the assumption named: *"that
authentication is not performed inside a helper this handler imports, which this pass does not
follow."*

When parsing a matcher, be conservative toward **under-claiming coverage**: an unparseable
pattern means "cannot demonstrate protection", so the route stays in the report as
undeterminable rather than being silently marked safe.

---

## FP-13 · A server-side service-role client reported as a leak

**Signal.** `lib/supabase/admin.ts` builds `createClient(url, SUPABASE_SERVICE_ROLE_KEY)`.

**The naive reading.** "Service-role key in the codebase. P0."

**Why it is wrong.** Server-side service-role usage is legitimate, extremely common, and often
necessary (webhooks, cron jobs, admin operations). The key never reaches the browser. What is
true is narrower: **RLS is not a control for anything this client touches**, so authorization
has to be enforced in the code around it.

**What to do instead.** If the module is **not** client-reachable → **`undeterminable`**, note:
*"server-side service-role client — RLS does not apply to it, so its own authorization is not
verified here."* That is an honest work-list row, not a finding.

It becomes a **P0** only when the module is client-reachable — and then FP-05 decides whether the
evidence is `strong` (direct import) or `weak` (through a barrel).

---

## FP-14 · A table from generated types assumed to have RLS off

**Signal.** `database.types.ts` lists `profiles`, `orders`, `messages`. No migration mentions
any of them.

**The naive reading.** Either *"no `enable row level security` found → RLS is off → three P0s"*
or *"nothing found → nothing to report"*.

**Why it is wrong.** Both directions are false. Claiming `false` **invents** a P0; claiming
`true` (or staying silent) **hides** one. The repo contains no evidence either way — the tables
were created in the Supabase dashboard, which is the normal workflow for this audience.

**What to do instead.** Mark every such table **`undeterminable`** — *"discovered from
supabase-types; no migration proves its RLS state"* — and emit **one** coverage finding for all
of them, not one per table: severity **P0** (impact-if-true: an unprotected table is total
exposure), evidence **`weak`** → `needs-review`, so it does not turn the verdict red. Then hand
over the verify query from `enumerate.md` §2 so the user can answer it in ten seconds.

One loud blocking unknown, not N quiet ones.

---

## FP-15 · `next.config` `env:` graded as definitive

**Signal.** `next.config.js` contains an `env: { ... }` block.

**The naive reading.** "`env:` inlines values into the client bundle. Definitive P0."

**Why it is wrong.** Half right, and the half that is wrong matters. The *block* is definitively
there and it definitively inlines whatever it lists — bypassing the prefix convention that
everything else in the model relies on. But **which** variables are inside it is a separate
question you may not have answered.

**What to do instead.** Severity **P0 if the repo contains a privileged (`high`-class) secret at
all**, otherwise **P2** — impact-if-true, decided once. Evidence **`strong`**, not `definitive`,
with the assumption named: *"that a privileged value is among the ones listed in the block."*
Same treatment for `publicRuntimeConfig`.

---

## FP-16 · A dependency CVE with no reachable call path

**Signal.** `npm audit` reports a critical CVE in a transitive dependency.

**The naive reading.** "Critical CVE. P0."

**Why it is wrong.** Severity is capped by **reachability**. A deserialization CVE in a package
only used by a build-time plugin is not a P0 for this app, and shipping a wall of upstream
advisories buries the two findings that are actually about this codebase.

**What to do instead.** Take the CVE's severity, cap it by whether the vulnerable path is
reachable from application code, and say which. If you cannot establish reachability, that is
`undeterminable` with the package named — not a P0.

---

## The general rule

When a signal is ambiguous, ask **"what would have to be true for this to be a real problem?"**
and then ask **"can I see that from here?"**

- If yes → grade it, with the mechanism in `why`.
- If no → it is `undeterminable`, and it goes on the work list with an instruction for settling
  it.

The one thing you may never do is resolve the ambiguity in the direction that makes the report
look more impressive.
