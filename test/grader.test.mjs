import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { grade } from '../plugin/scripts/grader.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')

function modelOf(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-gr-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return JSON.parse(execFileSync(process.execPath, [SCRIPT, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    }))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const NEXT_PKG = '{"name":"x","dependencies":{"next":"15.0.0"}}'

const subjectsIn = (set, disposition) => set[disposition].map(s => s.subject)
const entryFor = (set, disposition, subject) => set[disposition].find(s => s.subject === subject)
const findingsFor = (result, subject) => result.findings.filter(f => f.subject === subject)

// The confidence policy, restated here on purpose. If grader.mjs ever "fixes" a finding by
// nudging its confidence, this table — not the implementation — is what the tests believe.
const CONFIDENCE_BY_EVIDENCE = {
  definitive: 'confirmed',
  strong: 'likely',
  weak: 'needs-review',
  judgement: 'likely',
}

// ---------------------------------------------------------------------------
// One rich fixture, exercised by the whole-output laws (coverage adds up, confidence is a pure
// function of evidence, grading is deterministic). It deliberately contains a mix of definitive,
// strong and weak evidence, plus at least one subject in every disposition, because a law that is
// only ever checked against an empty report is not checked at all.
// ---------------------------------------------------------------------------

const RICH_FILES = {
  'package.json': '{"name":"rich","dependencies":{"next":"15.0.0","openai":"4.0.0","@supabase/supabase-js":"2.0.0"}}',

  'next.config.js': `module.exports = {
  env: { STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY },
  productionBrowserSourceMaps: true,
}`,

  // One table per migration file: the engine reads a policy's command and predicate from a small
  // look-ahead window, so packing unrelated policies together would let one table's `using (true)`
  // bleed into the next table's window.
  'supabase/migrations/001_orders.sql': 'create table public.orders ( id uuid primary key );',
  'supabase/migrations/002_profiles.sql': `create table public.profiles ( id uuid primary key );
alter table public.profiles enable row level security;
create policy "profiles are readable" on public.profiles for select using (true);`,
  'supabase/migrations/003_invoices.sql': `create table public.invoices ( id uuid primary key, owner uuid );
alter table public.invoices enable row level security;
create policy "own invoices" on public.invoices for select using (auth.uid() = owner);`,
  'supabase/migrations/004_promote.sql': `create function public.promote(uid uuid) returns void language plpgsql security definer as $$
begin
  update profiles set role = 'admin' where id = uid;
end;
$$;`,

  'lib/ai.ts': 'export const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY',
  'lib/cache.ts': 'export const ck = process.env.NEXT_PUBLIC_CACHE_KEY',
  'lib/db.ts': 'export const url = process.env.DATABASE_URL',
  'lib/admin.ts': `import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,

  'app/page.tsx': `'use client'
import { admin } from '../lib/admin'
export default function Page(){ return null }`,

  'app/api/orders/route.ts': 'export async function POST(req){ const body = await req.json(); return Response.json(body) }',
  'app/api/admin/route.ts': `export async function POST(req){
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY
  return Response.json({ ok: !!key })
}`,
  'app/api/me/route.ts': 'export async function GET(){ const u = await getUser(); return Response.json(u) }',
  'app/api/chat/route.ts': `import OpenAI from 'openai'
const client = new OpenAI()
export async function POST(req){
  const { prompt } = await req.json()
  return Response.json(await client.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: prompt }] }))
}`,
}

const RICH_OBSERVATIONS = [
  { tier: 'passive-live', kind: 'missing-csp', at: 'https://example.test/' },
  { tier: 'passive-live', kind: 'cookie-no-httponly', at: 'https://example.test/', detail: 'sb-access-token has no HttpOnly' },
]

// The engine is a subprocess; run it once for the whole file rather than once per assertion.
let RICH_MODEL = null
const richModel = () => (RICH_MODEL ??= modelOf(RICH_FILES))
const richResult = () => grade(richModel(), {
  observations: RICH_OBSERVATIONS,
  allowlist: ['route:app/api/me/route.ts'],
})

// ---------------------------------------------------------------------------
// LAW 1 — no subject may be marked `pass` because a token was present in the source.
//
// This is the failure the whole design exists to prevent. `getUser` appearing in a file proves
// nothing: the call may be unawaited, its result ignored, or its throw swallowed by a catch. A
// green checkmark there is worse than silence, because the user stops looking at the one route
// that was actually open.
// ---------------------------------------------------------------------------

test('LAW 1: a route that merely mentions getUser() is undeterminable, never a pass', () => {
  const result = grade(modelOf({
    'package.json': NEXT_PKG,
    'app/api/me/route.ts': 'export async function GET(){ const u = await getUser(); return Response.json(u) }',
  }))
  const subject = 'route:app/api/me/route.ts'

  assert.ok(!subjectsIn(result.coverage.routes, 'pass').includes(subject),
    'an auth token in the file is not proof the handler is gated — this must never read as verified')
  assert.deepEqual(subjectsIn(result.coverage.routes, 'undeterminable'), [subject])
  assert.match(entryFor(result.coverage.routes, 'undeterminable', subject).note, /not verified/,
    'the note must tell the reviewer WHY this landed on their work list')
  assert.match(entryFor(result.coverage.routes, 'undeterminable', subject).note, /authentication call is present/)
})

test('LAW 1: a SECURITY DEFINER function whose body mentions auth.uid() is undeterminable', () => {
  // A SECURITY DEFINER function bypasses RLS by design, so `auth.uid()` appearing in its body is
  // the only thing standing between anon and owner rights. "The string is in there somewhere" is
  // not the same as "the result of that call gates the update below it".
  const result = grade(modelOf({
    'supabase/migrations/001.sql': `create table public.notes ( id uuid primary key, owner uuid );
alter table public.notes enable row level security;
create policy "own notes" on public.notes for select using (auth.uid() = owner);

create function public.my_notes() returns setof notes language sql security definer set search_path = public as $$
  select * from notes where owner = auth.uid();
$$;`,
  }))
  const subject = 'sql-function:public.my_notes'

  assert.ok(!subjectsIn(result.coverage.sqlFunctions, 'pass').includes(subject),
    'pinning search_path and naming auth.uid() is necessary, not sufficient — it cannot be a pass')
  assert.ok(subjectsIn(result.coverage.sqlFunctions, 'undeterminable').includes(subject))
  assert.match(entryFor(result.coverage.sqlFunctions, 'undeterminable', subject).note,
    /whether the check actually gates the body is not verified/)
})

test('LAW 1: a server-side LLM call site is undeterminable, never a pass', () => {
  // Every LLM call site is somebody's monthly bill. Marking one `pass` because the file happens
  // to contain an auth token invites exactly the unbounded, unauthenticated endpoint that empties
  // a card overnight.
  const result = grade(modelOf({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","openai":"4.0.0"}}',
    'app/api/chat/route.ts': `import OpenAI from 'openai'
const client = new OpenAI()
export async function POST(req){
  const { user } = await getUser()
  return Response.json(await client.chat.completions.create({ model: 'gpt-4o-mini', messages: [] }))
}`,
  }))
  const subject = 'llm:app/api/chat/route.ts'

  assert.ok(!subjectsIn(result.coverage.llmSites, 'pass').includes(subject))
  assert.ok(subjectsIn(result.coverage.llmSites, 'undeterminable').includes(subject))
  assert.match(entryFor(result.coverage.llmSites, 'undeterminable', subject).note,
    /whether it is gated and bounded is not verified/)
})

// ---------------------------------------------------------------------------
// LAW 2 — enumerated === pass + fail + undeterminable + allowlisted, for every subject set.
//
// A subject that silently falls out of the ledger is how "we found nothing" comes to mean "we
// looked nowhere". The loop below reads the sets out of the output rather than naming them, so a
// set added next month is covered by this test the day it is added.
// ---------------------------------------------------------------------------

test('LAW 2: every subject set in coverage adds up', () => {
  const result = richResult()
  const sets = Object.entries(result.coverage)

  assert.ok(sets.length >= 8, 'the rich fixture must actually populate the ledger for this to mean anything')
  for (const [name, set] of sets) {
    const { pass, fail, undeterminable, allowlisted } = set.counts
    assert.equal(set.enumerated, pass + fail + undeterminable + allowlisted,
      `set "${name}" lost a subject between enumeration and reporting`)
    assert.equal(
      set.pass.length + set.fail.length + set.undeterminable.length + set.allowlisted.length,
      set.enumerated,
      `set "${name}" reports counts that disagree with the subjects it actually lists`)
  }

  // The equation is trivially satisfiable by an empty ledger, so prove the fixture exercises
  // every disposition at least once somewhere.
  const totals = { pass: 0, fail: 0, undeterminable: 0, allowlisted: 0 }
  for (const [, set] of sets) for (const d of Object.keys(totals)) totals[d] += set.counts[d]
  for (const [d, n] of Object.entries(totals)) assert.ok(n > 0, `no subject ever landed in "${d}"`)
})

test('LAW 2: recording the same subject twice throws instead of letting the last rule win', () => {
  // Two rules disagreeing about one subject is a bug in the rules, not something to paper over:
  // whichever ran last would silently overwrite the other, and a `fail` overwritten by a `pass`
  // is a hidden P0. Constructed by hand because the engine de-duplicates tables for us — the
  // guard has to hold for any model, including one a future engine hands over.
  const model = {
    database: {
      parserVersion: 2,
      tables: [
        {
          name: 'orders', knownFrom: ['migrations'], rlsCertainty: 'from-migrations',
          rlsEnabled: true, definedIn: 'a.sql:1',
          policies: [{ name: 'own orders', permissive: false, scopedToUid: true, at: 'a.sql:9' }],
        },
        { name: 'orders', knownFrom: ['supabase-types'], rlsCertainty: 'unknown-no-migration' },
      ],
    },
  }

  assert.throws(() => grade(model), /LAW 2: subject "table:orders"/)
  assert.throws(() => grade(model), /recorded twice \(pass then undeterminable\)/)
})

// ---------------------------------------------------------------------------
// LAW 3 — name-only evidence may never justify a P0.
//
// `FOO_API_KEY` in a variable name is not proof that a privileged credential exists. Half the
// names that look secret-ish are publishable identifiers, and firing a P0 at one is the anon-key
// trust catastrophe with a new variable name.
// ---------------------------------------------------------------------------

test('LAW 3: a credential-shaped name behind a public prefix is name-only evidence and is not P0', () => {
  const result = grade(modelOf({
    'package.json': NEXT_PKG,
    'lib/keys.ts': `export const cache = process.env.NEXT_PUBLIC_CACHE_KEY
export const pusher = process.env.NEXT_PUBLIC_PUSHER_APP_KEY`,
  }))

  const cache = findingsFor(result, 'env:NEXT_PUBLIC_CACHE_KEY')
  assert.equal(cache.length, 1)
  assert.equal(cache[0].evidence.nameOnly, true,
    'the only thing suggesting this is a secret is the identifier itself')
  assert.notEqual(cache[0].severity, 'P0',
    'a name is not a credential — P0 here is how a security tool teaches its audience to ignore it')
  assert.equal(cache[0].confidence, 'needs-review')
  assert.ok(cache[0].assumption, 'a needs-review finding must name what would make it a false positive')

  // PUSHER_APP_KEY is publishable by design — it belongs in the browser. It must not even reach
  // the name-only rule, or we would ask the user to "confirm" a key the vendor prints in its
  // quickstart.
  const pusher = 'env:NEXT_PUBLIC_PUSHER_APP_KEY'
  assert.ok(subjectsIn(result.coverage.envVars, 'allowlisted').includes(pusher))
  assert.equal(findingsFor(result, pusher).length, 0)
})

test('LAW 3 is enforced on the whole report, not just on the rules that remembered it', () => {
  for (const f of richResult().findings) {
    if (f.evidence.nameOnly) {
      assert.notEqual(f.severity, 'P0', `${f.id} claims P0 from a variable name`)
    }
  }
})

// ---------------------------------------------------------------------------
// Confidence is a pure function of Evidence.
//
// The same repo must always grade the same way. If any rule could pass a confidence in directly,
// the tool would drift toward whatever felt right the day each rule was written — and "confirmed"
// would stop meaning anything, which in turn breaks the verdict that counts only confirmed
// findings.
// ---------------------------------------------------------------------------

test('confidence is derived from evidence for every finding, with no exceptions', () => {
  const result = richResult()
  assert.ok(result.findings.length >= 8, 'a thin report would make this pass vacuously')

  for (const f of result.findings) {
    const expected = CONFIDENCE_BY_EVIDENCE[f.evidence.strength]
    assert.ok(expected, `${f.id} carries an evidence strength no policy covers: ${f.evidence.strength}`)
    assert.equal(f.confidence, expected,
      `${f.id} has evidence "${f.evidence.strength}" but confidence "${f.confidence}"`)
  }

  // The mapping is only meaningful if more than one strength is actually in play.
  const strengths = new Set(result.findings.map(f => f.evidence.strength))
  assert.ok(strengths.size >= 3, `only ${[...strengths]} appeared — the mapping is barely exercised`)
})

test('grading is deterministic — the same model twice yields the same report', () => {
  // Determinism is what lets a user re-run the tool after a fix and trust the diff. It is also
  // what makes the Set/Map iteration inside the ledger a liability worth pinning down.
  const model = richModel()
  const a = grade(model, { observations: RICH_OBSERVATIONS, allowlist: ['route:app/api/me/route.ts'] })
  const b = grade(model, { observations: RICH_OBSERVATIONS, allowlist: ['route:app/api/me/route.ts'] })
  assert.deepEqual(a, b)
})

// ---------------------------------------------------------------------------
// Severity is uncapped — and the verdict is what pays for the uncertainty.
//
// An earlier design capped severity by confidence. That buried the single most common real
// situation in this audience (no migrations, schema lives in the dashboard) at P3, where nobody
// looks. Severity now states impact-if-true and nothing else; the headline verdict counts only
// `confirmed` findings, so an unproven P0 is reported loudly without turning the badge red.
// These two behaviours only make sense together, so they are asserted together.
// ---------------------------------------------------------------------------

test('an unprovable RLS gap is P0 at needs-review, and does NOT make the verdict critical', () => {
  const result = grade(modelOf({
    'package.json': NEXT_PKG,
    'types/supabase.ts': `export type Database = {
  public: {
    Tables: {
      orders: { Row: { id: string } }
      profiles: { Row: { id: string } }
    }
    Views: {}
    Functions: {}
  }
}`,
  }))

  const cov = result.findings.find(f => f.id === 'CG-DB-COVERAGE')
  assert.ok(cov, 'a repo whose schema cannot be read must say so as a finding, not only as coverage')
  assert.equal(cov.severity, 'P0', 'impact-if-true: an unprotected table is a total exposure')
  assert.equal(cov.confidence, 'needs-review', 'the uncertainty lives here, not in the severity')
  assert.equal(cov.evidence.strength, 'weak')
  assert.match(cov.impact, /Run the query below/)
  assert.ok(result.verifyQuery, 'the user must be handed the query that settles it')

  assert.notEqual(result.verdict.level, 'critical',
    'the verdict counts only confirmed findings — an unproven P0 must not turn the badge red')
  assert.equal(result.verdict.confirmedP0, 0)
  assert.ok(result.verdict.needsReview >= 1)

  // Both tables must still be accounted for individually.
  assert.deepEqual(subjectsIn(result.coverage.tables, 'undeterminable').sort(),
    ['table:orders', 'table:profiles'])
})

test('a PROVEN P0 does turn the verdict critical — the other half of the same bargain', () => {
  const result = grade(modelOf({
    'supabase/migrations/001.sql': 'create table public.orders ( id uuid primary key );',
  }))
  const f = result.findings.find(x => x.id === 'CG-DB-001')
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'confirmed')
  assert.equal(result.verdict.level, 'critical')
})

// ---------------------------------------------------------------------------
// Key rules, one small fixture each.
// ---------------------------------------------------------------------------

test('NEXT_PUBLIC_OPENAI_API_KEY is a confirmed P0', () => {
  // Denial-of-wallet is the most common expensive mistake in this audience, and the public prefix
  // makes it provable rather than suspected: the bundler substitutes the value into client output
  // verbatim, so no graph reasoning stands between us and the claim.
  const result = grade(modelOf({
    'package.json': NEXT_PKG,
    'lib/ai.ts': 'export const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY',
  }))

  const f = result.findings.find(x => x.id === 'CG-ENV-001')
  assert.ok(f, 'a privileged provider key behind a bundler prefix must be reported')
  assert.equal(f.subject, 'env:NEXT_PUBLIC_OPENAI_API_KEY')
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'confirmed')
  assert.equal(f.evidence.strength, 'definitive')
  assert.equal(f.evidence.nameOnly, false, 'the prefix, not the name, is what proves this')
  assert.ok(subjectsIn(result.coverage.envVars, 'fail').includes('env:NEXT_PUBLIC_OPENAI_API_KEY'))
  assert.equal(result.verdict.level, 'critical')
})

test('REGRESSION: a non-prefixed secret read from a client-imported module is NOT a P0 leak', () => {
  // This is the exact shape that fired five confident P0s at a correct 184-star repo — one that
  // was using t3-env, the recommended guard against this very mistake. Bundlers inline only
  // allowlisted prefixes; a bare process.env.SECRET is simply absent from client output. The
  // engine was fixed for this; the grader is the second place it could regress, so it is guarded
  // here too.
  const result = grade(modelOf({
    'package.json': NEXT_PKG,
    'src/env.mjs': `export const env = createEnv({
  server: { STRIPE_SECRET_KEY: z.string() },
  client: { NEXT_PUBLIC_SITE_URL: z.string() },
  runtimeEnv: {
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
    NEXT_PUBLIC_SITE_URL: process.env.NEXT_PUBLIC_SITE_URL,
  },
})`,
    'src/providers/Provider.tsx': "'use client'\nimport { env } from '../env.mjs'\nexport default function P(){ return env.NEXT_PUBLIC_SITE_URL }",
  })).findings

  assert.equal(result.filter(f => f.severity === 'P0').length, 0,
    'no P0 may come out of a correctly-built repo that keeps its secrets on the server')
  const stripe = result.filter(f => f.subject === 'env:STRIPE_SECRET_KEY')
  for (const f of stripe) assert.notEqual(f.severity, 'P0')
})

test('the same non-prefixed secret lands in coverage.envVars.pass, not in a bucket that implies danger', () => {
  const result = grade(modelOf({
    'package.json': NEXT_PKG,
    'lib/cfg.ts': 'export const k = process.env.STRIPE_SECRET_KEY',
    'app/page.tsx': "'use client'\nimport { k } from '../lib/cfg'\nexport default () => k",
  }))

  assert.ok(subjectsIn(result.coverage.envVars, 'pass').includes('env:STRIPE_SECRET_KEY'))
  assert.match(entryFor(result.coverage.envVars, 'pass', 'env:STRIPE_SECRET_KEY').note,
    /absent from client output/)

  // The correctness bug is still reported — it is just a P3, not a breach. Users "fix" it by
  // adding NEXT_PUBLIC_, which WOULD be the P0, so saying nothing here is not an option either.
  const f = result.findings.find(x => x.id === 'CG-ENV-003')
  assert.ok(f, 'reading a server var from client code is a real bug worth one quiet line')
  assert.equal(f.severity, 'P3')
})

test('SUPABASE_ANON_KEY is allowlisted and produces a completely quiet report', () => {
  // The anon key is designed to sit in the browser; RLS is what protects the data behind it.
  // Reporting it as a leaked credential is the fastest way to teach this audience that the tool
  // cries wolf — after which nobody reads the P0 that matters.
  const result = grade(modelOf({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.0.0"}}',
    'lib/supabase.ts': `import { createClient } from '@supabase/supabase-js'
export const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)`,
  }))

  const subject = 'env:NEXT_PUBLIC_SUPABASE_ANON_KEY'
  assert.ok(subjectsIn(result.coverage.envVars, 'allowlisted').includes(subject))
  assert.match(entryFor(result.coverage.envVars, 'allowlisted', subject).note, /public by design/)
  assert.equal(result.findings.length, 0,
    'the idiomatic Supabase bootstrap is correct code and must grade silent')
  assert.ok(!JSON.stringify(result.findings).includes('ANON_KEY'))
})

test('a migration that creates a table and never enables RLS is a confirmed P0', () => {
  // Within the static tier the migration set IS the schema. It creates the table and never runs
  // `enable row level security`, so anyone holding the anon key from the bundle reads and writes
  // the whole table.
  const result = grade(modelOf({
    'supabase/migrations/001_init.sql': 'create table public.orders ( id uuid primary key, total numeric );',
  }))

  const f = result.findings.find(x => x.id === 'CG-DB-001')
  assert.ok(f)
  assert.equal(f.subject, 'table:orders')
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'confirmed')
  assert.equal(f.evidence.strength, 'definitive')
  assert.ok(f.assumption, 'the one way this can be wrong — RLS enabled in the dashboard — must be stated')
  assert.deepEqual(subjectsIn(result.coverage.tables, 'fail'), ['table:orders'])
})

test('a read-only `for select using (true)` policy is a needs-review world-readable finding, NOT a confirmed P0', () => {
  // The nuance the wild benchmark forced (bench/wild/nextjs-subscription-payments): `for select
  // using (true)` is the STANDARD Supabase pattern for public-by-design data — a products table,
  // published posts — so a confirmed P0 there turned the canonical starter `critical`, which is
  // cry-wolf. It is still surfaced (P1, world-readable IF the table is private) but as needs-review
  // with the public-by-design assumption, not a confirmed breach. Impact stays uncapped; confidence
  // carries the "we can't tell intent" doubt.
  const result = grade(modelOf({
    'supabase/migrations/001_init.sql': `create table public.profiles ( id uuid primary key );
alter table public.profiles enable row level security;
create policy "anyone can read" on public.profiles for select using (true);`,
  }))

  const f = result.findings.find(x => x.id === 'CG-DB-002')
  assert.ok(f)
  assert.equal(f.subject, 'table:profiles')
  assert.equal(f.severity, 'P1')
  assert.equal(f.confidence, 'needs-review')
  assert.ok(f.assumption, 'names the public-by-design escape so a one-second check settles it')
  assert.match(f.evidence.why, /anyone can read/, 'name the policy so the user can find it')
  assert.ok(!result.findings.some(x => x.id === 'CG-DB-001'),
    'RLS IS enabled — reporting both would be two rules disagreeing about one table')
})

test('a WRITABLE `using (true)` policy is STILL a confirmed P0 — world-writable is never intentional', () => {
  // The other half of the split: `for all`/insert/update/delete with a `true` predicate lets anyone
  // modify or delete every row. There is no public-by-design reading of that, so it stays definitive.
  const result = grade(modelOf({
    'supabase/migrations/001_init.sql': `create table public.notes ( id uuid primary key );
alter table public.notes enable row level security;
create policy "wide open" on public.notes for all using (true);`,
  }))
  const f = result.findings.find(x => x.id === 'CG-DB-002')
  assert.ok(f, 'a world-writable policy must still fire')
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'confirmed')
  assert.equal(f.evidence.strength, 'definitive')
})

test('a Prisma-only schema is allowlisted, not flagged for missing RLS', () => {
  // Prisma talks to Postgres as a privileged application user and enforces authorization in
  // application code. There is no RLS layer to be missing, so demanding one would bury a
  // correctly-built app under findings about a control it never adopted.
  const result = grade(modelOf({
    'package.json': '{"name":"x","dependencies":{"@prisma/client":"5.0.0"}}',
    'prisma/schema.prisma': 'model User {\n  id String @id\n}\nmodel Order {\n  id String @id\n}\n',
  }))

  assert.deepEqual(subjectsIn(result.coverage.tables, 'allowlisted').sort(), ['table:order', 'table:user'])
  assert.match(entryFor(result.coverage.tables, 'allowlisted', 'table:user').note, /ORM-managed/)
  assert.ok(!result.findings.some(f => f.id === 'CG-DB-001'))
  assert.ok(!result.findings.some(f => f.id === 'CG-DB-COVERAGE'),
    'an ORM schema is not an unknown — it is a schema with a different control')
  assert.equal(result.coverage.tables.counts.undeterminable, 0)
})

test('an unauthenticated mutating route is reported, but only at needs-review', () => {
  // The absence of an auth token proves nothing either: the check could live in a helper this
  // handler imports, which this pass does not follow. So the finding is real and worth a P1, and
  // the confidence says out loud that a human has to look.
  const result = grade(modelOf({
    'package.json': NEXT_PKG,
    'app/api/orders/route.ts': 'export async function POST(req){ const body = await req.json(); return Response.json(body) }',
  }))

  const f = result.findings.find(x => x.id === 'CG-WEB-001')
  assert.ok(f)
  assert.equal(f.subject, 'route:app/api/orders/route.ts')
  assert.equal(f.severity, 'P1')
  assert.equal(f.confidence, 'needs-review')
  assert.equal(f.evidence.strength, 'weak')
  assert.match(f.assumption, /helper/, 'name the way this can be wrong instead of hedging')
  assert.match(f.title_en, /\/api\/orders/, 'the user thinks in URLs, not in file paths')
  assert.deepEqual(subjectsIn(result.coverage.routes, 'fail'), ['route:app/api/orders/route.ts'])
})

test('an allowlisted subject moves to `allowlisted` and its finding disappears', () => {
  // A user who has decided a table is intentionally public must be able to say so once and stop
  // being told again — otherwise they stop reading the report entirely. It moves buckets rather
  // than vanishing, so LAW 2 still accounts for it.
  const model = modelOf({
    'supabase/migrations/001_init.sql': 'create table public.orders ( id uuid primary key );',
  })

  const before = grade(model)
  assert.ok(before.findings.some(f => f.subject === 'table:orders'))

  const after = grade(model, { allowlist: ['table:orders'] })
  assert.equal(after.findings.filter(f => f.subject === 'table:orders').length, 0)
  assert.deepEqual(subjectsIn(after.coverage.tables, 'allowlisted'), ['table:orders'])
  assert.equal(after.coverage.tables.counts.fail, 0)
  assert.equal(after.coverage.tables.enumerated, before.coverage.tables.enumerated,
    'allowlisting hides a finding, never a subject')
  assert.equal(after.verdict.level, 'clean')
})

// ---------------------------------------------------------------------------
// Live and DAST observations.
//
// The probes observe; they do not judge. The mapping from observation kind to severity lives in
// the grader with every other severity decision, and the tier travels with the finding because a
// fact about a running system can change tomorrow while a fact about committed code cannot.
// ---------------------------------------------------------------------------

test('live observations become findings that carry their tier', () => {
  const result = grade({}, {
    observations: [
      { tier: 'passive-live', kind: 'missing-csp', at: 'https://example.test/' },
      { tier: 'passive-live', kind: 'missing-hsts', at: 'https://example.test/' },
    ],
  })

  assert.equal(result.findings.length, 2)
  for (const f of result.findings) {
    assert.equal(f.tier, 'passive-live',
      'a reader must be able to tell a live fact from a source fact — the live one can change tomorrow')
    assert.equal(f.confidence, 'confirmed', 'the header was either there or it was not')
  }
  assert.ok(result.findings.some(f => f.id === 'CG-LIVE-CSP'))
  assert.ok(result.findings.some(f => f.id === 'CG-LIVE-HSTS'))
  assert.equal(result.coverage.liveObservations.counts.fail, 2)
})

test('an observation kind no rule owns is recorded as undeterminable, never dropped', () => {
  // A probe that learns a new trick before the grader does must not have its result silently
  // discarded — that is precisely how a report becomes quieter than the truth.
  const result = grade({}, {
    observations: [{ tier: 'passive-live', kind: 'quantum-entangled-cookie', at: 'https://example.test/' }],
  })

  assert.equal(result.findings.length, 0)
  assert.equal(result.coverage.liveObservations.enumerated, 1)
  assert.equal(result.coverage.liveObservations.counts.undeterminable, 1)
  assert.match(result.coverage.liveObservations.undeterminable[0].note,
    /no rule owns observation kind "quantum-entangled-cookie"/)
})

// ---------------------------------------------------------------------------
// The parserVersion guard.
// ---------------------------------------------------------------------------

test('a model from an SQL parser older than v2 is refused outright', () => {
  // v1 matched inside SQL comments, so
  //     -- alter table public.orders enable row level security;
  // made it report RLS as ENABLED on an unprotected table. Grading that model would print a
  // checkmark over a P0. Refusing is the only safe move: downgrading the finding would still
  // leave a report that says "we looked", and a security tool that says "you're fine" when you
  // are not is worse than no tool at all.
  const tables = [{
    name: 'orders', knownFrom: ['migrations'], rlsCertainty: 'from-migrations',
    rlsEnabled: true, definedIn: 'a.sql:1', rlsAt: 'a.sql:2', policies: [],
  }]

  assert.throws(() => grade({ database: { parserVersion: 1, tables } }), /older than version 2/)
  assert.throws(() => grade({ database: { tables } }), /older than version 2/,
    'a model with no parserVersion at all is just as untrustworthy')

  // The control: the identical model from a v2 parser grades normally.
  assert.doesNotThrow(() => grade({ database: { parserVersion: 2, tables } }))
})
