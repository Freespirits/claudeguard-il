import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { grade } from '../plugin/scripts/grader.mjs'
import {
  parseIntentYaml, validateIntent, proposeIntent, rlsProvesOwnerScope, routeIsRlsControlled,
  auditBusinessLogic, TAXONOMY, DECLARED_CLASSES,
} from '../plugin/scripts/business_logic.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ENGINE = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')

function scan(files, opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-bl-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    const model = JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    }))
    return { model, report: grade(model, opts) }
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const bizFindings = r => r.findings.filter(f => f.id.startsWith('CG-BIZ-'))

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS
//
// The business-logic tier asks the one question the code cannot answer by itself: what is this app
// SUPPOSED to permit? "User A can read user B's order" is a critical bug in a store and a deliberate
// feature in an admin console — byte-identical code, opposite verdicts. So this tier can never
// PROVE anything; it checks code against a STATED intent, and either the code or the intent may be
// wrong.
//
// That makes it the most dangerous tier in the tool, and it shipped with no tests at all. It was
// also, as committed, DEAD: `grader.mjs` imported `auditBusinessLogic` and never called it. Wiring
// it in is what surfaced the defect these tests now pin — see "the missing config file".
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE CEILING. Everything else here matters less than this.
// ---------------------------------------------------------------------------

test('THE CEILING: a business-logic finding can never be confirmed', () => {
  // This is the entire reason the tier is safe to ship. The verdict counts only `confirmed`
  // findings, so as long as this holds, a guess about business rules cannot move the badge no
  // matter how wrong it is. If this test ever fails, the tier is no longer safe — fix the policy,
  // do not relax the test.
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': `create table public.orders (
      id uuid primary key,
      user_id uuid not null,
      total numeric,
      status text
    );`,
    'lib/db.ts': `import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    'app/api/orders/[id]/route.ts': `import { admin } from '@/lib/db'
export async function GET(req, { params }) {
  const { data } = await admin.from('orders').select('*').eq('id', params.id).single()
  return Response.json(data)
}`,
  }, { intent: { roles: ['user'], default_role: 'user', resources: { orders: { owned_by: 'user_id' } } } })

  for (const f of bizFindings(report)) {
    assert.notEqual(f.confidence, 'confirmed', `${f.id} reached confirmed — the ceiling is broken`)
    assert.equal(f.provenance, 'reviewer', `${f.id} must be attributed to a reviewer, not a rule`)
    assert.equal(f.evidence.strength, 'judgement', `${f.id} must rest on judgement`)
  }
})

test('THE CEILING holds through the verdict: business logic never turns the badge red', () => {
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': 'create table public.orders (id uuid primary key, user_id uuid, total numeric);',
    'lib/db.ts': `import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    'app/api/orders/[id]/route.ts': `import { admin } from '@/lib/db'
export async function GET(req, { params }) {
  return Response.json(await admin.from('orders').select().eq('id', params.id))
}`,
  }, { intent: { roles: ['user'], resources: { orders: { owned_by: 'user_id' } } } })

  const confirmedBiz = bizFindings(report).filter(f => f.confidence === 'confirmed')
  assert.deepEqual(confirmedBiz, [], 'no business-logic finding may ever be confirmed')
})

// ---------------------------------------------------------------------------
// The missing config file. This is the defect that wiring the tier in exposed.
// ---------------------------------------------------------------------------

test('a repo with NO intent file produces no business-logic finding — a missing config is not a vulnerability', () => {
  // `bl-intent-unconfirmed` used to be a P2 finding. Since almost nobody has written a
  // claudeguard.intent.yml on their first scan, that put CG-BIZ-010 in the findings list of
  // essentially every report: the tool reporting a security finding because the user had not
  // configured it yet. Nothing about the app is wrong there — something about our knowledge is.
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}',
    'app/page.tsx': 'export default function Page() { return null }',
  })
  assert.deepEqual(bizFindings(report), [], 'not configuring the tool is not a finding about the app')
})

test('...but the gap is recorded LOUDLY as coverage, so it cannot read as a clean result', () => {
  // The other half. Silence would be worse than the false finding: a business-logic section that
  // says nothing reads as "checked and fine".
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': 'create table public.orders (id uuid primary key, user_id uuid);',
  })
  assert.equal(report.businessLogic.status, 'assumed')
  assert.ok(report.businessLogic.assumptions.some(a => /assumed|ASSUMED/.test(a)),
    'the report must state plainly that the ownership model was assumed')
  assert.ok(report.businessLogic.proposedIntent,
    'and hand back a proposed intent file the user can correct — proposing is what makes it a review rather than a guess')

  const row = report.coverage.businessLogic?.undeterminable
    ?.find(s => s.subject === 'business-logic:intent')
  assert.ok(row, 'the unconfirmed intent must appear as an undeterminable coverage row')
})

// ---------------------------------------------------------------------------
// The false-positive guard the spec calls out by name.
// ---------------------------------------------------------------------------

const RLS_MIGRATION = `create table public.orders (id uuid primary key, user_id uuid not null, total numeric);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for select using (auth.uid() = user_id);`

const ID_ROUTE = `import { db } from '@/lib/db'
export async function GET(req, { params }) {
  const { data } = await db().from('orders').select('*').eq('id', params.id).single()
  return Response.json(data)
}`

test('CRY WOLF: the recommended Supabase pattern is NOT flagged', () => {
  // A `@supabase/ssr` server client carries the user's session cookie, so `auth.uid()` resolves and
  // the RLS policy above genuinely scopes the rows. This is what Supabase's own documentation tells
  // people to build, and `.eq('id', params.id)` on top of it is correct code. Flagging it would fire
  // on the single largest group of users this tool has.
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/ssr":"0.5.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': RLS_MIGRATION,
    'lib/db.ts': `import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
export function db() {
  const store = cookies()
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, {
    cookies: { get: (n) => store.get(n)?.value },
  })
}`,
    'app/api/orders/[id]/route.ts': ID_ROUTE,
  }, { intent: { roles: ['user'], resources: { orders: { owned_by: 'user_id' } } } })

  const idor = bizFindings(report).filter(f => f.id === 'CG-BIZ-001')
  assert.deepEqual(idor, [], 'RLS on the owning column already enforces this — flagging it is a false positive')

  const cls = report.businessLogic.resources.find(r => r.resource === 'orders')
    ?.classes.find(c => c.class === 'object-level-authz')
  assert.equal(cls.disposition, 'pass', 'and the guard must record WHY it stayed quiet, not just stay quiet')
})

test('a BARE anon client is not user-scoped — auth.uid() is null, so RLS is not the control', () => {
  // The subtlety that makes the guard narrow, and it is easy to get backwards. `createClient(url,
  // ANON_KEY)` on a server route carries no session, so `auth.uid()` is NULL and a
  // `using (auth.uid() = user_id)` policy matches nothing. It must NOT satisfy the guard — only the
  // @supabase/ssr factories, which pass the user's cookies, do.
  const { model } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': RLS_MIGRATION,
    'lib/db.ts': `import { createClient } from '@supabase/supabase-js'
export const db = () => createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)`,
    'app/api/orders/[id]/route.ts': ID_ROUTE,
  })
  assert.equal(model.supabaseClients[0].identity, 'anon-public')
  const route = model.routes.find(r => r.file.includes('orders'))
  assert.equal(route.reachesAnonScopedClient, false,
    'a session-less anon client must not count as user-scoped, or the guard would silence a real IDOR')
})

test('CONTROL: the same route through a SERVICE-ROLE client is not protected by RLS', () => {
  // The other direction, and the reason the guard is narrow. A service-role key BYPASSES RLS, so
  // the database is no longer the control and the application code has to do the check itself. If
  // this stopped being reported, the guard above would be hiding real bugs.
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': `create table public.orders (id uuid primary key, user_id uuid not null);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for select using (auth.uid() = user_id);`,
    'lib/db.ts': `import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    'app/api/orders/[id]/route.ts': `import { admin } from '@/lib/db'
export async function GET(req, { params }) {
  const { data } = await admin.from('orders').select('*').eq('id', params.id).single()
  return Response.json(data)
}`,
  }, { intent: { roles: ['user'], resources: { orders: { owned_by: 'user_id' } } } })

  const cls = report.businessLogic.resources
    .find(r => r.resource === 'orders')?.classes
    .find(c => c.class === 'object-level-authz')
  assert.ok(cls, 'the class must be walked')
  assert.notEqual(cls.disposition, 'pass',
    'a service-role query is not protected by RLS, so this must not pass')
})

// ---------------------------------------------------------------------------
// rlsProvesOwnerScope — the unit behind the guard.
// ---------------------------------------------------------------------------

test('rlsProvesOwnerScope: RLS off is never proof', () => {
  assert.equal(rlsProvesOwnerScope({ name: 't', rlsEnabled: false, policies: [] }), false)
})

test('rlsProvesOwnerScope: only a MIGRATION proves RLS — generated types do not', () => {
  // The certainty requirement is the load-bearing part. A table whose RLS state was inferred from
  // generated Supabase types says nothing about whether RLS is actually on in the database, and
  // treating it as proof would silence the check on exactly the repos that cannot be verified.
  const proven = { name: 't', rlsEnabled: true, rlsCertainty: 'from-migrations', policies: [{ scopedToUid: true, permissive: false }] }
  assert.equal(rlsProvesOwnerScope(proven), true)
  assert.equal(rlsProvesOwnerScope({ ...proven, rlsCertainty: 'from-types' }), false,
    'RLS asserted by generated types is not proof')
})

test('rlsProvesOwnerScope: RLS on with NO policies is deny-all, so nothing leaks', () => {
  // Counter-intuitive but correct: RLS enabled with zero policies denies everything. Treating it as
  // unprotected would report a table nobody can read at all.
  assert.equal(rlsProvesOwnerScope({ name: 't', rlsEnabled: true, rlsCertainty: 'from-migrations', policies: [] }), true)
})

test('rlsProvesOwnerScope: one permissive policy defeats every scoped one beside it', () => {
  assert.equal(rlsProvesOwnerScope({
    name: 't', rlsEnabled: true, rlsCertainty: 'from-migrations',
    policies: [{ scopedToUid: true, permissive: false }, { permissive: true, scopedToUid: false }],
  }), false, 'a `using (true)` beside a scoped policy still grants every row')
})

test('routeIsRlsControlled: any service-role path disqualifies the route', () => {
  assert.equal(routeIsRlsControlled({ reachesAnonScopedClient: true }), true)
  assert.equal(routeIsRlsControlled({ reachesAnonScopedClient: true, usesServiceRole: true }), false)
  assert.equal(routeIsRlsControlled({ reachesAnonScopedClient: true, reachesServiceRoleClient: true }), false)
  assert.equal(routeIsRlsControlled({ reachesAnonScopedClient: false }), false,
    'a route that never reaches an anon client is not being protected by RLS')
})

// ---------------------------------------------------------------------------
// The intent file must fail CLOSED.
// ---------------------------------------------------------------------------

test('a malformed intent is ignored ENTIRELY, never half-applied', () => {
  // Half-applying a broken config is the worst option: some resources governed, some silently not,
  // and no way for the reader to tell which. The audit still runs, but against the proposal, and it
  // says the file was unreadable.
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': 'create table public.orders (id uuid primary key, user_id uuid);',
  }, { intentError: 'resources.orders.owned_by must be a string' })

  assert.equal(report.businessLogic.status, 'error')
  assert.match(String(report.businessLogic.error), /owned_by/)
  assert.deepEqual(bizFindings(report), [],
    'a broken config file is a coverage problem, not a finding about the app')
  const row = report.coverage.businessLogic?.undeterminable
    ?.find(s => s.subject === 'business-logic:intent')
  assert.ok(row && /could not be read/.test(row.note),
    'the coverage row must say the file was unreadable and therefore unused')
})

test('validateIntent throws on the shapes a hand-written file actually gets wrong', () => {
  assert.throws(() => validateIntent(null), /must be a YAML map/)
  assert.throws(() => validateIntent('orders'), /must be a YAML map/)
  assert.throws(() => validateIntent({ resources: 'orders' }), /`resources` is required/)
  assert.throws(() => validateIntent({ resources: { orders: 'user_id' } }), /must be a map/)
  assert.doesNotThrow(() => validateIntent({ resources: { orders: { owned_by: 'user_id' } } }),
    'the minimal correct shape must be accepted')
})

test('validateIntent rejects an UNKNOWN KEY rather than ignoring it', () => {
  // The important one. A typo'd `owner_by:` that is silently ignored disables the ownership check
  // while the file still looks configured — a check that is quietly off is the confident silence
  // this whole methodology exists to prevent.
  assert.throws(() => validateIntent({ resources: { orders: { owner_by: 'user_id' } } }), /unknown key "owner_by"/)
  assert.throws(() => validateIntent({ resourcess: {} }), /unknown top-level key "resourcess"/)
})

test('validateIntent catches a transition targeting a state that does not exist', () => {
  assert.throws(() => validateIntent({
    resources: { orders: { owned_by: 'user_id', states: ['cart', 'paid'], transitions: { 'cart->shipped': ['admin'] } } },
  }), /not in states/)
})

test('parseIntentYaml reads the inline flow lists the documented file is full of', () => {
  // `roles: [anonymous, user, admin]` is the form the spec publishes. Reading it as a STRING is a
  // silent failure: the roles list would exist, be non-empty, and mean nothing.
  const obj = parseIntentYaml(`roles: [anonymous, user, admin]
default_role: user
resources:
  orders:
    owned_by: user_id
    states: [cart, placed, paid]
`)
  assert.deepEqual(obj.roles, ['anonymous', 'user', 'admin'])
  assert.deepEqual(obj.resources.orders.states, ['cart', 'placed', 'paid'])
  assert.equal(obj.resources.orders.owned_by, 'user_id')
})

// ---------------------------------------------------------------------------
// Grade or declare, applied to the taxonomy itself.
// ---------------------------------------------------------------------------

test('every taxonomy class is either checked or DECLARED — none is silently skipped', () => {
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': 'create table public.orders (id uuid primary key, user_id uuid, status text);',
  }, { intent: { roles: ['user'], resources: { orders: { owned_by: 'user_id' } } } })

  const res = report.businessLogic.resources.find(r => r.resource === 'orders')
  assert.ok(res, 'the resource must be walked')
  assert.equal(res.rulesTotal, TAXONOMY.length)

  // The three classes whose facts do not exist must appear as their own declared rows.
  const declared = report.coverage.businessLogic.undeterminable.map(s => s.subject)
  for (const c of DECLARED_CLASSES) {
    assert.ok(declared.includes(`bl:*:${c.id}`),
      `class "${c.id}" cannot be supported by the engine's facts and must be DECLARED, not omitted`)
  }
})

test('rulesChecked counts only classes that reached a verdict, never undeterminable ones', () => {
  // Counting `undeterminable` as checked would turn the coverage number into the reassurance it
  // exists to withhold.
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': 'create table public.orders (id uuid primary key, user_id uuid);',
  }, { intent: { roles: ['user'], resources: { orders: { owned_by: 'user_id' } } } })

  const res = report.businessLogic.resources.find(r => r.resource === 'orders')
  const settled = res.classes.filter(c => c.disposition === 'pass' || c.disposition === 'fail').length
  assert.equal(res.rulesChecked, settled)
  assert.ok(res.rulesChecked <= res.rulesTotal)
})

test('a table the intent says nothing about is declared, not quietly ignored', () => {
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': `create table public.orders (id uuid primary key, user_id uuid);
create table public.invoices (id uuid primary key, user_id uuid);`,
  }, { intent: { roles: ['user'], resources: { orders: { owned_by: 'user_id' } } } })

  const declared = report.coverage.businessLogic.undeterminable.map(s => s.subject)
  assert.ok(declared.includes('bl:no-intent:invoices'),
    'invoices has no stated intent, so none of the classes could be checked against it — say so')
})

test('an intent naming a table that does not exist is declared, and does not crash', () => {
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': 'create table public.orders (id uuid primary key, user_id uuid);',
  }, { intent: { roles: ['user'], resources: { orders: { owned_by: 'user_id' }, ghosts: { owned_by: 'user_id' } } } })

  const declared = report.coverage.businessLogic.undeterminable.map(s => s.subject)
  assert.ok(declared.includes('bl:intent-resource:ghosts'),
    'a typo in the intent file must be surfaced, not silently dropped')
})

// ---------------------------------------------------------------------------
// LAW 2 — a duplicate subject THROWS and destroys the whole report.
// ---------------------------------------------------------------------------

test('LAW 2: the business-logic ledger reconciles', () => {
  const { report } = scan({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': `create table public.orders (id uuid primary key, user_id uuid, org_id uuid, status text);
create table public.invoices (id uuid primary key, user_id uuid);`,
    'lib/db.ts': `import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    'app/api/orders/[id]/route.ts': `import { admin } from '@/lib/db'
export async function GET(req, { params }) {
  return Response.json(await admin.from('orders').select().eq('id', params.id))
}`,
  }, { intent: { roles: ['user'], resources: { orders: { owned_by: 'user_id', tenant: 'org_id' }, invoices: { owned_by: 'user_id' } } } })

  for (const set of ['businessLogic', 'businessLogicScope']) {
    const c = report.coverage[set]
    assert.ok(c, `${set} must be declared`)
    assert.equal(c.counts.pass + c.counts.fail + c.counts.undeterminable + c.counts.allowlisted,
      c.enumerated, `${set}: LAW 2 arithmetic must hold`)
  }
})

test('LAW 2: two routes in the same file do not collide', () => {
  // An Express file declaring several handlers is the normal case, and a subject collision does not
  // merely miscount — it THROWS, and no report is produced at all.
  assert.doesNotThrow(() => scan({
    'package.json': '{"name":"x","dependencies":{"express":"4.19.0","@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': 'create table public.orders (id uuid primary key, user_id uuid);',
    'server.js': `const express = require('express')
const app = express()
app.get('/orders/:id', (req, res) => res.json({}))
app.post('/orders', (req, res) => res.json({}))
app.delete('/orders/:id', (req, res) => res.json({}))
app.listen(3000)`,
  }, { intent: { roles: ['user'], resources: { orders: { owned_by: 'user_id' } } } }))
})

// ---------------------------------------------------------------------------
// proposeIntent — the thing that turns a guess into a review.
// ---------------------------------------------------------------------------

test('proposeIntent survives a repo with no schema at all', () => {
  const p = proposeIntent({ database: { tables: [] }, routes: [] })
  assert.ok(p && typeof p === 'object', 'a proposal must always be produced, even an empty one')
  assert.deepEqual(Object.keys(p.resources || {}), [], 'and it must not invent resources')
})

test('proposeIntent picks an ownership column when the schema names one', () => {
  const p = proposeIntent({
    database: {
      tables: [{ name: 'orders', columns: [{ name: 'id' }, { name: 'user_id' }, { name: 'status' }] }],
    },
    routes: [],
  })
  assert.equal(p.resources.orders.owned_by, 'user_id')
})

test('an audit with no intent marks every resource ASSUMED', () => {
  const audit = auditBusinessLogic({
    database: { tables: [{ name: 'orders', columns: [{ name: 'id' }, { name: 'user_id' }] }] },
    routes: [],
  })
  assert.equal(audit.status, 'assumed')
  for (const r of audit.resources) {
    assert.equal(r.assumed, true, 'without a confirmed intent every resource must be marked assumed')
  }
})
