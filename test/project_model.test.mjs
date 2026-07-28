import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')

/** Build a throwaway project on disk and return its parsed model. */
function modelOf(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-pm-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    const out = execFileSync(process.execPath, [SCRIPT, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    })
    return JSON.parse(out)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// ---------------------------------------------------------------------------
// REGRESSION: the false negative that hid a P0.
// ---------------------------------------------------------------------------

test('REGRESSION: a commented-out RLS statement must NOT count as RLS enabled', () => {
  const m = modelOf({
    'supabase/migrations/001.sql': `
create table public.orders (id uuid primary key, user_id uuid);
-- (missing) alter table public.orders enable row level security;
`,
  })
  const orders = m.database.tables.find(t => t.name === 'orders')
  assert.ok(orders, 'table must be enumerated')
  assert.equal(orders.rlsEnabled, false,
    'RLS must be false — reporting true here tells the user their data is protected when it is world-readable')
})

test('a real RLS statement IS detected', () => {
  const m = modelOf({
    'supabase/migrations/001.sql': `
create table public.orders (id uuid primary key);
alter table public.orders enable row level security;
create policy "read own" on public.orders for select using ( auth.uid() = user_id );
`,
  })
  const orders = m.database.tables.find(t => t.name === 'orders')
  assert.equal(orders.rlsEnabled, true)
  assert.equal(orders.policies.length, 1)
  assert.equal(orders.policies[0].cmd, 'select')
  assert.equal(orders.policies[0].scopedToUid, true)
})

test('a permissive using(true) policy is flagged permissive', () => {
  const m = modelOf({
    'supabase/migrations/001.sql': `
create table public.notes (id uuid);
alter table public.notes enable row level security;
create policy "all" on public.notes for all using ( true );
`,
  })
  const t = m.database.tables.find(x => x.name === 'notes')
  assert.equal(t.policies[0].permissive, true, 'using(true) is RLS-on-but-open')
})

test('parserVersion is 2 so consumers know RLS facts are comment-safe', () => {
  const m = modelOf({ 'supabase/migrations/001.sql': 'create table public.a (id int);' })
  assert.equal(m.database.parserVersion, 2)
})

// ---------------------------------------------------------------------------
// REGRESSION: secret-name classification.
// ---------------------------------------------------------------------------

test('REGRESSION: AWS_ACCESS_KEY_ID and DATABASE_URL classify as high-confidence secrets', () => {
  const m = modelOf({
    '.env': 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDATABASE_URL=postgresql://u:p@h:5432/db\n',
    'package.json': '{"name":"x"}',
  })
  const byName = Object.fromEntries(m.envVars.map(v => [v.name, v]))
  assert.equal(byName.AWS_ACCESS_KEY_ID.secretClass, 'high')
  assert.equal(byName.DATABASE_URL.secretClass, 'high')
})

test('the Supabase anon key is public-by-design, never a secret', () => {
  // This is THE false positive that destroys trust with this audience.
  const m = modelOf({
    '.env': 'NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOi.abc.def\nNEXT_PUBLIC_SUPABASE_URL=https://x.supabase.co\n',
  })
  const byName = Object.fromEntries(m.envVars.map(v => [v.name, v]))
  assert.equal(byName.NEXT_PUBLIC_SUPABASE_ANON_KEY.secretClass, 'public-by-design')
  assert.equal(byName.NEXT_PUBLIC_SUPABASE_ANON_KEY.secretish, false)
  assert.equal(byName.NEXT_PUBLIC_SUPABASE_URL.secretish, false)
})

test('publishable third-party keys are public-by-design, not P0 material', () => {
  const m = modelOf({
    '.env': [
      'NEXT_PUBLIC_GOOGLE_MAPS_KEY=AIzaSyExample',
      'NEXT_PUBLIC_PUSHER_APP_KEY=abc123',
      'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_x',
      'NEXT_PUBLIC_SENTRY_DSN=https://x@y.ingest.sentry.io/1',
    ].join('\n'),
  })
  for (const v of m.envVars) {
    assert.equal(v.secretClass, 'public-by-design',
      `${v.name} must not be treated as a leaked secret — publishable keys are meant to ship`)
  }
})

test('named provider keys are high-confidence (an LLM key in the browser is P0, not P2)', () => {
  const m = modelOf({
    '.env': [
      'OPENAI_API_KEY=sk-x',
      'NEXT_PUBLIC_OPENAI_API_KEY=sk-y',   // catastrophic: billable key inlined into the bundle
      'ANTHROPIC_API_KEY=sk-ant-z',
      'STRIPE_SECRET_KEY=sk_live_q',
    ].join('\n'),
  })
  const byName = Object.fromEntries(m.envVars.map(v => [v.name, v]))
  for (const n of ['OPENAI_API_KEY', 'NEXT_PUBLIC_OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'STRIPE_SECRET_KEY']) {
    assert.equal(byName[n].secretClass, 'high', `${n} must be high-confidence, not weak`)
  }
  assert.equal(byName.NEXT_PUBLIC_OPENAI_API_KEY.exposure, 'bundler-inlined-public-prefix')
})

test('a genuinely ambiguous *_KEY stays weak so it cannot drive a P0 on its name alone', () => {
  const m = modelOf({ '.env': 'IDEMPOTENCY_KEY=abc\nCACHE_KEY=v1\nSORT_KEY=name\n' })
  for (const v of m.envVars) {
    assert.notEqual(v.secretClass, 'high',
      `${v.name} is not conclusively a credential — name-only evidence must cap below P0`)
  }
})

test('service_role is high-confidence even behind a public prefix', () => {
  const m = modelOf({ '.env': 'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOi.x.y\n' })
  const v = m.envVars.find(x => x.name.includes('SERVICE_ROLE'))
  assert.equal(v.secretClass, 'high')
  assert.equal(v.exposure, 'bundler-inlined-public-prefix',
    'a public prefix means the bundler inlines it — definitive client exposure')
})

// ---------------------------------------------------------------------------
// security definer functions — the blind spot that stripping could have created.
// ---------------------------------------------------------------------------

test('security definer functions are enumerated even though their bodies are stripped', () => {
  const m = modelOf({
    'supabase/migrations/002.sql': `
create or replace function public.get_all_orders()
returns setof public.orders as $$
  select * from public.orders;
$$ language sql security definer;
`,
  })
  const fn = m.database.functions.find(f => f.name === 'get_all_orders')
  assert.ok(fn, 'function must be enumerated')
  assert.equal(fn.securityDefiner, true)
  assert.equal(fn.setsSearchPath, false, 'missing search_path is part of the escalation risk')
  assert.equal(fn.bodyChecksAuth, false, 'body has no auth check — bypasses RLS for anon callers')
})

// ---------------------------------------------------------------------------
// Client/server boundary.
// ---------------------------------------------------------------------------

test("a secret imported by a 'use client' module is client-reachable", () => {
  const m = modelOf({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}',
    'lib/db.ts': "export const k = process.env.MY_SERVICE_ROLE_SECRET",
    'app/page.tsx': "'use client'\nimport { k } from '../lib/db'\nexport default function P(){return null}",
  })
  assert.ok(m.boundary.clientReachable.includes('lib/db.ts'),
    'transitive import from a client component puts the module in the browser bundle')
})

test('a server-only route does not mark its imports client-reachable', () => {
  const m = modelOf({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}',
    'lib/db.ts': "export const k = process.env.MY_SERVICE_ROLE_SECRET",
    'pages/api/x.ts': "import { k } from '../../lib/db'\nexport default function h(){return k}",
  })
  assert.ok(!m.boundary.clientReachable.includes('lib/db.ts'))
  const v = m.envVars.find(x => x.name === 'MY_SERVICE_ROLE_SECRET')
  assert.equal(v.exposure, 'server-only')
})

// ---------------------------------------------------------------------------
// Determinism — a core product promise.
// ---------------------------------------------------------------------------

test('the model is deterministic: same input, identical output', () => {
  const files = {
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}',
    'supabase/migrations/001.sql': 'create table public.a (id int);',
    'pages/api/x.ts': 'export default function h(req,res){ res.json({}) }',
    '.env': 'OPENAI_API_KEY=sk-x\n',
  }
  const a = JSON.stringify(modelOf(files).database)
  const b = JSON.stringify(modelOf(files).database)
  assert.equal(a, b, 'same repo must always produce the same facts')
})
