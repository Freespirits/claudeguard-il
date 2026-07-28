import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')

function modelOf(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-sp-'))
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

const SUPABASE_TYPES = `export type Database = {
  public: {
    Tables: {
      orders: { Row: { id: string } }
      profiles: { Row: { id: string } }
      payments: { Row: { id: string } }
    }
    Views: {}
    Functions: {}
  }
}
`

// ---------------------------------------------------------------------------
// The modal vibecoder: tables created in the Supabase DASHBOARD, no migrations.
// Enumerating only from .sql files would find ZERO tables here, and the flagship
// "table has no RLS" detector would silently produce nothing while implying coverage.
// ---------------------------------------------------------------------------

test('tables are enumerated from generated types when there are NO migrations', () => {
  const m = modelOf({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}',
    'database.types.ts': SUPABASE_TYPES,
  })
  const names = m.database.tables.map(t => t.name).sort()
  assert.deepEqual(names, ['orders', 'payments', 'profiles'],
    'generated types are authoritative — they come FROM the live DB, so they include dashboard tables')
  assert.ok(m.database.coverage.sources.includes('supabase-types'))
})

test('without migrations, RLS state is UNKNOWN — never silently reported as fine', () => {
  const m = modelOf({
    'package.json': '{"name":"x"}',
    'supabase/types.ts': SUPABASE_TYPES,
  })
  assert.equal(m.database.coverage.rlsVerifiable, false)
  for (const t of m.database.tables) {
    assert.equal(t.rlsCertainty, 'unknown-no-migration',
      'claiming RLS=false would be a false positive; claiming true would be a false negative')
  }
})

test('with NO schema source at all, one loud blocking note plus a runnable query', () => {
  const m = modelOf({ 'package.json': '{"name":"x"}', 'app/page.tsx': 'export default () => null' })
  assert.equal(m.database.coverage.sources.length, 0)
  assert.match(m.database.coverage.note, /CANNOT be determined/i)
  assert.match(m.database.coverage.verifyQuery, /relrowsecurity/,
    'the user must be handed a query they can run themselves')
})

test('migration provenance is not overwritten by a later source', () => {
  // Regression: the code-reference pass clobbered knownFrom, downgrading a table whose RLS
  // state we could actually verify from migrations.
  const m = modelOf({
    'supabase/migrations/001.sql': 'create table public.orders (id uuid);',
    'app/api/x/route.ts': "export async function GET(){ return supabase.from('orders').select() }",
  })
  const orders = m.database.tables.find(t => t.name === 'orders')
  assert.equal(orders.rlsCertainty, 'from-migrations')
  assert.ok(orders.knownFrom.includes('migrations'))
  assert.ok(orders.knownFrom.includes('code-reference'))
})

test('Prisma models and Drizzle pgTable declarations are enumerated', () => {
  const m = modelOf({
    'prisma/schema.prisma': 'model User {\n  id String @id\n}\nmodel Post {\n  id String @id\n}\n',
    'db/schema.ts': "export const invoices = pgTable('invoices', {})",
  })
  const names = m.database.tables.map(t => t.name).sort()
  assert.ok(names.includes('user') && names.includes('post'), 'prisma models')
  assert.ok(names.includes('invoices'), 'drizzle tables')
})

test('a non-literal .from(x) is surfaced, never silently skipped', () => {
  // A generic CRUD helper makes the table set unenumerable. Hiding that would let us claim
  // complete coverage while blind.
  const m = modelOf({
    'lib/crud.ts': 'export const all = (t) => supabase.from(t).select("*")',
  })
  assert.ok(m.database.coverage.dynamicTableRefs.length >= 1)
  assert.equal(m.database.coverage.dynamicTableRefs[0].expr, 't')
})

// ---------------------------------------------------------------------------
// False-positive blocker: the idiomatic @supabase/ssr app.
// ---------------------------------------------------------------------------

test('@supabase/ssr clients are recognised as user-scoped (RLS is the correct control)', () => {
  // Without this, every .eq('id', id) in the officially recommended pattern reads as an IDOR
  // and we flood a CORRECT app with false P1s.
  const m = modelOf({
    'package.json': '{"name":"x","dependencies":{"@supabase/ssr":"0.5.0"}}',
    'lib/server.ts': `import { createServerClient } from '@supabase/ssr'
export const sb = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, { cookies })`,
  })
  const c = m.supabaseClients.find(x => x.factory === 'createServerClient')
  assert.ok(c, 'createServerClient must be detected')
  assert.equal(c.identity, 'anon-user-scoped')
  assert.equal(c.rlsIsTheControl, true)
})

test('a service_role createClient is identified as RLS-bypassing', () => {
  const m = modelOf({
    'lib/admin.ts': "export const a = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)",
  })
  const c = m.supabaseClients.find(x => x.factory === 'createClient')
  assert.equal(c.identity, 'service-role')
  assert.equal(c.rlsIsTheControl, false, 'service_role bypasses RLS, so RLS is not a control for it')
})

// ---------------------------------------------------------------------------
// next.config.js — a P0 secret-exposure path that needs no public prefix.
// ---------------------------------------------------------------------------

test('next.config env: is flagged because it inlines server vars into the client bundle', () => {
  const m = modelOf({
    'next.config.js': `module.exports = {
  env: { STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY },
  productionBrowserSourceMaps: true,
}`,
  })
  const keys = m.nextConfig.map(x => x.key)
  assert.ok(keys.includes('env'), 'next.config env: defeats the public-prefix model entirely')
  assert.ok(keys.includes('productionBrowserSourceMaps'))
  const headers = m.nextConfig.find(x => x.key === 'securityHeadersConfigured')
  assert.equal(headers.present, false)
})

test('next.config parsing ignores commented-out config', () => {
  const m = modelOf({
    'next.config.js': `module.exports = {
  // env: { SECRET: process.env.SECRET },
}`,
  })
  assert.ok(!m.nextConfig.some(x => x.key === 'env'),
    'a commented-out setting is not a finding — same bug class as the RLS false negative')
})
