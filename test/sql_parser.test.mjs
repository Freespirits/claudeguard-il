import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { grade } from '../plugin/scripts/grader.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ENGINE = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')

function gradeRepo(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-sql-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return grade(JSON.parse(execFileSync(process.execPath, [ENGINE, dir], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}
const PKG = '{"name":"x","dependencies":{"@supabase/supabase-js":"2.45.0"}}'
const byId = (r, id) => r.findings.filter(f => f.id === id)
const tableSubjects = r => ['pass', 'fail', 'undeterminable', 'allowlisted'].flatMap(d => r.coverage.tables?.[d] || []).map(s => s.subject)
const dispo = (r, subject) => {
  for (const d of ['pass', 'fail', 'undeterminable', 'allowlisted']) if ((r.coverage.tables[d] || []).some(s => s.subject === subject)) return d
  return null
}

// ---------------------------------------------------------------------------
// AUDIT FIX A — the SQL parser was line-oriented with a fixed 6-line look-ahead window. That one
// design flaw produced the security-team audit's worst cluster: multi-line statements missed, an
// adjacent policy bleeding into a correct one (a CONFIRMED false P0 on production SQL), a blanket
// "any authenticated user" policy passing as safe, and a policy on a managed system table inventing
// a phantom. Parsing by complete STATEMENT retires all of them. Each is reproduced here.
// ---------------------------------------------------------------------------

test('a multi-line `create policy using (true)` is a P0, not a safe deny-all pass', () => {
  const r = gradeRepo({
    'package.json': PKG,
    'supabase/migrations/001.sql': `create table public.notes (id uuid primary key, body text);
alter table public.notes enable row level security;
create policy "read all"
  on public.notes
  for select
  using (true);`,
  })
  assert.ok(byId(r, 'CG-DB-002').some(f => f.subject === 'table:notes'),
    'a permissive policy formatted across lines (the Supabase-docs style) must still fire CG-DB-002')
})

test('a multi-line `create table` is enumerated (not dropped from the ledger)', () => {
  const r = gradeRepo({
    'package.json': PKG,
    'supabase/migrations/001.sql': `create table
  public.audit_log (id uuid primary key, msg text);`,
  })
  assert.ok(tableSubjects(r).includes('table:audit_log'),
    'a table whose name is on the next line must still be enumerated (LAW 2)')
  assert.ok(byId(r, 'CG-DB-001').some(f => f.subject === 'table:audit_log'), 'and its missing RLS flagged')
})

test('an adjacent `using(true)` policy does not bleed into a correct owner-scoped policy', () => {
  // The single worst audit defect: the 6-line window made a correct policy inherit a neighbour's
  // `using(true)` and fire a CONFIRMED false P0, flipping the badge to critical on correct SQL.
  const r = gradeRepo({
    'package.json': PKG,
    'supabase/migrations/001.sql': `create table public.secure (id uuid primary key, user_id uuid);
alter table public.secure enable row level security;
create policy own on public.secure for all using (auth.uid() = user_id);
create table public.open (id uuid primary key);
alter table public.open enable row level security;
create policy any on public.open for all using (true);`,
  })
  assert.equal(dispo(r, 'table:secure'), 'pass', 'the owner-scoped table must PASS, not inherit the neighbour')
  assert.ok(!byId(r, 'CG-DB-002').some(f => f.subject === 'table:secure'), 'no false P0 on the correct policy')
  assert.ok(byId(r, 'CG-DB-002').some(f => f.subject === 'table:open'), 'the genuinely permissive table still fails')
})

test('a blanket `auth.uid() is not null` policy is permissive, not a safe uid-scoped pass', () => {
  const r = gradeRepo({
    'package.json': PKG,
    'supabase/migrations/001.sql': `create table public.invoices (id uuid primary key, total numeric);
alter table public.invoices enable row level security;
create policy authed on public.invoices for all using (auth.uid() is not null);`,
  })
  assert.notEqual(dispo(r, 'table:invoices'), 'pass',
    'granting every row to every logged-in user is a cross-tenant leak, not a pass')
  assert.ok(byId(r, 'CG-DB-002').some(f => f.subject === 'table:invoices'))
})

test('a policy on the managed `storage.objects` table does not invent a phantom `objects` table', () => {
  const r = gradeRepo({
    'package.json': PKG,
    'supabase/migrations/001.sql': `create table public.items (id uuid primary key, owner uuid);
alter table public.items enable row level security;
create policy own on public.items for all using (auth.uid() = owner);
create policy "public read" on storage.objects for select using (bucket_id = 'public');`,
  })
  assert.ok(!tableSubjects(r).includes('table:objects'),
    'storage.objects is a Supabase-managed system table, not the user\'s — no phantom')
  assert.equal(dispo(r, 'table:items'), 'pass', 'the real table is unaffected')
})
