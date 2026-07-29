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

function gradeRepo(files, opts) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-meta-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    const model = JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    }))
    return grade(model, opts)
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const byId = (r, id) => r.findings.find(f => f.id === id)

function subjectsOf(r, setName) {
  const s = r.coverage[setName] || { pass: [], fail: [], undeterminable: [], allowlisted: [] }
  return ['pass', 'fail', 'undeterminable', 'allowlisted'].flatMap(d => s[d]).map(x => x.subject)
}

function dispositionOf(r, setName, subject) {
  const s = r.coverage[setName]
  for (const d of ['pass', 'fail', 'undeterminable', 'allowlisted']) {
    if ((s[d] || []).some(x => x.subject === subject)) return d
  }
  return null
}

// ---------------------------------------------------------------------------
// THE METAMORPHIC TEST.
//
// The engine's job is to state facts about committed code, and a fact must not depend on the
// spelling of that code. A finding that FLIPS under a semantics-preserving edit — renaming a
// local, aliasing an import, threading a module through a barrel, reindenting, or moving a route
// into a route group — is by definition a defect: two byte-different-but-behaviour-identical repos
// would get two different verdicts, and the user cannot know which one to trust.
//
// Each test below builds a BASE fixture that produces a specific finding (or coverage
// disposition), applies ONE harmless transform, and asserts the id / disposition is UNCHANGED.
//
// Where the tool genuinely FLIPS today, the test is written to assert the CORRECT invariant and
// marked `{ todo: true }`: node:test runs it, reports it as todo, and a failing todo does NOT fail
// the suite — so CI stays green while the real defect stays documented. The three todos are the
// point of the exercise; they are the engine bugs to fix.
// ---------------------------------------------------------------------------

const NEXT = JSON.stringify({
  name: 'meta',
  dependencies: {
    next: '15.0.0', '@supabase/supabase-js': '2.45.0', '@supabase/ssr': '0.5.0',
  },
})

// A service-role client built in a module a client component imports directly. This is the shape
// CG-DB-006 keys on: createClient(url, SERVICE_ROLE_KEY) reachable from the browser. The
// createClient call is on line 2, so the subject is `supabase-client:lib/db.ts:2`.
const SR_DB = `import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`
const CLIENT_PAGE = `'use client'
import { admin } from '../lib/db'
export default function Page() { return admin ? null : null }`

// ---------------------------------------------------------------------------
// 1. VARIABLE / FUNCTION RENAME
// ---------------------------------------------------------------------------

// TRANSFORM: rename the local that holds the service-role client (`admin` -> `serviceClient`).
// INVARIANT: CG-DB-006 is keyed on the createClient STRUCTURE, not the binding name, so the
// finding — same subject, same severity — must be unchanged. A finding that moved with the
// variable name would be reading spelling, not structure.
test('rename of the client-holding local leaves the service-role finding (CG-DB-006) unchanged', () => {
  const base = gradeRepo({ 'package.json': NEXT, 'lib/db.ts': SR_DB, 'app/page.tsx': CLIENT_PAGE })
  const renamed = gradeRepo({
    'package.json': NEXT,
    'lib/db.ts': `import { createClient } from '@supabase/supabase-js'
export const serviceClient = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    'app/page.tsx': `'use client'
import { serviceClient } from '../lib/db'
export default function Page() { return serviceClient ? null : null }`,
  })
  const a = byId(base, 'CG-DB-006')
  const b = byId(renamed, 'CG-DB-006')
  assert.ok(a && b, 'the service-role client must be found before and after the rename')
  assert.equal(a.subject, b.subject, 'the subject must not move when a local is renamed')
  assert.equal(a.severity, b.severity)
})

// TRANSFORM: rename an ordinary local in an UNRELATED JS file (`total` -> `grandTotal`).
// INVARIANT: CG-DB-001 (RLS off) is derived entirely from the SQL migration, so a JS rename
// elsewhere in the repo cannot touch it — the table subject and severity must be identical.
test('an unrelated JS rename does not perturb the RLS-off finding (CG-DB-001)', () => {
  const MIG = 'create table public.orders (id uuid primary key, user_id uuid);'
  const base = gradeRepo({
    'package.json': NEXT, 'supabase/migrations/001.sql': MIG,
    'lib/util.ts': 'export function calc() { const total = 1 + 1; return total }',
  })
  const renamed = gradeRepo({
    'package.json': NEXT, 'supabase/migrations/001.sql': MIG,
    'lib/util.ts': 'export function calc() { const grandTotal = 1 + 1; return grandTotal }',
  })
  const a = byId(base, 'CG-DB-001')
  const b = byId(renamed, 'CG-DB-001')
  assert.ok(a && b, 'RLS-off must be reported in both')
  assert.equal(a.subject, b.subject)
  assert.equal(a.subject, 'table:orders')
  assert.equal(a.severity, b.severity)
})

// ---------------------------------------------------------------------------
// 2. IMPORT ALIAS
// ---------------------------------------------------------------------------

// TRANSFORM: alias the imported BINDING at the client entrypoint — import { db as database }.
// INVARIANT: the import graph resolves by module specifier, not by the local name the binding is
// given, so reachability (and therefore the service-role finding it drives) must be identical.
test('aliasing an imported binding (`db as database`) keeps reachability and CG-DB-006', () => {
  const DB = `import { createClient } from '@supabase/supabase-js'
export function db() { return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY) }`
  const base = gradeRepo({
    'package.json': NEXT, 'lib/db.ts': DB,
    'app/page.tsx': `'use client'
import { db } from '../lib/db'
export default function Page() { return db() ? null : null }`,
  })
  const aliased = gradeRepo({
    'package.json': NEXT, 'lib/db.ts': DB,
    'app/page.tsx': `'use client'
import { db as database } from '../lib/db'
export default function Page() { return database() ? null : null }`,
  })
  const a = byId(base, 'CG-DB-006')
  const b = byId(aliased, 'CG-DB-006')
  assert.ok(a && b, 'renaming the import binding must not hide the service-role client')
  assert.equal(a.subject, b.subject)
  assert.equal(a.confidence, b.confidence)
})

// TRANSFORM: alias the FACTORY import name — import { createClient as cc } — and call cc(...).
// INVARIANT: an import alias is semantics-preserving, so the service-role client must still be
// found and CG-DB-006 must still fire, unchanged.
// FRAGILITY (real defect): the engine's Supabase-client scan matches the literal token
// `createClient(` (project_model.mjs, the plain-createClient regex). The aliased call `cc(...)`
// matches nothing, so the client is never enumerated at all — CG-DB-006 vanishes and the
// supabaseClients coverage silently drops the subject. Alias resolution for known factory names is
// the fix.
test('import alias `createClient as cc` must not hide the service-role client (CG-DB-006)', () => {
  const base = gradeRepo({ 'package.json': NEXT, 'lib/db.ts': SR_DB, 'app/page.tsx': CLIENT_PAGE })
  assert.ok(byId(base, 'CG-DB-006'), 'control: the un-aliased factory is detected')

  const aliased = gradeRepo({
    'package.json': NEXT,
    'lib/db.ts': `import { createClient as cc } from '@supabase/supabase-js'
export const admin = cc(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    'app/page.tsx': CLIENT_PAGE,
  })
  assert.ok(byId(aliased, 'CG-DB-006'),
    'aliasing the factory import is harmless — the service-role client must still be reported')
})

// ---------------------------------------------------------------------------
// 3. RE-EXPORT THROUGH A BARREL
// ---------------------------------------------------------------------------

// TRANSFORM: reach lib/db.ts through a lib/index.ts re-export barrel instead of importing it
// directly.
// INVARIANT: the subject must not VANISH — the service-role client is still there. Its evidence
// strength MAY legitimately weaken to `weak` (needs-review), because tree-shaking can drop a
// re-export, and that barrel-awareness is by design (see import_graph.test.mjs). We assert the
// finding survives at the barrel-aware strength, not that the strength is preserved.
test('routing the module through a barrel keeps CG-DB-006 (strength may weaken to weak)', () => {
  const base = gradeRepo({ 'package.json': NEXT, 'lib/db.ts': SR_DB, 'app/page.tsx': CLIENT_PAGE })
  const barrel = gradeRepo({
    'package.json': NEXT,
    'lib/db.ts': SR_DB,
    'lib/index.ts': "export * from './db'\n",
    'app/page.tsx': `'use client'
import { admin } from '../lib'
export default function Page() { return admin ? null : null }`,
  })
  const a = byId(base, 'CG-DB-006')
  const b = byId(barrel, 'CG-DB-006')
  assert.ok(a && b, 'the service-role client must survive the barrel — the subject must not vanish')
  assert.equal(a.subject, b.subject, 'same module, same subject, however it is imported')
  // Direct import is strong (likely); through a barrel it is weak (needs-review) by design.
  assert.equal(a.confidence, 'likely')
  assert.equal(b.confidence, 'needs-review')
})

// ---------------------------------------------------------------------------
// 4. FORMATTING & COMMENTS
// ---------------------------------------------------------------------------

// TRANSFORM: reformat the migration whitespace and add comments — including a commented-out
// `enable row level security`, both in a `--` line comment and inside a `/* */` block.
// INVARIANT: a commented statement is not code. RLS is still OFF, so CG-DB-001 must still fire on
// the table. This is a KNOWN PAST BUG (a commented ALTER once read as RLS-enabled, hiding a P0);
// stripSql now blanks comments, and this guards the fix.
test('a commented-out `enable row level security` is NOT read as enabled — RLS stays off', () => {
  const base = gradeRepo({
    'package.json': NEXT,
    'supabase/migrations/001.sql': 'create table public.orders (id uuid primary key, user_id uuid);',
  })
  const commented = gradeRepo({
    'package.json': NEXT,
    'supabase/migrations/001.sql': `-- Orders. TODO: alter table public.orders enable row level security;
create   table   public.orders (id uuid primary key,
  user_id uuid);
/* reminder to alter table public.orders enable row level security later */`,
  })
  const a = byId(base, 'CG-DB-001')
  const b = byId(commented, 'CG-DB-001')
  assert.ok(a && b, 'RLS-off must be reported whether or not a comment mentions enabling it')
  assert.equal(a.subject, b.subject)
  assert.equal(dispositionOf(commented, 'tables', 'table:orders'), 'fail',
    'the commented ALTER must not flip the table to a pass')
})

// TRANSFORM: reindent a route handler and sprinkle comments through it.
// INVARIANT: the no-auth finding is keyed on the route file, and whitespace/comments carry no
// behaviour, so CG-WEB-001 must be unchanged — same subject, same severity.
test('reformatting + comments on a route leaves the no-auth finding (CG-WEB-001) unchanged', () => {
  const base = gradeRepo({
    'package.json': NEXT,
    'app/api/things/route.ts': 'export async function GET() { return Response.json([]) }',
  })
  const reformatted = gradeRepo({
    'package.json': NEXT,
    'app/api/things/route.ts': `// list the things
export   async   function   GET() {
  // no body to read here
  return Response.json([])
}
`,
  })
  const a = byId(base, 'CG-WEB-001')
  const b = byId(reformatted, 'CG-WEB-001')
  assert.ok(a && b, 'the unauthenticated route must be flagged in both')
  assert.equal(a.subject, b.subject)
  assert.equal(a.severity, b.severity)
})

// ---------------------------------------------------------------------------
// 5. MIDDLEWARE PLACEMENT
// ---------------------------------------------------------------------------

const OPEN_ROUTE = 'export async function GET() { return Response.json([]) }'
const mwWith = matcher => `import { createServerClient } from '@supabase/ssr'
export async function middleware(req) {
  const s = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, { cookies: req.cookies })
  const { data: { user } } = await s.auth.getUser()
  if (!user) return Response.redirect(new URL('/login', req.url))
}
export const config = { matcher: ${matcher} }`

// TRANSFORM: move the auth check from inside the handler to a middleware whose matcher covers the
// route.
// INVARIANT: both placements are auth the tool cannot fully verify from source, so both must land
// the route in `undeterminable` (covered) — never a hard `fail`. Where the check lives is a
// refactor; a `fail` for the middleware form would be a false alarm on a protected route.
test('auth inline vs auth in a covering middleware both yield `undeterminable`, never `fail`', () => {
  const subject = 'route:app/api/orders/route.ts'
  const inline = gradeRepo({
    'package.json': NEXT,
    'app/api/orders/route.ts': `import { createServerClient } from '@supabase/ssr'
export async function GET(req) {
  const s = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, { cookies: req.cookies })
  const { data: { user } } = await s.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  return Response.json([])
}`,
  })
  const viaMiddleware = gradeRepo({
    'package.json': NEXT,
    'app/api/orders/route.ts': OPEN_ROUTE,
    'middleware.ts': mwWith("['/api/:path*']"),
  })
  assert.equal(dispositionOf(inline, 'routes', subject), 'undeterminable')
  assert.equal(dispositionOf(viaMiddleware, 'routes', subject), 'undeterminable')
  assert.equal(inline.coverage.routes.counts.fail, 0)
  assert.equal(viaMiddleware.coverage.routes.counts.fail, 0)
})

// TRANSFORM: rewrite the matcher into equivalent-but-differently-spelled forms — rename the named
// segment (`:path*` -> `:rest*`) and switch the array to the bare-string form.
// INVARIANT: all three describe the same set of paths, so the covered route must stay
// `undeterminable` in every form. Matcher coverage must be about the pattern's MEANING, not its
// spelling.
test('equivalent matcher spellings all keep the route `undeterminable`', () => {
  const subject = 'route:app/api/widgets/route.ts'
  for (const matcher of ["['/api/:path*']", "['/api/:rest*']", "'/api/:path*'"]) {
    const r = gradeRepo({
      'package.json': NEXT,
      'app/api/widgets/route.ts': OPEN_ROUTE,
      'middleware.ts': mwWith(matcher),
    })
    assert.equal(dispositionOf(r, 'routes', subject), 'undeterminable',
      `matcher ${matcher} covers /api/widgets and must not leave it a fail`)
  }
})

// TRANSFORM: write the same matcher with a capture group — `/api/(.*)` instead of `/api/:path*`.
// INVARIANT: `/api/(.*)` and `/api/:path*` both cover `/api/widgets`, so the route must stay
// `undeterminable`.
// FRAGILITY (real defect): matcherCovers (grader.mjs) rewrites `/(\.\*)` groups only in a very
// specific escaped shape; `/api/(.*)` slips through and is tested as a literal `(`, which
// `/api/widgets` cannot match. The route flips to a hard `fail` — a false "no auth" alarm on a
// route the middleware actually protects. `(.*)` is an extremely common Next.js matcher form, so
// this is a live false-positive generator.
test('a `(.*)` matcher must cover the route exactly as `:path*` does', () => {
  const subject = 'route:app/api/widgets/route.ts'
  const control = gradeRepo({
    'package.json': NEXT, 'app/api/widgets/route.ts': OPEN_ROUTE, 'middleware.ts': mwWith("['/api/:path*']"),
  })
  assert.equal(dispositionOf(control, 'routes', subject), 'undeterminable', 'control: :path* covers')

  const group = gradeRepo({
    'package.json': NEXT, 'app/api/widgets/route.ts': OPEN_ROUTE, 'middleware.ts': mwWith("['/api/(.*)']"),
  })
  assert.equal(dispositionOf(group, 'routes', subject), 'undeterminable',
    '`/api/(.*)` is equivalent to `/api/:path*` and must cover the route just the same')
})

// ---------------------------------------------------------------------------
// 6. ROUTE GROUPS & DYNAMIC PATHS
// ---------------------------------------------------------------------------

// TRANSFORM: move a route into a route group — app/(marketing)/api/widgets/route.ts vs
// app/api/widgets/route.ts.
// INVARIANT: a route group is an organisational folder that never appears in the URL, so urlPathOf
// strips it. The reported URL in the finding must be identical (`/api/widgets`) and never leak the
// `(marketing)` segment. Same severity, too.
test('moving a route into a route group does not change the reported URL path', () => {
  const flat = gradeRepo({ 'package.json': NEXT, 'app/api/widgets/route.ts': OPEN_ROUTE })
  const grouped = gradeRepo({ 'package.json': NEXT, 'app/(marketing)/api/widgets/route.ts': OPEN_ROUTE })
  const a = byId(flat, 'CG-WEB-001')
  const b = byId(grouped, 'CG-WEB-001')
  assert.ok(a && b, 'the unauthenticated route is flagged wherever the folder lives')
  assert.equal(a.title_en, b.title_en, 'the URL in the title must be group-stripped and identical')
  assert.match(b.title_en, /\/api\/widgets/)
  assert.doesNotMatch(b.title_en, /marketing/, 'the group segment must not appear in the URL')
  assert.equal(a.severity, b.severity)
})

// TRANSFORM: move a middleware-covered route into a route group, keeping the same `/api/:path*`
// matcher.
// INVARIANT: because urlPathOf strips the group, the URL matched against the matcher is still
// `/api/widgets`, so the route stays `undeterminable` (covered). If the group leaked into the URL
// the path would become `/(marketing)/api/widgets` and the matcher would miss it, flipping the
// route to a false `fail`.
test('middleware coverage survives moving the route into a route group', () => {
  const flat = gradeRepo({
    'package.json': NEXT, 'app/api/widgets/route.ts': OPEN_ROUTE, 'middleware.ts': mwWith("['/api/:path*']"),
  })
  const grouped = gradeRepo({
    'package.json': NEXT, 'app/(marketing)/api/widgets/route.ts': OPEN_ROUTE, 'middleware.ts': mwWith("['/api/:path*']"),
  })
  assert.equal(dispositionOf(flat, 'routes', 'route:app/api/widgets/route.ts'), 'undeterminable')
  assert.equal(dispositionOf(grouped, 'routes', 'route:app/(marketing)/api/widgets/route.ts'), 'undeterminable',
    'the matcher covers the group-stripped URL, so coverage must not change')
  assert.equal(grouped.coverage.routes.counts.fail, 0)
})

// ---------------------------------------------------------------------------
// 7. DESTRUCTURING / PROPERTY ALIASES
// ---------------------------------------------------------------------------

const DESTR_BASE = `import { createServerClient } from '@supabase/ssr'
export function q() {
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, {})
  return supabase.from('orders').select()
}`

// TRANSFORM: pull `.from` off the client first — const { from } = supabase; from('orders') —
// instead of chaining supabase.from('orders').
// INVARIANT: both reach the `orders` table, so it must be enumerated as a subject either way
// (undeterminable here, since there are no migrations to prove its RLS state). A table that exists
// in the code must not disappear because of how the method was called.
// FRAGILITY (real defect): the table-reference scan (project_model.mjs TABLE_REF_RE) requires the
// literal `.from('table')`. The destructured call `from('orders')` has no leading dot, so it is
// invisible: `orders` is never discovered, drops out of the tables coverage set, and any RLS
// exposure it carries is silent. This is the documented destructuring limit — the correct
// behaviour is still to enumerate the table.
test('a table reached via `const { from } = supabase` is still discovered', () => {
  const chained = gradeRepo({ 'package.json': NEXT, 'lib/data.ts': DESTR_BASE })
  assert.ok(subjectsOf(chained, 'tables').includes('table:orders'),
    'control: the chained `.from(\'orders\')` is discovered')

  const destructured = gradeRepo({
    'package.json': NEXT,
    'lib/data.ts': `import { createServerClient } from '@supabase/ssr'
export function q() {
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, {})
  const { from } = supabase
  return from('orders').select()
}`,
  })
  assert.ok(subjectsOf(destructured, 'tables').includes('table:orders'),
    'destructuring the client is semantics-preserving — the table must still be enumerated')
})

// ---------------------------------------------------------------------------
// 8. ADVERSARIAL FALSE-POSITIVE GUARDS
//
// Found by the adversarial verification pass that attacked the destructured-`from` fix. The scan
// must fire ONLY when `from` comes off a real Supabase client, and must never read code out of a
// comment or string. Each of these was a real false positive the loose first version produced.
// ---------------------------------------------------------------------------

// RxJS's `from` is destructured exactly like a Supabase query builder — `const { from } = rxjs` —
// but it is an Observable factory, not a table query. `from('heartbeat')` is a stream label, not a
// table. The loose fix invented a phantom `table:heartbeat` and a spurious needs-review P0 on this
// genuinely clean app.
test('a destructured `from` from RxJS (not a Supabase client) invents no phantom table', () => {
  const r = gradeRepo({
    'package.json': JSON.stringify({ name: 'x', dependencies: { '@supabase/supabase-js': '2.45.0', rxjs: '7.8.0' } }),
    'supabase/migrations/001.sql': `create table public.orders (id uuid primary key, user_id uuid not null);
alter table public.orders enable row level security;
create policy own on public.orders for all using (auth.uid() = user_id);`,
    'src/realtime.js': `import { createClient } from '@supabase/supabase-js'
import * as rxjs from 'rxjs'
const supabase = createClient(process.env.URL, process.env.ANON)
const { from } = rxjs
export function stream() {
  supabase.from('orders').select()
  return from('heartbeat')
}`,
  })
  assert.ok(!subjectsOf(r, 'tables').includes('table:heartbeat'),
    "RxJS's from('heartbeat') is a stream label, not a database table — it must not be enumerated")
  assert.ok(subjectsOf(r, 'tables').includes('table:orders'), 'the real dotted .from(orders) is still found')
  assert.ok(!r.findings.some(f => f.id === 'CG-DB-COVERAGE'),
    'no phantom coverage P0 for a table that does not exist')
})

// The real destructured case must still work — `from` off an actual client variable.
test('a destructured `from` off a real Supabase client still enumerates the table', () => {
  const r = gradeRepo({
    'package.json': JSON.stringify({ name: 'x', dependencies: { '@supabase/ssr': '0.5.0' } }),
    'lib/data.ts': `import { createServerClient } from '@supabase/ssr'
export function q() {
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, {})
  const { from } = supabase
  return from('orders').select()
}`,
  })
  assert.ok(subjectsOf(r, 'tables').includes('table:orders'))
})

// A service-role createClient that exists only in a COMMENT of a client component must not produce
// a P0. The scans now read comment/string-stripped code.
test('a service-role createClient in a comment produces no CG-DB-006', () => {
  const r = gradeRepo({
    'package.json': JSON.stringify({ name: 'x', dependencies: { next: '15.0.0', '@supabase/supabase-js': '2.45.0' } }),
    'app/page.tsx': `'use client'
import { createClient } from '@supabase/supabase-js'
// Bad example, never ship: const admin = createClient(url, SERVICE_ROLE_KEY)
export default function Page() { return null }`,
  })
  assert.ok(!byId(r, 'CG-DB-006'),
    'a createClient(SERVICE_ROLE) that lives only in a comment must not be flagged')
})

// A table named only in a comment must not be enumerated.
test('a commented-out `.from(\'x\')` does not enumerate a phantom table', () => {
  const r = gradeRepo({
    'package.json': JSON.stringify({ name: 'x', dependencies: { '@supabase/supabase-js': '2.45.0' } }),
    'lib/legacy.ts': `import { createClient } from '@supabase/supabase-js'
const supabase = createClient(process.env.URL, process.env.ANON)
// legacy path removed: supabase.from('ghost_table').select()
export const s = supabase`,
  })
  assert.ok(!subjectsOf(r, 'tables').includes('table:ghost_table'),
    'a table named only in a comment must not be enumerated')
})

// ---------------------------------------------------------------------------
// 9. AUDIT BYPASS GUARDS — the route / LLM / DEFINER / server-only detectors used to read RAW text
//
// The security-team audit reproduced a whole bypass tier: these detectors matched comment and
// string content as if it were code, so a decoy comment could silence a real finding or invent a
// false one. They now run over the stripper's CODE mask, like the table/client scans. Each test
// below reproduces one bypass and asserts it is closed.
// ---------------------------------------------------------------------------

test('a `service_role` mention in a COMMENT does not inflate a route to a false P0', () => {
  const r = gradeRepo({
    'package.json': NEXT,
    'app/api/public/route.ts': `// this route does NOT touch the service_role key
export async function GET() { return Response.json({ ok: true }) }`,
  })
  const f = byId(r, 'CG-WEB-001')
  assert.ok(f, 'the unauthenticated route is still flagged')
  assert.notEqual(f.severity, 'P0', 'a comment must not make it a service-role P0')
})

test('an ownership mention in a COMMENT does not silence a service-role IDOR (CG-WEB-004)', () => {
  const r = gradeRepo({
    'package.json': NEXT,
    'app/api/orders/[id]/route.ts': `import { createClient } from '@supabase/supabase-js'
const admin = createClient(process.env.URL, process.env.SUPABASE_SERVICE_ROLE_KEY)
export async function GET(req, { params }) {
  // ownership is enforced by user_id upstream (it is not)
  return Response.json(await admin.from('orders').select().eq('id', params.id).single())
}`,
  })
  assert.ok(byId(r, 'CG-WEB-004'), 'a comment must not suppress the IDOR finding')
})

test('an auth.uid() mention in a SECURITY DEFINER comment does not silence CG-DB-004', () => {
  const r = gradeRepo({
    'package.json': NEXT,
    'supabase/migrations/001.sql': `create function public.wipe() returns void
language plpgsql security definer set search_path = public as $$
begin
  -- access is gated by auth.uid() upstream (it is not)
  delete from public.orders;
end;
$$;`,
  })
  assert.ok(byId(r, 'CG-DB-004'), 'a commented auth.uid() must not clear the no-auth-check finding')
})

test("a commented 'server-only' does not prune reachability and bury a leak (CG-DB-006)", () => {
  const r = gradeRepo({
    'package.json': NEXT,
    'lib/db.ts': `// we intentionally do NOT import 'server-only' here
import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    'app/page.tsx': `'use client'
import { admin } from '../lib/db'
export default function P() { return admin ? null : null }`,
  })
  assert.ok(byId(r, 'CG-DB-006'), "a comment mentioning 'server-only' must not prune the client chain")
})

test('a commented `chat.completions.create` does not invent a phantom LLM site', () => {
  const r = gradeRepo({
    'package.json': JSON.stringify({ name: 'x', dependencies: { next: '15.0.0' } }),
    'app/api/x/route.ts': `export async function POST() {
  // TODO: later call openai.chat.completions.create(...) here
  return Response.json({ ok: true })
}`,
  })
  assert.ok(!byId(r, 'CG-LLM-002') && !byId(r, 'CG-LLM-004'),
    'a commented LLM call must not create a phantom denial-of-wallet finding')
})

test('CG-LLM-003 fires on a string-concat prompt + shorthand tools (the bypass)', () => {
  const r = gradeRepo({
    'package.json': JSON.stringify({ name: 'x', dependencies: { openai: '4.60.0', next: '15.0.0' } }),
    'app/api/agent/route.ts': `import OpenAI from 'openai'
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
export async function POST(req) {
  const prompt = 'Answer this: ' + req.body.message
  const tools = [{ name: 'sendMail' }]
  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: prompt }], tools }))
}`,
  })
  assert.ok(byId(r, 'CG-LLM-003'),
    'concat prompt + shorthand tools must still trigger the prompt-injection finding')
})

// Audit #6 — the worst reproduced finding. Moving the service-role client one import away used to
// delete the IDOR and downgrade the missing-auth from P0 to P2. The import graph already knows the
// helper is service-role; the route reachability post-pass now carries it through.
test('a service-role client extracted into a helper still drives the route IDOR (CG-WEB-004)', () => {
  const r = gradeRepo({
    'package.json': NEXT,
    'lib/db.ts': `import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    'app/api/orders/[id]/route.ts': `import { admin } from '@/lib/db'
export async function GET(req, { params }) {
  return Response.json(await admin.from('orders').select().eq('id', params.id).single())
}`,
  })
  assert.ok(byId(r, 'CG-WEB-004'), 'the IDOR must survive the client living in a helper')
})

test('an unauthenticated route reaching a service-role helper is a P0, not a P2', () => {
  const r = gradeRepo({
    'package.json': NEXT,
    'lib/db.ts': `import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
    'app/api/wipe/route.ts': `import { admin } from '@/lib/db'
export async function POST() { return Response.json(await admin.from('orders').delete()) }`,
  })
  const f = byId(r, 'CG-WEB-001')
  assert.ok(f, 'the unauthenticated route is flagged')
  assert.equal(f.severity, 'P0', 'reaching the service-role key via import makes an unauth route a total compromise')
})
