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
  const dir = mkdtempSync(join(tmpdir(), 'cg-clean-'))
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

// ---------------------------------------------------------------------------
// THE CRY-WOLF TEST.
//
// This project's whole thesis is that a security tool which fires at correct code loses its
// audience — and this audience, non-expert vibecoders, has no way to tell a false P0 from a real
// one. A wrong P0 makes someone rotate live keys and announce a breach that never happened.
//
// So the fixture below is deliberately built ONLY from the recommended patterns: t3-env guarding
// server variables, @supabase/ssr's user-scoped createServerClient, RLS on with uid-scoped
// policies, middleware auth with a matcher, zod validation, an Upstash rate limit, a server-side
// LLM call with max_tokens, and a CSP in next.config.
//
// A correct app must produce a QUIET report. Every finding this fixture produces is, by
// construction, a false positive.
//
// Three real defects were caught by exactly this test and are guarded by the assertions below:
//   1. A t3-env schema naming OPENAI_API_KEY was classified as an LLM call site (the detector
//      matched the substring "openai" in a variable name) and then reported for having no rate
//      limit — the recommended env pattern earning a finding.
//   2. A handler that reads no request body was reported for not validating one.
//   3. Non-prefixed server secrets referenced from a client-imported module were reported as
//      exposed. Bundlers inline only allowlisted prefixes, so nothing was exposed at all.
// ---------------------------------------------------------------------------

const CORRECT_APP = {
  'package.json': JSON.stringify({
    name: 'clean',
    dependencies: {
      next: '15.0.0', '@supabase/ssr': '0.5.0', '@t3-oss/env-nextjs': '0.11.0',
      zod: '3.23.0', '@upstash/ratelimit': '2.0.0', openai: '4.60.0',
    },
  }),

  '.env.example': 'NEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nSTRIPE_SECRET_KEY=\nDATABASE_URL=\nOPENAI_API_KEY=\n',

  // The textbook guard AGAINST leaking server vars into the client bundle. Its runtimeEnv block
  // necessarily names every server secret, which is what made naive readers cry wolf here.
  'src/env.mjs': `import { createEnv } from '@t3-oss/env-nextjs'
export const env = createEnv({
  server: { STRIPE_SECRET_KEY: z.string(), DATABASE_URL: z.string(), OPENAI_API_KEY: z.string() },
  client: { NEXT_PUBLIC_SUPABASE_URL: z.string(), NEXT_PUBLIC_SUPABASE_ANON_KEY: z.string() },
  runtimeEnv: {
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
    DATABASE_URL: process.env.DATABASE_URL,
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL,
    NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
  },
})`,

  // The officially recommended user-scoped client. RLS with auth.uid() is the correct and
  // sufficient control for it, so its .eq() calls are not IDOR.
  'lib/supabase.ts': `import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
export function db() {
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, { cookies })
}`,

  'app/api/orders/route.ts': `import { z } from 'zod'
import { db } from '@/lib/supabase'
const Body = z.object({ item: z.string() })
export async function POST(req: Request) {
  const supabase = db()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  const parsed = Body.safeParse(await req.json())
  if (!parsed.success) return new Response('bad request', { status: 400 })
  return Response.json(await supabase.from('orders').insert({ ...parsed.data, user_id: user.id }))
}`,

  'app/api/chat/route.ts': `import OpenAI from 'openai'
import { Ratelimit } from '@upstash/ratelimit'
import { db } from '@/lib/supabase'
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
const ratelimit = new Ratelimit({ limiter: Ratelimit.slidingWindow(10, '60 s') })
export async function POST(req: Request) {
  const supabase = db()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  const { success } = await ratelimit.limit(user.id)
  if (!success) return new Response('slow down', { status: 429 })
  const r = await openai.chat.completions.create({ model: 'gpt-4o-mini', max_tokens: 500, messages: [] })
  return Response.json(r)
}`,

  'middleware.ts': `import { createServerClient } from '@supabase/ssr'
export async function middleware(req) {
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, { cookies: req.cookies })
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return Response.redirect(new URL('/login', req.url))
}
export const config = { matcher: ['/api/:path*'] }`,

  'next.config.js': `module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: "default-src 'self'" }] }]
  },
}`,

  'supabase/migrations/001_init.sql': `create table public.orders (id uuid primary key, user_id uuid not null, item text);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for all using (auth.uid() = user_id);

create table public.profiles (id uuid primary key, display_name text);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for all using (auth.uid() = id);`,
}

test('a correct app produces NO findings at all', () => {
  const r = gradeRepo(CORRECT_APP)
  assert.deepEqual(r.findings.map(f => `${f.severity} ${f.id} ${f.title_en}`), [],
    'every finding listed here is a false positive against code that follows every recommendation')
  assert.equal(r.verdict.level, 'clean')
  assert.equal(r.verdict.confirmedP0, 0)
})

test('a t3-env schema naming OPENAI_API_KEY is not an LLM call site', () => {
  // The detector once matched the substring "openai" anywhere in a file, so the env schema was
  // enumerated as a call site and reported for having no rate limit.
  const r = gradeRepo(CORRECT_APP)
  const llm = r.coverage.llmSites
  assert.equal(llm.enumerated, 1, 'only the route that imports the SDK is a call site')
  const subjects = [...llm.pass, ...llm.fail, ...llm.undeterminable, ...llm.allowlisted].map(s => s.subject)
  assert.ok(!subjects.some(s => s.includes('env.mjs')),
    'naming a provider variable is not calling a provider')
})

test('server-only secrets in a correct app pass, and public identifiers are allowlisted', () => {
  const r = gradeRepo(CORRECT_APP)
  const env = r.coverage.envVars
  const passed = env.pass.map(s => s.subject)
  for (const name of ['env:STRIPE_SECRET_KEY', 'env:DATABASE_URL', 'env:OPENAI_API_KEY']) {
    assert.ok(passed.includes(name), `${name} is not inlined by the bundler, so it is not exposed`)
  }
  const allowed = env.allowlisted.map(s => s.subject)
  assert.ok(allowed.includes('env:NEXT_PUBLIC_SUPABASE_ANON_KEY'),
    'the anon key is a public identifier by design — calling it a leaked secret is the trust catastrophe')
})

test('RLS enabled with uid-scoped policies is a structural pass', () => {
  const r = gradeRepo(CORRECT_APP)
  assert.equal(r.coverage.tables.enumerated, 2)
  assert.equal(r.coverage.tables.counts.pass, 2)
  assert.equal(r.coverage.tables.counts.fail, 0)
})

test('a handler that reads no body is not asked to validate one', () => {
  // The chat route takes no request body. Demanding schema validation from it is noise, and noise
  // is what makes people stop reading the report.
  const r = gradeRepo(CORRECT_APP)
  assert.ok(!r.findings.some(f => f.id === 'CG-WEB-002'))
})

test('LAW 1: an authenticated route is undeterminable, never pass', () => {
  // Both routes call getUser() and check the result. We still refuse to mark them `pass`: from a
  // regex, a correct check is indistinguishable from an unawaited call whose result is ignored.
  // These rows are the reviewer's work list, and that hand-off is the whole architecture.
  const r = gradeRepo(CORRECT_APP)
  assert.equal(r.coverage.routes.counts.pass, 0, 'a token is not a proof')
  assert.equal(r.coverage.routes.counts.undeterminable, 2)
  for (const row of r.coverage.routes.undeterminable) {
    assert.match(row.note, /not verified/, 'the reason must say what was not established')
  }
})

test('coverage adds up on a correct app, and every subject set is accounted for', () => {
  const r = gradeRepo(CORRECT_APP)
  for (const [setName, set] of Object.entries(r.coverage)) {
    const c = set.counts
    assert.equal(c.pass + c.fail + c.undeterminable + c.allowlisted, set.enumerated,
      `LAW 2 broken in "${setName}": a subject fell out of the ledger`)
  }
})
