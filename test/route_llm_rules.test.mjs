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
  const dir = mkdtempSync(join(tmpdir(), 'cg-rules-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return grade(JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    })))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const NEXT = '{"name":"x","dependencies":{"next":"15.0.0","openai":"4.60.0","@supabase/supabase-js":"2.45.0"}}'

test('REGRESSION: a browser-exposed LLM SDK is still checked for rate limit and token ceiling', () => {
  // dangerouslyAllowBrowser used to `continue` past the denial-of-wallet checks, hiding them on
  // exactly the worst sites — the ones already leaking the key. Disposition is exclusive (fail),
  // but the findings are additive: the same site is a P0 leak AND unthrottled AND unbounded.
  const r = gradeRepo({
    'package.json': NEXT,
    'app/api/chat/route.ts': `import OpenAI from 'openai'
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY, dangerouslyAllowBrowser: true })
export async function POST() {
  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [] }))
}`,
  })
  const ids = r.findings.filter(f => f.subject.startsWith('llm:')).map(f => f.id)
  assert.ok(ids.includes('CG-LLM-001'), 'the browser-exposed SDK is a P0')
  assert.ok(ids.includes('CG-LLM-002'), 'and it is still flagged for no rate limit')
  assert.ok(ids.includes('CG-LLM-004'), 'and for no token ceiling')
  assert.equal(r.coverage.llmSites.counts.fail, 1, 'the disposition is a single exclusive fail')
  assert.equal(r.coverage.llmSites.counts.undeterminable, 0)
})

// ---------------------------------------------------------------------------
// These three rules exist because the engine was computing facts that no rule consumed —
// routes[].hasRateLimit, routes[].readsIdParam, routes[].ownershipFilter and
// llmSites[].hasMaxTokens were all calculated on every scan and then thrown away. A fact that
// nothing grades is worse than one that is never computed: it looks like coverage in the model
// output while contributing nothing to the report.
//
// Each rule below is deliberately NARROW, because the broad version of each is a known
// false-positive generator. The tests assert both directions — that the rule fires where it
// should, and stays silent in the case that would have flooded a correct app.
// ---------------------------------------------------------------------------

test('a credential endpoint with no rate limit is flagged', () => {
  const r = gradeRepo({
    'package.json': NEXT,
    'app/api/login/route.ts': `export async function POST(req: Request) {
  const { email, password } = await req.json()
  return Response.json({ ok: true })
}`,
  })
  const f = r.findings.find(x => x.id === 'CG-WEB-003')
  assert.ok(f, 'credential endpoints are the ones that actually get brute-forced')
  assert.equal(f.severity, 'P2')
  assert.equal(f.confidence, 'needs-review', 'the limiter could be at the edge, so evidence is weak')
  assert.match(f.assumption, /edge|middleware|provider/i, 'the assumption must name the way this is wrong')
})

test('an ordinary mutating route is NOT asked for a rate limit', () => {
  // The broad version of this rule demands a limiter on every mutating route. That buries the two
  // endpoints that matter under a dozen that do not, and volume is what destroys trust.
  const r = gradeRepo({
    'package.json': NEXT,
    'app/api/notes/route.ts': `export async function POST(req: Request) {
  const body = await req.json()
  return Response.json(body)
}`,
  })
  assert.ok(!r.findings.some(f => f.id === 'CG-WEB-003'))
})

test('IDOR is flagged when a service-role client reads an id with no ownership filter', () => {
  const r = gradeRepo({
    'package.json': NEXT,
    'app/api/orders/[id]/route.ts': `import { createClient } from '@supabase/supabase-js'
const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)
export async function GET(req: Request, { params }: any) {
  return Response.json(await admin.from('orders').select().eq('id', params.id).single())
}`,
  })
  const f = r.findings.find(x => x.id === 'CG-WEB-004')
  assert.ok(f, 'a service-role client bypasses RLS, so nothing else is checking ownership')
  assert.equal(f.severity, 'P1')
})

test('the SAME shape with a user-scoped client is NOT an IDOR', () => {
  // This is the false positive that would flood every idiomatic Supabase app. With an anon,
  // user-scoped client, RLS with auth.uid() is the correct and sufficient control, so
  // `.eq('id', id)` is exactly how the official docs tell you to write it.
  const r = gradeRepo({
    'package.json': NEXT,
    'app/api/orders/[id]/route.ts': `import { createServerClient } from '@supabase/ssr'
export async function GET(req: Request, { params }: any) {
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, {})
  return Response.json(await supabase.from('orders').select().eq('id', params.id).single())
}`,
  })
  assert.ok(!r.findings.some(f => f.id === 'CG-WEB-004'),
    'RLS is the control for a user-scoped client — flagging this punishes correct code')
})

test('REGRESSION: an unauthenticated route is still checked by every other rule', () => {
  // The auth verdict used to `continue` out of the loop, which made the validation, rate-limit and
  // IDOR rules unreachable for exactly the routes that need them most. A login endpoint has no
  // auth check BY DEFINITION, so it could never be checked for a rate limit — the one rule that
  // matters for it. A route's disposition is exclusive; its findings are not.
  const r = gradeRepo({
    'package.json': NEXT,
    'app/api/login/route.ts': `import { createClient } from '@supabase/supabase-js'
const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)
export async function POST(req: Request, { params }: any) {
  const body = await req.json()
  return Response.json(await admin.from('users').select().eq('id', params.id).single())
}`,
  })
  const ids = r.findings.map(f => f.id)
  for (const id of ['CG-WEB-001', 'CG-WEB-002', 'CG-WEB-003', 'CG-WEB-004']) {
    assert.ok(ids.includes(id), `${id} must still be evaluated on an unauthenticated route`)
  }
  // The disposition, unlike the findings, stays exclusive.
  assert.equal(r.coverage.routes.enumerated, 1)
  assert.equal(r.coverage.routes.counts.fail, 1)
})

test('an LLM call with no token ceiling is flagged, and one with a ceiling is not', () => {
  const without = gradeRepo({
    'package.json': NEXT,
    'app/api/chat/route.ts': `import OpenAI from 'openai'
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
export async function POST() {
  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [] }))
}`,
  })
  const f = without.findings.find(x => x.id === 'CG-LLM-004')
  assert.ok(f, 'no ceiling means one request can cost an unbounded amount')
  assert.equal(f.severity, 'P3')

  const with_ = gradeRepo({
    'package.json': NEXT,
    'app/api/chat/route.ts': `import OpenAI from 'openai'
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
export async function POST() {
  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o-mini', max_tokens: 500, messages: [] }))
}`,
  })
  assert.ok(!with_.findings.some(x => x.id === 'CG-LLM-004'))
})
