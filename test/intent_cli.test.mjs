import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseIntentYaml, validateIntent } from '../plugin/scripts/business_logic.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const GRADER = join(HERE, '..', 'plugin', 'scripts', 'grader.mjs')

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS
//
// business_logic.test.mjs covers the audit as a LIBRARY: it hands `grade()` an intent object it
// constructed in memory. Nobody using this tool does that. They run the CLI, and everything between
// the flag and the audit — argument parsing, `loadIntent`, auto-discovery next to the scanned repo,
// the exit codes — was untested. The tier shipped once already as dead code that grader.mjs imported
// and never called; the seam between "the audit works" and "the user can reach it" is exactly where
// that kind of defect lives.
//
// Two of the tests below are CRY-WOLF tests and they matter more than the rest. This project's
// thesis is that a security tool which fires at correct code loses an audience that cannot tell a
// false P0 from a real one — and business logic is the tier most able to do that, because it reasons
// about rules rather than about facts.
// ---------------------------------------------------------------------------

/** Run the grader CLI as a subprocess and report exactly what a user would see. */
function runGrader(args, { cwd } = {}) {
  const r = spawnSync(process.execPath, [GRADER, ...args], {
    cwd, encoding: 'utf8', input: '', timeout: 180000, maxBuffer: 64 * 1024 * 1024,
  })
  if (r.error) throw r.error
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' }
}

function withRepo(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-intent-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return fn(dir)
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const bizIds = report => report.findings.filter(f => f.id.startsWith('CG-BIZ-')).map(f => f.id)

// A deliberately broken app: a service-role client reads an order by id with no ownership filter,
// spreads the request body into a write, and lets a user set `status`.
const LEAKY_APP = {
  'package.json': '{"name":"x","dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.45.0"}}',
  'supabase/migrations/001_init.sql': `create table public.orders (
  id uuid primary key,
  user_id uuid not null,
  org_id uuid,
  item text,
  quantity int,
  price numeric,
  status text
);
create table public.profiles (id uuid primary key, display_name text);`,
  'lib/db.ts': `import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`,
  'app/api/orders/[id]/route.ts': `import { admin } from '@/lib/db'
export async function GET(req, { params }) {
  const { data } = await admin.from('orders').select('*').eq('id', params.id).single()
  return Response.json(data)
}
export async function POST(req, { params }) {
  const body = await req.json()
  const { price, status, item } = body
  return Response.json(await admin.from('orders').update({ ...body, status: 'paid' }).eq('id', params.id))
}`,
}

// The reference-correct app: RLS on with a uid-scoped policy, the recommended user-scoped
// @supabase/ssr client, an explicit ownership filter, zod narrowing the body to two fields. Used
// twice below — once with the tier OFF and once with it ON — because the pair is the actual claim:
// confirming intent must not start reporting the users who did everything right.
const CORRECT_APP = {
  'package.json': '{"name":"clean","dependencies":{"next":"15.0.0","@supabase/ssr":"0.5.0","zod":"3.23.0"}}',
  'supabase/migrations/001_init.sql': `create table public.orders (id uuid primary key, user_id uuid not null, item text, quantity int);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for all using (auth.uid() = user_id);

create table public.profiles (id uuid primary key, display_name text);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for all using (auth.uid() = id);`,
  'lib/supabase.ts': `import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
export function db() {
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, { cookies })
}`,
  'app/api/orders/[id]/route.ts': `import { db } from '@/lib/supabase'
export async function GET(req, { params }) {
  const supabase = db()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  return Response.json(await supabase.from('orders').select('*').eq('id', params.id).eq('user_id', user.id).single())
}`,
  'app/api/orders/route.ts': `import { z } from 'zod'
import { db } from '@/lib/supabase'
const Body = z.object({ item: z.string(), quantity: z.number() })
export async function POST(req: Request) {
  const supabase = db()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  const parsed = Body.safeParse(await req.json())
  if (!parsed.success) return new Response('bad request', { status: 400 })
  const { item, quantity } = parsed.data
  return Response.json(await supabase.from('orders').insert({ item, quantity, user_id: user.id }))
}`,
}

// The intent a careful user would confirm through /cg-intent for exactly that app.
const CORRECT_INTENT = `roles: [anonymous, user, admin]
default_role: user

resources:
  orders:
    owned_by: user_id
    tenant: null
    mutable_fields: [item, quantity]
  profiles:
    owned_by: id
    tenant: null
`

const LEAKY_INTENT = `roles: [anonymous, user, admin]
default_role: user

resources:
  orders:
    owned_by: user_id
    tenant: null
    state_column: status
    states: [cart, placed, paid]
    transitions:
      "any->paid": [system]
    mutable_fields: [item, quantity]
  profiles:
    owned_by: id
`

// ---------------------------------------------------------------------------
// 1–2. Reaching the tier at all: the explicit flag, and the file the user was told to commit.
// ---------------------------------------------------------------------------

test('--intent <file> makes the business-logic audit CONFIRMED rather than assumed', () => {
  withRepo({ ...LEAKY_APP, 'elsewhere/my-intent.yml': LEAKY_INTENT }, dir => {
    const r = runGrader([dir, '--intent', join(dir, 'elsewhere', 'my-intent.yml')])
    assert.equal(r.status, 0, r.stderr)
    const report = JSON.parse(r.stdout)
    assert.equal(report.businessLogic.status, 'confirmed',
      'an intent file the user named explicitly must be the one the audit runs against')
    assert.ok(report.businessLogic.resources.length > 0)
    for (const res of report.businessLogic.resources) {
      assert.equal(res.assumed, false, `${res.resource} is still marked assumed`)
    }
  })
})

test('claudeguard.intent.yml at the SCANNED repo root is discovered without a flag', () => {
  // The file the guard recipe and /cg-intent tell the user to commit. If auto-discovery did not
  // work, every one of those instructions would produce a file the tool silently ignores.
  withRepo({ ...LEAKY_APP, 'claudeguard.intent.yml': LEAKY_INTENT }, dir => {
    const r = runGrader([dir])
    assert.equal(r.status, 0, r.stderr)
    const report = JSON.parse(r.stdout)
    assert.equal(report.businessLogic.status, 'confirmed')
    assert.ok(report.businessLogic.intentPath, 'the report must name the file its conclusions rest on')
    assert.match(report.businessLogic.intentPath.split(/[\\/]/).pop(), /^claudeguard\.intent\.yml$/)
    assert.equal(report.businessLogic.proposedIntent, null,
      'a confirmed audit has nothing left to propose')
  })
})

// ---------------------------------------------------------------------------
// 3. The two failure modes that must be LOUD. A silently ignored intent file is the whole defect
//    this layer exists to prevent, one level up: the user thinks the rules are being checked.
// ---------------------------------------------------------------------------

test('an explicitly named intent file that does not exist exits 2 instead of grading without it', () => {
  withRepo(LEAKY_APP, dir => {
    const missing = join(dir, 'typo.intent.yml')
    const r = runGrader([dir, '--intent', missing])
    assert.equal(r.status, 2, 'a named file that is absent is a typo, not silence')
    assert.match(r.stderr, /no such file/i)
    assert.equal(r.stdout.trim(), '', 'nothing may be graded when the stated rules could not be read')
  })
})

test('--check-intent rejects a typo\'d key by NAME, which is what stops a check being silently off', () => {
  // `owner_by:` parses as perfectly good YAML. Without the unknown-key rejection it would be read,
  // ignored, and the ownership check for that resource would quietly never run — while the report
  // showed a business-logic section that ran and concluded nothing was wrong.
  withRepo({ ...LEAKY_APP, 'claudeguard.intent.yml': 'resources:\n  orders:\n    owner_by: user_id\n' }, dir => {
    const r = runGrader([dir, '--check-intent', join(dir, 'claudeguard.intent.yml')])
    assert.notEqual(r.status, 0, 'a file the audit cannot use must not validate')
    assert.match(r.stderr, /unknown key "owner_by"/, 'the message must name the typo, not just fail')
    assert.match(r.stderr, /owned_by/, 'and it must name the key that was meant')
  })
})

test('--check-intent accepts a well-formed file and exits 0', () => {
  withRepo({ ...LEAKY_APP, 'claudeguard.intent.yml': LEAKY_INTENT }, dir => {
    const r = runGrader([dir, '--check-intent', join(dir, 'claudeguard.intent.yml')])
    assert.equal(r.status, 0, r.stderr)
    assert.match(r.stdout, /^ok:/)
  })
})

// ---------------------------------------------------------------------------
// 4–5. THE CRY-WOLF TESTS.
// ---------------------------------------------------------------------------

test('CRY-WOLF: no intent file means zero CG-BIZ findings, exit 0, and an empty stderr', () => {
  // Pinned at the CLI layer on purpose. `bl-intent-unconfirmed` was once a P2 finding, which put a
  // CG-BIZ id in the findings list of every repository on its first run — the tool reporting a
  // security finding because the user had not written an optional config file yet. The library test
  // covers the audit; this one covers the thing a user actually runs, including the exit code a CI
  // job reads and the stderr a person sees.
  withRepo(CORRECT_APP, dir => {
    const r = runGrader([dir])
    assert.equal(r.status, 0, 'not configuring the tool is not an error')
    assert.equal(r.stderr, '', 'and it is not a warning on stderr either')
    const report = JSON.parse(r.stdout)
    assert.deepEqual(bizIds(report), [], 'a missing optional config is never a finding about the app')
    // The other half: silence would be worse than the false finding.
    assert.equal(report.businessLogic.status, 'assumed')
    assert.equal(report.businessLogic.intentPath, null)
    assert.ok(report.businessLogic.proposedIntent, 'the draft has to travel so the gap is actionable')
    assert.ok(report.businessLogic.assumptions.some(a => /assumed|guess/i.test(a)))
  })
})

test('the MISSING FILE itself is never a finding, even on an app the guessed model does flag', () => {
  // The sharper half of the same rule. On a broken app the assumed model legitimately produces
  // business-logic leads — that is the tier doing its job against a guess, and the report says so.
  // What must never appear is a finding ABOUT THE CONFIGURATION: `business-logic:intent` has no
  // policy in the grader and must never be given one. Nothing about the app is wrong when the file
  // is absent; something about our knowledge of it is, and that is a coverage row.
  withRepo(LEAKY_APP, dir => {
    const r = runGrader([dir])
    assert.equal(r.status, 0)
    assert.equal(r.stderr, '')
    const report = JSON.parse(r.stdout)
    assert.ok(!report.findings.some(f => f.subject === 'business-logic:intent'),
      'a config file the user has not written yet is not a vulnerability')
    assert.ok(report.businessLogic.assumptions.length > 0,
      'and the gap must still be stated, or an assumed section reads as a checked one')
  })
})

test('CRY-WOLF: a CONFIRMED intent on a reference-correct app is still completely silent', () => {
  // Nobody had ever checked this direction. Every other cry-wolf test scans a correct app with NO
  // intent file, so the whole tier is inert in them. This one turns the tier ON over the same code
  // that follows every recommendation and asserts the report stays empty.
  //
  // If confirming intent on a correct app produces a CG-BIZ-001, then the feature punishes exactly
  // the users who did the work, and it is a cry-wolf machine rather than a review aid.
  withRepo({ ...CORRECT_APP, 'claudeguard.intent.yml': CORRECT_INTENT }, dir => {
    const r = runGrader([dir])
    assert.equal(r.status, 0, r.stderr)
    const report = JSON.parse(r.stdout)
    assert.equal(report.businessLogic.status, 'confirmed', 'the tier really is switched on here')
    assert.deepEqual(
      report.findings.filter(f => f.id.startsWith('CG-BIZ-')).map(f => `${f.id} ${f.subject}`), [],
      'every business-logic finding on this fixture is, by construction, a false positive')
    assert.equal(report.verdict.level, 'clean')
    // And it did not merely go quiet by checking nothing: rules were actually reached.
    const orders = report.businessLogic.resources.find(x => x.resource === 'orders')
    assert.ok(orders, 'orders must have been walked')
    assert.ok(orders.rulesChecked > 0, 'silence with zero rules checked would prove nothing')
  })
})

// ---------------------------------------------------------------------------
// 6. A broken intent file is ignored ENTIRELY rather than half-applied.
// ---------------------------------------------------------------------------

test('a malformed intent file yields status "error" and still no CG-BIZ finding', () => {
  // Half-reading an intent file is the worst outcome available: the audit would check some rules
  // against the author's model and the rest against a guess, and the report would call the whole
  // thing confirmed. So a parse failure discards the file and says so.
  withRepo({ ...CORRECT_APP, 'claudeguard.intent.yml': 'resources:\n  orders:\n\towned_by: user_id\n' }, dir => {
    const r = runGrader([dir])
    assert.equal(r.status, 0, 'a broken config is reported, not thrown')
    assert.equal(r.stderr, '')
    const report = JSON.parse(r.stdout)
    assert.equal(report.businessLogic.status, 'error')
    assert.match(report.businessLogic.error, /tab/i, 'the reason has to be actionable')
    assert.deepEqual(bizIds(report), [], 'a broken config file is still not a vulnerability in the app')
    assert.equal(report.businessLogic.intentPath, null, 'a file that was ignored must not be cited')
    assert.ok(report.businessLogic.assumptions.some(a => /could not be read/i.test(a)))
    assert.ok(report.businessLogic.proposedIntent,
      'and the user is handed a working draft rather than left with the broken file')
  })
})

// ---------------------------------------------------------------------------
// 7. The draft the user is handed must be a file the tool can read back.
// ---------------------------------------------------------------------------

test('--propose-intent emits a draft that round-trips and names every table', () => {
  // /cg-intent tells the model to take this draft rather than compose YAML by hand. That is only
  // safe if the renderer and the reader are genuinely one matched pair — a draft the reader rejects
  // would send every first-time user to a file the grader refuses.
  withRepo(LEAKY_APP, dir => {
    const r = runGrader([dir, '--propose-intent'])
    assert.equal(r.status, 0, r.stderr)
    const yaml = r.stdout
    assert.ok(yaml.trim(), 'the draft must not be empty for a repo that has tables')

    const intent = validateIntent(parseIntentYaml(yaml))
    assert.deepEqual(Object.keys(intent.resources).sort(), ['orders', 'profiles'],
      'a table missing from the draft is a table the user is never asked about')
    assert.equal(intent.resources.orders.owned_by, 'user_id')
    assert.equal(intent.default_role, 'user')
    // The keys the proposer cannot know stay as guidance, never as an invented answer.
    assert.match(yaml, /# TODO: mutable_fields/)
    assert.ok(intent.resources.orders.mutable_fields === undefined,
      'an unstated rule must be absent, not guessed at')
  })
})

test('a filled-in draft round-trips through the reader as well as an empty one', () => {
  // The half /cg-intent depends on: the interview's answers go back out through renderIntentYaml,
  // so the file the user commits is produced by the same code that produced the draft. If the
  // filled-in form did not parse, the skill would have to hand-write YAML — and a hand-written file
  // can parse and still mean something other than what the user said.
  const filled = `roles: [anonymous, user, admin]
default_role: user

resources:
  orders:
    owned_by: user_id
    tenant: null
    state_column: status
    states: [cart, placed, paid]
    transitions:
      "any->paid": [system]
    mutable_fields: [item, quantity]
    read_only_for: []

rules:
  - "A coupon code may be applied at most once per order."

system_routes:
  - "app/api/webhooks/**"
`
  const intent = validateIntent(parseIntentYaml(filled))
  assert.deepEqual(intent.resources.orders.transitions['any->paid'], ['system'])
  assert.deepEqual(intent.resources.orders.mutable_fields, ['item', 'quantity'])
  assert.deepEqual(intent.resources.orders.read_only_for, [])
  assert.deepEqual(intent.system_routes, ['app/api/webhooks/**'])
  assert.equal(intent.rules.length, 1)
})

// ---------------------------------------------------------------------------
// 8. THE CEILING, over the CLI, with nothing left unstated.
// ---------------------------------------------------------------------------

test('THE CEILING: even a fully-populated intent can never produce a confirmed finding', () => {
  // The most-informed run the tool can have — every resource keyed, states and transitions
  // declared, mutable fields listed, system routes named — over an app that genuinely violates all
  // of it. It must still produce reviewer leads and nothing more. A multiple-choice answer is not
  // a proof, and the verdict counts only `confirmed`, so this is what keeps a wrong answer in a
  // config file from turning somebody's badge red.
  const FULL_INTENT = `roles: [anonymous, user, admin]
default_role: user

resources:
  orders:
    owned_by: user_id
    tenant: org_id
    state_column: status
    states: [cart, placed, paid]
    transitions:
      "any->paid": [system]
    mutable_fields: [item, quantity]
    read_only_for: [user]
  profiles:
    owned_by: id
    tenant: null
    mutable_fields: [display_name]

rules:
  - "The price of an order is computed server-side, never taken from the request body."

system_routes:
  - "app/api/webhooks/**"
`
  const baseline = withRepo(LEAKY_APP, d => JSON.parse(runGrader([d]).stdout))
  withRepo({ ...LEAKY_APP, 'claudeguard.intent.yml': FULL_INTENT }, dir => {
    const r = runGrader([dir])
    assert.equal(r.status, 0, r.stderr)
    const report = JSON.parse(r.stdout)
    assert.equal(report.businessLogic.status, 'confirmed')

    const biz = report.findings.filter(f => f.id.startsWith('CG-BIZ-'))
    assert.ok(biz.length > 0, 'this fixture violates the stated rules; silence here would be the other failure')
    for (const f of biz) {
      assert.notEqual(f.confidence, 'confirmed', `${f.id} reached confirmed — the ceiling is broken`)
      assert.equal(f.provenance, 'reviewer', `${f.id} must be attributed to a reviewer, not a rule`)
      assert.equal(f.evidence.strength, 'judgement', `${f.id} must rest on judgement`)
    }
    assert.ok(!report.findings.some(f => f.confidence === 'confirmed' && f.id.startsWith('CG-BIZ-')),
      'nothing in this tier may reach the confidence the verdict counts')

    // The property that makes the ceiling matter, stated directly: the BADGE is identical with the
    // intent file and without it. Confirming intent moves `verdict.likely` — that is the reviewer
    // work list growing, which is the whole point — but `confirmedP0`, `confirmedP1` and `level`
    // cannot move, because the verdict counts only `confirmed`. (The badge here is red for reasons
    // the business-logic tier had nothing to do with: this fixture also leaves RLS off.)
    const badge = v => ({ confirmedP0: v.confirmedP0, confirmedP1: v.confirmedP1, level: v.level })
    assert.deepEqual(badge(report.verdict), badge(baseline.verdict),
      'confirming a business model must not move the headline verdict, in either direction')
    assert.ok(report.verdict.likely > baseline.verdict.likely,
      'it should, however, have grown the reviewer work list — otherwise nothing was gained')

    // Confirming really did buy coverage, which is the only thing it claims to buy.
    const orders = report.businessLogic.resources.find(x => x.resource === 'orders')
    assert.equal(orders.assumed, false)
    assert.ok(orders.rulesChecked > 0 && orders.rulesChecked <= orders.rulesTotal)
    // And the prose rule the user wrote is reported as a reviewer task, never silently dropped.
    const rows = report.coverage.businessLogic.undeterminable.map(x => x.subject)
    assert.ok(rows.includes('bl:free-form-rule:1'), 'a stated rule the tool cannot check must still be listed')
  })
})

test('a table the intent says nothing about gets an honest bl:no-intent row', () => {
  // The outcome behind /cg-intent's "I don't know — skip this table" answer. Skipping must produce
  // a visible, countable gap — never a silently absent resource, and never a guessed rule.
  withRepo({ ...LEAKY_APP, 'claudeguard.intent.yml': 'roles: [user]\nresources:\n  orders:\n    owned_by: user_id\n' }, dir => {
    const r = runGrader([dir])
    assert.equal(r.status, 0, r.stderr)
    const report = JSON.parse(r.stdout)
    const rows = report.coverage.businessLogic.undeterminable.map(x => x.subject)
    assert.ok(rows.includes('bl:no-intent:profiles'),
      'skipping a table has to be recorded, or a skip reads as a clean result')
    assert.deepEqual(bizIds(report).filter(id => id === 'CG-BIZ-XXX'), [],
      'and it must not manufacture a finding about the skipped table')
  })
})
