import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  urlPathOf, candidatesFromGraded, classifyResponse, resolveWorklist,
} from '../plugin/scripts/dynamic_runner.mjs'
import { GateSession, RunRegistry } from '../plugin/scripts/dynamic_gate.mjs'
import { grade } from '../plugin/scripts/grader.mjs'

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS
//
// The runner is the honest route to `confirmed`. The static engine leaves a route `undeterminable`
// when it cannot tell whether an auth call gates the handler; this runner sends one unauthenticated
// request and lets the answer settle it — a 200 is a confirmed auth bypass with a live proof, a
// 401/403 is the control working. Every send goes through the gate, nothing is sent on a dry run,
// and the response body is never read. These tests drive the whole loop with an injected sender, so
// no socket is ever opened.
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000_000

// A config that WOULD send traffic against `staging.myapp.com` at active tier — what an authz_probe
// needs. Modeled on the gate suite's own fixtures.
function liveConfig(over = {}) {
  return {
    dynamic_testing: {
      enabled: true,
      authorization: { attested_by: 'Jane <jane@app.com>', relationship: 'owner', authorization_ref: null, attested_at: '2026-07-29' },
      scope: { allowlist: ['staging.myapp.com'], blocklist: [], exclude_paths: [] },
      tier: 'active',
      execution: { dry_run: false, destructive: false, require_confirmation: true, max_requests_per_minute: 60 },
      tools: { hexstrike: { allow: ['authz_probe', 'idor_probe', 'rls_probe'], deny: [] } },
      ...over,
    },
  }
}

// A resolver that answers with a public address — passes the resolved-IP gate (only private/metadata
// space needs explicit attestation). Never does real DNS.
const publicResolver = async () => ['93.184.216.34']

function session(config, { interactive = true, confirmation = true, resolver = publicResolver } = {}) {
  return new GateSession({ config, clock: () => NOW, interactive, confirmation, resolver, registry: new RunRegistry({ clock: () => NOW }), killSwitch: () => false })
}

const graded = subjects => ({ coverage: { routes: { undeterminable: subjects.map(s => ({ subject: s, note: 'auth call present, gating unverified' })) } } })

// ---------------------------------------------------------------------------

test('urlPathOf derives the probe path from the route file', () => {
  assert.equal(urlPathOf('app/api/orders/route.ts'), '/api/orders')
  assert.equal(urlPathOf('src/app/api/orders/[id]/route.ts'), '/api/orders/[id]')
  assert.equal(urlPathOf('pages/api/login.ts'), '/api/login')
})

test('candidatesFromGraded takes ONLY undeterminable routes, dedups, and derives paths', () => {
  const c = candidatesFromGraded(graded(['route:app/api/orders/route.ts', 'route:app/api/orders/route.ts', 'route:pages/api/login.ts']))
  assert.equal(c.length, 2, 'the duplicate subject collapses')
  assert.deepEqual(c.map(x => x.path).sort(), ['/api/login', '/api/orders'])
})

test("candidatesFromGraded uses the model's urlPath when it has one", () => {
  const model = { routes: [{ file: 'server.js', routeKey: 'DELETE /admin/users', urlPath: '/admin/users' }] }
  const c = candidatesFromGraded(graded(['route:server.js:DELETE /admin/users']), model)
  assert.equal(c.length, 1)
  assert.equal(c[0].path, '/admin/users')
})

test('classifyResponse: 2xx is exposed, 401/403 protected, everything else inconclusive', () => {
  assert.equal(classifyResponse(200), 'exposed')
  assert.equal(classifyResponse(204), 'exposed')
  assert.equal(classifyResponse(401), 'protected')
  assert.equal(classifyResponse(403), 'protected')
  assert.equal(classifyResponse(404), 'inconclusive')
  assert.equal(classifyResponse(500), 'inconclusive')
  assert.equal(classifyResponse(302), 'inconclusive', 'a redirect to /login is not a 200')
})

test('A DRY RUN sends nothing — the sender is never called', async () => {
  let sends = 0
  const send = async () => { sends++; return 200 }
  const r = await resolveWorklist({
    candidates: candidatesFromGraded(graded(['route:app/api/orders/route.ts'])),
    base: 'https://staging.myapp.com', execute: false, send,
    session: session(liveConfig()),
  })
  assert.equal(sends, 0, 'a dry run must open no socket')
  assert.deepEqual(r.observations, [])
  assert.equal(r.dynamic.dryRun, true)
})

test('EXECUTE + a 200 to an unauthenticated route = a confirmed auth bypass', async () => {
  const send = async () => 200
  const r = await resolveWorklist({
    candidates: candidatesFromGraded(graded(['route:app/api/orders/route.ts'])),
    base: 'https://staging.myapp.com', execute: true, send,
    session: session(liveConfig()),
  })
  assert.equal(r.observations.length, 1)
  const o = r.observations[0]
  assert.equal(o.kind, 'auth-bypass-confirmed')
  assert.equal(o.subject, 'route:app/api/orders/route.ts', 'the observation anchors to the worklist subject')

  // …and the grader turns it into a definitive, CONFIRMED P0.
  const model = { database: { parserVersion: 2, tables: [] } }
  const report = grade(model, { observations: [o] })
  const f = report.findings.find(x => x.id === 'CG-DAST-AUTHZ-POC')
  assert.ok(f, 'a live proof must produce CG-DAST-AUTHZ-POC')
  assert.equal(f.confidence, 'confirmed', 'a PoC is definitive evidence — the honest route to confirmed')
  assert.equal(f.severity, 'P0')
})

test('EXECUTE + a 401 = a resolved pass, no finding', async () => {
  const send = async () => 401
  const r = await resolveWorklist({
    candidates: candidatesFromGraded(graded(['route:app/api/orders/route.ts'])),
    base: 'https://staging.myapp.com', execute: true, send,
    session: session(liveConfig()),
  })
  assert.deepEqual(r.observations, [], 'a 401 proves the control works — nothing to report')
  const executed = r.dynamic.decisions.filter(d => d.mode === 'execute')
  assert.equal(executed.length, 1)
  assert.equal(executed[0].verdict, 'protected')
})

test('the gate refuses an out-of-scope host, and the runner sends nothing to it', async () => {
  let sends = 0
  const send = async () => { sends++; return 200 }
  const r = await resolveWorklist({
    candidates: candidatesFromGraded(graded(['route:app/api/orders/route.ts'])),
    base: 'https://evil.example.com', execute: true, send,   // NOT in the allowlist
    session: session(liveConfig()),
  })
  assert.equal(sends, 0, 'a host the scope does not attest gets no packet')
  assert.deepEqual(r.observations, [])
  assert.equal(r.dynamic.decisions[0].allowed, false)
  assert.ok(r.dynamic.decisions[0].reasons.join(' ').length > 0, 'the refusal is explained')
})

test('a HEADLESS run refuses the active probe — no human, no active traffic', async () => {
  let sends = 0
  const send = async () => { sends++; return 200 }
  const r = await resolveWorklist({
    candidates: candidatesFromGraded(graded(['route:app/api/orders/route.ts'])),
    base: 'https://staging.myapp.com', execute: true, send,
    session: session(liveConfig(), { interactive: false }),   // cron / CI, no human
  })
  assert.equal(sends, 0, 'active tier headless must be refused (D0)')
  assert.deepEqual(r.observations, [])
  assert.equal(r.dynamic.decisions[0].allowed, false)
})

test("the emitted `dynamic` block is the shape gradeScanners consumes, and refusals become coverage rows", async () => {
  const send = async () => 200
  const r = await resolveWorklist({
    candidates: candidatesFromGraded(graded(['route:app/api/x/route.ts'])),
    base: 'https://evil.example.com', execute: true, send,   // refused
    session: session(liveConfig()),
  })
  const model = { database: { parserVersion: 2, tables: [] } }
  const report = grade(model, { scanners: { dynamic: r.dynamic } })
  const rows = report.coverage.scanCoverage.undeterminable.map(s => s.subject)
  assert.ok(rows.some(s => s.startsWith('scan:dynamic')), 'a refused probe must surface as a dynamic coverage row')
})
