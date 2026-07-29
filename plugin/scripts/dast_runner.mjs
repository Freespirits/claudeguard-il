#!/usr/bin/env node
// Tier 2 — active DAST. Sends REAL attack traffic. Hard-gated + dry-run by default.
// Enforces the Tier-2 authorization gate. Without --execute (and dry_run:false in scope) it only
// PLANS requests and sends nothing.
// Usage:
//   node dast_runner.mjs --url https://app.example.com --scope claudeguard.scope.yml            # dry run
//   node dast_runner.mjs --url https://app.example.com --scope claudeguard.scope.yml --execute  # real run
//
// This runner emits Facts and nothing else. It used to stamp a severity onto its own results, which
// meant the severity policy lived here as well as in the engine and the report, and the three
// copies drifted. What a probe can honestly report is what came back on the wire; grader.mjs owns
// the step from there to a severity. See CONTEXT.md, "Fact" and "Grader".
import { loadScope, gateTier2, normalizeHost, canonicalUrl, parseArgs } from './_scope.mjs'

const args = parseArgs(process.argv.slice(2))
const url = args.url
const scopePath = args.scope || 'claudeguard.scope.yml'
const executeFlag = !!args.execute || !!args['i-am-authorized']

if (!url) { console.error('Missing --url'); process.exit(2) }

const loaded = loadScope(scopePath)
if (!loaded.ok) { console.error('GATE FAILED: ' + loaded.error); process.exit(2) }

// One parse for both the host the gate checks and the URL the attack traffic is sent to. Deriving
// them separately from the same raw string is what let `https://staging.myapp.com:443@evil.com`
// clear the gate as `staging.myapp.com` and land on evil.com.
const canon = canonicalUrl(url)
if (!canon) { console.error(`GATE FAILED: "${url}" is not a fetchable http(s) URL.`); process.exit(2) }

const host = normalizeHost(canon)
const gate = gateTier2(host, loaded.scope, { execute: executeFlag })

// Build the (non-destructive, GET-only) probe plan.
// The plan is printed verbatim on a dry run so the user can read exactly what would be sent before
// authorizing it — that is its whole job. Its `id` labels a planned request; it is not a finding id
// and nothing here decides how bad a result would be.
const base = canon
const MARKER = 'cgil7391marker'
const plan = [
  { id: 'CG-DAST-XSS', name: 'reflected-xss', method: 'GET', url: `${base}${base.includes('?') ? '&' : '?'}q=<b>${MARKER}</b>`, purpose: 'Check if a query value is reflected unescaped.' },
  { id: 'CG-DAST-SQLI', name: 'error-sqli', method: 'GET', url: `${base}${base.includes('?') ? '&' : '?'}id=1%27`, purpose: 'Look for SQL error strings from an injected quote.' },
  { id: 'CG-DAST-REDIRECT', name: 'open-redirect', method: 'GET', url: `${base}${base.includes('?') ? '&' : '?'}next=https://example.org/${MARKER}`, purpose: 'Check for open redirect to an external host.' },
  { id: 'CG-DAST-HEADERS', name: 'headers', method: 'GET', url: base, purpose: 'Confirm security headers.' },
]

if (!gate.allowed) {
  console.error('GATE FAILED — Tier 2 preconditions not met:')
  for (const r of gate.reasons) console.error('  - ' + r)
  console.error('\nNothing was sent. Fix the scope file and try again.')
  process.exit(2)
}

console.error('🚨  ACTIVE DAST — real attack traffic to a target you attested you OWN and are AUTHORIZED to test.')
console.error(`    Rate cap: ${gate.rateCap} req/s · avoid_destructive: ${gate.avoidDestructive} · dry_run: ${gate.dryRun}`)

// Dry run (default): plan only, send nothing.
if (gate.dryRun || !gate.willExecute) {
  console.log(JSON.stringify({
    tier: 'active-dast', mode: 'dry-run', target: host, willSend: false,
    plan,
    note: gate.dryRun
      ? 'dry_run is true in the scope file — no traffic sent. Set dry_run: false AND pass --execute to run for real.'
      : 'Pass --execute to send this plan (only after confirming the gate).',
  }, null, 2))
  process.exit(0)
}

// Real run — bounded, non-destructive, rate-limited.
const UA = 'ClaudeGuardIL/0.1 (authorized security test)'
const sleep = ms => new Promise(r => setTimeout(r, ms))
const delay = Math.ceil(1000 / gate.rateCap)

// Each `kind` below must be a key of OBSERVATION_POLICY in grader.mjs. A misspelt kind does not
// throw — the grader files it under coverage.liveObservations.undeterminable as "no rule owns
// observation kind", which is where a reviewer checking that the run was fully accounted for will
// see it. `detail` says what came back and nothing more; the words "vulnerable", "unsafe" and any
// P-number belong to the grader.
const observations = []
function observe(kind, subject, at, detail) {
  observations.push({ tier: 'active-dast', kind, subject, at, detail })
}

// A step that never completed is not an observation of the target — it is an observation of the
// network. Mixing the two would let a timeout masquerade as a clean probe, so transport failures
// stay in their own list and are reported alongside the observations.
const errors = []

// Probes differ only in the parameter they exercise, so the path plus that parameter is the stable
// subject: two runs against the same endpoint produce the same subject and the grader's ledger
// counts them once.
const probePath = new URL(base).pathname

async function get(u) {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), 8000)
  try { return await fetch(u, { method: 'GET', redirect: 'manual', signal: ctrl.signal, headers: { 'User-Agent': UA } }) }
  catch (e) { return { error: String(e.message || e) } }
  finally { clearTimeout(t) }
}

const SQL_ERRORS = /(SQL syntax|SQLSTATE|psql:|ORA-\d+|SQLite|mysql_fetch|PostgreSQL.*ERROR|unterminated quoted string)/i

for (const step of plan) {
  if (gate.avoidDestructive && step.method !== 'GET') continue // never state-changing in this build
  await sleep(delay)
  const r = await get(step.url)
  if (r.error) { errors.push({ id: step.id, step: step.name, url: step.url, detail: r.error }); continue }
  const body = await r.text().catch(() => '')
  if (step.name === 'reflected-xss' && body.includes(`<b>${MARKER}</b>`)) {
    observe('reflected-xss', `${probePath}?q`, step.url,
      `The <b> markup sent in the q parameter came back inside the response body unescaped, marker ${MARKER} included.`)
  }
  if (step.name === 'error-sqli' && SQL_ERRORS.test(body)) {
    // Quoting the matched string is what lets a reader tell a real query error from a validation
    // layer politely echoing the character back.
    const matched = SQL_ERRORS.exec(body)?.[0] || ''
    observe('sql-error-leak', `${probePath}?id`, step.url,
      `A single quote appended to the id parameter produced a database error string in the response body: "${matched}".`)
  }
  if (step.name === 'open-redirect') {
    const loc = r.headers?.get?.('location') || ''
    if (loc.includes('example.org')) {
      observe('open-redirect', `${probePath}?next`, step.url,
        `The response redirected to the host supplied in the next parameter (Location: ${loc}).`)
    }
  }
  if (step.name === 'headers') {
    if (!r.headers?.get?.('content-security-policy')) {
      observe('missing-csp', probePath, step.url, 'The response carried no Content-Security-Policy header.')
    }
  }
}

console.log(JSON.stringify({
  tier: 'active-dast', mode: 'executed', target: host, sent: plan.length,
  count: observations.length, observations, errors,
  note: 'Non-destructive GET-based probes only. Observations carry no severity — grader.mjs assigns it. Fixes belong in the codebase (/cg-harden, /cg-fix).',
}, null, 2))
