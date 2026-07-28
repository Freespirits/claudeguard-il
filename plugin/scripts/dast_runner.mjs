#!/usr/bin/env node
// Tier 2 — active DAST. Sends REAL attack traffic. Hard-gated + dry-run by default.
// Enforces the Tier-2 authorization gate. Without --execute (and dry_run:false in scope) it only
// PLANS requests and sends nothing.
// Usage:
//   node dast_runner.mjs --url https://app.example.com --scope claudeguard.scope.yml            # dry run
//   node dast_runner.mjs --url https://app.example.com --scope claudeguard.scope.yml --execute  # real run
import { loadScope, gateTier2, normalizeHost, parseArgs } from './_scope.mjs'

const args = parseArgs(process.argv.slice(2))
const url = args.url
const scopePath = args.scope || 'claudeguard.scope.yml'
const executeFlag = !!args.execute || !!args['i-am-authorized']

if (!url) { console.error('Missing --url'); process.exit(2) }

const loaded = loadScope(scopePath)
if (!loaded.ok) { console.error('GATE FAILED: ' + loaded.error); process.exit(2) }

const host = normalizeHost(url)
const gate = gateTier2(host, loaded.scope, { execute: executeFlag })

// Build the (non-destructive, GET-only) probe plan.
const base = url.startsWith('http') ? url : 'https://' + url
const origin = new URL(base).origin
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
const findings = []

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
  if (r.error) { findings.push({ id: step.id, result: 'error', detail: r.error }); continue }
  const body = await r.text().catch(() => '')
  if (step.name === 'reflected-xss' && body.includes(`<b>${MARKER}</b>`)) {
    findings.push({ id: step.id, severity: 'P1', title: 'Reflected XSS', detail: 'Injected markup was reflected unescaped.' })
  }
  if (step.name === 'error-sqli' && SQL_ERRORS.test(body)) {
    findings.push({ id: step.id, severity: 'P1', title: 'SQL error leakage / possible injection', detail: 'A single quote produced a database error in the response.' })
  }
  if (step.name === 'open-redirect') {
    const loc = r.headers?.get?.('location') || ''
    if (loc.includes('example.org')) findings.push({ id: step.id, severity: 'P2', title: 'Open redirect', detail: `Redirects to attacker-controlled host: ${loc}` })
  }
  if (step.name === 'headers') {
    if (!r.headers?.get?.('content-security-policy')) findings.push({ id: 'CG-DAST-CSP', severity: 'P2', title: 'Missing CSP', detail: 'No Content-Security-Policy header.' })
  }
}

console.log(JSON.stringify({
  tier: 'active-dast', mode: 'executed', target: host, sent: plan.length, count: findings.length, findings,
  note: 'Non-destructive GET-based probes only. Confirmed findings should be fixed in the codebase (/cg-harden, /cg-fix).',
}, null, 2))
