#!/usr/bin/env node
// The worklist resolver — the honest route to `confirmed`.
//
// Every other tier of this tool SUSPECTS. The static engine can see that a route mentions
// `getUser()` but not whether the result gates the handler, so it records the route
// `undeterminable` and says so. This runner takes that list of suspicions and RESOLVES each one
// against the running system: an unauthenticated request that comes back 200 turns a guess into a
// `confirmed` finding with a live proof; a 401/403 turns it into a pass. A live proof is the
// definitive evidence a heuristic can never have, and it is the only route to `confirmed` for a
// class the static tier could only call `undeterminable`.
//
// It is NOT a scanner. It sends one GET per suspected route, carrying no credentials, and records
// the STATUS CODE, never the body — proof of access, not the data behind it. Everything goes
// through the gate in dynamic_gate.mjs: the host is the one the scope file attests, the path is the
// one the static tier flagged, and nothing is sent on a dry run (the default).
//
// Usage:
//   node dynamic_runner.mjs --graded cg-graded.json --base https://staging.myapp.com --scope claudeguard.scope.yml
//   node dynamic_runner.mjs --graded cg-graded.json --base https://staging.myapp.com --scope claudeguard.scope.yml --execute
//
// Then feed the two files it writes back to the grader:
//   node grader.mjs --model cg-model.json --observations cg-dyn.observations.json --dynamic cg-dyn.dynamic.json
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import { canonicalUrl, normalizeHost, parseArgs, loadScope } from './_scope.mjs'
import { GateSession, RunRegistry } from './dynamic_gate.mjs'

// ---------------------------------------------------------------------------
// The worklist: which routes the static tier could not settle, and where to probe them.
// ---------------------------------------------------------------------------

/** `app/api/orders/route.ts` -> `/api/orders`; `pages/api/orders.ts` -> `/api/orders`. */
export function urlPathOf(routeFile) {
  let p = String(routeFile || '')
    .replace(/^src\//, '').replace(/^app\//, '').replace(/^pages\//, '')
    .replace(/\/route\.(t|j)sx?$/, '').replace(/\.(t|j)sx?$/, '')
    .replace(/\/index$/, '')
  if (!p.startsWith('/')) p = '/' + p
  return p === '/' ? '/' : p.replace(/\/$/, '')
}

/**
 * Build the candidate list from a graded report. A candidate is a route the coverage ledger left
 * `undeterminable` — the ONLY rows this runner probes, because a route the static tier already
 * settled (`pass`/`fail`) needs no live confirmation and a route nobody enumerated has no path to
 * send to. The model, when supplied, gives a route its real `urlPath`; otherwise it is derived from
 * the file. Subjects are carried verbatim so the resolved finding anchors to the row it came from.
 */
export function candidatesFromGraded(graded, model = null) {
  const undeter = graded?.coverage?.routes?.undeterminable || []
  const routesByFile = new Map()
  for (const r of (model?.routes || [])) routesByFile.set(r.file, r)

  const seen = new Set()
  const out = []
  for (const row of undeter) {
    const subject = row.subject || ''
    // `route:<file>` or `route:<file>:<method path>` — the file is the first segment after `route:`.
    const m = /^route:([^:]+(?::[^:]+)*?)(?::[A-Z]+ .*)?$/.exec(subject) || /^route:(.+)$/.exec(subject)
    const file = m ? m[1] : null
    if (!file) continue
    const modelRoute = routesByFile.get(file)
    const path = (modelRoute && modelRoute.urlPath) ? modelRoute.urlPath : urlPathOf(file)
    const key = `${subject}::${path}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ subject, file, path, note: row.note || '' })
  }
  return out
}

// ---------------------------------------------------------------------------
// The probe. One GET, no credentials, status only.
// ---------------------------------------------------------------------------

/**
 * Classify a response the way the observation contract needs it. A 200/2xx to an unauthenticated
 * request against a route the static tier flagged is `auth-bypass-confirmed` — the endpoint answered
 * with no session at all. A 401/403 is the control doing its job: a resolved pass. Anything else
 * (404, 5xx, a redirect to a login page) resolves nothing and is left for a human, because it is not
 * proof of either.
 */
export function classifyResponse(status) {
  if (status >= 200 && status < 300) return 'exposed'
  if (status === 401 || status === 403) return 'protected'
  return 'inconclusive'
}

/** Perform one probe. `send` is injectable so tests never open a socket. */
async function probe(session, base, candidate, { execute, send }) {
  const url = base.replace(/\/$/, '') + candidate.path
  const host = normalizeHost(base)
  const action = { tool: 'authz_probe', target: host, path: candidate.path, origin: 'config' }

  const decision = await session.askResolved(action)
  const record = {
    subject: candidate.subject, path: candidate.path, url,
    allowed: decision.allowed, tool: 'authz_probe', target: host,
    reasons: decision.reasons || [],
  }

  // Dry run, or the gate refused: nothing is sent. On a dry run the gate returns mode 'plan', so
  // `willExecute` is false and this is where every candidate lands until the run is authorised.
  if (!execute || decision.willExecute !== true) {
    record.mode = decision.mode
    return { record, observation: null }
  }

  // A live send. Register the abort handle with the run BEFORE the request goes out, so the kill
  // switch can reach a probe that is already in flight, not merely refuse the next one.
  const handle = session.registry.controller({ tool: 'authz_probe', path: candidate.path })
  let status = null, transportError = null
  try {
    status = await send(url, handle.signal)
  } catch (e) {
    transportError = String(e && e.message || e).slice(0, 160)
  } finally {
    handle.release()
  }
  session.commit(decision)

  record.mode = 'execute'
  if (transportError) { record.error = transportError; return { record, observation: null } }
  record.status = status

  const verdict = classifyResponse(status)
  record.verdict = verdict
  if (verdict !== 'exposed') return { record, observation: null }

  return {
    record,
    observation: {
      tier: 'active-dast',
      kind: 'auth-bypass-confirmed',
      subject: candidate.subject,
      at: url,
      detail: `An unauthenticated GET to ${candidate.path} returned HTTP ${status}. The static tier could not tell whether this route enforces authentication (${candidate.note.slice(0, 120)}); a request carrying no session at all was answered, which settles it.`,
    },
  }
}

// ---------------------------------------------------------------------------
// The run.
// ---------------------------------------------------------------------------

/**
 * Resolve a worklist against a running target. Pure of process concerns: the scope config, the
 * candidate list, the base URL and a `send` function are all passed in, so a test drives the whole
 * loop with a fake sender and never touches the network.
 *
 * @returns {{observations, dynamic}} the two shapes the grader consumes (`--observations`, `--dynamic`).
 */
export async function resolveWorklist({ config, candidates, base, execute = false, session, send }) {
  // `interactive` and `confirmation` are set HONESTLY from the environment, never asserted: a run is
  // interactive only when a human terminal is attached, and the human's `--execute` at that terminal
  // is the per-run confirmation the gate demands for an active-tier probe. In CI or a pipe there is
  // no TTY, so an active probe is refused — which is the D0 headless rule doing its job, not a bug.
  const human = !!(process.stderr && process.stderr.isTTY)
  const gate = session || new GateSession({
    config, interactive: human, confirmation: execute && human, registry: new RunRegistry(),
  })
  const dryRun = !execute
  const observations = []
  const decisions = []

  for (const c of candidates) {
    const { record, observation } = await probe(gate, base, c, { execute, send })
    decisions.push(record)
    if (observation) observations.push(observation)
  }

  const anyExecuted = decisions.some(d => d.mode === 'execute')
  return {
    observations,
    dynamic: {
      enabled: true,
      available: true,
      dryRun: dryRun || !anyExecuted,
      tier: 'active',
      base,
      decisions,
    },
  }
}

// A real GET, GET-only, 8s timeout, no credentials, no redirect-following (a 302 to /login is not a
// 200). Returns the status code and nothing else — the body is never read, so no data leaves the
// target. This is the only function in the file that opens a socket.
async function httpProbe(url, signal) {
  const ctrl = new AbortController()
  const onAbort = () => ctrl.abort()
  if (signal) signal.addEventListener('abort', onAbort, { once: true })
  const t = setTimeout(() => ctrl.abort(), 8000)
  try {
    const r = await fetch(url, {
      method: 'GET', redirect: 'manual', signal: ctrl.signal,
      headers: { 'User-Agent': 'ClaudeGuardIL/0.2 (authorized authz probe)' },
    })
    return r.status
  } finally {
    clearTimeout(t)
    if (signal) signal.removeEventListener('abort', onAbort)
  }
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  const args = parseArgs(process.argv.slice(2))
  const gradedPath = args.graded
  const baseArg = args.base
  const scopePath = args.scope || 'claudeguard.scope.yml'
  const execute = !!args.execute
  const fail = m => { console.error('dynamic_runner: ' + m); process.exit(2) }

  if (!gradedPath) fail('missing --graded <cg-graded.json>')
  if (!baseArg) fail('missing --base <url> (the running target, which must be in the scope allowlist)')

  const canonBase = canonicalUrl(baseArg)
  if (!canonBase) fail(`--base "${baseArg}" is not a fetchable http(s) URL`)

  // The RAW scope object — `decide()` normalises and attestation-checks it itself, so a config that
  // is unreadable or switched off surfaces as every action being denied with its reason in the plan,
  // which is more useful than a bare parse error.
  const loaded = loadScope(scopePath)
  if (!loaded.ok) fail(`scope file: ${loaded.error}`)
  const scopeConfig = loaded.scope

  // A byte-order mark survives `grader.mjs > cg-graded.json` on Windows PowerShell, which is exactly
  // how this file is produced, so strip it rather than fail on the common path.
  const readJson = p => JSON.parse(readFileSync(p, 'utf8').replace(/^﻿/, ''))
  let graded, model = null
  try { graded = readJson(gradedPath) } catch (e) { fail(`could not read --graded: ${e.message}`) }
  if (args.model) { try { model = readJson(args.model) } catch { /* optional */ } }

  const candidates = candidatesFromGraded(graded, model)
  if (!candidates.length) {
    console.log(JSON.stringify({ note: 'no undeterminable routes to resolve — nothing to probe', observations: [], dynamic: { enabled: true, available: true, dryRun: !execute, tier: 'active', decisions: [] } }, null, 2))
    process.exit(0)
  }

  if (execute) {
    console.error(`🚨  ACTIVE PROBES — ${candidates.length} unauthenticated GET request(s) to ${normalizeHost(canonBase)}, a target the scope file attests you own. No credentials, status only, gated per request.`)
  } else {
    console.error(`dry run: planning ${candidates.length} probe(s) against ${normalizeHost(canonBase)}. Nothing is sent. Pass --execute (with dynamic_testing.execution.dry_run: false) to run for real.`)
  }

  const result = await resolveWorklist({
    config: scopeConfig, candidates, base: canonBase, execute, send: httpProbe,
  })
  console.log(JSON.stringify({
    ...result,
    note: 'observations carry no severity — grader.mjs owns that, and maps auth-bypass-confirmed to a definitive CG-DAST-AUTHZ-POC (P0). Feed both keys back: grader.mjs --observations <this>.observations --dynamic <this>.dynamic.',
  }, null, 2))
}
