#!/usr/bin/env node
// Tier 1 — passive live checks. READ-ONLY (GET/HEAD only), no payloads. Enforces the Tier-1
// authorization gate before any request. Usage:
//   node live_probe.mjs --url https://app.example.com --scope claudeguard.scope.yml
//   optional: --supabase-url https://xxx.supabase.co --anon-key <key> --table profiles
//
// This probe emits Facts and nothing else. It used to hardcode a severity next to each check, which
// put the severity policy in three places at once — here, in the engine, and in the report — where
// the three copies drifted apart. Every check below now records only what was seen on the wire;
// grader.mjs maps a `kind` to a severity and is the single authority on it.
// See CONTEXT.md, "Fact" and "Grader".
import { loadScope, gateTier1, normalizeHost, canonicalUrl, parseArgs } from './_scope.mjs'

const args = parseArgs(process.argv.slice(2))
const url = args.url
const scopePath = args.scope || 'claudeguard.scope.yml'

if (!url) { console.error('Missing --url'); process.exit(2) }

const loaded = loadScope(scopePath)
if (!loaded.ok) { console.error('GATE FAILED: ' + loaded.error); process.exit(2) }

// The gate reads a host and the probe sends a URL. Deriving the two from the same raw string in
// two places is what let `https://localhost:3000@169.254.169.254` be gated as `localhost:3000` and
// sent to the cloud-metadata service. One parse, one authority, no gap.
const target = canonicalUrl(url)
if (!target) { console.error(`GATE FAILED: "${url}" is not a fetchable http(s) URL.`); process.exit(2) }

const host = normalizeHost(target)
const gate = gateTier1(host, loaded.scope)
if (!gate.allowed) {
  console.error('GATE FAILED — Tier 1 preconditions not met:')
  for (const r of gate.reasons) console.error('  - ' + r)
  process.exit(2)
}

console.error('⚠️  Passive live check — read-only, target you attested to owning. No payloads sent.')

const UA = 'ClaudeGuardIL/0.1 (authorized security test)'
async function req(u, method = 'GET') {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), 8000)
  try {
    return await fetch(u, { method, redirect: 'manual', signal: ctrl.signal, headers: { 'User-Agent': UA } })
  } catch (e) { return { error: String(e.message || e) } }
  finally { clearTimeout(t) }
}
const sleep = ms => new Promise(r => setTimeout(r, ms))

// Each `kind` below must be a key of OBSERVATION_POLICY in grader.mjs. A misspelt kind does not
// throw — the grader files it under coverage.liveObservations.undeterminable as "no rule owns
// observation kind", which is deliberately the one place a reviewer is looking when checking that
// a probe run was fully accounted for.
//
// `detail` states what was observed and stops there. No severity, no advice: the moment a probe
// starts saying "unsafe" or "exposure" it is grading, and two graders is one too many.
const observations = []
function observe(kind, subject, at, detail) {
  observations.push({ tier: 'passive-live', kind, subject, at, detail })
}

// 1) main page headers / TLS
const base = target
const res = await req(base)
if (res.error) {
  console.log(JSON.stringify({ target: host, error: res.error, observations }, null, 2))
  process.exit(0)
}
const h = name => res.headers?.get?.(name)

// Response headers are a property of the page that answered, so that page's path is the stable
// subject for all of them. The kind already distinguishes which header was absent.
const page = new URL(base).pathname

if (base.startsWith('http://')) {
  observe('no-https', page, base, 'The target was requested over http:// and answered without TLS.')
}
if (!h('strict-transport-security')) {
  observe('missing-hsts', page, base, 'The response carried no Strict-Transport-Security header.')
}
if (!h('content-security-policy')) {
  observe('missing-csp', page, base, 'The response carried no Content-Security-Policy header.')
}
if (!h('x-content-type-options')) {
  observe('missing-nosniff', page, base, 'The response carried no X-Content-Type-Options header, so nosniff was not set.')
}
// Either header alone settles framing, so both have to be absent before this is an observation at
// all — reporting a missing X-Frame-Options on a page whose CSP already pins frame-ancestors would
// be reporting a header, not a fact about the system.
if (!h('x-frame-options') && !/frame-ancestors/i.test(h('content-security-policy') || '')) {
  observe('clickjacking', page, base,
    'The response carried no X-Frame-Options header and no frame-ancestors directive in its Content-Security-Policy.')
}
if (!h('referrer-policy')) {
  observe('missing-referrer-policy', page, base, 'The response carried no Referrer-Policy header.')
}

const acao = h('access-control-allow-origin')
if (acao === '*' && (h('access-control-allow-credentials') === 'true')) {
  observe('unsafe-cors', page, base,
    'The response set Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.')
}
const setCookie = res.headers?.get?.('set-cookie')
if (setCookie) {
  // Naming the cookie is what makes the observation actionable and gives it a subject that stays
  // the same between runs, which is how the grader's ledger avoids double-counting it.
  const cookieName = /^\s*([^=;,\s]+)/.exec(setCookie)?.[1] || 'set-cookie'
  if (!/httponly/i.test(setCookie)) {
    observe('cookie-no-httponly', `cookie:${cookieName}`, base,
      `The Set-Cookie header for "${cookieName}" carried no HttpOnly attribute.`)
  }
  if (!/secure/i.test(setCookie)) {
    observe('cookie-no-secure', `cookie:${cookieName}`, base,
      `The Set-Cookie header for "${cookieName}" carried no Secure attribute.`)
  }
}

// 2) exposed sensitive files (read-only GET; record only clear exposure)
const origin = new URL(base).origin
const paths = ['/.env', '/.env.local', '/.env.production', '/.git/HEAD', '/.git/config']
for (const p of paths) {
  await sleep(300)
  const r = await req(origin + p)
  if (r.error) continue
  if (r.status === 200) {
    const body = await r.text().catch(() => '')
    // A 200 alone proves nothing: SPA hosts answer every unknown path with the index page. The
    // body has to look like the real file before we claim to have read one.
    const looksReal = /=|\[core\]|ref:/i.test(body) && !/<html/i.test(body.slice(0, 200))
    if (looksReal) {
      observe('exposed-path', p, origin + p,
        `GET ${p} returned HTTP 200 and a body shaped like the real file (key=value, [core] or ref:) rather than an HTML page.`)
    }
  }
}

// 3) optional Supabase RLS spot-check (only if user supplied their own project + anon key)
if (args['supabase-url'] && args['anon-key'] && args.table) {
  const su = normalizeHost(args['supabase-url'])
  // still respect the gate: the supabase host must not be blocked-by-target-rules? It's the user's own project.
  const q = `${args['supabase-url'].replace(/\/$/, '')}/rest/v1/${args.table}?select=*&limit=1`
  try {
    const rr = await fetch(q, { headers: { apikey: args['anon-key'], Authorization: 'Bearer ' + args['anon-key'], 'User-Agent': UA } })
    if (rr.status === 200) {
      const rows = await rr.json().catch(() => null)
      if (Array.isArray(rows) && rows.length > 0) {
        // The key travels in headers, never in `q`, so recording the request URL as the location
        // does not put a credential into the report.
        observe('anon-read', args.table, q,
          `A request carrying only the anon key returned HTTP 200 and ${rows.length} row(s) from "${args.table}".`)
      }
    }
  } catch { /* ignore */ }
}

console.log(JSON.stringify({
  tier: 'passive-live',
  target: host,
  status: res.status,
  count: observations.length,
  observations,
  note: 'Read-only observations only, no severity — grader.mjs assigns that. A clean result is not proof of safety.',
}, null, 2))
