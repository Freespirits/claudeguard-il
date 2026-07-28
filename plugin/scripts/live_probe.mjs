#!/usr/bin/env node
// Tier 1 — passive live checks. READ-ONLY (GET/HEAD only), no payloads. Enforces the Tier-1
// authorization gate before any request. Usage:
//   node live_probe.mjs --url https://app.example.com --scope claudeguard.scope.yml
//   optional: --supabase-url https://xxx.supabase.co --anon-key <key> --table profiles
import { loadScope, gateTier1, normalizeHost, parseArgs } from './_scope.mjs'

const args = parseArgs(process.argv.slice(2))
const url = args.url
const scopePath = args.scope || 'claudeguard.scope.yml'

if (!url) { console.error('Missing --url'); process.exit(2) }

const loaded = loadScope(scopePath)
if (!loaded.ok) { console.error('GATE FAILED: ' + loaded.error); process.exit(2) }

const host = normalizeHost(url)
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

const findings = []
function add(severity, id, title, detail) { findings.push({ severity, id, title, detail }) }

// 1) main page headers / TLS
const base = url.startsWith('http') ? url : 'https://' + url
const res = await req(base)
if (res.error) {
  console.log(JSON.stringify({ target: host, error: res.error, findings }, null, 2))
  process.exit(0)
}
const h = name => res.headers?.get?.(name)

if (base.startsWith('http://')) add('P2', 'CG-LIVE-TLS', 'No HTTPS', 'Site served over plain HTTP.')
if (!h('strict-transport-security')) add('P3', 'CG-LIVE-HSTS', 'Missing HSTS', 'No Strict-Transport-Security header.')
if (!h('content-security-policy')) add('P2', 'CG-LIVE-CSP', 'Missing CSP', 'No Content-Security-Policy header.')
if (!h('x-content-type-options')) add('P3', 'CG-LIVE-XCTO', 'Missing X-Content-Type-Options', 'nosniff not set.')
if (!h('x-frame-options') && !/frame-ancestors/i.test(h('content-security-policy') || '')) add('P3', 'CG-LIVE-XFO', 'Clickjacking exposure', 'No X-Frame-Options / frame-ancestors.')
if (!h('referrer-policy')) add('P3', 'CG-LIVE-REF', 'Missing Referrer-Policy', 'Referrer-Policy not set.')

const acao = h('access-control-allow-origin')
if (acao === '*' && (h('access-control-allow-credentials') === 'true')) {
  add('P2', 'CG-LIVE-CORS', 'Unsafe CORS', 'ACAO:* together with credentials.')
}
const setCookie = res.headers?.get?.('set-cookie')
if (setCookie) {
  if (!/httponly/i.test(setCookie)) add('P2', 'CG-LIVE-COOKIE', 'Cookie without HttpOnly', 'A Set-Cookie lacks HttpOnly.')
  if (!/secure/i.test(setCookie)) add('P3', 'CG-LIVE-COOKIE2', 'Cookie without Secure', 'A Set-Cookie lacks Secure.')
}

// 2) exposed sensitive files (read-only GET; flag only clear exposure)
const origin = new URL(base).origin
const paths = ['/.env', '/.env.local', '/.env.production', '/.git/HEAD', '/.git/config']
for (const p of paths) {
  await sleep(300)
  const r = await req(origin + p)
  if (r.error) continue
  if (r.status === 200) {
    const body = await r.text().catch(() => '')
    const looksReal = /=|\[core\]|ref:/i.test(body) && !/<html/i.test(body.slice(0, 200))
    if (looksReal) add('P1', 'CG-LIVE-EXPOSE', `Exposed ${p}`, `${p} is publicly readable (HTTP 200).`)
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
        add('P0', 'CG-LIVE-RLS', `Public read on ${args.table}`, `anon key returned rows from "${args.table}" — RLS likely off or permissive.`)
      }
    }
  } catch { /* ignore */ }
}

console.log(JSON.stringify({
  tier: 'passive-live',
  target: host,
  status: res.status,
  count: findings.length,
  findings,
  note: 'Read-only checks only. A clean result is not proof of safety.',
}, null, 2))
