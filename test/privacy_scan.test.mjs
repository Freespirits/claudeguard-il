import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  scanTransport, scanCookies,
  isLocalHost, isNamespaceHost, isSessionName, hostFromAuthority, isExcludedPath,
} from '../plugin/scripts/lib/privacy_scan.mjs'

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS
//
// privacy_scan is the static slice of the privacy / data-security compliance domain (תקנות הגנת
// הפרטיות (אבטחת מידע) 2017): CG-PRIV-TLS (cleartext in transit, תקנה 14(ב)) and CG-PRIV-COOKIE
// (session-cookie flags). For a non-expert owner a cry-wolf "you are breaking the privacy law" is
// worse than a miss, so the WHOLE job is the false-positive discipline. Every FP trap in the spec is
// pinned here as its own test: a wrong http:// on an XML namespace, a localhost, a commented URL, a
// log-line string, or an env-conditional `secure` flag is exactly the finding this pillar must never
// produce. Detection tests prove the real signals still fire.
// ---------------------------------------------------------------------------

const kinds = facts => facts.map(f => f.kind)

// === CG-PRIV-TLS · http-target: detection ===================================

test('http:// to a real host used as a fetch target → one http-target; https:// → none', () => {
  const http = scanTransport(`const r = await fetch('http://api.example.com/users')`, 'src/api.js')
  assert.equal(http.length, 1)
  assert.equal(http[0].kind, 'http-target')
  assert.equal(http[0].host, 'api.example.com')
  assert.equal(http[0].at.line, 1)

  const https = scanTransport(`const r = await fetch('https://api.example.com/users')`, 'src/api.js')
  assert.deepEqual(https, [], 'https is encrypted — nothing to report')
})

test('http-target fires for an API base URL, a webhook target and an XHR open, not only fetch', () => {
  const baseUrl = scanTransport(`const client = axios.create({ baseURL: 'http://api.example.com' })`, 'a.js')
  assert.deepEqual(kinds(baseUrl), ['http-target'])

  const webhook = scanTransport(`const webhookUrl = 'http://hooks.example.com/incoming'`, 'a.js')
  assert.deepEqual(kinds(webhook), ['http-target'])

  const xhr = scanTransport(`xhr.open('GET', 'http://data.example.com/feed')`, 'a.js')
  assert.deepEqual(kinds(xhr), ['http-target'])
})

// === CG-PRIV-TLS · http-target: false-positive traps ========================

test('FP TRAP — XML/JSON-LD namespace URLs are names, never fetched → zero', () => {
  assert.deepEqual(scanTransport(`<svg xmlns="http://www.w3.org/2000/svg" />`, 'Icon.tsx'), [])
  assert.deepEqual(scanTransport(`const ld = { "@context": "http://schema.org", "@type": "Person" }`, 'ld.ts'), [])
  assert.deepEqual(scanTransport(`<use xmlns:xlink="http://www.w3.org/1999/xlink" />`, 'Icon.tsx'), [])
  // even if a namespace host is dressed up as a fetch, the host allowlist still suppresses it
  assert.deepEqual(scanTransport(`fetch('http://www.w3.org/2001/XMLSchema')`, 'a.js'), [])
})

test('FP TRAP — localhost / loopback / private / container hosts → zero', () => {
  for (const url of [
    `fetch('http://localhost:3000/api')`,
    `fetch('http://127.0.0.1:5000/api')`,
    `fetch('http://0.0.0.0:8080/api')`,
    `fetch('http://[::1]:3000/api')`,
    `fetch('http://api.local/api')`,
    `fetch('http://db.internal/api')`,
    `fetch('http://backend.test/api')`,
    `fetch('http://host.docker.internal:5432/api')`,
    `fetch('http://postgres/api')`,          // bare docker-compose service name
    `fetch('http://10.0.0.5/api')`,          // RFC1918 private
    `fetch('http://192.168.1.9/api')`,       // RFC1918 private
  ]) {
    assert.deepEqual(scanTransport(url, 'a.js'), [], `local host must not fire: ${url}`)
  }
})

test('FP TRAP — http:// in a comment or in a non-target string → zero', () => {
  // A commented-out fetch: masked as COMMENT before any matching happens.
  assert.deepEqual(scanTransport(`// fetch('http://api.example.com/users') -- legacy`, 'a.js'), [])
  assert.deepEqual(scanTransport(`/* old: http://api.example.com/v1 */`, 'a.js'), [])
  // A plain string with no request-target context (a log line / copy) — real host, still zero.
  assert.deepEqual(scanTransport(`const msg = "could not reach http://api.example.com"`, 'a.js'), [])
  assert.deepEqual(scanTransport(`log.info("posting to http://api.example.com failed")`, 'a.js'), [])
})

test('FP TRAP — a real host in a test / fixture / .example / markdown file → zero', () => {
  const src = `fetch('http://api.example.com/users')`
  assert.deepEqual(scanTransport(src, 'src/api.test.js'), [])
  assert.deepEqual(scanTransport(src, 'src/__tests__/api.js'), [])
  assert.deepEqual(scanTransport(src, 'fixtures/sample.js'), [])
  assert.deepEqual(scanTransport(src, 'README.md'), [])
  assert.deepEqual(scanTransport('DATABASE_URL=postgres://u@db.example.com/app?sslmode=disable', '.env.example'), [])
})

// === CG-PRIV-TLS · db-tls-disabled ==========================================

test('db-tls-disabled: ssl:false / sslmode=disable to a real DB host → one; localhost → zero', () => {
  const objReal = scanTransport(`const pool = new Pool({\n  host: 'db.example.com',\n  port: 5432,\n  ssl: false,\n})`, 'db.js')
  assert.deepEqual(kinds(objReal), ['db-tls-disabled'])
  assert.equal(objReal[0].host, 'db.example.com')

  const objLocal = scanTransport(`const pool = new Pool({ host: 'localhost', ssl: false })`, 'db.js')
  assert.deepEqual(objLocal, [], 'ssl:false to localhost is not a cleartext transmission')

  const urlReal = scanTransport(`const url = 'postgres://u:p@db.example.com:5432/app?sslmode=disable'`, 'db.js')
  assert.deepEqual(kinds(urlReal), ['db-tls-disabled'])
  assert.equal(urlReal[0].host, 'db.example.com')

  const urlLocal = scanTransport(`const url = 'postgres://localhost:5432/app?sslmode=disable'`, 'db.js')
  assert.deepEqual(urlLocal, [], 'sslmode=disable to localhost → zero')
})

test('db-tls-disabled: rejectUnauthorized:false with a visible non-local host fires; with none → zero (LAW 1)', () => {
  const withHost = scanTransport(`createConnection({ host: 'pg.example.com', ssl: { rejectUnauthorized: false } })`, 'db.js')
  assert.deepEqual(kinds(withHost), ['db-tls-disabled'])
  assert.equal(withHost[0].host, 'pg.example.com')

  // No host literal anywhere — host comes from an env var we cannot resolve → undeterminable, emit nothing.
  const noHost = scanTransport(`const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })`, 'db.js')
  assert.deepEqual(noHost, [])
})

// === CG-PRIV-COOKIE: detection ==============================================

test('session cookie with httpOnly:false and no secure → detected with missing flags', () => {
  const facts = scanCookies(`res.cookie('session', token, { httpOnly: false })`)
  assert.equal(facts.length, 1)
  assert.equal(facts[0].name, 'session')
  assert.ok(facts[0].missing.includes('httpOnly'), 'literal httpOnly:false is reported missing')
  assert.ok(facts[0].missing.includes('secure'), 'absent secure is reported missing')
  assert.equal(facts[0].at.line, 1)
})

test('session cookie detection across setter shapes: cookies().set, Set-Cookie header, document.cookie', () => {
  const next = scanCookies(`cookies().set('next-auth.session-token', jwt, { secure: true })`) // httpOnly absent
  assert.equal(next.length, 1)
  assert.ok(next[0].missing.includes('httpOnly'))

  const header = scanCookies(`res.setHeader('Set-Cookie', 'sid=abc123; Path=/; SameSite=Lax')`) // Secure + HttpOnly absent
  assert.equal(header.length, 1)
  assert.equal(header[0].name, 'sid')
  assert.ok(header[0].missing.includes('secure') && header[0].missing.includes('httpOnly'))

  const doc = scanCookies(`document.cookie = 'auth_token=' + t + ';path=/'`)
  assert.equal(doc.length, 1)
  assert.equal(doc[0].name, 'auth_token')
})

// === CG-PRIV-COOKIE: false-positive traps ===================================

test('FP TRAP — non-session cookies (theme, locale, consent, analytics, flag) → zero', () => {
  assert.deepEqual(scanCookies(`res.cookie('theme', 'dark', { httpOnly: false })`), [])
  assert.deepEqual(scanCookies(`res.cookie('locale', 'he', {})`), [])
  assert.deepEqual(scanCookies(`res.cookie('cookie-consent', '1', { secure: false })`), [])
  assert.deepEqual(scanCookies(`res.cookie('_ga', gaId, {})`), [])
  assert.deepEqual(scanCookies(`res.cookie('feature-flags', flags, { httpOnly: false })`), [])
})

test('FP TRAP — secure:process.env.NODE_ENV===\"production\" is the correct pattern → zero', () => {
  const src = `res.cookie('session', token, { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'lax' })`
  assert.deepEqual(scanCookies(src), [], 'the env-conditional secure and its dev-branch false must not fire')
})

test('FP TRAP — a fully-flagged session cookie → zero', () => {
  assert.deepEqual(scanCookies(`res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' })`), [])
})

test('FP TRAP — options behind indirection or absent → zero (a token is not a pass, LAW 1)', () => {
  assert.deepEqual(scanCookies(`res.cookie('session', token, opts)`), [], 'options is a variable we cannot follow')
  assert.deepEqual(scanCookies(`res.cookie('session', token)`), [], 'no options object visible at all')
})

test('FP TRAP — a cookie set inside a comment → zero', () => {
  assert.deepEqual(scanCookies(`// res.cookie('session', token, { httpOnly: false })`), [])
})

// === helper units + determinism =============================================

test('host classification helpers', () => {
  assert.equal(isLocalHost('api.example.com'), false)
  assert.equal(isLocalHost('localhost'), true)
  assert.equal(isLocalHost('db'), true, 'a bare service name has no public TLD')
  assert.equal(isLocalHost('10.1.2.3'), true)
  assert.equal(isNamespaceHost('www.w3.org'), true)
  assert.equal(isNamespaceHost('api.example.com'), false)
  assert.equal(hostFromAuthority('user:pass@db.example.com:5432/app'), 'db.example.com')
  assert.equal(hostFromAuthority('[::1]:6379'), '[::1]')
  assert.equal(isSessionName('sessionId'), true)
  assert.equal(isSessionName('accessToken'), true)
  assert.equal(isSessionName('theme'), false)
  assert.equal(isExcludedPath('src/x.test.ts'), true)
  assert.equal(isExcludedPath('src/x.ts'), false)
})

test('deterministic: same input yields identical facts', () => {
  const src = `fetch('http://api.example.com/a')\nres.cookie('session', t, { httpOnly: false })`
  assert.deepEqual(scanTransport(src, 'a.js'), scanTransport(src, 'a.js'))
  assert.deepEqual(scanCookies(src), scanCookies(src))
})
