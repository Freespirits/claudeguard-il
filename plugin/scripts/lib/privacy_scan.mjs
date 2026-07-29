// The privacy / data-security transport & cookie scanner — the static slice of the compliance
// pillar's privacy domain (תקנות הגנת הפרטיות (אבטחת מידע), התשע"ז-2017).
//
// It EMITS FACTS, never verdicts. `scanTransport` reports cleartext request targets and DB
// connections that disable TLS; `scanCookies` reports session cookies set without Secure/HttpOnly.
// The grader (project_model / grader) owns every severity, every P-label and every pillar tag —
// this file only says "here is an http:// request target to host X on line N". Same text in, same
// facts out: no Date.now, no Math.random, only small focused regexes over a comment/string-masked
// view of the source.
//
// WHY THIS IS ALL ABOUT FALSE POSITIVES: for a non-expert owner a cry-wolf "you are breaking the
// privacy law" is worse than a miss (core/checks/privacy-data-security.md#cry-wolf). Cleartext
// detectors classically drown in XML-namespace URLs, localhost, log lines and commented code. Every
// suppression below is deliberate, documented next to the code that implements it, and pinned by a
// test in test/privacy_scan.test.mjs.
//
// MASKING: we reuse the one blessed stripper (strip_comments.mjs, stripJs) exactly as its contract
// intends — `mask` tells us which byte is COMMENT/STRING/CODE, and `code` is the comment- AND
// string-blanked view. We scan RAW text to read the actual URL / host / cookie-name characters (they
// live inside string literals), reject any hit whose byte is a COMMENT, and test request-target
// CONTEXT against `code` so a commented-out `fetch(` or a `fetch(` sitting inside a string can never
// manufacture a target. Newlines are preserved by the stripper, so every offset maps 1:1 onto the
// raw source and line numbers stay honest.

import { stripJs, COMMENT } from './strip_comments.mjs'

const MAX_FACTS = 500 // bound the model on a huge generated/minified file

// ---------------------------------------------------------------------------
// Shared: line indexing + a trimmed one-line snippet, both from the RAW source.
// ---------------------------------------------------------------------------
function indexer(text) {
  const starts = [0]
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1)
  const lineOf = idx => {
    let lo = 0, hi = starts.length - 1
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= idx) lo = mid; else hi = mid - 1 }
    return lo + 1
  }
  const snippetAt = idx => {
    let s = idx, e = idx
    while (s > 0 && text[s - 1] !== '\n') s--
    while (e < text.length && text[e] !== '\n') e++
    return text.slice(s, e).trim().slice(0, 200)
  }
  return { lineOf, snippetAt }
}

// ---------------------------------------------------------------------------
// Shared: host extraction + locality / namespace classification.
// ---------------------------------------------------------------------------

// Extract the bare host from an authority like `user:pass@db.example.com:5432`, `[::1]:6379`,
// `db.example.com/app` or `localhost`. Strips userinfo, port, path/query/fragment and brackets-aware
// IPv6. Returns '' when nothing host-like is present.
export function hostFromAuthority(auth) {
  if (!auth) return ''
  let a = String(auth).trim().split(/[\/?#]/)[0] // drop any path/query/fragment tail
  const at = a.lastIndexOf('@')
  if (at !== -1) a = a.slice(at + 1) // drop userinfo
  if (a.startsWith('[')) { const c = a.indexOf(']'); return (c === -1 ? a : a.slice(0, c + 1)).toLowerCase() }
  const colon = a.indexOf(':')
  if (colon !== -1) a = a.slice(0, colon) // drop :port
  return a.toLowerCase()
}

// FP TRAP (the big one): local / dev / container / reserved hosts. Traffic to these never leaves the
// machine, so http:// or ssl:false against them is not a cleartext transmission of personal data.
// Covers localhost / 127.0.0.1 / 0.0.0.0 / ::1 / [::1], host.docker.internal, the RFC1918 private
// ranges (10/8, 192.168/16, 172.16-31/12), link-local (169.254/16), the reserved dev TLDs
// (.local, .internal, .test, .example, .invalid, .localhost) and any bare single-label hostname
// (a docker-compose service name like `db`, `postgres`, `redis` — no dot means not a public host).
export function isLocalHost(host) {
  if (!host) return true // no host visible → cannot prove a non-local target → treat as suppressed
  const h = host.toLowerCase().replace(/^\[|\]$/g, '')
  if (h === 'localhost' || h === '127.0.0.1' || h === '0.0.0.0' || h === '::1' || h === '::') return true
  if (h === 'host.docker.internal' || h === 'gateway.docker.internal') return true
  if (/^127\./.test(h)) return true                       // loopback block
  if (/^10\./.test(h)) return true                        // RFC1918 private
  if (/^192\.168\./.test(h)) return true                  // RFC1918 private
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true   // RFC1918 private
  if (/^169\.254\./.test(h)) return true                  // link-local
  if (/\.(local|internal|localhost|test|example|invalid)$/.test(h)) return true // reserved dev TLDs
  if (!h.includes('.')) return true                       // bare service name / container hostname
  return false
}

// FP TRAP (the single largest cleartext-detector FP source): XML / RDF / JSON-LD namespace hosts.
// These http:// URLs are NAMES, never network targets — an `xmlns`, an XSD/DTD schema, a JSON-LD
// `@context`, an SVG namespace. Suppress by host, unconditionally, even inside a fetch-looking call
// (the spec: "These are names, never fetched ... suppress it explicitly").
const NAMESPACE_HOSTS = new Set([
  'www.w3.org', 'w3.org', 'schema.org', 'www.schema.org', 'purl.org', 'www.purl.org',
  'purl.oclc.org', 'ns.adobe.com', 'xmlns.com', 'www.xmlns.com', 'docbook.org', 'www.docbook.org',
  'oasis-open.org', 'www.oasis-open.org', 'openoffice.org', 'apache.org', 'xml.apache.org',
  'java.sun.com', 'iptc.org', 'www.iptc.org', 'dublincore.org', 'ns.useplus.org',
  'www.inkscape.org', 'sodipodi.sourceforge.net', 'www.opengis.net', 'www.aiim.org', 'www.iso.org',
])
export function isNamespaceHost(host) {
  const h = (host || '').toLowerCase()
  if (NAMESPACE_HOSTS.has(h)) return true
  // any subdomain of the canonical namespace registries
  return /(?:^|\.)w3\.org$|(?:^|\.)schema\.org$|(?:^|\.)purl\.org$/.test(h)
}

// FP TRAP: never treat a test / spec / fixture / *.example (incl .env.example) / Markdown file as a
// live target. The scheme is real but the file is illustrative, so a hit there is cry-wolf.
const EXCLUDED_PATH = /(?:\.test\.|\.spec\.|__tests__|__mocks__|__fixtures__|(?:^|\/)fixtures?\/|\.fixtures?\.|\.example(?:\.|$)|\.stories\.|\.mdx?$|\.markdown$)/i
export function isExcludedPath(path) {
  return !!path && EXCLUDED_PATH.test(String(path).replace(/\\/g, '/'))
}

// ---------------------------------------------------------------------------
// scanTransport — CG-PRIV-TLS (תקנה 14(ב)): cleartext in transit.
// ---------------------------------------------------------------------------

// Positive REQUEST-TARGET evidence that must sit immediately before the URL (anchored with $ so a
// distant / earlier-line `fetch(` cannot reach forward). Tested against the comment+string-blanked
// `code`, so only real code context counts. Matches: an http client (fetch/axios/ky/got/...), a
// method/XHR call (.get(/.post(/.open(), or a url-ish key (url:/baseURL=/endpoint:/apiUrl:/webhook*:
// /proxy:/target:). Deliberately NOT `href` — an href in copy is navigation, not a data transmission
// (spec FP trap), so links are left out. The trailing filler class allows the blanked opening quote
// and an XHR method arg (`.open('GET', 'http://...')`) between the signal and the URL.
const REQUEST_CONTEXT = new RegExp(
  '(?:' +
    '\\b(?:fetch|axios|ky|got|superagent|needle|undici|phin)\\b\\s*\\.?\\s*\\w*\\s*\\(' +   // http client
    '|\\.(?:get|post|put|patch|del|delete|head|request|open)\\s*\\(' +                       // method / XHR open
    '|\\b(?:base_?url|url|uri|endpoint|api_?base|api_?url|webhook\\w*|proxy|target)\\b\\s*[:=]' + // url-ish key
  ')' +
  "[\\s,'\"`(]*$",
  'i',
)

// Read the host out of an `http://…` occurrence at `idx` in the RAW text.
function parseHttpHost(text, idx) {
  const i = idx + 7 // past 'http://'
  if (text[i] === '[') { const c = text.indexOf(']', i); return c === -1 ? '' : text.slice(i, c + 1).toLowerCase() }
  let j = i
  while (j < text.length && !/[\/?#"'`<>\s)}\],|\\]/.test(text[j])) j++
  return hostFromAuthority(text.slice(i, j))
}

// Resolve the host a TLS-disable token applies to. Two shapes:
//   1) a connection string — `postgres://user:pass@host:5432/db?sslmode=disable` — the host sits in
//      the same unbroken string just before the token.
//   2) a client config object — `new Pool({ host: 'db.example.com', ssl: false })` — the host is a
//      sibling `host`/`hostname`/`server` property, or a connection string, in the surrounding window.
// Returns '' when no host is visible → the caller then declines to emit (LAW 1: absence under
// indirection is undeterminable, not a violation).
function resolveDbHost(text, mIdx) {
  // (1) same-string connection URL
  const back = text.slice(Math.max(0, mIdx - 240), mIdx)
  const p = back.lastIndexOf('://')
  if (p !== -1) {
    const between = back.slice(p)
    if (!/["'`\n]/.test(between)) { // token and scheme:// live in one unbroken string
      const auth = between.slice(3).split(/[\/?#'"`\s,)}|\\]/)[0]
      const host = hostFromAuthority(auth)
      if (host) return host
    }
  }
  // (2) nearest host-ish property or connection string in a ±300 char window
  const winStart = Math.max(0, mIdx - 300)
  const win = text.slice(winStart, Math.min(text.length, mIdx + 300))
  const rel = mIdx - winStart
  let best = '', bestDist = Infinity
  const consider = (at, host) => { if (host && !isBadHostToken(host)) { const d = Math.abs(at - rel); if (d < bestDist) { bestDist = d; best = host } } }
  for (const mm of win.matchAll(/(?:\bhostname|\bhost|\bserver)\s*:\s*(['"`])([^'"`]+)\1/gi)) consider(mm.index, hostFromAuthority(mm[2]))
  for (const mm of win.matchAll(/(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|mssql|sqlserver|amqps?):\/\/([^\s'"`,)}|\\]+)/gi)) consider(mm.index, hostFromAuthority(mm[1]))
  return best
}
// A `host: process.env.DB_HOST` value resolves to an empty/expression host we cannot classify — the
// property regex only captures string literals, so a dynamic host simply yields no candidate.
function isBadHostToken(h) { return !h || h.includes('$') || h.includes('{') }

/**
 * Scan one file's source for cleartext-in-transit facts.
 * @param {string} text  the file source
 * @param {string} [path] the file path (used only to skip test/fixture/example/markdown files)
 * @returns {Array<{kind:'http-target'|'db-tls-disabled', host:string, at:{line:number}, snippet:string}>}
 */
export function scanTransport(text, path = '') {
  if (typeof text !== 'string' || text.length === 0) return []
  if (isExcludedPath(path)) return [] // FP trap: illustrative files are never live targets

  const { code, mask } = stripJs(text)
  const { lineOf, snippetAt } = indexer(text)
  const out = []

  // --- http-target: an http:// (not https) REQUEST TARGET to a non-local host ---
  const httpRe = /http:\/\//gi
  let m
  while ((m = httpRe.exec(text)) && out.length < MAX_FACTS) {
    const idx = m.index
    if (mask[idx] === COMMENT) continue                    // FP trap: http:// inside a comment
    const host = parseHttpHost(text, idx)
    if (isLocalHost(host)) continue                        // FP trap: localhost / private / dev host / dynamic host
    if (isNamespaceHost(host)) continue                    // FP trap: xmlns / schema.org / w3.org — a name, not a target
    // FP trap (belt-and-suspenders to the host allowlist): an xmlns / xmlns:x / @context identifier.
    const pre = text.slice(Math.max(0, idx - 24), idx)
    if (/xmlns(?::[\w-]+)?\s*=\s*["'`]?$/i.test(pre) || /@context["'\s:]+$/i.test(pre)) continue
    // Require positive request-target evidence in the comment/string-free code right before the URL.
    // FP trap: an http:// in a log line, an href in copy, or any non-target string has no such
    // context, so it is skipped — the whole reason a plain string does not fire.
    const ctx = code.slice(Math.max(0, idx - 100), idx)
    if (!REQUEST_CONTEXT.test(ctx)) continue
    out.push({ kind: 'http-target', host, at: { line: lineOf(idx) }, snippet: snippetAt(idx) })
  }

  // --- db-tls-disabled: a DB/backend connection config that explicitly turns TLS off ---
  // Weak evidence by design (a managed provider may enforce TLS server-side anyway) — the grader
  // keeps this needs-review; here we only emit when a NON-LOCAL host is actually visible.
  const tlsRe = /sslmode\s*=\s*disable|(?<![a-z])ssl\s*[:=]\s*false|rejectUnauthorized\s*:\s*false/gi
  while ((m = tlsRe.exec(text)) && out.length < MAX_FACTS) {
    const idx = m.index
    if (mask[idx] === COMMENT) continue                    // FP trap: the token inside a comment
    const host = resolveDbHost(text, idx)
    if (!host) continue                                    // LAW 1: no visible host → undeterminable, do not emit
    if (isLocalHost(host)) continue                        // FP trap: sslmode=disable / ssl:false pointing at localhost
    out.push({ kind: 'db-tls-disabled', host, at: { line: lineOf(idx) }, snippet: snippetAt(idx) })
  }

  out.sort((a, b) => a.at.line - b.at.line || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0))
  return out
}

// ---------------------------------------------------------------------------
// scanCookies — CG-PRIV-COOKIE (supports תקנה 9(ב)/14): session cookie flags.
// ---------------------------------------------------------------------------

// FP TRAP: scope strictly to authentication / session cookies. A theme, locale, cookie-consent,
// analytics-id or feature-flag cookie carries no credential and is out of scope. Substring match
// (case-insensitive) so camelCase names like `sessionId` / `accessToken` and dotted framework names
// like `connect.sid` / `next-auth.session-token` are all caught by their session-bearing part.
const SESSION_TOKENS = ['session', 'sess', 'sid', 'auth', 'token', 'jwt']
export function isSessionName(name) {
  const n = (name || '').toLowerCase()
  return SESSION_TOKENS.some(t => n.includes(t))
}

// Find `flag:` at the top level of an options-object source and return its value token.
function flagValue(objText, flag) {
  const re = new RegExp('\\b' + flag + '\\s*:', 'i')
  const mm = re.exec(objText)
  if (!mm) return undefined
  let i = mm.index + mm[0].length
  while (i < objText.length && /\s/.test(objText[i])) i++
  let depth = 0
  const start = i
  while (i < objText.length) {
    const c = objText[i]
    if (c === '"' || c === "'" || c === '`') { const q = c; i++; while (i < objText.length && objText[i] !== q) { if (objText[i] === '\\') i++; i++ } i++; continue }
    if (c === '(' || c === '{' || c === '[') depth++
    else if (c === ')' || c === '}' || c === ']') { if (depth === 0) break; depth-- }
    else if (c === ',' && depth === 0) break
    i++
  }
  return objText.slice(start, i).trim()
}
// 'set' | 'false' | 'absent'.
//   FP TRAP: `secure: process.env.NODE_ENV === 'production'` is the CORRECT pattern — its value is an
//   expression, not the literal `false`, so it reads as 'set' and the dev-branch `false` never fires.
//   Only a literal `false` (or an absent key) is a problem; a variable / env-conditional is 'set'
//   (LAW 1 — we do not follow indirection to prove a weakness).
function flagState(objText, flag) {
  const v = flagValue(objText, flag)
  if (v === undefined) return 'absent'
  if (/^false$/i.test(v)) return 'false'
  return 'set'
}

// Flags in a Set-Cookie / document.cookie STRING: `; Secure`, `; HttpOnly`, `; SameSite=Lax`.
function stringMissing(cookieStr) {
  const has = w => new RegExp('(?:^|;)\\s*' + w + '(?:\\s*(?:=|;)|\\s*$)', 'i').test(cookieStr)
  const missing = []
  if (!has('secure')) missing.push('secure')
  if (!has('httponly')) missing.push('httpOnly')
  if (!has('samesite')) missing.push('sameSite')
  return missing
}

// Walk to the matching close of the (){}[]-delimiter at openIdx, string-aware. Returns -1 if unclosed.
function matchDelim(s, openIdx) {
  const open = s[openIdx]
  const close = open === '(' ? ')' : open === '{' ? '}' : open === '[' ? ']' : null
  if (!close) return -1
  let depth = 0, i = openIdx
  while (i < s.length) {
    const c = s[i]
    if (c === '"' || c === "'" || c === '`') { const q = c; i++; while (i < s.length && s[i] !== q) { if (s[i] === '\\') i++; i++ } i++; continue }
    if (c === open) depth++
    else if (c === close) { depth--; if (depth === 0) return i }
    i++
  }
  return -1
}
// First `{` in `s` that is not inside a string literal.
function indexOfTopLevelBrace(s) {
  let i = 0
  while (i < s.length) {
    const c = s[i]
    if (c === '"' || c === "'" || c === '`') { const q = c; i++; while (i < s.length && s[i] !== q) { if (s[i] === '\\') i++; i++ } i++; continue }
    if (c === '{') return i
    i++
  }
  return -1
}
// From a call's argument region, pull the cookie name and the literal options-object source.
//   name : the first string argument, or a `name:` property in an object-form first argument.
//   options : the first top-level `{…}` object, or null when none is present.
// FP TRAP (indirection / no-visible-options): when the options are a bare identifier or absent
// (`res.cookie('sid', v, opts)` / `res.cookie('sid', v)`) there is no object to read, so `options`
// is null and the caller emits NOTHING — a token is not a pass, and we do not flag a cookie whose
// flags we cannot see (LAW 1).
function parseCookieArgs(region) {
  let name = null
  let k = 0
  while (k < region.length && /\s/.test(region[k])) k++
  if (region[k] === '"' || region[k] === "'" || region[k] === '`') {
    const q = region[k]; let i = k + 1
    while (i < region.length && region[i] !== q) { if (region[i] === '\\') i++; i++ }
    name = region.slice(k + 1, i)
  }
  let options = null
  const b = indexOfTopLevelBrace(region)
  if (b !== -1) { const e = matchDelim(region, b); if (e !== -1) options = region.slice(b, e + 1) }
  if (name === null && options) { const nm = /\bname\s*:\s*(['"`])([^'"`]+)\1/.exec(options); if (nm) name = nm[2] }
  return { name, options }
}

/**
 * Scan one file's source for session-cookie flag facts.
 * @param {string} text the file source
 * @returns {Array<{at:{line:number}, name:string, missing:string[], snippet:string}>}
 *   `missing` is a subset of ['secure','httpOnly','sameSite'], always in that order. A fact is only
 *   emitted when Secure and/or HttpOnly is the problem (SameSite alone is too weak); SameSite is
 *   listed alongside when it is also absent.
 */
export function scanCookies(text) {
  if (typeof text !== 'string' || text.length === 0) return []
  const { mask } = stripJs(text)
  const { lineOf, snippetAt } = indexer(text)
  const found = []
  const record = (idx, name, missing) => {
    if (mask[idx] === COMMENT) return                       // FP trap: a cookie set inside a comment
    if (!isSessionName(name)) return                        // FP trap: theme / locale / consent / analytics / flag
    if (!missing.includes('secure') && !missing.includes('httpOnly')) return // SameSite-only is too weak to assert
    found.push({ idx, at: { line: lineOf(idx) }, name, missing, snippet: snippetAt(idx) })
  }

  // (A) call setters with a literal options object:
  //     res.cookie('name', v, {..}) · reply.setCookie(..) · cookies().set('name', v, {..}) ·
  //     cookieStore.set(..) · <ident>Cookies.set(..) · serialize('name', v, {..})
  const setterRe = /(?:\.\s*setCookie|\.\s*cookie|(?:cookies\(\s*\)|cookieStore|cookieJar|[A-Za-z_$][\w$]*Cookies?)\s*\.\s*set|\bserialize)\s*\(/g
  let m
  while ((m = setterRe.exec(text)) && found.length < MAX_FACTS) {
    if (mask[m.index] === COMMENT) continue
    const paren = m.index + m[0].length - 1 // the '(' is the last char of the match
    const close = matchDelim(text, paren)
    if (close === -1) continue
    const { name, options } = parseCookieArgs(text.slice(paren + 1, close))
    if (name === null || options === null) continue         // FP trap: no visible options object → undeterminable
    const secure = flagState(options, 'secure')
    const httpOnly = flagState(options, 'httpOnly')
    const sameSite = flagState(options, 'sameSite')
    const missing = []
    if (secure !== 'set') missing.push('secure')
    if (httpOnly !== 'set') missing.push('httpOnly')
    if (sameSite !== 'set') missing.push('sameSite')
    record(m.index, name, missing)
  }

  // (B) a Set-Cookie header string — res.setHeader('Set-Cookie', 'sid=..; HttpOnly') / { 'Set-Cookie': '..' }
  const setCookieRe = /(['"`])set-cookie\1\s*[,:]\s*(['"`])([^'"`]*)\2/gi
  while ((m = setCookieRe.exec(text)) && found.length < MAX_FACTS) {
    const cookieStr = m[3]
    record(m.index, cookieStr.split('=')[0].trim(), stringMissing(cookieStr))
  }

  // (C) document.cookie = 'sid=..; ..'
  const docCookieRe = /document\.cookie\s*=\s*(['"`])([^'"`]*)\1/gi
  while ((m = docCookieRe.exec(text)) && found.length < MAX_FACTS) {
    const cookieStr = m[2]
    record(m.index, cookieStr.split('=')[0].trim(), stringMissing(cookieStr))
  }

  // Deterministic order; drop duplicates that two detectors might report on the same line+name.
  found.sort((a, b) => a.idx - b.idx)
  const seen = new Set()
  const out = []
  for (const f of found) {
    const key = f.at.line + '|' + f.name
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ at: f.at, name: f.name, missing: f.missing, snippet: f.snippet })
  }
  return out
}
