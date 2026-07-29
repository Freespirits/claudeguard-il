// Shared scope parsing + authorization gate for Tier 1 (live) and Tier 2 (DAST).
// Minimal YAML reader for the claudeguard.scope.yml template shape (2-space nesting + lists).
// Fails CLOSED: any parse/precondition problem denies the run.
import { readFileSync } from 'node:fs'

// Providers refused by default even if listed in targets (defense-in-depth).
export const DEFAULT_BLOCKED = [
  '*.supabase.co', '*.supabase.in', '*.firebaseio.com', '*.firebaseapp.com',
  '*.web.app', '*.amazonaws.com', '*.googleapis.com', '*.azurewebsites.net',
  'api.openai.com', 'api.anthropic.com', 'api.stripe.com',
]

function stripComment(line) {
  // remove a trailing " # comment" or a full-line comment; our values contain no '#'
  if (/^\s*#/.test(line)) return ''
  return line.replace(/\s+#.*$/, '')
}

function coerceScalar(s) {
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1)
  }
  if (s === 'true') return true
  if (s === 'false') return false
  if (s === 'null' || s === '~' || s === '') return null
  if (/^-?\d+$/.test(s)) return Number(s)
  return s
}

function coerce(v) {
  const s = v.trim()
  // Flow sequences — `allow: [nmap_scan, nuclei_scan]` and `blocklist: []`.
  //
  // Without this the value came back as the STRING "[nmap_scan, nuclei_scan]", which
  // `Array.isArray` rejects, so a per-tool allowlist written in the form the docs themselves use
  // silently became "no list at all". Deny-by-default made that fail closed rather than open, but
  // a config that reads as empty when it is not is one refactor away from being read as a
  // substring instead — and a substring check on "[nmap_scan]" would match `nmap`, `nmap_sc`, and
  // anything else a caller passed. Parsing the form the user actually wrote is the only version
  // with no trap in it.
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim()
    if (!inner) return []
    return inner.split(',').map(part => coerceScalar(part.trim()))
  }
  return coerceScalar(s)
}

// Indentation-based parser for maps + simple lists.
export function parseSimpleYaml(text) {
  const root = {}
  const stack = [{ indent: -1, container: root, parent: null, key: null }]
  for (const raw of text.split(/\r?\n/)) {
    const stripped = stripComment(raw)
    if (!stripped.trim()) continue
    const indent = raw.length - raw.trimStart().length
    const content = stripped.trim()
    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) stack.pop()
    const top = stack[stack.length - 1]

    if (content.startsWith('- ')) {
      // list item: the current block's value becomes an array on its parent
      if (!Array.isArray(top.container) && top.parent && top.key != null) {
        if (!Array.isArray(top.parent[top.key])) top.parent[top.key] = []
        top.parent[top.key].push(coerce(content.slice(2)))
        top.container = top.parent[top.key]
      } else if (Array.isArray(top.container)) {
        top.container.push(coerce(content.slice(2)))
      }
      continue
    }

    const idx = content.indexOf(':')
    if (idx === -1) continue
    const key = content.slice(0, idx).trim()
    const rest = content.slice(idx + 1).trim()
    if (rest === '') {
      const child = {}
      if (!Array.isArray(top.container)) top.container[key] = child
      stack.push({ indent, container: child, parent: top.container, key })
    } else if (!Array.isArray(top.container)) {
      top.container[key] = coerce(rest)
    }
  }
  return root
}

export function loadScope(path) {
  let text
  try { text = readFileSync(path, 'utf8') }
  catch { return { ok: false, error: `Scope file not found: ${path}. Copy SCOPE.example.yml to ${path}.` } }
  try { return { ok: true, scope: parseSimpleYaml(text) } }
  catch (e) { return { ok: false, error: `Could not parse scope file: ${e.message}` } }
}

/**
 * The value `normalizeHost` returns when the input is not a host it can vouch for. It contains a
 * NUL, so it can never equal, prefix or suffix any pattern: an input we could not parse is denied
 * by every matcher instead of being compared as a raw string.
 */
export const UNMATCHABLE = '\u0000unparseable'

/**
 * Reduce any input to the host `fetch` would ACTUALLY open, in one canonical spelling.
 *
 * This used to be string surgery — strip the scheme, cut at the first `/` — and every bypass the
 * audit found came from the same place: the string that was checked was not the string that was
 * sent. All of these passed the shipped Tier-1/Tier-2 gate while the request went somewhere else:
 *
 *   https://staging.myapp.com:443@evil.com   userinfo. `split(':')[0]` yielded the allowlisted
 *                                            name; fetch opened evil.com.
 *   https://localhost:3000@169.254.169.254   the same trick against the DEFAULT target that ships
 *                                            in SCOPE.example.yml — cloud-metadata SSRF out of the
 *                                            box.
 *   https://evil.com?x=.staging.example.com  `?` ends the authority for the URL parser but not for
 *   https://evil.com#.staging.example.com    a scan for `/`, so the wildcard suffix matched.
 *   https://api.stripe.com.                  a trailing root dot is the same name to DNS and a
 *                                            different string to `===`, so DEFAULT_BLOCKED missed it.
 *   https://[::ffff:169.254.169.254]         `split(':')[0]` is `[` for every `::`-leading IPv6
 *                                            literal, so a `[::1]` target matched all of them.
 *   https://2130706433                       a decimal-encoded 127.0.0.1 is a different string.
 *
 * The fix is to stop pattern-matching text and to parse with the same URL parser `fetch` uses.
 * WHATWG parsing settles all seven at once: it discards userinfo, ends the authority at `/ \ ? #`,
 * lowercases, converts IDN to punycode, and canonicalises decimal / octal / hex / IPv4-mapped-IPv6
 * addresses to one spelling. The root dot is stripped here, because DNS treats `example.com.` and
 * `example.com` as the same name and so must a blocklist.
 *
 * @returns {string} canonical `host` or `host:port`, or UNMATCHABLE.
 */
export function normalizeHost(input) {
  let s = String(input == null ? '' : input).trim()
  if (!s) return UNMATCHABLE
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    // has a scheme and an authority — parse as-is
  } else if (/^[a-z][a-z0-9+.-]*:(?!\d)/i.test(s)) {
    // `javascript:`, `data:`, `file:` — a scheme with no authority is not a host, and guessing
    // one from the opaque part is how a gate ends up vouching for something it never saw.
    return UNMATCHABLE
  } else {
    s = 'https://' + s   // bare `host`, `host:port` or `[::1]:port`
  }
  let u
  try { u = new URL(s) } catch { return UNMATCHABLE }
  const name = u.hostname.replace(/\.+$/, '')
  if (!name) return UNMATCHABLE
  return u.port ? `${name}:${u.port}` : name
}

/** Split a canonical host into `[name, port]`. IPv6 literals keep their brackets. */
function splitHostPort(h) {
  const i = h.lastIndexOf(':')
  if (i === -1 || h.endsWith(']')) return [h, '']
  return [h.slice(0, i), h.slice(i + 1)]
}

const CIDR_RE = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/

function ipv4ToInt(ip) {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const b = Number(part)
    if (b > 255) return null
    n = (n * 256) + b
  }
  return n
}

/**
 * IPv4 CIDR containment. The dynamic-testing spec's own example allowlist contains `10.0.5.0/24`,
 * and before this the `/` was read as the start of a path — so the entry silently collapsed to the
 * single host `10.0.5.0` and denied the other 255. A config that means something other than what it
 * says is a gate nobody can reason about, in either direction.
 */
function cidrContains(pattern, hostName) {
  const m = CIDR_RE.exec(pattern)
  if (!m) return false
  const bits = Number(m[2])
  if (bits > 32) return false
  const net = ipv4ToInt(m[1])
  const ip = ipv4ToInt(hostName)
  if (net == null || ip == null) return false
  if (bits === 0) return false   // `0.0.0.0/0` is "everything"; an allowlist of everything is not one
  const mask = (0xffffffff << (32 - bits)) >>> 0
  return ((net & mask) >>> 0) === ((ip & mask) >>> 0)
}

/**
 * Does `host` match one allowlist / blocklist pattern? Exported because the dynamic-testing gate
 * must match hosts exactly the way the Tier-1/Tier-2 gate does — two host matchers is one too many.
 *
 * Forms: `example.com`, `example.com:8443`, `*.example.com`, `10.0.5.0/24`, `[::1]`.
 */
export function hostMatches(host, pattern) {
  const h = normalizeHost(host)
  if (h === UNMATCHABLE) return false
  const [hName, hPort] = splitHostPort(h)

  const raw = String(pattern == null ? '' : pattern).trim()
  if (!raw) return false

  if (CIDR_RE.test(raw)) return cidrContains(raw, hName)
  if (raw.includes('/')) return false   // the only legal `/` in a pattern is a CIDR prefix

  if (raw.startsWith('*.')) {
    const suffix = normalizeHost(raw.slice(2))
    if (suffix === UNMATCHABLE) return false
    const [sName, sPort] = splitHostPort(suffix)
    if (sPort && sPort !== hPort) return false
    return hName === sName || hName.endsWith('.' + sName)
  }

  const p = normalizeHost(raw)
  if (p === UNMATCHABLE) return false
  const [pName, pPort] = splitHostPort(p)
  if (pName !== hName) return false
  // A pattern that names a port means THAT port. `localhost:3000` — the target that ships in
  // SCOPE.example.yml — used to license `localhost:22` and `localhost:5432` too, because the port
  // was dropped from both sides before comparing. A pattern with no port still covers any port,
  // which is what makes `app.example.com` cover `app.example.com:8443`.
  return !pPort || pPort === hPort
}

/**
 * The URL a runner may actually request, with the parts that let a gated string differ from a sent
 * one removed: credentials (the userinfo bypass) and any non-HTTP scheme. Returns null when the
 * input is not a fetchable http(s) URL, and null means "do not send anything".
 *
 * The gate reads a host; the runner sends a URL. Before this they were derived from the same raw
 * string by two different pieces of code, which is exactly the gap the userinfo bypass drove
 * through. Both now come from one parse.
 */
export function canonicalUrl(input) {
  let s = String(input == null ? '' : input).trim()
  if (!s) return null
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    if (/^[a-z][a-z0-9+.-]*:(?!\d)/i.test(s)) return null
    s = 'https://' + s
  }
  let u
  try { u = new URL(s) } catch { return null }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
  if (!u.hostname) return null
  u.username = ''
  u.password = ''
  u.hash = ''
  return u.toString()
}

export function isBlocked(host, scope) {
  const never = Array.isArray(scope?.never_touch) ? scope.never_touch : []
  const all = [...never, ...DEFAULT_BLOCKED]
  return all.some(p => hostMatches(host, p))
}

export function inTargets(host, scope) {
  const targets = Array.isArray(scope?.targets) ? scope.targets : []
  return targets.some(p => hostMatches(host, p))
}

// Tier 1 gate. Returns { allowed, reasons: [] }.
export function gateTier1(host, scope) {
  const reasons = []
  const pl = scope?.passive_live || {}
  if (pl.enabled !== true) reasons.push('set passive_live.enabled: true in claudeguard.scope.yml')
  if (pl.i_own_or_control_these_targets !== true) reasons.push('set passive_live.i_own_or_control_these_targets: true')
  if (!inTargets(host, scope)) reasons.push(`add "${host}" to targets in the scope file`)
  if (isBlocked(host, scope)) reasons.push(`"${host}" is in never_touch or is a blocked third-party provider`)
  return { allowed: reasons.length === 0, reasons }
}

// Tier 2 gate. Returns { allowed, reasons, dryRun, rateCap, avoidDestructive }.
export function gateTier2(host, scope, { execute = false } = {}) {
  const t1 = gateTier1(host, scope) // Tier 2 also requires host/target validity
  const reasons = [...t1.reasons.filter(r => r.includes('targets') || r.includes('never_touch') || r.includes('blocked'))]
  const ad = scope?.active_dast || {}
  if (ad.enabled !== true) reasons.push('set active_dast.enabled: true')
  if (ad.i_am_authorized_in_writing !== true) reasons.push('set active_dast.i_am_authorized_in_writing: true')
  if (ad.i_own_or_control_these_targets !== true) reasons.push('set active_dast.i_own_or_control_these_targets: true')
  const dryRun = ad.dry_run !== false // default true
  const rateCap = Math.min(Number(ad.max_requests_per_second) || 2, 2) // hard cap 2 req/s
  const avoidDestructive = ad.avoid_destructive !== false // default true
  // A real (non-dry-run) run also needs the --i-am-authorized flag.
  const willExecute = execute && !dryRun
  if (execute && dryRun) reasons.push('scope has dry_run: true — set dry_run: false to actually send traffic')
  return { allowed: reasons.length === 0, reasons, dryRun, willExecute, rateCap, avoidDestructive }
}

export function parseArgs(argv) {
  const args = {}
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const key = a.slice(2)
      const next = argv[i + 1]
      if (next && !next.startsWith('--')) { args[key] = next; i++ }
      else args[key] = true
    }
  }
  return args
}
