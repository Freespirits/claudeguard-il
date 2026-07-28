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

function coerce(v) {
  let s = v.trim()
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1)
  }
  if (s === 'true') return true
  if (s === 'false') return false
  if (s === 'null' || s === '~' || s === '') return null
  if (/^-?\d+$/.test(s)) return Number(s)
  return s
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

export function normalizeHost(input) {
  let s = String(input).trim().toLowerCase()
  s = s.replace(/^[a-z]+:\/\//, '')          // strip scheme
  s = s.split('/')[0]                          // strip path
  return s                                     // may include :port
}

function hostMatches(host, pattern) {
  const p = normalizeHost(pattern)
  const h = normalizeHost(host)
  const hNoPort = h.split(':')[0]
  const pNoPort = p.split(':')[0]
  if (p.startsWith('*.')) {
    const suffix = pNoPort.slice(2)
    return hNoPort === suffix || hNoPort.endsWith('.' + suffix)
  }
  // exact: match with or without port
  return h === p || hNoPort === pNoPort
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
