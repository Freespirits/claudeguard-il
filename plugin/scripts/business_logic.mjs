#!/usr/bin/env node
// Business logic — the part a static tool cannot do alone.
//
// Every other check in ClaudeGuardIL asks a question the code can answer by itself: is RLS on, is
// the key behind a public prefix. This one asks a question the code CANNOT answer: what is this app
// supposed to permit? "User A can read user B's order" is a critical bug in a store and a deliberate
// feature in an admin console — byte-identical code, opposite verdicts.
//
// So the pipeline is three steps, and the middle one is the crux:
//
//   Engine facts (deterministic)  →  Intent model (proposed, then USER-CONFIRMED)  →  Audit
//      what the app manipulates        what the app is supposed to permit          where code ≠ intent
//
// See core/methodology/business-logic.md. Three properties of this file are load-bearing:
//
//   1. It emits OBSERVATIONS, never severity. `{ tier: 'business-logic', kind, subject, at, detail }`
//      is the same shape the gitleaks / semgrep / DAST adapters emit, and grader.mjs owns the
//      P-level exactly as it does for those. There is no parallel findings path.
//   2. Every result is a REVIEWER result: provenance `reviewer`, evidence `judgement`, capped at
//      confidence `likely` and never `confirmed`. The tool did not PROVE the app's intent; it
//      checked code against a STATED intent, and either could be wrong. grader.mjs asserts the cap.
//   3. Grade-or-declare applies to the taxonomy ITSELF. Each of the ten classes is either checked
//      or declared undeterminable WITH THE REASON — never silent. A confident silence is most
//      dangerous exactly here, because business-logic bugs are the ones a scanner is expected to
//      miss, so silence about them reads as "clean" to the person about to deploy.
//
// Zero runtime dependencies — node builtins only, a hard project constraint. That includes YAML:
// the intent reader below is a local, deliberately small parser, not a library.
import { readFileSync } from 'node:fs'

// ---------------------------------------------------------------------------
// The taxonomy — the ten classes, and which of them this pass can actually check
// ---------------------------------------------------------------------------

/**
 * The ten classes from core/methodology/business-logic.md, in the spec's order.
 *
 * `scope: 'resource'` means the class is walked once per resource in the intent.
 * `scope: 'declared'` means the FACTS THIS ENGINE HAS CANNOT SUPPORT IT, so it is declared once for
 * the whole repo with the reason. A declared gap is a good outcome; a fabricated check is not.
 */
export const TAXONOMY = [
  { id: 'object-level-authz', scope: 'resource', title_en: 'Object-level authorization (IDOR)' },
  { id: 'wrong-owner-column', scope: 'resource', title_en: 'Ownership checked against the wrong column' },
  { id: 'function-level-authz', scope: 'resource', title_en: 'Function-level authorization' },
  { id: 'state-transition-authz', scope: 'resource', title_en: 'State-transition authorization' },
  { id: 'tenant-isolation', scope: 'resource', title_en: 'Tenant isolation' },
  {
    id: 'workflow-sequence-bypass',
    scope: 'declared',
    title_en: 'Workflow / sequence bypass',
    reason: 'answering "can a required step be skipped?" needs an ordering between endpoints and a model of the server-side state that guards each step. The engine has neither: it enumerates routes independently, and a step guard can live in a database trigger, a queue, or a helper this pass does not follow. Review each multi-step flow by hand against core/methodology/business-logic.md.',
  },
  { id: 'value-tampering', scope: 'resource', title_en: 'Value / quantity tampering' },
  {
    id: 'replay-idempotency',
    scope: 'declared',
    title_en: 'Replay / idempotency',
    reason: 'answering "can this action be repeated for gain?" needs a fact for the CONSUMED MARKER — a unique constraint, an idempotency key, a redeemed-at column that the handler actually writes and re-reads. The engine models none of those, and guessing from a route name would flag every /apply and /redeem endpoint in the repo. Review coupon, refund, credit and transfer endpoints by hand.',
  },
  {
    id: 'privilege-escalation-chain',
    scope: 'declared',
    title_en: 'Privilege escalation across endpoints',
    reason: 'answering "do two safe endpoints combine into an unsafe one?" needs inter-route data flow — that endpoint A returns an internal id which endpoint B then trusts. The engine models each route in isolation and does not track a value from one response into another request. Review any endpoint that accepts an id it did not itself issue.',
  },
  { id: 'mass-assignment', scope: 'resource', title_en: 'Mass assignment' },
]

export const RESOURCE_CLASSES = TAXONOMY.filter(c => c.scope === 'resource').map(c => c.id)
export const DECLARED_CLASSES = TAXONOMY.filter(c => c.scope === 'declared')

// Column-name hints, used ONLY by the proposer. They are how a DRAFT is offered to the user; they
// are never treated as a confirmed statement of intent, because "this column means ownership" is
// precisely the claim only the app's author can make.
const OWNERSHIP_COLUMN_HINTS = ['user_id', 'owner_id', 'author_id', 'created_by', 'owned_by', 'uid', 'profile_id', 'customer_id']
const TENANT_COLUMN_HINTS = ['org_id', 'organization_id', 'organisation_id', 'team_id', 'workspace_id', 'tenant_id', 'account_id', 'company_id', 'group_id']
const STATE_COLUMN_HINTS = ['status', 'state', 'stage', 'phase']
// Tables whose PRIMARY KEY is the user id — the `profiles: owned_by: id` shape in the spec's own
// example. Proposing `owned_by: id` for an arbitrary table would be nonsense, so the guess is
// limited to the handful of names where it is the overwhelming convention.
const SELF_KEYED_TABLES = new Set(['profiles', 'users', 'accounts', 'members', 'user_profiles', 'user_settings', 'user_preferences'])

// ---------------------------------------------------------------------------
// The intent file reader
//
// The repo's existing YAML reader (`_scope.mjs`, parseSimpleYaml) now reads inline flow sequences
// (`allow: [a, b]`), but it still fails OPEN: a malformed line is silently skipped and a duplicate
// key silently overwrites — the right trade for a scope file whose gate is deny-by-default, and the
// wrong one here, where a half-read intent looks confirmed and checks the wrong rules. So this is a
// local reader for one documented shape, and it FAILS CLOSED: every parse or schema problem throws,
// the caller reports the file as broken and IGNORES it entirely, and the audit falls back to an
// explicitly ASSUMED intent.
// ---------------------------------------------------------------------------

export class IntentError extends Error {}

/** Remove a `#` comment, but only when the `#` is outside quotes — rule text may contain one. */
function stripYamlComment(line) {
  let quote = null
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (quote) { if (c === quote) quote = null; continue }
    if (c === '"' || c === "'") { quote = c; continue }
    if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i)
  }
  return line
}

/** Index of the `key: value` separator: the first `:` outside quotes that is followed by space/EOL. */
function colonIndex(s) {
  let quote = null
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (quote) { if (c === quote) quote = null; continue }
    if (c === '"' || c === "'") { quote = c; continue }
    if (c === ':' && (i + 1 === s.length || /\s/.test(s[i + 1]))) return i
  }
  return -1
}

/** Split a flow sequence's body on commas that are outside quotes and outside nested brackets. */
function splitFlow(s, line) {
  const out = []
  let depth = 0, quote = null, start = 0
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (quote) { if (c === quote) quote = null; continue }
    if (c === '"' || c === "'") { quote = c; continue }
    if (c === '[' || c === '{') depth++
    else if (c === ']' || c === '}') depth--
    else if (c === ',' && depth === 0) { out.push(s.slice(start, i)); start = i + 1 }
  }
  if (quote) throw new IntentError(`line ${line}: unterminated quote`)
  out.push(s.slice(start))
  return out
}

function coerceScalar(v, line) {
  const s = v.trim()
  if ((s.startsWith('"') && s.endsWith('"') && s.length > 1) ||
      (s.startsWith("'") && s.endsWith("'") && s.length > 1)) return s.slice(1, -1)
  if (s === 'true') return true
  if (s === 'false') return false
  if (s === 'null' || s === '~' || s === '') return null
  if (/^-?\d+$/.test(s)) return Number(s)
  if (s.startsWith('[') || s.startsWith('{')) throw new IntentError(`line ${line}: malformed inline value ${s.slice(0, 40)}`)
  return s
}

/** A scalar, or an inline flow sequence `[a, b, c]` — the form parseSimpleYaml cannot read. */
function coerceValue(v, line) {
  const s = v.trim()
  if (!s.startsWith('[')) {
    if (s.startsWith('{')) throw new IntentError(`line ${line}: inline maps ({…}) are not supported in claudeguard.intent.yml — use an indented block`)
    return coerceScalar(s, line)
  }
  if (!s.endsWith(']')) throw new IntentError(`line ${line}: inline list is not closed with "]"`)
  const body = s.slice(1, -1).trim()
  if (!body) return []
  return splitFlow(body, line).map(part => coerceScalar(part, line))
}

/**
 * Indentation-based reader for the claudeguard.intent.yml shape: nested maps, `- item` block lists,
 * and inline flow sequences at any depth. Anything else throws.
 */
export function parseIntentYaml(text) {
  if (typeof text !== 'string') throw new IntentError('intent file is not text')
  const root = {}
  const stack = [{ indent: -1, container: root }]
  // A `key:` whose value has not appeared yet. The first line UNDER it decides whether it becomes a
  // map or a list; a key with nothing under it is null.
  let pending = null

  const lines = text.split(/\r?\n/)
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i]
    const ln = i + 1
    if (!rawLine.trim()) continue
    if (/^ *\t/.test(rawLine)) throw new IntentError(`line ${ln}: tab used for indentation — YAML forbids tabs, use spaces`)
    const content = stripYamlComment(rawLine).trim()
    if (!content) continue
    const indent = rawLine.length - rawLine.trimStart().length
    const isSeqItem = content === '-' || content.startsWith('- ')

    if (pending) {
      if (indent > pending.indent || (isSeqItem && indent === pending.indent)) {
        const child = isSeqItem ? [] : {}
        pending.parent[pending.key] = child
        // The container is anchored at its KEY's indent, so a list written flush with its key
        // (legal YAML) is not popped by the sibling check below.
        stack.push({ indent: pending.indent, container: child })
      } else {
        pending.parent[pending.key] = null
      }
      pending = null
    }

    while (stack.length > 1) {
      const top = stack[stack.length - 1]
      if (indent > top.indent) break
      if (isSeqItem && Array.isArray(top.container) && indent === top.indent) break
      stack.pop()
    }
    const top = stack[stack.length - 1]

    if (isSeqItem) {
      if (!Array.isArray(top.container)) throw new IntentError(`line ${ln}: list item "-" is not inside a list`)
      const item = content === '-' ? '' : content.slice(2).trim()
      if (colonIndex(item) !== -1 && !item.startsWith('"') && !item.startsWith("'")) {
        throw new IntentError(`line ${ln}: a list of maps is not supported in claudeguard.intent.yml`)
      }
      top.container.push(coerceValue(item, ln))
      continue
    }

    if (Array.isArray(top.container)) throw new IntentError(`line ${ln}: expected a list item ("- …") here, got "${content.slice(0, 40)}"`)
    const ci = colonIndex(content)
    if (ci === -1) throw new IntentError(`line ${ln}: expected "key: value", got "${content.slice(0, 40)}"`)
    const key = String(coerceScalar(content.slice(0, ci).trim(), ln) ?? '')
    const rest = content.slice(ci + 1).trim()
    if (!key) throw new IntentError(`line ${ln}: empty key`)
    // A duplicate key silently discards one of the two statements, and which one wins depends on
    // file order. That is exactly the kind of quiet wrongness this file exists to prevent.
    if (Object.prototype.hasOwnProperty.call(top.container, key)) throw new IntentError(`line ${ln}: duplicate key "${key}"`)
    if (rest === '') pending = { parent: top.container, key, indent }
    else top.container[key] = coerceValue(rest, ln)
  }
  if (pending) pending.parent[pending.key] = null
  return root
}

const TOP_LEVEL_KEYS = new Set(['roles', 'default_role', 'resources', 'rules', 'system_routes'])
const RESOURCE_KEYS = new Set(['owned_by', 'tenant', 'state_column', 'states', 'transitions', 'mutable_fields', 'read_only_for'])

const isPlainObject = v => v != null && typeof v === 'object' && !Array.isArray(v)
const isStringList = v => Array.isArray(v) && v.every(x => typeof x === 'string' && x.trim())

/**
 * Reject anything the audit would otherwise misread. An UNKNOWN KEY is an error on purpose: a
 * typo'd `owner_by:` would silently disable the ownership check, and a check that is silently off is
 * the confident silence this whole methodology exists to prevent.
 */
export function validateIntent(obj) {
  if (!isPlainObject(obj)) throw new IntentError('the intent file must be a YAML map')
  for (const k of Object.keys(obj)) {
    if (!TOP_LEVEL_KEYS.has(k)) {
      throw new IntentError(`unknown top-level key "${k}" — expected one of: ${[...TOP_LEVEL_KEYS].join(', ')}`)
    }
  }
  if (obj.roles != null && !isStringList(obj.roles)) throw new IntentError('`roles` must be a list of role names, e.g. roles: [anonymous, user, admin]')
  if (obj.default_role != null && typeof obj.default_role !== 'string') throw new IntentError('`default_role` must be a role name')
  if (obj.roles && obj.default_role && !obj.roles.includes(obj.default_role)) {
    throw new IntentError(`\`default_role: ${obj.default_role}\` is not one of the declared roles (${obj.roles.join(', ')})`)
  }
  if (obj.rules != null && !isStringList(obj.rules)) throw new IntentError('`rules` must be a list of sentences')
  if (obj.system_routes != null && !isStringList(obj.system_routes)) throw new IntentError('`system_routes` must be a list of path patterns')
  if (!isPlainObject(obj.resources)) throw new IntentError('`resources` is required and must be a map of resource names to their rules')

  for (const [name, r] of Object.entries(obj.resources)) {
    if (!isPlainObject(r)) throw new IntentError(`resource "${name}" must be a map (owned_by, tenant, states, …)`)
    for (const k of Object.keys(r)) {
      if (!RESOURCE_KEYS.has(k)) throw new IntentError(`resource "${name}": unknown key "${k}" — expected one of: ${[...RESOURCE_KEYS].join(', ')}`)
    }
    for (const k of ['owned_by', 'tenant', 'state_column']) {
      if (r[k] != null && typeof r[k] !== 'string') throw new IntentError(`resource "${name}": \`${k}\` must be a column name or null`)
    }
    for (const k of ['states', 'mutable_fields', 'read_only_for']) {
      if (r[k] != null && !isStringList(r[k]) && !(Array.isArray(r[k]) && !r[k].length)) {
        throw new IntentError(`resource "${name}": \`${k}\` must be a list, e.g. ${k}: [a, b]`)
      }
    }
    if (r.transitions != null) {
      if (!isPlainObject(r.transitions)) throw new IntentError(`resource "${name}": \`transitions\` must be a map of "from->to" to a list of roles`)
      for (const [t, actors] of Object.entries(r.transitions)) {
        if (!/^[\w*-]+->[\w*-]+$/.test(t)) throw new IntentError(`resource "${name}": transition "${t}" must read "from->to" (use "any" for any source state)`)
        if (!isStringList(actors) && !(Array.isArray(actors) && !actors.length)) {
          throw new IntentError(`resource "${name}": transition "${t}" must list who may perform it, e.g. ${t}: [admin]`)
        }
        const to = t.split('->')[1]
        if (r.states && !r.states.includes(to) && to !== 'any' && to !== '*') {
          throw new IntentError(`resource "${name}": transition "${t}" targets "${to}", which is not in states: [${r.states.join(', ')}]`)
        }
      }
    }
  }
  return obj
}

/**
 * Read and validate an intent file.
 * @returns {{status:'confirmed'|'missing'|'error', intent:object|null, error:string|null, path:string}}
 */
export function loadIntent(path) {
  let text
  try { text = readFileSync(path, 'utf8') }
  catch { return { status: 'missing', intent: null, error: null, path } }
  try {
    return { status: 'confirmed', intent: validateIntent(parseIntentYaml(text)), error: null, path }
  } catch (e) {
    return { status: 'error', intent: null, error: String(e.message || e), path }
  }
}

// ---------------------------------------------------------------------------
// The proposer
//
// Proposing is the whole difference between guessing and reviewing. The tool drafts the intent from
// the schema and the routes; the user corrects it. What it cannot draft — which state transitions
// are legal, which fields a user may set, which operations are admin-only — it leaves out, because
// an invented rule that happens to match the code would report a clean audit of a rule nobody wrote.
// ---------------------------------------------------------------------------

export function proposeIntent(model) {
  const resources = {}
  for (const t of (model.database?.tables || [])) {
    const names = (t.columns || []).map(c => c.name)
    const owned = OWNERSHIP_COLUMN_HINTS.find(h => names.includes(h))
      ?? (SELF_KEYED_TABLES.has(t.name) && names.includes('id') ? 'id' : null)
    const r = {
      owned_by: owned ?? null,
      tenant: TENANT_COLUMN_HINTS.find(h => names.includes(h)) ?? null,
    }
    const stateColumn = STATE_COLUMN_HINTS.find(h => names.includes(h))
    if (stateColumn) r.state_column = stateColumn
    resources[t.name] = r
  }
  return {
    roles: ['anonymous', 'user', 'admin'],
    default_role: 'user',
    resources,
    rules: [],
    system_routes: [],
  }
}

/** The proposal as a file the user can save, correct, and commit. */
export function renderIntentYaml(intent, { columnsKnown = true } = {}) {
  const q = s => (/^[\w./-]+$/.test(String(s)) ? String(s) : JSON.stringify(String(s)))
  const out = [
    '# claudeguard.intent.yml — what this app is supposed to PERMIT.',
    '#',
    '# ClaudeGuardIL proposed this from your schema and your routes. IT IS A DRAFT: the tool can see',
    '# that `orders` has a `user_id` column, but only you know whether one user may read another',
    '# user\'s order. Correct this file and commit it — every business-logic conclusion in the report',
    '# rests on it being right.',
    '#',
    '# Delete the resources you do not care about. Fill in the TODOs to unlock the checks that need',
    '# them; a rule that is not stated is reported as undeterminable, never as passing.',
    '',
    `roles: [${(intent.roles || []).map(q).join(', ')}]`,
    `default_role: ${q(intent.default_role || 'user')}`,
    '',
  ]
  if (!columnsKnown) {
    out.push(
      '# NOTE: no migrations were found in this repo, so the engine could not read your columns and',
      '# could not propose an ownership column for anything below. Fill in `owned_by` by hand.',
      '')
  }
  out.push('resources:')
  const names = Object.keys(intent.resources || {})
  if (!names.length) out.push('  {}')
  for (const name of names) {
    const r = intent.resources[name] || {}
    out.push(`  ${q(name)}:`)
    out.push(`    owned_by: ${r.owned_by ? q(r.owned_by) : 'null'}${r.owned_by ? '' : '   # TODO: which column says a row belongs to a user?'}`)
    out.push(`    tenant: ${r.tenant ? q(r.tenant) : 'null'}`)
    if (r.state_column) {
      out.push(`    state_column: ${q(r.state_column)}`)
      out.push('    # TODO: states: [draft, published]           # the legal values')
      out.push('    # TODO: transitions:                          # and who may move between them')
      out.push('    #   draft->published: [admin]')
    }
    out.push('    # TODO: mutable_fields: [title, quantity]      # fields a USER may set (price is not one)')
    out.push('    # TODO: read_only_for: [user]                  # roles that may read but never write')
  }
  out.push(
    '',
    'rules:',
    '  # Free-form invariants. The tool cannot check prose, so each line here is reported as a',
    '  # reviewer task rather than silently ignored.',
    '  # - "A coupon code may be applied at most once per order."',
    '',
    'system_routes:',
    '  # Routes driven by the SYSTEM rather than by a user — payment webhooks, cron handlers. Listing',
    '  # them here stops a legitimate `status = paid` write from being reported as a user-driven one.',
    '  # - "pages/api/webhooks/**"',
    '')
  return out.join('\n')
}

// ---------------------------------------------------------------------------
// The audit
// ---------------------------------------------------------------------------

const tableByName = (model, name) => (model.database?.tables || []).find(t => t.name === name) || null

/**
 * Is RLS PROVEN to scope this table's rows to their owner?
 *
 * Half of the false-positive guard the spec calls out by name. With an anon, user-scoped Supabase
 * client and RLS on the owning column, object-level authorization is ALREADY ENFORCED by the
 * database — flagging it would fire on the officially recommended Supabase pattern, which is the
 * worst possible false positive for this audience (FP-03).
 *
 * Only a migration proves it. A table whose RLS state came from generated types says nothing, and a
 * permissive `using (true)` policy un-proves it — that case is already a confirmed P0 from
 * gradeTables, so it needs no second finding here.
 */
export function rlsProvesOwnerScope(table) {
  if (!table || table.rlsCertainty !== 'from-migrations' || !table.rlsEnabled) return false
  const policies = table.policies || []
  // RLS on with zero policies is deny-all: nothing is reachable, so nothing leaks (FP-07).
  if (!policies.length) return true
  if (policies.some(p => p.permissive)) return false
  return policies.some(p => p.scopedToUid)
}

/** The other half of the guard: does this route talk to the database AS THE USER? */
export function routeIsRlsControlled(route) {
  return !!route.reachesAnonScopedClient && !route.usesServiceRole && !route.reachesServiceRoleClient
}

/** `pages/api/webhooks/**` → a regex over the route's file path and URL path. */
function globToRegex(pattern) {
  const src = String(pattern)
    .split('**').map(seg => seg.split('*').map(s => s.replace(/[.+^${}()|[\]\\?]/g, '\\$&')).join('[^/]*'))
    .join('.*')
  return new RegExp(`^${src}$`)
}

function isSystemRoute(route, intent) {
  const pats = intent.system_routes || []
  if (!pats.length) return false
  const candidates = [route.file, route.urlPath].filter(Boolean)
  return pats.some(p => {
    let re
    try { re = globToRegex(p) } catch { return false }
    return candidates.some(c => re.test(c))
  })
}

const routeSubjectOf = r => (r.routeKey ? `route:${r.file}:${r.routeKey}` : `route:${r.file}`)
const routeLabelOf = r => r.routeKey || r.urlPath || r.file
const atOf = r => [{ file: r.file, line: r.line ?? null, snippet: null }]

/** Routes whose facts link them to this resource. `null` tablesTouched means "not modelled". */
const routesTouching = (model, resource) =>
  (model.routes || []).filter(r => Array.isArray(r.tablesTouched) && r.tablesTouched.includes(resource))

/**
 * Run the business-logic audit.
 *
 * @param {object} model                 output of project_model.mjs
 * @param {object} [opts]
 * @param {object|null} [opts.intent]    a VALIDATED intent, or null to run against a proposal
 * @param {string|null} [opts.intentError] the parse error, when an intent file existed and was broken
 * @returns {object} observations (for the grader to grade) plus the coverage the report must print
 */
export function auditBusinessLogic(model, opts = {}) {
  const intentError = opts.intentError || null
  const confirmed = !!opts.intent && !intentError
  const columnsKnown = (model.database?.tables || []).some(t => t.columnsKnownFrom === 'migrations')
  const proposal = proposeIntent(model)
  const intent = confirmed ? opts.intent : proposal
  const status = intentError ? 'error' : confirmed ? 'confirmed' : 'assumed'
  const defaultRole = intent.default_role || 'user'

  const observations = []
  const scope = []
  const extra = []
  const assumptions = []
  const resources = []

  // ---- the honest header ---------------------------------------------------
  if (!confirmed) {
    assumptions.push(
      intentError
        ? `claudeguard.intent.yml could not be read (${intentError}), so NOTHING in it was used — every ownership model below was assumed from column names.`
        : 'No claudeguard.intent.yml was provided, so every ownership model below was ASSUMED from column names rather than confirmed by the author.')
    if (!columnsKnown) {
      assumptions.push('No migrations were found, so the engine could not read any table\'s columns — even the assumed ownership model is empty.')
    }
    observations.push({
      tier: 'business-logic',
      kind: 'bl-intent-unconfirmed',
      subject: 'business-logic:intent',
      class: null,
      resource: null,
      at: [],
      detail: intentError
        ? `An intent file exists but could not be read: ${intentError}. It was ignored entirely rather than half-applied, and the audit below ran against a model this tool guessed from column names.`
        : 'No claudeguard.intent.yml was provided, so the audit below ran against an ownership model this tool guessed from column names. A guess that happens to match the code produces a clean business-logic section that means nothing.',
      proposal: renderIntentYaml(proposal, { columnsKnown }),
    })
  }

  // ---- the three classes no facts support ---------------------------------
  const globalRows = DECLARED_CLASSES.map(c => ({
    class: c.id,
    subject: `bl:*:${c.id}`,
    disposition: 'undeterminable',
    note: c.reason,
  }))

  // ---- route → resource link ----------------------------------------------
  //
  // `tables[].usedIn` is a FILE-level reverse mapping, which is exact for a Next.js route (the file
  // IS the route) and meaningless for an Express file that declares twelve handlers. Rather than
  // attribute a `.from('orders')` to a handler by proximity, the unmodelled case is declared.
  for (const r of model.routes || []) {
    const subject = `bl-scope:${routeSubjectOf(r)}`
    if (r.businessFacts !== 'file-scoped') {
      scope.push({
        subject, disposition: 'undeterminable',
        note: `${r.kind} routes are declared as calls and many share one file, so this pass cannot attribute a table reference to this specific handler — open the handler and note which resource it reads or writes`,
      })
    } else if (!r.tablesTouched.length) {
      scope.push({
        subject, disposition: 'undeterminable',
        note: 'no literal table reference in this route file, so the resource it operates on could not be determined — it may use an ORM, a shared helper, or a table name built at runtime',
      })
    } else {
      scope.push({
        subject, disposition: 'pass',
        note: `linked to ${r.tablesTouched.join(', ')} by a literal table reference in the route file`,
      })
    }
  }

  // ---- the intent's own free-form rules ------------------------------------
  //
  // Grade-or-declare applied to the intent: a rule the user wrote down and the tool never mentioned
  // again reads, to the user, as a rule that was checked.
  ;(intent.rules || []).forEach((rule, i) => {
    extra.push({
      subject: `bl:free-form-rule:${i + 1}`,
      disposition: 'undeterminable',
      note: `"${rule}" — stated as prose in claudeguard.intent.yml. No rule can check a sentence; a reviewer must confirm this one by hand.`,
    })
  })

  // ---- resources named in the intent that the engine never saw -------------
  for (const name of Object.keys(intent.resources || {})) {
    if (tableByName(model, name)) continue
    extra.push({
      subject: `bl:intent-resource:${name}`,
      disposition: 'undeterminable',
      note: `the intent states rules for "${name}", but the engine found no such table and no code that queries it — either the name is wrong, or the table is reached in a way this pass cannot follow`,
    })
  }
  // ---- and the reverse: tables the intent says nothing about ---------------
  for (const t of (model.database?.tables || [])) {
    if (intent.resources?.[t.name]) continue
    extra.push({
      subject: `bl:no-intent:${t.name}`,
      disposition: 'undeterminable',
      note: `no intent was stated for table "${t.name}", so none of the ten business-logic classes could be checked against it — add it to claudeguard.intent.yml`,
    })
  }

  // ---- the taxonomy, per resource -----------------------------------------
  for (const [name, spec] of Object.entries(intent.resources || {})) {
    const table = tableByName(model, name)
    if (!table) continue
    const routes = routesTouching(model, name)
    const columns = (table.columns || []).map(c => c.name)
    const ctx = { model, intent, name, spec, table, routes, columns, defaultRole, confirmed }

    const classes = []
    for (const cls of RESOURCE_CLASSES) classes.push({ class: cls, ...CHECKS[cls](ctx) })

    for (const c of classes) {
      for (const o of c.observations || []) {
        observations.push({ tier: 'business-logic', kind: `bl-${c.class}`, resource: name, class: c.class, ...o })
      }
    }
    resources.push({
      resource: name,
      rulesTotal: TAXONOMY.length,
      // A rule is CHECKED when it reached a verdict — pass or fail. `undeterminable` is the honest
      // disposition for "the facts to answer this do not exist", and counting it as checked would
      // turn the coverage number into the very reassurance it exists to withhold.
      rulesChecked: classes.filter(c => c.disposition === 'pass' || c.disposition === 'fail').length,
      ownedBy: spec.owned_by ?? null,
      tenant: spec.tenant ?? null,
      assumed: !confirmed,
      classes: classes.map(c => ({ class: c.class, disposition: c.disposition, note: c.note })),
    })
  }

  if (confirmed) {
    assumptions.push('The ownership model came from claudeguard.intent.yml, which the tool trusts as written. If the file is wrong, every conclusion below is wrong in the same direction.')
  }
  if ((model.routes || []).some(r => r.businessFacts !== 'file-scoped')) {
    assumptions.push('Routes declared as framework calls (Express / Fastify / Hono / Koa / Nest) were not linked to a resource — see the `businessLogicScope` coverage rows.')
  }

  return {
    status,
    error: intentError,
    intent,
    proposedYaml: confirmed ? null : renderIntentYaml(proposal, { columnsKnown }),
    columnsKnown,
    observations,
    global: globalRows,
    resources,
    scope,
    extra,
    assumptions,
  }
}

// ---------------------------------------------------------------------------
// The seven checks
//
// Each returns { disposition, note, observations }. A check may only:
//   pass            — a STRUCTURAL reason this resource is not exposed to the class (LAW 1: never
//                     because a token appeared).
//   fail            — with one observation per resource, listing every offending route in `at`. One
//                     loud row beats N quiet ones, and it keeps the ledger arithmetic exact.
//   undeterminable  — the facts to answer it do not exist here, WITH the reason and an instruction.
//   allowlisted     — another rule already owns this subject, or the intent says it does not apply.
// ---------------------------------------------------------------------------

/** Shared: split a resource's routes into those the database already protects and those it does not. */
function partitionByRlsGuard(routes, table) {
  const guarded = [], unproven = [], unguarded = []
  const rlsOk = rlsProvesOwnerScope(table)
  for (const r of routes) {
    if (!routeIsRlsControlled(r)) unguarded.push(r)
    else if (rlsOk) guarded.push(r)
    else unproven.push(r)
  }
  return { guarded, unproven, unguarded }
}

const CHECKS = {
  // ---- 1. Object-level authorization (IDOR) -------------------------------
  'object-level-authz'({ spec, table, routes, name }) {
    if (!spec.owned_by) {
      return {
        disposition: 'undeterminable',
        note: `the intent states no \`owned_by\` column for "${name}", so there is nothing to check a row lookup against — set owned_by in claudeguard.intent.yml, or set it to null deliberately if rows are not user-owned`,
        observations: [],
      }
    }
    const col = spec.owned_by
    const idRoutes = routes.filter(r => r.readsIdParam)
    if (!idRoutes.length) {
      return {
        disposition: routes.length ? 'pass' : 'undeterminable',
        note: routes.length
          ? `no route that touches "${name}" reads an id from the request, so there is no row to reach by guessing one`
          : `no route was linked to "${name}", so no request path to its rows could be examined`,
        observations: [],
      }
    }
    const { guarded, unproven, unguarded } = partitionByRlsGuard(idRoutes, table)

    // THE FALSE-POSITIVE GUARD, stated in code. An anon user-scoped client plus RLS on the owning
    // column IS the enforcement — this is the recommended Supabase pattern, not a bug.
    if (guarded.length === idRoutes.length) {
      return {
        disposition: 'pass',
        note: `every route that reads an id for "${name}" queries through an anon, user-scoped Supabase client, and RLS on ${table.name} is proven on with a uid-scoped policy — the database enforces this, so application code does not need a second check`,
        observations: [],
      }
    }

    // A route that already qualifies for CG-WEB-004 is graded there. Reporting the same defect twice
    // under two ids is the volume failure that makes people stop reading the report.
    const owned = unguarded.filter(r => !(r.eqColumns || []).includes(col))
    const deferred = owned.filter(r => (r.usesServiceRole || r.reachesServiceRoleClient) && !r.ownershipFilter)
    const offenders = owned.filter(r => !deferred.includes(r))

    if (offenders.length) {
      return {
        disposition: 'fail',
        note: `${offenders.length} route(s) read a "${name}" row by id without comparing ${col}`,
        observations: [{
          subject: `bl:${name}:object-level-authz`,
          at: offenders.flatMap(atOf),
          detail: `The intent says a "${name}" row belongs to the user named by \`${col}\`. ${offenders.map(routeLabelOf).join(', ')} read an id from the request and query ${name}, but never compare \`${col}\` — and the query does not run as the user, so RLS is not enforcing it either.`,
          columns: [col],
          routes: offenders.map(routeSubjectOf),
        }],
      }
    }
    if (deferred.length) {
      return {
        disposition: 'allowlisted',
        note: `already graded as CG-WEB-004 for ${deferred.map(routeLabelOf).join(', ')} — a service-role route that reads an id with no ownership comparison. One defect, one finding.`,
        observations: [],
      }
    }
    if (unproven.length) {
      return {
        disposition: 'undeterminable',
        note: `${unproven.map(routeLabelOf).join(', ')} query "${name}" as the user, so RLS would be the correct control — but no migration proves RLS is on for this table, so whether it is enforced cannot be established from the repo. Run the verifyQuery this report prints.`,
        observations: [],
      }
    }
    // LAW 1. The remaining routes COMPARE `owned_by` — but a comparison token in the file does not
    // prove the comparison gates the query: it may compare against a body value the caller chose,
    // or sit on a different query than the id lookup. A checkmark here would be the exact false
    // pass the law forbids, so this is reviewer work, not a pass.
    return {
      disposition: 'undeterminable',
      note: `every route that reads a "${name}" row by id also compares \`${col}\`, but whether that comparison actually gates the lookup (and compares against the SESSION user, not a request value) is not verified — open each route and check what \`${col}\` is compared to`,
      observations: [],
    }
  },

  // ---- 2. Ownership checked against the WRONG column ----------------------
  'wrong-owner-column'({ spec, name, routes, columns }) {
    if (!spec.owned_by) {
      return { disposition: 'undeterminable', note: `no \`owned_by\` column is stated for "${name}", so there is no right column to compare against`, observations: [] }
    }
    const col = spec.owned_by
    // Only a filter on ANOTHER ownership-shaped column is the tell. A filter on `id` or `status` is
    // not a mis-aimed ownership check; it is a different filter entirely.
    const otherOwnerish = new Set([...OWNERSHIP_COLUMN_HINTS, ...TENANT_COLUMN_HINTS]
      .filter(c => c !== col && (!columns.length || columns.includes(c))))
    if (spec.tenant) otherOwnerish.add(spec.tenant)

    const offenders = []
    for (const r of routes) {
      const eq = r.eqColumns || []
      if (eq.includes(col)) continue
      const wrong = eq.filter(c => otherOwnerish.has(c))
      if (wrong.length) offenders.push({ route: r, wrong })
    }
    if (!offenders.length) {
      return {
        disposition: routes.length ? 'pass' : 'undeterminable',
        note: routes.length
          ? `no route filters "${name}" by an ownership-shaped column other than \`${col}\``
          : `no route was linked to "${name}"`,
        observations: [],
      }
    }
    return {
      disposition: 'fail',
      note: `${offenders.length} route(s) scope "${name}" by a column the intent does not name as its owner`,
      observations: [{
        subject: `bl:${name}:wrong-owner-column`,
        at: offenders.flatMap(o => atOf(o.route)),
        detail: `The intent says a "${name}" row belongs to \`${col}\`, but ${offenders.map(o => `${routeLabelOf(o.route)} filters by ${o.wrong.join(', ')}`).join('; ')}. A filter on the wrong column looks like an ownership check in review and lets every user in the same group read every row.`,
        columns: [col, ...offenders.flatMap(o => o.wrong)],
        routes: offenders.map(o => routeSubjectOf(o.route)),
      }],
    }
  },

  // ---- 3. Function-level authorization ------------------------------------
  'function-level-authz'({ spec, name, routes, intent, defaultRole }) {
    const readOnlyFor = spec.read_only_for
    if (!Array.isArray(readOnlyFor) || !readOnlyFor.length) {
      return {
        disposition: 'undeterminable',
        note: `the intent states no role restriction for "${name}". If any operation on it is admin-only or system-only, add \`read_only_for: [user]\` — this pass has no facts about ROLES, so a restriction that is not written down cannot be checked`,
        observations: [],
      }
    }
    if (!readOnlyFor.includes(defaultRole)) {
      return { disposition: 'pass', note: `the intent restricts "${name}" writes for ${readOnlyFor.join(', ')}, which does not include the default role (${defaultRole})`, observations: [] }
    }
    const offenders = routes.filter(r => r.mutating && !isSystemRoute(r, intent))
    if (!offenders.length) {
      return {
        disposition: routes.length ? 'pass' : 'undeterminable',
        note: routes.length
          ? `no user-reachable route writes "${name}"`
          : `no route was linked to "${name}"`,
        observations: [],
      }
    }
    return {
      disposition: 'fail',
      note: `${offenders.length} mutating route(s) touch "${name}", which the intent says ${readOnlyFor.join(', ')} may only read`,
      observations: [{
        subject: `bl:${name}:function-level-authz`,
        at: offenders.flatMap(atOf),
        detail: `The intent says a ${readOnlyFor.join('/')} may READ "${name}" and never write it, but ${offenders.map(routeLabelOf).join(', ')} write it and are not listed under \`system_routes\`. Any caller who reaches these endpoints performs an operation the intent reserves for the system.`,
        routes: offenders.map(routeSubjectOf),
      }],
    }
  },

  // ---- 4. State-transition authorization ----------------------------------
  'state-transition-authz'({ spec, name, routes, intent, defaultRole, columns }) {
    const stateColumn = spec.state_column
      || STATE_COLUMN_HINTS.find(h => columns.includes(h))
      || null
    const transitions = spec.transitions
    if (!stateColumn || !transitions || !Object.keys(transitions).length) {
      return {
        disposition: 'undeterminable',
        note: !stateColumn
          ? `no state column was stated for "${name}" and none was found in its schema, so no workflow could be checked — set \`state_column\` if this resource moves through statuses`
          : `"${name}" has a state column (\`${stateColumn}\`) but the intent declares no \`transitions\`, so who may move it between states is unstated and unverifiable — declare them to unlock this check`,
        observations: [],
      }
    }
    const offenders = []
    for (const r of routes) {
      if (isSystemRoute(r, intent)) continue
      const writes = (r.literalAssignments || []).filter(a => a.key === stateColumn.toLowerCase())
      for (const w of writes) {
        // Every declared transition that ENDS at the value this route writes.
        const matching = Object.entries(transitions).filter(([t]) => {
          const to = t.split('->')[1]
          return to === w.value || to === 'any' || to === '*'
        })
        if (!matching.length) continue
        const actors = new Set(matching.flatMap(([, a]) => a))
        if (actors.has(defaultRole) || actors.has('any') || actors.has('*')) continue
        offenders.push({ route: r, value: w.value, actors: [...actors], transitions: matching.map(([t]) => t) })
      }
    }
    if (!offenders.length) {
      return {
        disposition: routes.length ? 'pass' : 'undeterminable',
        note: routes.length
          ? `no route linked to "${name}" writes a \`${stateColumn}\` value the intent reserves for another actor`
          : `no route was linked to "${name}"`,
        observations: [],
      }
    }
    return {
      disposition: 'fail',
      note: `${offenders.length} route(s) drive a "${name}" transition the intent reserves for ${[...new Set(offenders.flatMap(o => o.actors))].join(', ')}`,
      observations: [{
        subject: `bl:${name}:state-transition-authz`,
        at: offenders.flatMap(o => atOf(o.route)),
        detail: offenders.map(o =>
          `${routeLabelOf(o.route)} writes \`${stateColumn} = '${o.value}'\`, which the intent (${o.transitions.join(', ')}) reserves for ${o.actors.join(', ')} — not for ${defaultRole}`).join('. ') + '.',
        routes: offenders.map(o => routeSubjectOf(o.route)),
      }],
    }
  },

  // ---- 5. Tenant isolation ------------------------------------------------
  'tenant-isolation'({ spec, name, table, routes }) {
    if (!spec.tenant) {
      return { disposition: 'allowlisted', note: `the intent states "${name}" is not a multi-tenant resource, so there is no tenant column to isolate on`, observations: [] }
    }
    const col = spec.tenant
    if (!routes.length) {
      return { disposition: 'undeterminable', note: `no route was linked to "${name}", so its tenant scoping could not be examined`, observations: [] }
    }
    const { guarded, unproven, unguarded } = partitionByRlsGuard(routes, table)
    if (guarded.length === routes.length) {
      return { disposition: 'pass', note: `every route that touches "${name}" queries through an anon, user-scoped client and RLS on ${table.name} is proven on with a uid-scoped policy`, observations: [] }
    }
    const offenders = unguarded.filter(r => !(r.eqColumns || []).includes(col))
    if (offenders.length) {
      return {
        disposition: 'fail',
        note: `${offenders.length} route(s) query "${name}" without filtering \`${col}\``,
        observations: [{
          subject: `bl:${name}:tenant-isolation`,
          at: offenders.flatMap(atOf),
          detail: `The intent says "${name}" rows belong to the tenant named by \`${col}\`, but ${offenders.map(routeLabelOf).join(', ')} query the table without filtering it, through a client RLS does not scope. One customer's account reads another customer's rows.`,
          columns: [col],
          routes: offenders.map(routeSubjectOf),
        }],
      }
    }
    if (unproven.length) {
      return { disposition: 'undeterminable', note: `${unproven.map(routeLabelOf).join(', ')} query "${name}" as the user, but no migration proves RLS is on for this table — run the verifyQuery to settle it`, observations: [] }
    }
    // LAW 1: a `.eq('org_id', …)` token does not prove the filter compares against the CALLER's
    // tenant rather than one taken from the request. Reviewer work, not a pass.
    return { disposition: 'undeterminable', note: `every route that touches "${name}" filters \`${col}\`, but whether the value compared is the caller's own tenant (and not one supplied in the request) is not verified`, observations: [] }
  },

  // ---- 7. Value / quantity tampering --------------------------------------
  'value-tampering'({ spec, name, routes, columns }) {
    const mutable = spec.mutable_fields
    if (!Array.isArray(mutable)) {
      return {
        disposition: 'undeterminable',
        note: `the intent does not list \`mutable_fields\` for "${name}", so which fields a user may set is unstated — without it, a \`price\` taken from the request body is indistinguishable from a \`title\` taken from the request body`,
        observations: [],
      }
    }
    if (!columns.length) {
      return { disposition: 'undeterminable', note: `no migration establishes the columns of "${name}", so a body field cannot be matched against a real column`, observations: [] }
    }
    const allowed = new Set(mutable.map(f => f.toLowerCase()))
    const offenders = []
    for (const r of routes) {
      if (!r.mutating || !Array.isArray(r.bodyFields)) continue
      const bad = r.bodyFields.filter(f => columns.includes(f) && !allowed.has(f))
      if (bad.length) offenders.push({ route: r, fields: bad })
    }
    if (!offenders.length) {
      return {
        disposition: routes.length ? 'pass' : 'undeterminable',
        note: routes.length
          ? `no route reads a "${name}" column from the request body that the intent does not list as user-settable`
          : `no route was linked to "${name}"`,
        observations: [],
      }
    }
    return {
      disposition: 'fail',
      note: `${offenders.length} route(s) read "${name}" fields from the request body that the intent does not allow a user to set`,
      observations: [{
        subject: `bl:${name}:value-tampering`,
        at: offenders.flatMap(o => atOf(o.route)),
        detail: `The intent says a user may set ${[...allowed].join(', ') || '(nothing)'} on "${name}". ${offenders.map(o => `${routeLabelOf(o.route)} reads ${o.fields.join(', ')} from the request body`).join('; ')}. A value the client supplies is a value the client chooses.`,
        columns: [...new Set(offenders.flatMap(o => o.fields))],
        routes: offenders.map(o => routeSubjectOf(o.route)),
      }],
    }
  },

  // ---- 10. Mass assignment ------------------------------------------------
  'mass-assignment'({ spec, name, routes, columns }) {
    const offenders = routes.filter(r => r.spreadsBodyIntoWrite === true)
    if (!offenders.length) {
      const modelled = routes.filter(r => r.spreadsBodyIntoWrite != null)
      return {
        disposition: modelled.length ? 'pass' : 'undeterminable',
        note: modelled.length
          ? `no route hands a whole request body to a write on "${name}"`
          : `no route with modelled body facts was linked to "${name}"`,
        observations: [],
      }
    }
    const mutable = Array.isArray(spec.mutable_fields) ? spec.mutable_fields.map(f => f.toLowerCase()) : null
    const exposed = mutable ? columns.filter(c => !mutable.includes(c)) : columns
    return {
      disposition: 'fail',
      note: `${offenders.length} route(s) write "${name}" from the whole request body with no field allowlist`,
      observations: [{
        subject: `bl:${name}:mass-assignment`,
        at: offenders.flatMap(atOf),
        detail: `${offenders.map(routeLabelOf).join(', ')} spread the request body straight into a write on "${name}", so the caller decides which columns are set — not the handler.` +
          (exposed.length ? ` Columns reachable this way include ${exposed.slice(0, 8).join(', ')}${exposed.length > 8 ? ', …' : ''}.` : '') +
          (mutable ? ` The intent allows a user to set only ${mutable.join(', ') || '(nothing)'}.` : ' The intent does not list which fields a user may set, so the allowlist to compare against is missing too.'),
        columns: exposed,
        routes: offenders.map(routeSubjectOf),
      }],
    }
  },
}
