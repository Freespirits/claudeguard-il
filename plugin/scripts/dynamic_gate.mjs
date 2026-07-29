#!/usr/bin/env node
// The dynamic-testing gate — the seatbelt around real offensive tooling.
//
// HexStrike and Strix are raw offensive capability with nothing in front of them: no
// authentication, no target allowlist, no rate limit, no sandbox. Their safety model is "run it in
// a VM and supervise". ClaudeGuardIL's job is not to add more attack tools — it is to BE the thing
// they are missing: a deterministic, deny-by-default gate that sits between the model and the
// tools and that the model cannot talk its way past. See core/authorization/dynamic-testing-gate.md.
//
// The design rule that makes this testable, and therefore trustworthy:
//
//   `decide()` is PURE. It takes a config object and a proposed action and returns an
//   allow/deny with reasons. It reads no file, opens no socket, calls no clock and mutates
//   nothing — the clock and the rate-limit history are passed IN.
//
// That is what lets the adversarial suite in test/dynamic_gate.test.mjs enumerate bypasses with
// neither HexStrike nor Strix installed. A gate is worth exactly what its bypass tests prove, and
// a gate you can only exercise by attacking something is a gate nobody exercises.
//
// Two properties are load-bearing and are asserted by tests rather than asserted here:
//
//   DENY WINS. Every check appends to `reasons`; the decision is `allowed: reasons.length === 0`.
//   There is no early `return true` anywhere, so no check can short-circuit a later denial and an
//   explicit allowlist entry can never overrule the blocklist.
//
//   THE MODEL CANNOT ELECT A TIER. The aggressiveness of an action is a property of the TOOL, read
//   from TOOL_TIERS below, never of what the caller claimed. A caller that labels `sqlmap_scan` as
//   `recon` gets `sqlmap_scan`'s real tier and a note saying its claim was discarded.
//
// Usage (plumbing; the decision itself is the exported function):
//   node dynamic_gate.mjs --scope claudeguard.scope.yml --tool nmap_scan --target staging.myapp.com
//   node dynamic_gate.mjs --scope claudeguard.scope.yml --tool nuclei_scan --target x --path /api/pay
import { appendFileSync, existsSync, readFileSync } from 'node:fs'
import { loadScope, hostMatches, normalizeHost, UNMATCHABLE, DEFAULT_BLOCKED, parseArgs } from './_scope.mjs'

// ===========================================================================================
// PURE CORE — BEGIN
//
// Nothing between these markers may read a file, open a socket, read the clock, generate a random
// number, or mutate its arguments. `test/dynamic_gate.test.mjs` reads this file and asserts it,
// because "pure" written in a comment is not a property, it is a wish.
// ===========================================================================================

/** Tiers of aggressiveness, least to most. Each higher tier includes the lower ones. */
export const TIERS = ['recon', 'active', 'exploit']
const TIER_RANK = { recon: 0, active: 1, exploit: 2 }

/**
 * The tool catalog: which tier each tool belongs to.
 *
 * This is the reason a tool must be KNOWN before it can run. An unlisted tool has no tier, so
 * `tier(X) <= authorized` cannot be established for it, so it is denied. That is deliberate and it
 * is the property that survives HexStrike shipping its 151st tool: a new capability nobody has
 * classified arrives switched off, not switched on at whatever tier the caller fancies.
 */
export const TOOL_TIERS = {
  // recon — read-only discovery. No payloads.
  nmap_scan: 'recon',
  gobuster_scan: 'recon',
  dirb_scan: 'recon',
  subfinder_scan: 'recon',
  amass_scan: 'recon',
  httpx_scan: 'recon',
  whois_lookup: 'recon',
  dns_enum: 'recon',
  // active — non-destructive probing. Payloads that do not modify state.
  nuclei_scan: 'active',
  ffuf_scan: 'active',
  nikto_scan: 'active',
  wpscan: 'active',
  zap_scan: 'active',
  xsstrike_scan: 'active',
  // exploit — actual exploitation / PoC generation. May modify state.
  sqlmap_scan: 'exploit',
  hydra: 'exploit',
  metasploit: 'exploit',
  msfconsole: 'exploit',
  commix_scan: 'exploit',
  strix_agent: 'exploit',
}

/** Relationships that can appear in `authorization.relationship`. */
const RELATIONSHIPS = ['owner', 'written-authorization', 'bug-bounty-program']

/**
 * Only these relationships can authorize the `exploit` tier. The spec's tier table reads
 * "Written authorization with a reference (contract id / bug-bounty program)" — so `owner` alone,
 * which needs no reference at all, cannot reach it. Exploitation against production is the one
 * tier where "I own it" is not a document anybody can produce afterwards.
 */
const EXPLOIT_RELATIONSHIPS = ['written-authorization', 'bug-bounty-program']

/** Requests per minute. The file may lower this; it may never raise it above the cap. */
const DEFAULT_RATE = 60
const HARD_RATE_CAP = 60
const RATE_WINDOW_MS = 60_000

/**
 * Allowlist entries that mean "everything". An allowlist of everything is not an allowlist, and
 * accepting one would turn the deny-by-default property off with a single character. Rejected at
 * config load, so the whole config is refused rather than one entry being dropped quietly.
 */
const WILDCARD_ALLOWLIST_ENTRIES = ['*', '*.*', '**', '0.0.0.0/0', '::/0', 'any', 'all']

/** A proposed target must be a bare host, optionally with a port. Nothing else is a host. */
const TARGET_RE = /^[A-Za-z0-9._\-:[\]]{1,253}$/

/** A tool name is an identifier. Anything else is a payload wearing a tool's clothes. */
const TOOL_RE = /^[A-Za-z0-9_-]{1,64}$/

/** Stable deny codes. Tests assert on these; the human sentences beside them may be reworded. */
export const DENY = {
  KILL_SWITCH: 'kill-switch',
  CONFIG_MISSING: 'config-missing',
  CONFIG_MALFORMED: 'config-malformed',
  NOT_ENABLED: 'not-enabled',
  ATTESTATION_INCOMPLETE: 'attestation-incomplete',
  INVALID_TARGET: 'invalid-target',
  INVALID_TOOL: 'invalid-tool',
  UNKNOWN_TOOL: 'unknown-tool',
  TOOL_NOT_ALLOWED: 'tool-not-allowed',
  TOOL_DENIED: 'tool-denied',
  TIER_NOT_AUTHORIZED: 'tier-not-authorized',
  TARGET_NOT_IN_ALLOWLIST: 'target-not-in-allowlist',
  DISCOVERED_HOST: 'discovered-host-is-a-finding-not-a-target',
  TARGET_BLOCKED: 'target-blocked',
  INVALID_PATH: 'invalid-path',
  PATH_EXCLUDED: 'path-excluded',
  RATE_LIMIT: 'rate-limit-exceeded',
  DESTRUCTIVE_NOT_ENABLED: 'destructive-not-enabled',
  CONFIRMATION_REQUIRED: 'confirmation-required',
  NO_CLOCK: 'no-clock',
  INTERNAL_ERROR: 'internal-error',
}

const isPlainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v)
const isNonEmptyString = v => typeof v === 'string' && v.trim() !== ''

/**
 * Normalise and validate the `dynamic_testing` block. Every problem is a DENIAL, never a default:
 * a missing key, a wrong type, a null allowlist and an allowlist containing `"*"` all end here
 * with `ok: false`, because the failure mode this whole file exists to prevent is a config that
 * could not be read being treated as a config that permitted something.
 *
 * @param {unknown} raw  a parsed scope file, or the `dynamic_testing` block on its own
 * @returns {{ok: boolean, code: string|null, problems: string[], config: object|null}}
 */
export function normalizeConfig(raw) {
  const problems = []
  const deny = (code, ...msgs) => ({ ok: false, code, problems: msgs.length ? msgs : problems, config: null })

  if (!isPlainObject(raw)) {
    return deny(DENY.CONFIG_MISSING, 'no scope config was supplied — copy SCOPE.example.yml to claudeguard.scope.yml and fill in the dynamic_testing block')
  }
  const dt = isPlainObject(raw.dynamic_testing) ? raw.dynamic_testing
    : ('enabled' in raw && !('dynamic_testing' in raw)) ? raw
      : null
  if (!isPlainObject(dt)) {
    return deny(DENY.CONFIG_MISSING, 'claudeguard.scope.yml has no dynamic_testing block — dynamic testing is off until one exists')
  }

  // `enabled` is checked with === true on purpose. The string "true", the number 1 and the empty
  // object are all truthy, and every one of them is a config the author did not write.
  if (dt.enabled !== true) {
    return { ok: false, code: DENY.NOT_ENABLED, config: null,
      problems: ['set dynamic_testing.enabled: true in claudeguard.scope.yml (it is off by default, and off means nothing is testable)'] }
  }

  // ---- tier ------------------------------------------------------------------------------
  if (!TIERS.includes(dt.tier)) {
    problems.push(`dynamic_testing.tier must be one of ${TIERS.join(' | ')} — an absent or unrecognised tier grants nothing`)
  }

  // ---- scope -----------------------------------------------------------------------------
  const scope = isPlainObject(dt.scope) ? dt.scope : null
  if (!scope) problems.push('dynamic_testing.scope must be a block containing an allowlist')
  const allowlist = scope ? scope.allowlist : null
  if (!Array.isArray(allowlist) || allowlist.length === 0) {
    problems.push('dynamic_testing.scope.allowlist must be a non-empty list of hosts — deny-by-default means an absent or empty allowlist permits nothing')
  } else {
    for (const entry of allowlist) {
      if (!isNonEmptyString(entry)) {
        problems.push(`dynamic_testing.scope.allowlist contains a non-string or empty entry (${JSON.stringify(entry)})`)
      } else if (WILDCARD_ALLOWLIST_ENTRIES.includes(entry.trim().toLowerCase())) {
        problems.push(`dynamic_testing.scope.allowlist contains "${entry}", which means every host — an allowlist of everything is not an allowlist`)
      }
    }
  }
  const blocklist = scope ? (scope.blocklist ?? []) : []
  if (!Array.isArray(blocklist) || blocklist.some(e => !isNonEmptyString(e))) {
    problems.push('dynamic_testing.scope.blocklist must be a list of host patterns')
  }
  const excludePaths = scope ? (scope.exclude_paths ?? []) : []
  if (!Array.isArray(excludePaths) || excludePaths.some(e => !isNonEmptyString(e))) {
    problems.push('dynamic_testing.scope.exclude_paths must be a list of path patterns')
  } else {
    for (const p of excludePaths) {
      if (normalizePath(p) === null) {
        problems.push(`dynamic_testing.scope.exclude_paths entry ${JSON.stringify(p)} is not a readable path — an exclusion nobody can parse is not an exclusion`)
      }
    }
  }

  // ---- execution -------------------------------------------------------------------------
  const execution = isPlainObject(dt.execution) ? dt.execution : {}
  const dryRun = execution.dry_run !== false                      // plan-only until explicitly flipped
  const destructive = execution.destructive === true              // state-changing payloads: off unless named
  const requireConfirmation = execution.require_confirmation !== false
  let rate = DEFAULT_RATE
  if (execution.max_requests_per_minute !== undefined && execution.max_requests_per_minute !== null) {
    const n = execution.max_requests_per_minute
    if (typeof n !== 'number' || !Number.isFinite(n) || !Number.isInteger(n) || n < 1) {
      problems.push('dynamic_testing.execution.max_requests_per_minute must be a whole number of at least 1')
    } else {
      rate = Math.min(n, HARD_RATE_CAP)   // the file may lower the cap; it may never raise it
    }
  }

  // ---- tools -----------------------------------------------------------------------------
  // Flattened across providers: the action names a tool, not a provider, and a tool denied under
  // one provider must not be reachable by asking for it under another.
  const toolAllow = new Set()
  const toolDeny = new Set()
  const tools = isPlainObject(dt.tools) ? dt.tools : {}
  for (const [provider, cfg] of Object.entries(tools)) {
    if (!isPlainObject(cfg)) continue
    for (const [key, bucket] of [['allow', toolAllow], ['deny', toolDeny]]) {
      const list = cfg[key]
      if (list === undefined || list === null) continue
      if (!Array.isArray(list) || list.some(e => !isNonEmptyString(e))) {
        problems.push(`dynamic_testing.tools.${provider}.${key} must be a list of tool names`)
        continue
      }
      for (const t of list) bucket.add(t.trim())
    }
  }

  // ---- authorization ---------------------------------------------------------------------
  const auth = isPlainObject(dt.authorization) ? dt.authorization : {}
  const attestation = []
  if (!isNonEmptyString(auth.attested_by)) {
    attestation.push('dynamic_testing.authorization.attested_by must name a person who can be reached')
  }
  if (!RELATIONSHIPS.includes(auth.relationship)) {
    attestation.push(`dynamic_testing.authorization.relationship must be one of ${RELATIONSHIPS.join(' | ')}`)
  }
  if (auth.relationship !== 'owner' && !isNonEmptyString(auth.authorization_ref)) {
    attestation.push('dynamic_testing.authorization.authorization_ref is required unless relationship is "owner" — name the contract, ticket or bug-bounty program')
  }
  if (!(typeof auth.attested_at === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(auth.attested_at))) {
    attestation.push('dynamic_testing.authorization.attested_at must be a YYYY-MM-DD date')
  }

  if (problems.length) return deny(DENY.CONFIG_MALFORMED)

  return {
    ok: true,
    code: null,
    problems: [],
    config: {
      enabled: true,
      tier: dt.tier,
      allowlist: allowlist.map(e => e.trim()),
      // DEFAULT_BLOCKED is folded in HERE so it cannot be forgotten at a call site, and the
      // top-level `never_touch` of the Tier-1/Tier-2 gate travels with it so the two gates can
      // never disagree about a host one of them refuses.
      blocklist: [
        ...blocklist.map(e => e.trim()),
        ...(Array.isArray(raw.never_touch) ? raw.never_touch.filter(isNonEmptyString) : []),
        ...DEFAULT_BLOCKED,
      ],
      excludePaths: excludePaths.map(p => String(p)),
      dryRun, destructive, requireConfirmation,
      maxRequestsPerMinute: rate,
      toolAllow: [...toolAllow],
      toolDeny: [...toolDeny],
      authorization: {
        attested_by: auth.attested_by,
        relationship: auth.relationship,
        authorization_ref: auth.authorization_ref ?? null,
        attested_at: auth.attested_at,
      },
      attestationProblems: attestation,
    },
  }
}

/**
 * Reduce a request path to one comparable spelling, or null when it is not a path we can vouch for.
 *
 * Path exclusions die on encoding, not on logic: `/admin/x/../../api/payments`, `/API/Payments`,
 * `/api//payments`, `/api/payments/` and `%2fapi%2fpayments` all reach the same handler and none of
 * them equals `/api/payments`. Anything still ambiguous after one decode — a second layer of
 * percent-encoding, a control character, a backslash — returns null and is denied, because an
 * exclusion list is only as good as the worst spelling it fails to recognise.
 */
export function normalizePath(input) {
  if (input === undefined || input === null || input === '') return '/'
  if (typeof input !== 'string') return null
  let s = input
  if (/[\u0000-\u001f\u007f\\]/.test(s)) return null
  s = s.split('?')[0].split('#')[0]
  if (!s.startsWith('/')) s = '/' + s
  let decoded
  try { decoded = decodeURIComponent(s) } catch { return null }
  // A path that still contains an escape after one decode was encoded twice. That is not a path a
  // user typed, it is an attempt to spell `/admin/x/delete` in a way this function will not.
  if (/%[0-9a-fA-F]{2}/.test(decoded)) return null
  if (/[\u0000-\u001f\u007f\\]/.test(decoded)) return null
  const segments = []
  for (const seg of decoded.split('/')) {
    if (seg === '' || seg === '.') continue
    if (seg === '..') { segments.pop(); continue }
    segments.push(seg)
  }
  return '/' + segments.join('/')
}

/** `*` matches one segment, `**` matches across segments. A pattern also covers its own subtree. */
function globToRegex(pattern) {
  let out = '^'
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]
    if (c === '*') {
      if (pattern[i + 1] === '*') { out += '.*'; i++ }
      else out += '[^/]*'
    } else if ('\\^$.|?+()[]{}'.includes(c)) {
      out += '\\' + c
    } else {
      out += c
    }
  }
  // The subtree: excluding `/api/payments` must also exclude `/api/payments/refund`, or the
  // exclusion protects exactly one URL and nothing under it.
  return new RegExp(out + '(?:/.*)?$')
}

function pathIsExcluded(path, patterns) {
  const p = path.toLowerCase()
  for (const raw of patterns) {
    const pat = normalizePath(raw)
    if (pat === null) return true   // validated at config load; belt and braces if that is bypassed
    if (globToRegex(pat.toLowerCase()).test(p)) return true
  }
  return false
}

/**
 * THE GATE. Pure, deterministic, side-effect-free.
 *
 * @param {unknown} rawConfig  the parsed scope file (or the dynamic_testing block)
 * @param {unknown} action     { tool, target, path?, destructive?, tier?, origin? }
 * @param {unknown} ctx        { now, recent?, confirmation?, killSwitch? }
 * @returns {object} decision — see the fields assembled at the bottom of this function
 */
export function decide(rawConfig, action, ctx = {}) {
  try {
    return decideInner(rawConfig, action, ctx)
  } catch (e) {
    // A gate that throws is a gate whose caller decides what to do next, and callers under
    // pressure decide to continue. There is no input for which this function raises.
    return buildDecision({
      tool: null, target: null, path: null, tier: null, mode: 'deny',
      reasons: [`the gate could not evaluate this request, so it was refused: ${String(e && e.message || e)}`],
      denyCodes: [DENY.INTERNAL_ERROR], notes: [], at: null,
    })
  }
}

function decideInner(rawConfig, action, ctx) {
  const reasons = []
  const denyCodes = []
  const notes = []
  const refuse = (code, reason) => { denyCodes.push(code); reasons.push(reason) }

  const act = isPlainObject(action) ? action : {}
  const context = isPlainObject(ctx) ? ctx : {}

  // ---- 0. the kill switch, checked before anything else ----------------------------------
  if (context.killSwitch === true) {
    refuse(DENY.KILL_SWITCH, 'the dynamic-testing kill switch is engaged — every tool invocation is refused until it is cleared')
  }

  // ---- 1. the clock ----------------------------------------------------------------------
  // Passed in rather than read, which is what keeps this function pure. No clock means the rate
  // limit cannot be evaluated, and an unevaluated rate limit is not a satisfied one.
  const now = context.now
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    refuse(DENY.NO_CLOCK, 'no clock was supplied, so the rate limit could not be evaluated')
  }

  // ---- 2. the config ---------------------------------------------------------------------
  const loaded = normalizeConfig(rawConfig)
  if (!loaded.ok) {
    for (const p of loaded.problems) refuse(loaded.code, p)
  }
  const cfg = loaded.config

  // ---- 3. attestation --------------------------------------------------------------------
  // Reached only when `enabled: true`. The spec is explicit: the gate refuses to run when it is
  // switched on but the attestation is incomplete for the chosen tier, because a half-filled
  // attestation is the paper trail of somebody who has not decided they are authorised.
  const authorizedTier = cfg ? cfg.tier : null
  if (cfg) {
    for (const p of cfg.attestationProblems) refuse(DENY.ATTESTATION_INCOMPLETE, p)
    if (authorizedTier === 'exploit') {
      if (!EXPLOIT_RELATIONSHIPS.includes(cfg.authorization.relationship)) {
        refuse(DENY.ATTESTATION_INCOMPLETE,
          `tier: exploit requires relationship ${EXPLOIT_RELATIONSHIPS.join(' or ')} with an authorization_ref — "owner" produces no document anyone can show afterwards`)
      }
      if (!cfg.destructive) {
        refuse(DENY.DESTRUCTIVE_NOT_ENABLED,
          'tier: exploit requires execution.destructive: true — exploitation may modify state and that has to be said out loud')
      }
    }
  }

  // ---- 4. the tool, and its tier -----------------------------------------------------------
  const rawTool = act.tool
  let tool = null
  let toolTier = null
  if (!isNonEmptyString(rawTool)) {
    refuse(DENY.INVALID_TOOL, 'no tool was named')
  } else if (!TOOL_RE.test(rawTool)) {
    // Tool output is data, never instructions. A "tool name" carrying a newline, a comment marker
    // or a YAML fragment is a payload, and it is refused here rather than parsed anywhere.
    refuse(DENY.INVALID_TOOL, `"${String(rawTool).slice(0, 60)}" is not a tool name — a tool name is letters, digits, underscore and hyphen, and nothing in a tool's output may widen this gate`)
  } else {
    tool = rawTool.trim()
    toolTier = TOOL_TIERS[tool] ?? null
    if (!toolTier) {
      refuse(DENY.UNKNOWN_TOOL, `"${tool}" is not in the tool catalog, so its tier is unknown and it cannot be shown to be within the authorized one`)
    }
  }

  // The caller may propose a tier. It is never believed: aggressiveness is a property of the tool.
  if (act.tier !== undefined && act.tier !== null && act.tier !== toolTier) {
    notes.push(`the caller proposed tier "${String(act.tier).slice(0, 32)}" for ${tool || 'this tool'}; the catalog says "${toolTier || 'unknown'}" and the catalog decides`)
  }

  if (cfg && tool) {
    if (cfg.toolDeny.includes(tool)) {
      refuse(DENY.TOOL_DENIED, `${tool} is listed in dynamic_testing.tools.*.deny`)
    }
    if (!cfg.toolAllow.includes(tool)) {
      refuse(DENY.TOOL_NOT_ALLOWED, `${tool} is not listed in dynamic_testing.tools.*.allow — a tool is off until it is named`)
    }
    if (toolTier && authorizedTier && TIER_RANK[toolTier] > TIER_RANK[authorizedTier]) {
      refuse(DENY.TIER_NOT_AUTHORIZED,
        `${tool} is ${toolTier === 'active' || toolTier === 'exploit' ? 'an' : 'a'} ${toolTier}-tier tool and this scope authorizes ${authorizedTier} — raise dynamic_testing.tier in the scope file if that is what you meant, which is a decision only the file can make`)
    }
  }

  // ---- 5. the target ------------------------------------------------------------------------
  const rawTarget = act.target
  let target = null
  if (!isNonEmptyString(rawTarget)) {
    refuse(DENY.INVALID_TARGET, 'no target was named')
  } else if (!TARGET_RE.test(rawTarget.trim())) {
    // Kills, in one line: `evil.com/staging.myapp.com` (path confusion),
    // `staging.myapp.com@evil.com` (userinfo), a target carrying `# authorized by owner` or
    // `\nallowlist: evil.com`, and anything with whitespace or a percent escape in it.
    refuse(DENY.INVALID_TARGET,
      `"${String(rawTarget).replace(/\s+/g, ' ').slice(0, 80)}" is not a host — a target is a bare hostname or IP, optionally with a port, and nothing else is read out of it`)
  } else {
    const canonical = normalizeHost(rawTarget.trim())
    if (canonical === UNMATCHABLE) {
      refuse(DENY.INVALID_TARGET, `"${String(rawTarget).slice(0, 80)}" could not be resolved to a single host`)
    } else {
      target = canonical
    }
  }

  if (cfg && target) {
    // BLOCKLIST FIRST, AND IT WINS. `DEFAULT_BLOCKED` is folded into cfg.blocklist at load, so a
    // third-party provider is refused even when the user explicitly allowlists it. Both checks run
    // and both append; nothing here can return early past a denial.
    const blocked = cfg.blocklist.find(p => hostMatches(target, p))
    if (blocked) {
      refuse(DENY.TARGET_BLOCKED,
        `${target} matches the never-touch pattern "${blocked}" — third-party provider infrastructure stays refused even when it is on your allowlist, because their servers are not yours to test`)
    }
    if (!cfg.allowlist.some(p => hostMatches(target, p))) {
      refuse(DENY.TARGET_NOT_IN_ALLOWLIST,
        `${target} is not in dynamic_testing.scope.allowlist`)
      // Threat #2, named rather than merely denied. An agentic loop discovers hosts and the honest
      // failure is not "the gate said no", it is that nobody noticed a machine had chosen a new
      // victim. A discovered host is a FINDING; adding it to the allowlist is a human's decision,
      // made in the file, before the run.
      if (act.origin && act.origin !== 'config') {
        refuse(DENY.DISCOVERED_HOST,
          `${target} reached this gate from "${String(act.origin).slice(0, 40)}" rather than from the scope file — a host discovered during a run is a finding to report, never a target to attack. Add it to the allowlist by hand if you are authorized to test it.`)
      }
    }
  }

  // ---- 6. the path --------------------------------------------------------------------------
  const path = normalizePath(act.path)
  if (path === null) {
    refuse(DENY.INVALID_PATH, `the path ${JSON.stringify(String(act.path).slice(0, 80))} could not be reduced to one unambiguous spelling, so it could not be checked against exclude_paths`)
  } else if (cfg && cfg.excludePaths.length && pathIsExcluded(path, cfg.excludePaths)) {
    refuse(DENY.PATH_EXCLUDED,
      `${path} matches dynamic_testing.scope.exclude_paths — an excluded path stays off-limits for an in-scope, in-tier, allowed tool, which is the entire point of listing it`)
  }

  // ---- 7. destructive actions and confirmation ----------------------------------------------
  if (cfg) {
    if (act.destructive === true && !cfg.destructive) {
      refuse(DENY.DESTRUCTIVE_NOT_ENABLED, 'this action is state-changing and execution.destructive is false')
    }
    const needsConfirmation = toolTier === 'exploit' ||
      (cfg.requireConfirmation && toolTier && TIER_RANK[toolTier] > TIER_RANK.recon)
    if (needsConfirmation && context.confirmation !== true) {
      refuse(DENY.CONFIRMATION_REQUIRED,
        `${tool || 'this tool'} is ${toolTier}-tier and needs a human confirmation for this run — the gate does not accept one from the model`)
    }
  }

  // ---- 8. the rate limit --------------------------------------------------------------------
  if (cfg && typeof now === 'number' && Number.isFinite(now)) {
    const recent = Array.isArray(context.recent) ? context.recent : []
    const inWindow = recent.filter(t => typeof t === 'number' && Number.isFinite(t) && t <= now && now - t < RATE_WINDOW_MS).length
    if (inWindow >= cfg.maxRequestsPerMinute) {
      refuse(DENY.RATE_LIMIT,
        `${inWindow} request(s) already went out in the last minute and the cap is ${cfg.maxRequestsPerMinute}`)
    }
  }

  // ---- 9. dry run ---------------------------------------------------------------------------
  const allowed = reasons.length === 0
  const dryRun = cfg ? cfg.dryRun : true
  const mode = !allowed ? 'deny' : dryRun ? 'plan' : 'execute'

  return buildDecision({
    tool, target, path, tier: toolTier, mode, reasons, denyCodes, notes,
    at: typeof now === 'number' && Number.isFinite(now) ? now : null,
    authorizedTier,
    plan: allowed && dryRun
      ? {
        tool, tier: toolTier, target, path, willSend: false,
        note: 'dry_run is true in the scope file, so this is what WOULD be sent. Nothing was sent. Set execution.dry_run: false to run it for real.',
      }
      : null,
  })
}

/** One shape for every decision, so a caller can never read a field that is only sometimes there. */
function buildDecision({ tool, target, path, tier, mode, reasons, denyCodes, notes = [], at, plan = null, authorizedTier = null }) {
  const allowed = mode !== 'deny'
  return {
    allowed,
    mode,                              // 'deny' | 'plan' | 'execute'
    willExecute: mode === 'execute',   // the ONLY field a runner may switch on to send traffic
    tool: tool ?? null,
    target: target ?? null,
    path: path ?? null,
    tier: tier ?? null,
    authorizedTier,
    reasons,
    denyCodes,
    notes,
    plan,
    // Every decision is logged, allowed AND denied. A gate that only records its refusals cannot
    // answer the question anyone actually asks afterwards: what did this thing touch?
    audit: {
      at,
      decision: allowed ? (mode === 'plan' ? 'plan' : 'allow') : 'deny',
      tool: tool ?? null,
      target: target ?? null,
      path: path ?? null,
      tier: tier ?? null,
      reasons: reasons.slice(),
      denyCodes: denyCodes.slice(),
    },
  }
}

// ===========================================================================================
// PURE CORE — END
// ===========================================================================================

/**
 * Rate-limit history. Deliberately outside the pure core: it holds state and reads a clock the
 * caller gives it, and it hands `decide` a plain array so the decision stays a pure function of
 * its arguments.
 */
export class RateWindow {
  constructor() { this.stamps = [] }
  /** Timestamps inside the last minute, oldest first. */
  recent(now) {
    this.stamps = this.stamps.filter(t => now - t < RATE_WINDOW_MS)
    return this.stamps.slice()
  }
  /** Record that an action actually went out. Only executed actions count against the cap. */
  record(now) { this.stamps.push(now); return this }
}

/** Load the scope file. I/O lives here and nowhere in the decision. */
export function loadDynamicConfig(path) {
  const loaded = loadScope(path)
  if (!loaded.ok) return { ok: false, code: DENY.CONFIG_MISSING, problems: [loaded.error], config: null }
  return normalizeConfig(loaded.scope)
}

/**
 * The kill switch: one file, checked before every call. A file rather than a flag because the
 * person who wants everything to stop is not necessarily the person holding the terminal that
 * started it, and `touch STOP` works from anywhere.
 */
export function killSwitchEngaged(path = 'claudeguard.STOP') {
  try { return existsSync(path) } catch { return true }   // cannot tell => assume stop
}

/**
 * Append one decision to the audit log. Opened with 'a' so an existing log cannot be truncated by
 * a later run; one JSON object per line so a partial write costs one record and not the file.
 */
export function appendAudit(path, record) {
  appendFileSync(path, JSON.stringify(record) + '\n', 'utf8')
  return record
}

/** Read an audit log back. Unparseable lines are surfaced, never skipped. */
export function readAudit(path) {
  if (!existsSync(path)) return []
  return readFileSync(path, 'utf8').split(/\r?\n/).filter(Boolean).map(line => {
    try { return JSON.parse(line) } catch { return { unparseable: line } }
  })
}

// ---- CLI --------------------------------------------------------------------
// A thin shell around `decide`: read the file, ask, print, log. It decides nothing itself.
const isMain = process.argv[1] && process.argv[1].endsWith('dynamic_gate.mjs')
if (isMain) {
  const args = parseArgs(process.argv.slice(2))
  const scopePath = args.scope || 'claudeguard.scope.yml'
  const loaded = loadScope(scopePath)
  const auditPath = typeof args.audit === 'string' ? args.audit : 'claudeguard-dynamic-audit.jsonl'

  const decision = decide(loaded.ok ? loaded.scope : null, {
    tool: typeof args.tool === 'string' ? args.tool : null,
    target: typeof args.target === 'string' ? args.target : null,
    path: typeof args.path === 'string' ? args.path : '/',
    origin: typeof args.origin === 'string' ? args.origin : 'config',
    destructive: args.destructive === true,
  }, {
    now: Date.now(),
    recent: [],
    confirmation: args.confirm === true,
    killSwitch: killSwitchEngaged(typeof args['kill-switch'] === 'string' ? args['kill-switch'] : 'claudeguard.STOP'),
  })

  try { appendAudit(auditPath, decision.audit) } catch { /* the log is evidence, not a precondition */ }

  console.log(JSON.stringify(decision, null, 2))
  if (!decision.allowed) {
    console.error('GATE REFUSED:')
    for (const r of decision.reasons) console.error('  - ' + r)
  }
  process.exit(decision.allowed ? 0 : 2)
}
