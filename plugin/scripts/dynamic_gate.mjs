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
import { lookup } from 'node:dns/promises'
import { loadScope, hostMatches, normalizeHost, splitHostPort, UNMATCHABLE, DEFAULT_BLOCKED, parseArgs } from './_scope.mjs'

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
  // ClaudeGuardIL's own probers, driven by the offensive runner. `rls_probe` reads a table with the
  // anon key and reports what came back — no payload, so recon. `authz_probe` and `idor_probe` send
  // requests as one principal for another principal's data: no state changes, but they are payloads
  // aimed at a control, which is the definition of `active`.
  rls_probe: 'recon',
  // active — non-destructive probing. Payloads that do not modify state.
  nuclei_scan: 'active',
  ffuf_scan: 'active',
  nikto_scan: 'active',
  wpscan: 'active',
  zap_scan: 'active',
  xsstrike_scan: 'active',
  authz_probe: 'active',
  idor_probe: 'active',
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
 * The RUN budget, which is a different question from the rate limit and was missing entirely.
 *
 * A cap of 60 requests/minute permits 86,400 requests a day and a scan that never ends. "How fast"
 * and "how much, for how long" are separate promises, and only the first one was being kept. These
 * are the defaults a run gets when nobody chose; a config or a runner may lower them, and — like the
 * rate cap — may never raise them past the hard ceilings.
 */
export const DEFAULT_MAX_ACTIONS = 500
export const HARD_MAX_ACTIONS = 5000
export const DEFAULT_MAX_WALL_CLOCK_MS = 15 * 60_000
export const HARD_MAX_WALL_CLOCK_MS = 4 * 60 * 60_000

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
  /** Alias. The offensive runner reads `RATE_LIMITED`; the code on the wire is unchanged. */
  RATE_LIMITED: 'rate-limit-exceeded',
  DESTRUCTIVE_NOT_ENABLED: 'destructive-not-enabled',
  CONFIRMATION_REQUIRED: 'confirmation-required',
  NO_CLOCK: 'no-clock',
  INTERNAL_ERROR: 'internal-error',
  /** The name passed; the ADDRESS it resolves to did not. Includes rebinding between two calls. */
  RESOLVED_IP_REFUSED: 'resolved-ip-refused',
  /** The name could not be resolved at all, so its address could not be shown to be in scope. */
  RESOLUTION_FAILED: 'resolution-failed',
  /** The run's total action count or wall clock ran out. Separate from the per-minute rate cap. */
  BUDGET_EXHAUSTED: 'budget-exhausted',
  /** Tier `active` or above proposed by a run with no human at the other end. */
  HEADLESS_REFUSED: 'headless-refused',
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

// ---- the resolved-address gate ---------------------------------------------------------------
//
// THE NEXT LAYER OF THE BYPASS FAMILY THAT WAS ALREADY FIXED ONCE.
//
// `normalizeHost` closed the gap between the string the gate CHECKED and the string `fetch` SENT by
// routing both through one WHATWG parse. That fixed userinfo, path confusion, the root dot, decimal
// IPv4 and IPv4-mapped IPv6 — every case where two pieces of code disagreed about a hostname.
//
// A hostname is still not a destination. The gate validates a NAME; the network stack resolves that
// name to an ADDRESS and opens a socket to the address. Nothing above constrains the answer:
//
//   staging.myapp.com.  A  169.254.169.254     an allowlisted name whose DNS points at the cloud
//                                              metadata service — one request away from the
//                                              instance's IAM credentials.
//   staging.myapp.com.  A  127.0.0.1           the allowlisted name aimed back at the box running
//                                              the scanner, at whatever admin port it has open.
//   staging.myapp.com.  A  10.0.0.7            an internal host nobody put on the allowlist,
//                                              reached through a name that is on it.
//   TTL 0, answer flips between the check and the connect (classic DNS rebinding / TOCTOU).
//
// So the ADDRESS is gated too, and — because DNS is I/O — the resolution and this check live in
// `decideWithResolution` below, outside the pure core, with the resolver injected. What follows is
// only the arithmetic, which is pure and therefore testable with no network at all.

/** Cloud instance-metadata endpoints. Never reachable, whatever the config says. */
export const METADATA_ADDRESSES = [
  '169.254.169.254',   // AWS / GCP / Azure / DigitalOcean IMDS
  '169.254.170.2',     // AWS ECS task metadata
  'fd00:ec2::254',     // AWS IMDS over IPv6
  '100.100.100.200',   // Alibaba Cloud
  '192.0.0.192',       // Oracle Cloud
]

/** Dotted-quad only. `dns.lookup` answers in this form; anything else is not an address we vouch for. */
function parseIPv4(input) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(input ?? ''))
  if (!m) return null
  const bytes = m.slice(1).map(Number)
  if (bytes.some(b => b > 255)) return null
  return bytes
}

/**
 * Parse an IPv6 literal into 16 bytes. Handles `::` elision, an embedded IPv4 tail
 * (`::ffff:169.254.169.254`), surrounding brackets and a zone id. Returns null when it is not one
 * unambiguous address — and null is refused, never guessed.
 */
function parseIPv6(input) {
  let s = String(input ?? '').trim()
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)
  s = s.split('%')[0]
  if (!s.includes(':')) return null
  const lastColon = s.lastIndexOf(':')
  const tail = s.slice(lastColon + 1)
  if (tail.includes('.')) {
    const v4 = parseIPv4(tail)
    if (!v4) return null
    s = s.slice(0, lastColon + 1) +
      ((v4[0] << 8) | v4[1]).toString(16) + ':' + ((v4[2] << 8) | v4[3]).toString(16)
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const rest = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : []
  if (halves.length === 1 ? head.length !== 8 : head.length + rest.length > 7) return null
  const groups = [...head, ...Array(8 - head.length - rest.length).fill('0'), ...rest]
  const bytes = new Uint8Array(16)
  for (let i = 0; i < 8; i++) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) return null
    const v = parseInt(groups[i], 16)
    bytes[i * 2] = v >> 8
    bytes[i * 2 + 1] = v & 0xff
  }
  return bytes
}

/** IPv4 range test on the parsed byte array. */
const v4In = (b, a0, bits, a1 = 0, a2 = 0, a3 = 0) => {
  const ip = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0
  const net = ((a0 << 24) | (a1 << 16) | (a2 << 8) | a3) >>> 0
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
  return ((ip & mask) >>> 0) === ((net & mask) >>> 0)
}

function classifyIPv4(b) {
  if (v4In(b, 169, 16, 254)) return 'link-local'          // 169.254/16 — includes 169.254.169.254
  if (v4In(b, 127, 8)) return 'loopback'
  if (v4In(b, 0, 8)) return 'unspecified'
  if (v4In(b, 10, 8)) return 'private'
  if (v4In(b, 172, 12, 16)) return 'private'
  if (v4In(b, 192, 16, 168)) return 'private'
  if (v4In(b, 100, 10, 64)) return 'private'              // CGNAT
  if (v4In(b, 192, 24, 0, 0)) return 'reserved'           // 192.0.0/24 — Oracle metadata lives here
  if (v4In(b, 198, 15, 18)) return 'reserved'             // benchmarking
  if (v4In(b, 224, 4)) return 'multicast'
  if (v4In(b, 240, 4)) return 'reserved'                  // includes 255.255.255.255
  return 'public'
}

function classifyIPv6(b) {
  const allZero = b.every(x => x === 0)
  if (allZero) return 'unspecified'
  if (b.slice(0, 15).every(x => x === 0) && b[15] === 1) return 'loopback'
  // IPv4-mapped (::ffff:0:0/96), NAT64 (64:ff9b::/96) and 6to4 (2002::/16) all carry a v4
  // destination inside them, and a gate that stops at "looks like a public v6 address" is a gate
  // that tunnels straight to 169.254.169.254.
  const embedded = embeddedIPv4(b)
  if (embedded) return classifyIPv4(parseIPv4(embedded))
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return 'link-local'   // fe80::/10
  if ((b[0] & 0xfe) === 0xfc) return 'unique-local'                  // fc00::/7 — fd00:ec2::254 too
  if (b[0] === 0xff) return 'multicast'
  return 'public'
}

/**
 * What kind of address is this? Pure, and the whole basis of the refusal below.
 *
 * @returns {{ok: boolean, kind: string, family: 4|6|0, canonical: string|null}}
 *   kind ∈ metadata | link-local | loopback | private | unique-local | unspecified | multicast |
 *          reserved | public | unparseable
 */
export function classifyAddress(input) {
  let s = String(input ?? '').trim()
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)
  if (!s) return { ok: false, kind: 'unparseable', family: 0, canonical: null }

  const v4 = parseIPv4(s)
  if (v4) {
    const canonical = v4.join('.')
    const kind = METADATA_ADDRESSES.includes(canonical) ? 'metadata' : classifyIPv4(v4)
    return { ok: true, kind, family: 4, canonical }
  }
  const v6 = parseIPv6(s)
  if (v6) {
    // Compare metadata addresses by BYTES, so `fd00:0ec2:0000::0254` cannot spell its way past a
    // string comparison — the same lesson as the trailing root dot, one layer down.
    const isMeta = METADATA_ADDRESSES.some(m => {
      const mb = m.includes(':') ? parseIPv6(m) : parseIPv6('::ffff:' + m)
      return mb && mb.every((x, i) => x === v6[i])
    })
    // An IPv4 hiding inside a v6 wrapper is still that IPv4, metadata list included.
    const embedded = embeddedIPv4(v6)
    const kind = (isMeta || (embedded && METADATA_ADDRESSES.includes(embedded)))
      ? 'metadata'
      : classifyIPv6(v6)
    return { ok: true, kind, family: 6, canonical: canonicalIPv6(v6) }
  }
  return { ok: false, kind: 'unparseable', family: 0, canonical: null }
}

/** The IPv4 an IPv4-mapped / NAT64 / 6to4 address really points at, or null. */
function embeddedIPv4(b) {
  if (b.slice(0, 10).every(x => x === 0) && b[10] === 0xff && b[11] === 0xff) {
    return [b[12], b[13], b[14], b[15]].join('.')
  }
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b.slice(4, 12).every(x => x === 0)) {
    return [b[12], b[13], b[14], b[15]].join('.')
  }
  if (b[0] === 0x20 && b[1] === 0x02) return [b[2], b[3], b[4], b[5]].join('.')
  return null
}

/** One spelling per IPv6 address: lowercase hextets, longest zero run elided. */
function canonicalIPv6(b) {
  const groups = []
  for (let i = 0; i < 8; i++) groups.push(((b[i * 2] << 8) | b[i * 2 + 1]).toString(16))
  let bestStart = -1, bestLen = 0, start = -1, len = 0
  for (let i = 0; i < 9; i++) {
    if (i < 8 && groups[i] === '0') { if (start < 0) start = i; len++ }
    else { if (len > bestLen) { bestLen = len; bestStart = start } start = -1; len = 0 }
  }
  if (bestLen < 2) return groups.join(':')
  return groups.slice(0, bestStart).join(':') + '::' + groups.slice(bestStart + bestLen).join(':')
}

/** Kinds no attestation can license. Metadata and link-local are never a legitimate scan target. */
const NEVER_REACHABLE_KINDS = ['metadata', 'link-local', 'unspecified', 'multicast', 'reserved', 'unparseable']
/** Kinds that need the config to have said, in the file, that this address space is in scope. */
const NEEDS_ATTESTATION_KINDS = ['loopback', 'private', 'unique-local']

/** RFC 6761: `localhost` and anything under `.localhost` are loopback by definition. */
function isLoopbackName(name) {
  const n = String(name ?? '').toLowerCase()
  return n === 'localhost' || n.endsWith('.localhost')
}

/** IPv6 needs its brackets back before it can be matched against a host pattern. */
const forMatching = addr => (String(addr).includes(':') && !String(addr).startsWith('[')) ? `[${addr}]` : String(addr)

/**
 * May a run connect to this resolved address? Pure.
 *
 * `allowlist`/`blocklist` are the NORMALIZED lists from `normalizeConfig` (blocklist already has
 * DEFAULT_BLOCKED folded in). `targetName` is the bare hostname that was resolved, used only to
 * recognise the one case where a loopback answer is exactly what the operator asked for.
 *
 * @returns {{ok: boolean, kind: string, reason: string|null}}
 */
export function gateResolvedAddress(address, { allowlist = [], blocklist = [], targetName = '' } = {}) {
  const { ok, kind, canonical } = classifyAddress(address)
  const shown = canonical ?? String(address).slice(0, 64)

  if (!ok) {
    return { ok: false, kind, reason: `"${shown}" is not an address this gate can parse, so it cannot be shown to be in scope` }
  }
  // An explicit refusal binds the address exactly as it binds the name.
  const blocked = blocklist.find(p => hostMatches(forMatching(canonical), p))
  if (blocked) {
    return { ok: false, kind, reason: `${shown} matches the never-touch pattern "${blocked}"` }
  }
  if (NEVER_REACHABLE_KINDS.includes(kind)) {
    return {
      ok: false, kind,
      reason: kind === 'metadata'
        ? `${shown} is a cloud instance-metadata endpoint — a name that resolves there is an SSRF target, not a scan target, and no attestation makes it one`
        : `${shown} is ${kind === 'link-local' ? 'link-local' : `a ${kind}`} address — a name resolving into that space is not something this gate will connect to`,
    }
  }
  if (NEEDS_ATTESTATION_KINDS.includes(kind)) {
    const attested = allowlist.some(p => hostMatches(forMatching(canonical), p)) ||
      (kind === 'loopback' && isLoopbackName(targetName))
    if (!attested) {
      return {
        ok: false, kind,
        reason: `${shown} is ${kind === 'loopback' ? 'a loopback' : `a ${kind}`} address and nothing in dynamic_testing.scope.allowlist names that space — a public name that resolves onto the internal network is how an in-scope host reaches an out-of-scope one. List the address or the CIDR by hand if it really is in scope.`,
      }
    }
  }
  return { ok: true, kind, reason: null }
}

// ---- rate history and run budget, read from ctx --------------------------------------------

/**
 * The timestamps that count against the per-minute cap. Accepts a plain array (as before) AND a
 * `RateWindow`'s non-mutating snapshot, and UNIONS them — more history can only ever deny more, so
 * a caller that supplies both cannot use one to cancel the other.
 */
function readRateHistory(context, now) {
  const out = []
  if (Array.isArray(context.recent)) out.push(...context.recent)
  const w = context.rateWindow
  if (w && typeof w.snapshot === 'function') {
    const snap = w.snapshot(now)
    if (Array.isArray(snap)) out.push(...snap)
  }
  return out.filter(t => typeof t === 'number' && Number.isFinite(t) && t <= now && now - t < RATE_WINDOW_MS)
}

/**
 * Read the run budget out of ctx. Accepts a `RunBudget` (via its non-mutating `snapshot(now)`) or a
 * plain `{ actions, startedAt, maxActions, maxWallClockMs }`.
 *
 * `null` means no budget was supplied. `{ readable: false }` means one WAS supplied and could not be
 * read — which denies, because a budget nobody can evaluate is not a budget anybody is inside of.
 */
function readBudget(context, now) {
  const raw = context.budget
  if (raw === undefined || raw === null) return null
  let b = raw
  if (typeof raw.snapshot === 'function') {
    b = raw.snapshot(now)
  }
  if (!isPlainObject(b)) return { readable: false }
  const int = v => typeof v === 'number' && Number.isFinite(v) && Number.isInteger(v) && v >= 0
  const ms = v => typeof v === 'number' && Number.isFinite(v) && v > 0
  const actions = b.actions
  const maxActions = b.maxActions
  const maxWallClockMs = b.maxWallClockMs
  const elapsedMs = typeof b.elapsedMs === 'number' ? b.elapsedMs
    : (typeof b.startedAt === 'number' && Number.isFinite(b.startedAt) ? now - b.startedAt : null)
  if (!int(actions) || !int(maxActions) || !ms(maxWallClockMs) ||
      typeof elapsedMs !== 'number' || !Number.isFinite(elapsedMs)) {
    return { readable: false }
  }
  return { readable: true, actions, maxActions, maxWallClockMs, elapsedMs }
}

/**
 * THE GATE. Pure, deterministic, side-effect-free.
 *
 * @param {unknown} rawConfig  the parsed scope file (or the dynamic_testing block)
 * @param {unknown} action     { tool, target, path?, destructive?, tier?, origin? }
 * @param {unknown} ctx        { now, recent?, rateWindow?, budget?, interactive?, confirmation?, killSwitch? }
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

  // ---- 7b. headless runs may not reach active or above -----------------------------------------
  //
  // `confirmation: true` is whatever the caller put in the object. In an interactive run that flag
  // is downstream of a human who was asked and said yes; in a cron job, a CI step or a detached
  // agent loop there is nobody to ask, and the flag is then just a field the process set for itself.
  // The confirmation check above cannot tell those apart — it only sees `true`.
  //
  // So interactivity is asked as its own question, and it is asked the deny-by-default way: a run is
  // headless unless it says `interactive: true`. A runner that forgets the flag gets recon, which is
  // the tier that needs no human. Nothing about this is a substitute for the confirmation; it is the
  // precondition that makes a confirmation mean anything.
  if (toolTier && TIER_RANK[toolTier] >= TIER_RANK.active && context.interactive !== true) {
    refuse(DENY.HEADLESS_REFUSED,
      `${tool || 'this tool'} is ${toolTier}-tier and this run is headless — a per-run human confirmation cannot be produced by a process with nobody attached to it, so active and exploit tiers are refused here. Run it interactively, or lower the run to recon.`)
  }

  // ---- 8. the rate limit --------------------------------------------------------------------
  // The history arrives through ctx — as a plain array, or as a RateWindow that lives across the
  // whole run and is snapshotted here without being mutated. Before this, the CLI passed a fresh
  // `recent: []` on every call, so nothing ever accumulated and the cap was decorative.
  if (cfg && typeof now === 'number' && Number.isFinite(now)) {
    const inWindow = readRateHistory(context, now).length
    if (inWindow >= cfg.maxRequestsPerMinute) {
      refuse(DENY.RATE_LIMIT,
        `${inWindow} request(s) already went out in the last minute and the cap is ${cfg.maxRequestsPerMinute}`)
    }
  }

  // ---- 8b. the run budget ---------------------------------------------------------------------
  //
  // A rate cap answers "how fast", and 60/minute is 86,400 a day: it says nothing about how much or
  // for how long. Total executed actions and wall clock are the two limits an operator actually
  // reasons about when deciding what they are willing to have running unattended, and neither
  // existed. The clock is `ctx.now`, so this stays a pure function of its arguments.
  if (typeof now === 'number' && Number.isFinite(now)) {
    const budget = readBudget(context, now)
    if (budget && !budget.readable) {
      refuse(DENY.BUDGET_EXHAUSTED,
        'a run budget was supplied but could not be read, so this action could not be shown to be inside it')
    } else if (budget) {
      if (budget.actions >= budget.maxActions) {
        refuse(DENY.BUDGET_EXHAUSTED,
          `this run has already executed ${budget.actions} action(s) and its budget is ${budget.maxActions} — start a new run deliberately rather than letting one drift on`)
      }
      if (budget.elapsedMs >= budget.maxWallClockMs) {
        refuse(DENY.BUDGET_EXHAUSTED,
          `this run has been going for ${Math.round(budget.elapsedMs / 1000)}s and its wall-clock budget is ${Math.round(budget.maxWallClockMs / 1000)}s`)
      }
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
function buildDecision({ tool, target, path, tier, mode, reasons, denyCodes, notes = [], at, plan = null, authorizedTier = null, resolved = null, pinned = null }) {
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
    // Filled in by `decideWithResolution` only. `pinned` is the address the runner MUST connect to:
    // re-resolving the name at send time reopens the rebinding window this gate exists to close.
    resolved,
    pinned,
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
      // "What did this thing touch?" is an address question, not a hostname question.
      resolved: Array.isArray(resolved) ? resolved.slice() : null,
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
  /** Timestamps inside the last minute, oldest first. Compacts the history as a side effect. */
  recent(now) {
    this.stamps = this.stamps.filter(t => now - t < RATE_WINDOW_MS)
    return this.stamps.slice()
  }
  /**
   * The same answer, with nothing mutated. `decide()` calls THIS, because a pure function that
   * quietly compacts an object it was handed is not one, and the 1000-identical-calls test that
   * proves the gate does nothing on the way would be proving it about a lie.
   */
  snapshot(now) {
    return this.stamps.filter(t => now - t < RATE_WINDOW_MS)
  }
  /** Record that an action actually went out. Only executed actions count against the cap. */
  record(now) { this.stamps.push(now); return this }
  get size() { return this.stamps.length }
}

/**
 * The RUN budget: how many actions in total, and for how long. One instance lives for one run and is
 * handed to every `decide()` through `ctx.budget`.
 *
 * `record()` is called only for actions that were actually EXECUTED — a plan is not a probe and a
 * refusal is not an action, and counting either would exhaust a run that never touched anything.
 */
export class RunBudget {
  constructor({ startedAt = 0, maxActions = DEFAULT_MAX_ACTIONS, maxWallClockMs = DEFAULT_MAX_WALL_CLOCK_MS } = {}) {
    this.startedAt = startedAt
    // Clamped, never honoured as given: the same rule the per-minute cap already follows, for the
    // same reason — a config or a caller may tighten a limit and may not loosen one.
    this.maxActions = Math.max(0, Math.min(Number.isInteger(maxActions) ? maxActions : DEFAULT_MAX_ACTIONS, HARD_MAX_ACTIONS))
    this.maxWallClockMs = Math.max(1, Math.min(Number.isFinite(maxWallClockMs) ? maxWallClockMs : DEFAULT_MAX_WALL_CLOCK_MS, HARD_MAX_WALL_CLOCK_MS))
    this.actions = 0
  }
  /** Start (or restart) the wall clock. A run that has not begun has not spent any of it. */
  start(now) { this.startedAt = now; return this }
  /** Non-mutating, for the pure core. */
  snapshot(now) {
    return {
      actions: this.actions,
      maxActions: this.maxActions,
      maxWallClockMs: this.maxWallClockMs,
      elapsedMs: Math.max(0, now - this.startedAt),
    }
  }
  record() { this.actions += 1; return this }
}

/**
 * REAL TERMINATION — the registry of things a STOP has to reach.
 *
 * `killSwitchEngaged()` refuses the NEXT decision. That is a control over what has not happened yet
 * and no control at all over what is happening now: an `nmap` already spawned, a `fetch` already in
 * flight, a Strix container already running keep going, and "stop" means "stop soon, probably".
 * `touch claudeguard.STOP` has to mean the traffic stops.
 *
 * So every dispatch registers a KILLABLE handle before it starts, and STOP walks the registry. A
 * killable is anything carrying one of these — the registry calls the first it finds and never
 * throws if there is none:
 *
 *   { abort(reason?) }        an AbortController — the in-process `fetch` case (see `controller()`)
 *   { kill(signal?) , pid }   a child_process: Strix, nmap, anything spawned
 *   { terminate() }           a Worker, or a client for an HTTP-proxy tool like HexStrike, whose
 *                             terminate() can POST /api/processes/terminate/<pid> as the spec's
 *                             enforcement principle #6 already describes
 *
 * The ordering that matters: `terminateAll` marks the registry stopped BEFORE it kills anything, so
 * a dispatch that registers during the sweep — the race a scanner in a tight loop will find — is
 * aborted at registration instead of slipping through behind it.
 */
export class RunRegistry {
  constructor({ clock = () => Date.now() } = {}) {
    this.clock = clock
    this.handles = new Map()
    this.stopped = false
    this.stopReason = null
    this.seq = 0
  }

  get size() { return this.handles.size }

  /** Everything currently in flight, for the audit log and for a human asking "what is running?". */
  list() {
    return [...this.handles.values()].map(e => ({ id: e.id, meta: e.meta, startedAt: e.startedAt }))
  }

  /**
   * Put a killable under the registry's control.
   * @returns {{id: string, stopped: boolean, release: () => void}}
   *   `stopped: true` means the run was ALREADY stopped and the handle was killed on the spot —
   *   the caller must not dispatch.
   */
  register(handle, meta = {}) {
    const id = `run-${++this.seq}`
    if (this.stopped) {
      killOne(handle, this.stopReason)
      return { id, stopped: true, release: () => {} }
    }
    this.handles.set(id, { id, handle, meta, startedAt: this.clock() })
    return { id, stopped: false, release: () => { this.handles.delete(id) } }
  }

  /**
   * The in-process case, wired up for you: an AbortController whose signal is already under STOP's
   * control. Pass `signal` straight to `fetch`.
   */
  controller(meta = {}) {
    const ctrl = new AbortController()
    const { id, stopped, release } = this.register(ctrl, meta)
    return { id, stopped, release, controller: ctrl, signal: ctrl.signal }
  }

  release(id) { this.handles.delete(id) }

  /**
   * Stop everything, now. Idempotent, and it never throws: a handle that fails to die must not
   * prevent the next one from being asked to.
   * @returns {{terminated: number, errors: string[]}}
   */
  terminateAll(reason = 'the dynamic-testing kill switch was engaged') {
    this.stopped = true                       // FIRST — see the class comment
    this.stopReason = reason
    const entries = [...this.handles.values()]
    this.handles.clear()
    const errors = []
    for (const e of entries) {
      const err = killOne(e.handle, reason)
      if (err) errors.push(`${e.id}: ${err}`)
    }
    return { terminated: entries.length, errors }
  }

  /** A new run in the same process. Deliberately explicit: STOP does not time out by itself. */
  reset() { this.terminateAll('registry reset'); this.stopped = false; this.stopReason = null; return this }
}

/** Call whichever kill verb a handle has. Returns an error string, or null. */
function killOne(handle, reason) {
  try {
    if (!handle) return null
    if (typeof handle.abort === 'function') { handle.abort(new Error(reason)); return null }
    if (typeof handle.kill === 'function') { handle.kill('SIGTERM'); return null }
    if (typeof handle.terminate === 'function') { handle.terminate(); return null }
    return 'handle exposes no abort(), kill() or terminate()'
  } catch (e) {
    return String(e && e.message || e)
  }
}

/**
 * Watch the STOP file and terminate the registry when it appears.
 *
 * `poll()` is separated from the timer so the behaviour can be tested without one, and `check` is
 * injectable for the same reason. Returns a disposer.
 */
export function watchKillSwitch(registry, { check = () => killSwitchEngaged(), intervalMs = 500 } = {}) {
  let timer = null
  const poll = () => {
    let engaged
    try { engaged = check() } catch { engaged = true }   // cannot tell => assume stop
    if (engaged && !registry.stopped) return registry.terminateAll('claudeguard.STOP appeared during the run')
    return null
  }
  const start = () => {
    if (timer) return
    timer = setInterval(poll, intervalMs)
    if (typeof timer.unref === 'function') timer.unref()   // never hold the process open
  }
  const stop = () => { if (timer) { clearInterval(timer); timer = null } }
  start()
  return { poll, stop }
}

/**
 * What each hostname resolved to the FIRST time this run asked.
 *
 * DNS rebinding is a TOCTOU bug with a network in the middle: the name answers `93.184.216.34` when
 * the gate checks it and `169.254.169.254` a few milliseconds later when the socket opens, and every
 * check above passes on the first answer. The pin is how the run notices: the first answer is the
 * one the whole run is held to, and a name that starts answering differently is refused rather than
 * re-approved.
 */
export class ResolutionPins {
  constructor() { this.byHost = new Map() }
  get(host) { return this.byHost.get(String(host).toLowerCase()) ?? null }
  /** First answer wins. A later, different answer must never overwrite the pin it contradicts. */
  pin(host, addresses) {
    const k = String(host).toLowerCase()
    if (!this.byHost.has(k)) this.byHost.set(k, [...addresses].sort())
    return this.byHost.get(k)
  }
  clear() { this.byHost.clear() }
}

/**
 * The real resolver. Never called by a unit test — `decideWithResolution` takes it as a parameter
 * precisely so the suite can hand it fixed answers and stay offline and deterministic.
 *
 * `all: true` because ONE bad address is enough: a name with an A record on the allowlisted host and
 * a second A record on 169.254.169.254 is a name whose connection lands wherever the stack feels
 * like, and gating only the first answer gates a coin flip.
 */
export async function dnsResolver(hostname) {
  const answers = await lookup(hostname, { all: true, verbatim: true })
  return answers.map(a => a.address)
}

/** The bare name to resolve, with any port and IPv6 brackets removed. */
function resolvableName(canonicalTarget) {
  const [name] = splitHostPort(String(canonicalTarget))
  return name.startsWith('[') && name.endsWith(']') ? name.slice(1, -1) : name
}

/**
 * THE GATE, plus the address the name actually points at.
 *
 * `decide()` stays pure and stays the source of truth for every question that can be answered from
 * three plain objects. DNS is I/O, so it lives out here — and the resolver is a parameter so tests
 * pass fake answers and never touch a network.
 *
 * Deny still wins by construction: this calls `decide()`, then APPENDS its own refusals. There is no
 * path in which a resolution result upgrades a decision the pure core refused.
 *
 * @param {unknown} config    the parsed scope file (or the dynamic_testing block)
 * @param {unknown} action    { tool, target, path?, destructive?, tier?, origin? }
 * @param {object}  ctx       everything `decide()` takes, plus `pins?: ResolutionPins`
 * @param {(hostname: string) => Promise<string[]>} resolver  injectable; defaults to node:dns
 * @returns {Promise<object>} the decision, with `resolved: string[]|null` and `pinned: string|null`.
 *   A runner MUST connect to `pinned` (with the original Host header) — resolving the name again at
 *   send time reopens exactly the window this closes.
 */
export async function decideWithResolution(config, action, ctx = {}, resolver = dnsResolver) {
  const base = decide(config, action, ctx)

  // No target, or already refused: nothing to resolve. Sending a DNS query for a host the gate has
  // just refused would be the run's first out-of-scope packet.
  if (!base.target || !base.allowed) return base

  const loaded = normalizeConfig(config)
  const allowlist = loaded.ok ? loaded.config.allowlist : []
  const blocklist = loaded.ok ? loaded.config.blocklist : DEFAULT_BLOCKED
  const name = resolvableName(base.target)

  let addresses = null
  try {
    addresses = await resolver(name)
  } catch (e) {
    return refused(base, [DENY.RESOLUTION_FAILED],
      [`${name} could not be resolved (${String(e && e.message || e).slice(0, 120)}), so the address this action would open a socket to is unknown — and an unverified destination is not an approved one`], null)
  }
  if (!Array.isArray(addresses) || addresses.length === 0 || addresses.some(a => typeof a !== 'string' || !a.trim())) {
    return refused(base, [DENY.RESOLUTION_FAILED],
      [`${name} produced no usable address, so it could not be shown to be in scope`], null)
  }

  const reasons = []
  const codes = []

  // Rebinding, across calls: the first answer of the run is the answer for the run.
  const pins = ctx && ctx.pins
  // Canonicalised and sorted, so the pin compares SETS: a resolver is free to shuffle the order of
  // an unchanged answer, and treating that as a rebind would refuse every honest run on its second call.
  const canonicalAddrs = addresses.map(a => classifyAddress(a).canonical ?? String(a)).sort()
  if (pins && typeof pins.get === 'function') {
    const prior = pins.get(name)
    if (prior && (prior.length !== canonicalAddrs.length || prior.some((p, i) => p !== canonicalAddrs[i]))) {
      codes.push(DENY.RESOLVED_IP_REFUSED)
      reasons.push(
        `${name} resolved to ${prior.join(', ')} earlier in this run and now resolves to ${canonicalAddrs.join(', ')} — a name whose address changes mid-run is DNS rebinding until somebody proves otherwise, and the gate does not re-approve it. The run is held to the first answer.`)
    } else if (typeof pins.pin === 'function') {
      pins.pin(name, canonicalAddrs)
    }
  }

  // Every address, not just the first: the stack may pick any of them.
  for (const addr of addresses) {
    const verdict = gateResolvedAddress(addr, { allowlist, blocklist, targetName: name })
    if (!verdict.ok) {
      codes.push(DENY.RESOLVED_IP_REFUSED)
      reasons.push(`${base.target} resolves to ${addr}, and ${verdict.reason}`)
    }
  }

  if (reasons.length) return refused(base, codes, reasons, canonicalAddrs)

  return {
    ...base,
    resolved: canonicalAddrs,
    pinned: canonicalAddrs[0],
    audit: { ...base.audit, resolved: canonicalAddrs.slice() },
  }
}

/** Turn an allowed decision into a refusal, preserving everything the pure core already said. */
function refused(base, codes, reasons, resolvedAddrs) {
  const allReasons = [...base.reasons, ...reasons]
  const allCodes = [...base.denyCodes, ...codes]
  return {
    ...base,
    allowed: false,
    mode: 'deny',
    willExecute: false,
    plan: null,
    resolved: resolvedAddrs,
    pinned: null,
    reasons: allReasons,
    denyCodes: allCodes,
    audit: {
      ...base.audit,
      decision: 'deny',
      resolved: Array.isArray(resolvedAddrs) ? resolvedAddrs.slice() : null,
      reasons: allReasons.slice(),
      denyCodes: allCodes.slice(),
    },
  }
}

/**
 * ONE RUN, with every piece of cross-call state threaded through it.
 *
 * The rate limit, the budget and the resolution pins are all only worth anything if the SAME object
 * reaches every decision — and "remember to pass these four things every time" is not a control, it
 * is a note. `dynamic_runner.mjs` should hold one of these and never build a ctx by hand.
 *
 * The division of labour, which is the point:
 *   ask()     decides. Reads state; changes none of it.
 *   commit()  is called ONLY after an action really went out, and is the only thing that spends the
 *             rate window and the budget. A plan, a refusal and a crash all cost nothing.
 */
export class GateSession {
  constructor({
    config,
    clock = () => Date.now(),
    interactive = false,
    confirmation = false,
    budget = null,
    rateWindow = new RateWindow(),
    registry = new RunRegistry({ clock }),
    pins = new ResolutionPins(),
    resolver = dnsResolver,
    killSwitchPath = 'claudeguard.STOP',
    killSwitch = null,
  } = {}) {
    this.config = config
    this.clock = clock
    this.interactive = interactive === true
    this.confirmation = confirmation === true
    this.rateWindow = rateWindow
    this.registry = registry
    this.pins = pins
    this.resolver = resolver
    this.killSwitchPath = killSwitchPath
    this.killSwitch = killSwitch ?? (() => killSwitchEngaged(this.killSwitchPath))
    this.budget = budget ?? new RunBudget()
    this.budget.start(this.clock())
    this.decisions = []
  }

  /** The ctx every decision in this run is made against. */
  ctx(over = {}) {
    let stopped = this.registry.stopped
    if (!stopped) {
      try { stopped = this.killSwitch() === true } catch { stopped = true }
    }
    // Noticing STOP at decision time is also the moment to make it real for what is already running.
    if (stopped && !this.registry.stopped) this.registry.terminateAll('the dynamic-testing kill switch is engaged')
    return {
      now: this.clock(),
      rateWindow: this.rateWindow,
      budget: this.budget,
      pins: this.pins,
      interactive: this.interactive,
      confirmation: this.confirmation,
      killSwitch: stopped,
      ...over,
    }
  }

  /** The pure decision, with this run's state threaded in. */
  ask(action, over = {}) {
    const d = decide(this.config, action, this.ctx(over))
    this.decisions.push(d.audit)
    return d
  }

  /** The same, plus the resolved-address gate. This is what a runner about to send traffic calls. */
  async askResolved(action, over = {}) {
    const d = await decideWithResolution(this.config, action, this.ctx(over), this.resolver)
    this.decisions.push(d.audit)
    return d
  }

  /**
   * Spend the run's budget for one action that ACTUALLY went out. Refuses to count anything the
   * gate did not mark `willExecute`, so a caller cannot exhaust a run by committing plans.
   */
  commit(decision) {
    if (!decision || decision.willExecute !== true) return false
    this.rateWindow.record(this.clock())
    this.budget.record()
    return true
  }

  /** Everything stops: what is in flight is aborted, and the next decision is refused. */
  stop(reason = 'stop requested') {
    const result = this.registry.terminateAll(reason)
    return result
  }
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

/**
 * Rebuild a run's spent state from the audit log.
 *
 * The CLI is one process per decision, so an in-memory RateWindow would be empty every time — which
 * is exactly the bug: `recent: []` on every call meant nothing ever accumulated and the per-minute
 * cap was decorative. The log is already written before every action, so it is the run's memory.
 *
 * Only `allow` rows count. A `plan` is not a probe and a `deny` is not an action, and counting
 * either would exhaust a run that never sent a packet.
 */
export function replayAudit(path, { since = 0 } = {}) {
  const window = new RateWindow()
  let actions = 0
  let firstAt = null
  for (const row of readAudit(path)) {
    if (!row || row.decision !== 'allow' || typeof row.at !== 'number') continue
    if (row.at < since) continue
    window.record(row.at)
    actions += 1
    if (firstAt === null || row.at < firstAt) firstAt = row.at
  }
  return { window, actions, firstAt }
}

// ---- CLI --------------------------------------------------------------------
// A thin shell around `decide`: read the file, ask, print, log. It decides nothing itself.
const isMain = process.argv[1] && process.argv[1].endsWith('dynamic_gate.mjs')
if (isMain) {
  const args = parseArgs(process.argv.slice(2))
  const scopePath = args.scope || 'claudeguard.scope.yml'
  const loaded = loadScope(scopePath)
  const auditPath = typeof args.audit === 'string' ? args.audit : 'claudeguard-dynamic-audit.jsonl'
  const now = Date.now()

  // The run's spent rate window and budget, read back from the log this same CLI writes.
  const num = (v, fallback) => (typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : fallback)
  const runSince = num(args['run-since'], 0)
  const spent = replayAudit(auditPath, { since: runSince })
  const budget = new RunBudget({
    maxActions: num(args['max-actions'], DEFAULT_MAX_ACTIONS),
    maxWallClockMs: num(args['max-runtime-ms'], DEFAULT_MAX_WALL_CLOCK_MS),
  })
  budget.start(runSince || spent.firstAt || now)
  for (let i = 0; i < spent.actions; i++) budget.record()

  const decision = decide(loaded.ok ? loaded.scope : null, {
    tool: typeof args.tool === 'string' ? args.tool : null,
    target: typeof args.target === 'string' ? args.target : null,
    path: typeof args.path === 'string' ? args.path : '/',
    origin: typeof args.origin === 'string' ? args.origin : 'config',
    destructive: args.destructive === true,
  }, {
    now,
    rateWindow: spent.window,
    budget,
    // Deny by default: a CLI invoked by a cron job, a CI step or an agent loop is headless unless
    // the person driving it says otherwise, and `--interactive` is a claim the runner makes, not
    // one the model can make for it.
    interactive: args.interactive === true,
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
