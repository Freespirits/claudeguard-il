#!/usr/bin/env node
// Snyk adapter. Snyk observes; the grader grades — the same contract gitleaks, semgrep and the
// dependency auditors already live under.
//
// Snyk is worth wiring up for exactly two things a regex cannot know, and both of them buy
// CONFIDENCE rather than noise:
//
//   * SCA reachability. `run_dep_audit` must cap every dependency CVE at `needs-review`, because it
//     cannot tell whether the vulnerable function is ever called. Snyk can. A `reachable` advisory
//     is a direct, single-hop observation; a `not-reachable` one is not a finding at all.
//   * Snyk Code dataflow. A SAST hit with a proven source→sink path is a stronger lead than a
//     pattern match. Still an external tool's judgement, so the grader caps it at `likely`.
//
// The adapter never decides any of that. It emits observations carrying `reachability` and
// `hasDataflow` as FACTS, plus `advisorySeverity` — Snyk's own critical/high/medium/low, named so
// it cannot be mistaken for ours. `grader.mjs` owns the P-level and the evidence strength.
//
// THE NORMALISER CONTRACT (the same one run_dep_audit.mjs documents, for the same reason):
//
//   []    the payload was RECOGNISED and contains zero results
//   null  the payload was NOT recognised — we do not know what it means
//
// Collapsing those two is how an adapter lies. `snyk test` without a token returns an
// authentication error envelope; a normaliser that answered `[]` to that would make the grader
// record the scan as a PASS — "checked, nothing found" over a check that never ran. A shape adapter
// fails silently by nature: nothing throws, the output just goes quiet. So the normalisers are
// exported and unit-tested over recorded payloads (test/snyk_adapter.test.mjs) instead of living
// inside the CLI body.
//
// CONSENT. `snyk_sca_scan`, `snyk_iac_scan` and `snyk_container_scan` analyse locally — manifest
// metadata leaves the machine, not source. **`snyk_code_scan` (SAST) uploads source to Snyk's
// cloud.** That is a different trust decision, and this audience audits private repos, so Code is
// OFF unless the user says yes: `--code` on the command line, or `snyk.code_scan_uploads_source:
// true` in claudeguard.scope.yml. When it is skipped, the report says so as a coverage row — a
// skipped scan is never a silent gap.
//
// TRUST. Snyk refuses to scan a folder nobody has vouched for. That mechanism lives in the MCP
// server and the language server (`snyk_trust`), not in a plain CLI subcommand, so this file does
// not invent one — it computes `trustPath`, the repo under scan and never a parent, for whoever
// does the trusting. A trust grant covers every subdirectory, so trusting a parent would quietly
// authorise every future scan of every sibling project on the machine.
//
// Usage:
//   node run_snyk.mjs [path]                    # SCA + IaC + container, local-only
//   node run_snyk.mjs [path] --code             # ...and Snyk Code, with source upload consented
//   node run_snyk.mjs [path] --scope claudeguard.scope.yml
//   node run_snyk.mjs [path] --from-mcp mcp.json  # normalise payloads captured from `snyk mcp`
import { execFileSync, execSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// ---------------------------------------------------------------------------
// Payload plumbing
// ---------------------------------------------------------------------------

function safeParse(s) { try { return JSON.parse(s) } catch { return null } }

/**
 * Snyk ships its own MCP server inside the CLI (`snyk mcp -t stdio --experimental`), and MCP tools
 * answer with `{content: [{type: 'text', text: '<the CLI JSON, as a string>'}]}` — the payload is
 * JSON encoded inside a string inside an envelope. An adapter that forgot the extra hop would see
 * a `content` array, fail to find `vulnerabilities`, and return null for every scan Snyk ever ran.
 *
 * Accepts the envelope, a raw string, or an already-parsed object, so the same normalisers serve
 * both the MCP path (an agent calls the tool) and the CLI path (this file shells out).
 *
 * @returns the parsed payload, or null when there is nothing JSON-shaped in it.
 */
export function unwrapMcpContent(payload) {
  if (payload == null) return null
  if (typeof payload === 'string') return safeParse(payload)
  if (Array.isArray(payload)) return payload
  if (typeof payload !== 'object') return null

  // MCP tool result envelope.
  if (Array.isArray(payload.content)) {
    const text = payload.content
      .filter(c => c && (c.type === 'text' || typeof c.text === 'string'))
      .map(c => c.text)
      .filter(Boolean)
      .join('')
    if (!text) return null
    return safeParse(text)
  }
  // Some hosts hand back the structured result directly.
  if (payload.structuredContent != null) return unwrapMcpContent(payload.structuredContent)
  return payload
}

/**
 * Snyk's own failure envelope. Recognising it is what turns a silent zero into a stated gap.
 *
 * The exact keys Snyk uses for a failure are NOT publicly documented — the error catalogue gives
 * codes (`SNYK-CLI-0006` is "you are not authenticated") but no payload schema. So this function is
 * deliberately not the safety net: the safety net is that each normaliser demands a POSITIVE
 * structural signature, and anything without one is `null` whatever it turned out to be. This
 * function only makes the resulting coverage row say something useful instead of "unrecognised
 * shape".
 *
 * The one thing it must get right is the trap that produced the npm-audit defect: an error payload
 * that ALSO carries an empty results array. `{"ok": false, "error": "...", "vulnerabilities": []}`
 * has to read as a failure, not as a clean scan — so the presence of an error key wins outright,
 * and `ok: false` alone never does, because `ok: false` is also how Snyk says "I found
 * vulnerabilities".
 *
 * @returns a human-readable reason, or null when the payload is not an error.
 */
export function snykError(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null

  const message = [data.error, data.userMessage, data.detail, data.message, data.title]
    .find(v => typeof v === 'string' && v.trim())
  const nested = data.error && typeof data.error === 'object'
    ? [data.error.message, data.error.detail, data.error.title, data.error.code].filter(Boolean).join(': ')
    : null
  const code = data.errorCode ?? data.code ?? (data.error && typeof data.error === 'object' ? data.error.code : null)

  // An error key present at all is decisive, results array or not.
  if (nested) return String(nested).slice(0, 400)
  if ('error' in data && message) return String(message).slice(0, 400)
  if (Array.isArray(data.errors) && data.errors.length) {
    const e = data.errors[0] || {}
    return String(e.detail || e.title || e.code || 'the tool reported an error').slice(0, 400)
  }

  const hasResults = Array.isArray(data.vulnerabilities) ||
    Array.isArray(data.infrastructureAsCodeIssues) || Array.isArray(data.runs)
  if (hasResults) return null
  if (message) return code ? `${code}: ${String(message).slice(0, 380)}` : String(message).slice(0, 400)
  if (code != null) return `the tool reported error ${code}`
  return null
}

// The refusals below have to be recognised in RAW TEXT, not only inside a JSON envelope, because
// Snyk frequently does not produce one. Verified behaviours:
//   * an unauthenticated `snyk test --json` prints a Node STACK TRACE to stdout — the CLI serialises
//     `error.json || error.stack`, and the auth error carries no `.json`;
//   * `snyk_trust` / `snyk_auth` refusals from the MCP server are plain sentences;
//   * Snyk Code that is not enabled for the org exits 2 with `Snyk Code is not enabled` on stdout
//     and an EMPTY stderr.
// None of those parse as JSON, so a normaliser alone would only ever say "not valid JSON" — true,
// and useless to a user who needs to be told to run `snyk auth`.

/** Is this refusal about folder trust? The user has to answer that one, and generic text hides it. */
export function isTrustError(reason) {
  return /\btrust(ed|s)?\b|untrusted|snyk_trust/i.test(String(reason || ''))
}

/**
 * Is this refusal about authentication? Same reasoning — "run snyk auth" is the actionable answer.
 *
 * `FailedToGetIacOrgSettingsError` is in here because that is what `snyk iac test --json` really
 * prints, as a bare stack trace, when there is no token: it is an auth failure wearing the name of
 * a settings fetch, and without this line the user is told "unrecognised shape" and sent nowhere.
 */
export function isAuthError(reason) {
  return /auth|token|unauthori[sz]ed|not logged in|SNYK_TOKEN|credential|org.{0,3}settings|FailedToGetIacOrgSettings/i
    .test(String(reason || ''))
}

/** Snyk Code disabled for the org — a licensing answer, not a security one. */
export function isCodeDisabledError(reason) {
  return /Snyk Code is not (enabled|supported)/i.test(String(reason || ''))
}

/**
 * Turn whatever Snyk actually emitted into a sentence a non-expert can act on.
 * @param {string} raw    stdout/stderr, JSON or not
 * @param {string|null} envelopeError  the message snykError() found, when there was an envelope
 */
export function failureReason(raw, envelopeError, ranWhat) {
  // The payload may still be an MCP envelope object whose refusal lives inside `content[].text`,
  // so it is flattened rather than String()'d into "[object Object]".
  const body = typeof raw === 'string' ? raw : (() => { try { return JSON.stringify(raw) } catch { return '' } })()
  const text = `${envelopeError || ''} ${body.slice(0, 4000)}`
  if (isCodeDisabledError(text)) {
    return `${ranWhat} could not run because Snyk Code is not enabled for this Snyk organisation — a plan/entitlement limit, not a finding and not a clean result (enable it in Snyk's Settings → Snyk Code, or rely on semgrep for SAST)`
  }
  // Recorded verbatim from a real run: {"ok": false, "error": "Missing node_modules folder: we
  // can't test without dependencies.\nPlease run 'npm install' first."}. This is the COMMON case
  // for this audience — a cloned repo that was never `npm install`ed — and it is the exact Snyk
  // spelling of the ENOLOCK defect: normalising it to [] would record a project with eleven known
  // CVEs as a clean pass.
  if (/missing node_modules|can't test without dependencies/i.test(text)) {
    return `${ranWhat} needs installed dependencies and this project has none (run \`npm install\` first), so its dependencies were NOT checked against advisories`
  }
  // Trust is checked BEFORE auth: the MCP server refuses an untrusted folder without ever looking
  // at the token, so an untrusted repo would otherwise be reported as an authentication problem and
  // send the user to fix the wrong thing.
  if (isTrustError(text)) {
    return `${ranWhat} refused to scan because the folder is not trusted, so nothing was checked (trust the repository directory itself with snyk_trust, never a parent)`
  }
  if (isAuthError(text)) {
    return `${ranWhat} is not authenticated, so nothing was checked (run \`snyk auth\`, or set SNYK_TOKEN)`
  }
  if (envelopeError) return `${ranWhat} reported an error instead of results (${envelopeError})`
  return `${ranWhat} produced output in a shape this adapter does not recognise`
}

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

const ADVISORY_SEVERITIES = new Set(['critical', 'high', 'medium', 'low'])

/**
 * Snyk's own label, normalised to its four values. Never our severity — the grader owns that.
 *
 * The SARIF levels are mapped per Snyk's documented Code severity table: high = error,
 * medium = warning, low = note/info.
 */
function advisorySeverity(s) {
  const v = String(s ?? '').toLowerCase()
  if (v === 'moderate') return 'medium'                      // npm's word for the same rung
  if (v === 'error') return 'high'                           // SARIF level
  if (v === 'warning') return 'medium'
  if (v === 'note' || v === 'info' || v === 'none') return 'low'
  return ADVISORY_SEVERITIES.has(v) ? v : 'medium'
}

/**
 * Reachability, reduced to the three states the grader has a policy for.
 *
 * Snyk has THREE overlapping vocabularies here and they do not agree, so every one of them is
 * accepted:
 *   - the legacy CLI enum (`src/lib/snyk-test/legacy.ts`): `function`, `package`, `not-reachable`,
 *     `no-info` — and it has since been REMOVED from that file;
 *   - the values that actually appear in recorded output: only `reachable` and `no-path-found`;
 *   - the `--reachability-filter` flag: `reachable | no-info | not-applicable`.
 *
 * `no-info` is the one that matters, and it stays `unknown` ON PURPOSE. The evidence genuinely
 * points both ways: `snyk test --help` on the installed CLI calls the filter "only reachable or
 * non-reachable (no-info)", which reads as a firm no — while the same CLI's own enum lists
 * `no-info` and `not-reachable` as SEPARATE values, and the value that actually appears in recorded
 * output is a third spelling, `no-path-found`.
 *
 * With the tool contradicting itself, the tie goes to the reading that cannot hurt anyone. A
 * `not-reachable` result becomes a `pass` row, and a `pass` is an instruction to stop looking:
 * printing a checkmark over a live CVE is worse than leaving one more row on a work list. So
 * anything short of an explicit no stays `unknown` and grades exactly as it does today.
 *
 * Snyk also warns that `--reachability=true` returns "a new findings schema" in which "some legacy
 * fields may not be available", so this mapping is the first thing to revisit against a real run.
 */
export function normalizeReachability(v) {
  const s = String(v ?? '').toLowerCase().replace(/[\s_]+/g, '-')
  // `function` is the legacy REACHABILITY enum's value for "a call path to the vulnerable FUNCTION
  // was found" — the strongest answer Snyk gives. `package` is its weaker sibling ("the package is
  // reached, the function is unproven") and is deliberately NOT treated as a yes.
  if (s === 'reachable' || s === 'function' || s === 'reachable-function') return 'reachable'
  if (s === 'not-reachable' || s === 'unreachable' ||
      s === 'no-path' || s === 'no-path-found') return 'not-reachable'
  return 'unknown'
}

/**
 * Which weakness class a Snyk Code rule is about. Driven by CWE first (a stable, cross-tool
 * vocabulary) and by the rule id only as a fallback, because rule ids are Snyk's to rename.
 *
 * Anything unrecognised becomes `sast-other` rather than being dropped: grade-or-declare means a
 * result we cannot classify still has to reach the ledger. A silent drop here would be the exact
 * defect this file's contract exists to prevent, one level up.
 */
export function sastKind(cwes = [], ruleId = '', text = '') {
  const c = new Set((cwes || []).map(x => String(x).toUpperCase().replace(/\s+/g, '')))
  const t = `${ruleId} ${text}`.toLowerCase()
  if (c.has('CWE-89') || c.has('CWE-564') || /\bsqli\b|sql-?injection/.test(t)) return 'sast-sqli'
  if (c.has('CWE-79') || c.has('CWE-80') || /\bxss\b|cross-?site-?scripting/.test(t)) return 'sast-xss'
  if (c.has('CWE-918') || /\bssrf\b|server-?side-?request/.test(t)) return 'sast-ssrf'
  if (c.has('CWE-22') || c.has('CWE-23') || c.has('CWE-36') || c.has('CWE-73') ||
      /path-?traversal|\bpt\b|zip-?slip|directory-?traversal/.test(t)) return 'sast-path-traversal'
  return 'sast-other'
}

const norm = p => String(p == null ? '' : p).split(/[\\/]/).join('/')

/**
 * Snyk reports ABSOLUTE paths — a real recorded subject was
 * `snyk:iac-misconfig:C:/Users/hoya2/.../main.tf:1:SNYK-CC-TF-56`. Two things are wrong with that,
 * and the second is the one that bites.
 *
 * A report carrying the author's home directory gets SHARED — screenshots, pasted into a group,
 * handed to a client. That is what this tool is for, so it must not leak a username or a local
 * layout on the way.
 *
 * And a subject id containing a machine-specific path is not STABLE. Subjects are what the user
 * allowlists and what the benchmark's determinism check compares, so an absolute path means an
 * allowlist entry silently stops matching the moment the same scan runs on another machine or in
 * CI, and the finding comes back. Every other finding in ClaudeGuardIL is repo-relative; these are
 * too.
 *
 * Applied once, here, rather than threaded through every normalizer: the normalizers' job is to
 * understand a tool's shape, and where a path is rooted is a different concern.
 */
export function relativizeObservations(observations, root) {
  const base = norm(resolve(String(root || '.'))).replace(/\/+$/, '')
  const lowerBase = base.toLowerCase()
  const strip = p => {
    const n = norm(p)
    if (!base || !n) return n
    if (n.toLowerCase() === lowerBase) return '.'
    // Case-insensitive compare: on Windows the drive letter's case is not meaningful, and snyk and
    // node do not always agree on it.
    return n.toLowerCase().startsWith(lowerBase + '/') ? n.slice(base.length + 1) : n
  }
  return (observations || []).map(o => {
    const was = o.at?.file
    if (!was) return o
    const now = strip(was)
    return {
      ...o,
      at: { ...o.at, file: now },
      // The subject embeds the path verbatim, so rewriting one without the other would leave the
      // finding and its id disagreeing about which file it is.
      subject: typeof o.subject === 'string' ? o.subject.split(was).join(now) : o.subject,
    }
  })
}

/** Every observation is built here, so the shape cannot drift between the four scan types. */
function observation(o) {
  return {
    tier: 'static',
    source: 'snyk',
    scan: o.scan,
    kind: o.kind,
    subject: o.subject,
    at: { file: o.file ? norm(o.file) : null, line: o.line ?? null },
    detail: String(o.detail ?? '').slice(0, 400),
    // Snyk's OWN critical/high/medium/low. An INPUT to the grader, never our severity.
    advisorySeverity: advisorySeverity(o.advisorySeverity),
    // SCA only. `null` where the question does not apply, so a missing answer and an
    // inapplicable one are never the same value.
    reachability: o.reachability ?? null,
    // Snyk Code only. `true` when Snyk proved a source→sink path.
    hasDataflow: o.hasDataflow ?? null,
    cwe: o.cwe ?? null,
    ruleId: o.ruleId ?? null,
    title: String(o.title ?? '').slice(0, 200),
  }
}

const firstCwe = ids => {
  for (const i of ids || []) {
    const m = /CWE-\d+/i.exec(String(i))
    if (m) return m[0].toUpperCase()
  }
  return null
}

// ---------------------------------------------------------------------------
// The MCP summary shape — INFERRED, and labelled as such
//
// What was verified against the LIVE local server (`snyk mcp -t stdio --experimental`,
// snyk 1.1306.2): the 13 tool names and their input schemas, results arriving as
// `{content: [{type: 'text', text: …}]}`, and the untrusted-folder refusal text. What was NOT
// verified is the payload of a SUCCESSFUL MCP scan, because the folder-trust gate fired before any
// scan could run on this machine. The `{success, issueCount, issues[]}` summary handled below is
// inferred from Snyk's published MCP materials — it is a candidate shape, not a recorded one.
//
// That is why the same normalisers ALSO accept the raw CLI documents (which ARE recorded): if the
// server proxies CLI JSON, the CLI branch recognises it; if it returns the summary, this branch
// does; and if it returns something else, the answer is null and an honest coverage row — never a
// silent zero. An adapter that guessed ONE of these and guessed wrong would return null on every
// real call, forever, with nothing throwing to say why.
// ---------------------------------------------------------------------------

function looksLikeMcpScan(d) {
  return !!d && typeof d === 'object' && !Array.isArray(d) && Array.isArray(d.issues) &&
    ('success' in d || 'issueCount' in d)
}

/**
 * The `{success, issueCount, issues[]}` summary attributed to the Snyk MCP server (inferred — see
 * the block comment above).
 *
 * `success` is ambiguous: it could mean "the command ran" or, like the CLI's `ok`, "nothing was
 * found". Both readings are honoured without guessing — `success: false` **with** issues is taken
 * as "here are the issues" (the `ok: false` reading), and `success: false` **without** them is
 * taken as a failed scan and returns null. Under either reading that pair is the answer that cannot
 * mislead: it never invents a clean result, and it never discards findings Snyk actually reported.
 */
export function normalizeMcpScanResult(payload, { scan = 'sca', kind = 'dep-vuln' } = {}) {
  const data = unwrapMcpContent(payload)
  if (data == null) return null
  if (snykError(data)) return null
  if (!looksLikeMcpScan(data)) return null
  if (data.success === false && !data.issues.length) return null

  const out = []
  const seen = new Set()
  for (const i of data.issues) {
    if (!i || typeof i !== 'object') continue
    const cwes = i.cwes || i.CWEs || []
    const isCode = scan === 'code'
    const k = isCode ? sastKind(cwes, i.id, `${i.title ?? ''} ${i.message ?? ''}`) : kind
    const file = i.filePath || null
    const line = Number.isFinite(i.line) && i.line > 0 ? i.line : null
    const pkg = i.packageName ? `${i.packageName}@${i.version ?? '?'}` : null
    const id = String(i.id ?? i.fingerPrint ?? i.title ?? 'unknown')
    const subject = isCode
      ? `snyk:${k}:${norm(file)}:${line ?? '?'}:${id}`
      : `snyk:${k}:${pkg || norm(file) || 'unknown'}:${id}`
    if (seen.has(subject)) continue
    seen.add(subject)
    // A user-suppressed issue is Snyk's own allowlist. Re-raising it would be this tool arguing
    // with a decision the user already recorded in the place they recorded it.
    if (i.isIgnored === true) continue
    out.push(observation({
      scan, kind: k, subject,
      file, line,
      detail: [i.title, i.message].filter(Boolean).join(' — ') ||
        (pkg ? `${id} in ${pkg}` : id),
      advisorySeverity: i.severity,
      // No reachability field exists in this payload. `unknown` is a fact about what we were told,
      // not a default we chose.
      reachability: isCode ? null : 'unknown',
      hasDataflow: isCode ? Array.isArray(i.dataflow) && i.dataflow.length >= 2 : null,
      cwe: firstCwe(cwes),
      ruleId: id,
      title: i.title || id,
    }))
  }
  return out
}

// ---------------------------------------------------------------------------
// snyk_sca_scan  —  `snyk test --json`, or the MCP summary
// ---------------------------------------------------------------------------

/**
 * Positive structural signature. "Not an error" is not a recognition test — and `ok` is NOT one
 * either. The recorded payloads show `ok: false` on BOTH a successful scan that found
 * vulnerabilities and a failed scan ("Missing node_modules folder"): `ok` means "not clean", not
 * "it worked". The discriminator is which KEY is present — `vulnerabilities` (recognised) versus
 * `error` (not recognised) — and snykError() implements the error half.
 */
function looksLikeSca(d) {
  return !!d && typeof d === 'object' && !Array.isArray(d) && Array.isArray(d.vulnerabilities) &&
    ('ok' in d || 'packageManager' in d || 'dependencyCount' in d || 'projectName' in d ||
     'summary' in d || 'displayTargetFile' in d || 'docker' in d)
}

/**
 * How reachability is read, stated exactly because inventing it would be worse than lacking it.
 *
 * The RECORDED free-tier payload (snyk 1.1306.2, 11 real vulns) has NO `reachability` key — the
 * reachability-adjacent fields it does carry are `insights` (only `{triageAdvice: null}`),
 * `functions` and `functions_new` (both empty). Reachability itself is a Snyk Preview behind
 * `--reachability=true`, and its output was not capturable on this plan.
 *
 * So the adapter reads `v.reachability`, then `v.insights.reachability`, and treats absence as
 * `unknown` — which grades weak → needs-review, exactly where run_dep_audit already sits. The
 * upgrade to `likely` fires ONLY when a field is genuinely present and says reachable. A fabricated
 * field that never matched would silently cap everything at unknown while claiming the win; one
 * that matched wrongly would promote findings about code the app never calls.
 */
function reachabilityOf(v) {
  const raw = v.reachability ?? v.insights?.reachability ?? null
  return raw == null ? 'unknown' : normalizeReachability(raw)
}

/**
 * Dependency (open-source) vulnerabilities, with reachability when Snyk computed it.
 *
 * `--all-projects` returns an ARRAY of these documents and a single project returns a bare object
 * — the same command, two top-level types (confirmed for IaC by capture; SCA mirrors it). Inside an
 * array, per-project error documents are SKIPPED rather than poisoning the scan: one member with no
 * node_modules must not delete another member's eleven real CVEs. The skipped ones are surfaced by
 * the CLI as `skippedTargets`, so the partial failure is a stated fact, not a silence. Only when NO
 * document is recognised is the whole payload null — nothing was scanned.
 */
export function normalizeSnykSca(payload, { scan = 'sca', kind = 'dep-vuln' } = {}) {
  const data = unwrapMcpContent(payload)
  if (data == null) return null
  if (Array.isArray(data)) {
    if (!data.length) return null // an empty array says nothing about whether a scan happened
    let recognised = false
    const out = []
    for (const doc of data) {
      if (snykError(doc)) continue // a per-project failure; surfaced separately, never a poison pill
      const part = normalizeSnykSca(doc, { scan, kind })
      if (part === null) return null // a non-error document we cannot read means we do not know what this is
      recognised = true
      out.push(...part)
    }
    return recognised ? out : null
  }
  if (snykError(data)) return null
  // The same tool name serves two transports with two payloads. Checked before the CLI signature
  // because the two are structurally disjoint — `issues` versus `vulnerabilities`.
  if (looksLikeMcpScan(data)) return normalizeMcpScanResult(data, { scan, kind })
  if (!looksLikeSca(data)) return null

  const project = data.projectName || data.displayTargetFile || data.path || null
  const target = data.displayTargetFile || data.targetFile || null
  const out = []
  const seen = new Set()
  for (const v of data.vulnerabilities) {
    if (!v || typeof v !== 'object') continue
    const name = String(v.packageName ?? v.moduleName ?? v.name ?? 'unknown')
    const version = String(v.version ?? '?')
    const id = String(v.id ?? v.identifiers?.CVE?.[0] ?? v.title ?? 'unknown')
    // Snyk lists one entry per (vulnerability, dependency path), so the SAME advisory on the SAME
    // package arrives several times in a normal payload. The grader's subject set answers a repeat
    // with a LAW 2 throw, so the de-duplication has to happen before it gets there.
    const subject = `snyk:${kind}:${name}@${version}:${id}`
    if (seen.has(subject)) continue
    seen.add(subject)
    out.push(observation({
      scan, kind, subject,
      file: target || project, line: null,
      detail: `${v.title || id} in ${name}@${version}` +
        (Array.isArray(v.from) && v.from.length > 1 ? ` (via ${v.from.slice(1).join(' → ')})` : ''),
      advisorySeverity: v.severity,
      reachability: reachabilityOf(v),
      cwe: firstCwe(v.identifiers?.CWE) || null,
      ruleId: id,
      title: v.title || id,
    }))
  }
  return out
}

// ---------------------------------------------------------------------------
// snyk_container_scan  —  `snyk container test --json`
// ---------------------------------------------------------------------------

/**
 * Container image vulnerabilities. Snyk answers in the SCA document shape (plus a `docker` block),
 * so the parsing is shared and only the `kind` differs — the grader grades an OS package CVE the
 * same way it grades an npm one, and reachability analysis does not apply to either.
 */
export function normalizeSnykContainer(payload) {
  return normalizeSnykSca(payload, { scan: 'container', kind: 'container-vuln' })
}

// ---------------------------------------------------------------------------
// snyk_code_scan  —  `snyk code test --json`   (SARIF 2.1.0)
// ---------------------------------------------------------------------------

/**
 * `$schema` is deliberately NOT the gate. Genuine Snyk Code output carries at least two different
 * schema URLs (the oasis-tcs raw one and the docs.oasis-open errata one), so pinning to either
 * would reject half of real output. `version` plus the driver name is the stable signature.
 */
function looksLikeSarif(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d) || !Array.isArray(d.runs)) return false
  if (/^2\./.test(String(d.version ?? ''))) return true
  if (/sarif/i.test(String(d.$schema ?? ''))) return true
  return d.runs.some(r => /snyk/i.test(String(r?.tool?.driver?.name ?? '')))
}

/**
 * Does this result carry a PROVEN source→sink path?
 *
 * SARIF records one in `codeFlows[].threadFlows[].locations[]`. A thread flow with a single
 * location is the sink on its own — Snyk pointing at where the bad thing happens, not at how
 * tainted data got there — so a path needs at least two steps to count. Being strict here is the
 * whole point: `hasDataflow` is what earns `strong` evidence in the grader, and inflating it would
 * hand `likely` to a plain pattern match.
 */
export function hasProvenDataflow(result) {
  for (const cf of result?.codeFlows || []) {
    for (const tf of cf?.threadFlows || []) {
      if (Array.isArray(tf.locations) && tf.locations.length >= 2) return true
    }
  }
  return false
}

/** Rule metadata lives once per run in `tool.driver.rules[]`; results reference it by `ruleId`. */
function ruleIndex(run) {
  const idx = new Map()
  const driver = run?.tool?.driver || {}
  const all = [...(driver.rules || []), ...((run?.tool?.extensions || []).flatMap(e => e.rules || []))]
  for (const r of all) {
    if (r && r.id != null) idx.set(String(r.id), r)
  }
  return idx
}

/**
 * Snyk Code (SAST). The one scan that can upload source, and the one that knows about dataflow.
 *
 * Returns `[]` for a clean run — SARIF with an empty `results` array is a completed scan that found
 * nothing, and it must not be confused with the payload Snyk returns when Code is not enabled for
 * the org, which has no `runs` at all and comes back null.
 */
export function normalizeSnykCode(payload) {
  const data = unwrapMcpContent(payload)
  if (data == null) return null
  if (snykError(data)) return null
  // Over MCP, `snyk_code_scan` runs `snyk code test --sarif` and then REPLACES the SARIF with its
  // own summary, so the same tool name yields two disjoint shapes.
  if (looksLikeMcpScan(data)) return normalizeMcpScanResult(data, { scan: 'code', kind: 'sast-other' })
  if (!looksLikeSarif(data)) return null

  const out = []
  const seen = new Set()
  for (const run of data.runs) {
    const rules = ruleIndex(run)
    for (const r of run?.results || []) {
      if (!r || typeof r !== 'object') continue
      const ruleId = String(r.ruleId ?? '')
      const rule = rules.get(ruleId) || {}
      const cwes = rule.properties?.cwe || rule.properties?.CWE || []
      const text = `${rule.name ?? ''} ${rule.shortDescription?.text ?? ''} ${(rule.properties?.tags || []).join(' ')}`
      const kind = sastKind(cwes, ruleId, text)

      const loc = r.locations?.[0]?.physicalLocation || {}
      const file = loc.artifactLocation?.uri ?? null
      const line = loc.region?.startLine ?? null
      const dataflow = hasProvenDataflow(r)

      const subject = `snyk:${kind}:${norm(file)}:${line ?? '?'}:${ruleId || 'rule'}`
      if (seen.has(subject)) continue
      seen.add(subject)

      out.push(observation({
        scan: 'code', kind, subject,
        file, line,
        detail: r.message?.text ?? rule.shortDescription?.text ?? ruleId,
        // SARIF `level` is Snyk Code's own opinion of this result. Rule-level configuration is the
        // fallback when the result does not restate it.
        advisorySeverity: r.level ?? rule.defaultConfiguration?.level,
        hasDataflow: dataflow,
        cwe: firstCwe(cwes),
        ruleId: ruleId || null,
        title: rule.shortDescription?.text || rule.name || ruleId,
      }))
    }
  }
  return out
}

// ---------------------------------------------------------------------------
// snyk_iac_scan  —  `snyk iac test --json`
// ---------------------------------------------------------------------------

function looksLikeIac(d) {
  return !!d && typeof d === 'object' && !Array.isArray(d) &&
    Array.isArray(d.infrastructureAsCodeIssues) &&
    ('targetFile' in d || 'projectType' in d || 'ok' in d || 'path' in d || 'targetFilePath' in d)
}

/**
 * Dockerfile / Terraform / Kubernetes / CloudFormation / ARM misconfiguration.
 *
 * This is the gap the security-team audit found: the engine listed IaC files and no rule read some
 * of them. Two behaviours confirmed by recorded runs:
 *
 *   * One target returns a bare OBJECT; several return an ARRAY of them. Same command, two
 *     top-level types.
 *   * Snyk IaC does NOT parse GitHub Actions workflows — every `.github/workflows/*.yml` in a
 *     scanned tree comes back as its own `{ok: false, code: 1022, error: 'Failed to parse YAML
 *     file', path}` document. That is a statement about Snyk's parser, not about the workflow, and
 *     this tool's own CG-CI rules grade that surface — so per-file error documents are SKIPPED (and
 *     surfaced by the CLI as `skippedTargets`), never reported as findings and never allowed to
 *     poison the real Terraform results next to them. Only when NO document is recognised is the
 *     payload null.
 */
export function normalizeSnykIac(payload) {
  const data = unwrapMcpContent(payload)
  if (data == null) return null
  if (Array.isArray(data)) {
    if (!data.length) return null
    let recognised = false
    const out = []
    for (const doc of data) {
      if (snykError(doc)) continue
      const part = normalizeSnykIac(doc)
      if (part === null) return null
      recognised = true
      out.push(...part)
    }
    return recognised ? out : null
  }
  if (snykError(data)) return null
  if (!looksLikeIac(data)) return null

  const file = data.targetFilePath || data.targetFile || data.path || null
  const out = []
  const seen = new Set()
  for (const i of data.infrastructureAsCodeIssues) {
    if (!i || typeof i !== 'object') continue
    if (i.isIgnored === true) continue
    const line = Number.isFinite(i.lineNumber) && i.lineNumber > 0 ? i.lineNumber : null
    const id = String(i.publicId ?? i.id ?? i.title ?? 'unknown')
    // An issue's `path` is NOT a file path. It is an array of RESOURCE-GRAPH segments — recorded:
    // `["resource", "aws_security_group[open]", "description"]` — and `msg` is the same thing
    // dot-joined. The file lives on the PARENT document (`targetFilePath`), so reading `i.path` as
    // a filename would point every finding at nothing. Here it disambiguates the subject instead:
    // several issues share one line in one file (three at line 9 in the recorded run), and a
    // repeated subject is a LAW 2 throw.
    const where = Array.isArray(i.path) ? i.path.join('.') : String(i.path ?? i.msg ?? '')
    const subject = `snyk:iac-misconfig:${norm(file)}:${line ?? '?'}:${id}${where ? ':' + where : ''}`
    if (seen.has(subject)) continue
    seen.add(subject)
    // The prose is duplicated: `iacDescription.{issue,impact,resolve}` mirrors the flat keys.
    const d = i.iacDescription || {}
    const title = i.title || d.issue || i.issue || id
    out.push(observation({
      scan: 'iac', kind: 'iac-misconfig', subject,
      file, line,
      detail: [title, d.impact || i.impact].filter(Boolean).join(' — ') || id,
      advisorySeverity: i.severity,
      cwe: firstCwe([i.cwe]),
      ruleId: id,
      title,
    }))
  }
  return out
}

// ---------------------------------------------------------------------------
// Folder trust
// ---------------------------------------------------------------------------

/**
 * The ONE path Snyk may be trusted with.
 *
 * Folder trust is a Snyk MCP / language-server mechanism (`snyk_trust`), not a plain CLI
 * subcommand, so this adapter does not shell out to it — it computes the path an agent must pass,
 * and refuses anything wider. Trust is a persistent grant that covers every subdirectory, so
 * trusting a parent silently authorises every future scan of every sibling project on the machine.
 * The repo under scan, exactly, or nothing.
 *
 * @returns {{path: string|null, refused: string|null}}
 */
export function trustTarget(repoRoot, home = process.env.USERPROFILE || process.env.HOME || '') {
  const p = resolve(String(repoRoot || '.'))
  const h = home ? resolve(home) : null
  if (h && p === h) {
    return { path: null, refused: 'the scan path is your home directory; trusting it would grant Snyk every project on this machine' }
  }
  const parts = p.split(/[\\/]/).filter(Boolean)
  // A drive root or a bare `/` is never a project.
  if (parts.length <= 1) {
    return { path: null, refused: `"${p}" is a filesystem root, not a project directory` }
  }
  return { path: p, refused: null }
}

// ---------------------------------------------------------------------------
// Consent — the source-upload gate
// ---------------------------------------------------------------------------

/**
 * Snyk Code is the only scan that sends the user's SOURCE to a third party. Everything else sends
 * manifest metadata. Uploading a private repository because a security tool defaulted to it is the
 * kind of thing that ends a tool's credibility permanently, so the answer has to be an explicit
 * yes, recorded, with the scan named in the report when it is a no.
 *
 * Two ways to say yes, and no third: the `--code` flag, or a scope-file key. The scope file is the
 * same `claudeguard.scope.yml` the live and DAST tiers already gate on, so consent lives in one
 * place the user can read.
 */
export function readCodeConsent({ flag = false, scope = null } = {}) {
  if (flag) return { granted: true, source: 'flag' }
  const s = scope?.snyk || {}
  const key = s.code_scan_uploads_source ?? s.code_scan ?? null
  if (key === true) return { granted: true, source: 'scope-file' }
  return { granted: false, source: 'none' }
}

// ---------------------------------------------------------------------------
// CLI
//
// Guarded, so importing this module for its normalisers never shells out to `snyk`.
// ---------------------------------------------------------------------------

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  // Parsed in one pass, like grader.mjs: searching the array with indexOf silently picks the wrong
  // element as soon as a flag's value repeats a positional argument.
  const argv = process.argv.slice(2)
  const TAKES_VALUE = new Set(['--scope', '--from-mcp', '--image', '--org'])
  const flags = new Map()
  const positional = []
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (TAKES_VALUE.has(a)) flags.set(a, argv[++i] ?? null)
    else if (a.startsWith('--')) flags.set(a, true)
    else positional.push(a)
  }
  const valueOf = name => { const v = flags.get(name); return typeof v === 'string' ? v : null }
  const root = resolve(positional[0] || '.')

  const has = cmd => {
    try {
      const probe = process.platform === 'win32' ? `where ${cmd}` : `command -v ${cmd}`
      execSync(probe, { stdio: 'ignore' }); return true
    } catch { return false }
  }

  // On Windows an npm-installed CLI is a `snyk.cmd` shim, not an executable. Node refuses to spawn
  // `.cmd`/`.bat` without a shell — the fix for CVE-2024-27980 — so `execFileSync('snyk', …)` threw
  // ENOENT for every scan, `e.stdout` was empty, and each one reported "produced no output at all".
  // The adapter failed closed, which is correct, but it was INERT on Windows: authenticated, no
  // errors, four coverage rows, and it could never have produced a single finding. Dogfooding it is
  // the only reason this was found.
  //
  // `shell: true` would fix it and open a command-injection seam — our argv carries a user-supplied
  // `--image` value and the repo path, and Node deprecated arg-passing under `shell` for exactly
  // that reason. So resolve the CLI's own JS entry point and run it with the node we are already
  // running under: no shell, nothing concatenated, no seam.
  const snykInvocation = (() => {
    if (process.platform !== 'win32') return { cmd: 'snyk', prefix: [] }
    const dirs = []
    try {
      for (const line of execSync('where snyk', { encoding: 'utf8' }).split(/\r?\n/)) {
        const t = line.trim()
        if (t) dirs.push(t.replace(/[\\/][^\\/]+$/, ''))
      }
    } catch { /* not on PATH; the availability check reports that separately */ }
    try { dirs.push(execSync('npm root -g', { encoding: 'utf8' }).trim().replace(/[\\/]node_modules$/i, '')) } catch { /* npm absent */ }
    for (const d of dirs) {
      for (const rel of ['node_modules/snyk/bin/snyk', 'node_modules/snyk/dist/cli/index.js']) {
        const p = resolve(d, rel)
        if (existsSync(p)) return { cmd: process.execPath, prefix: [p] }
      }
    }
    return null
  })()

  const runSnyk = args => {
    if (!snykInvocation) {
      return { out: null, failed: true, stderr: 'snyk is on PATH as a .cmd shim but its JS entry point could not be located, so it could not be run without a shell' }
    }
    try {
      return {
        out: execFileSync(snykInvocation.cmd, [...snykInvocation.prefix, ...args], {
          cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
          maxBuffer: 128 * 1024 * 1024,
          // The CLI is interactive about folder trust unless it already knows the answer. A prompt
          // in a non-interactive run hangs the scan, so the timeout is the backstop.
          timeout: 10 * 60 * 1000,
          env: { ...process.env, SNYK_DISABLE_ANALYTICS: '1' },
        }),
        failed: false,
      }
    } catch (e) {
      // Snyk exits 1 WHEN IT FINDS ISSUES, so the interesting path throws. The JSON is on stdout.
      return { out: e.stdout || null, failed: !e.stdout, stderr: String(e.stderr || e.message || '').slice(0, 400) }
    }
  }

  // ---- scope file / consent -----------------------------------------------
  let scope = null
  const scopeFile = valueOf('--scope') || (existsSync('claudeguard.scope.yml') ? 'claudeguard.scope.yml' : null)
  if (scopeFile && existsSync(scopeFile)) {
    try {
      const { parseSimpleYaml } = await import('./_scope.mjs')
      scope = parseSimpleYaml(readFileSync(scopeFile, 'utf8'))
    } catch { scope = null }
  }
  const consent = readCodeConsent({ flag: flags.get('--code') === true, scope })

  // ---- the environment ----------------------------------------------------
  const available = has('snyk')
  const authenticated = !!(process.env.SNYK_TOKEN || '').trim()
  const trust = trustTarget(root)

  const scans = {
    sca: { ran: false, observations: null, reason: null },
    code: { ran: false, observations: null, reason: null },
    iac: { ran: false, observations: null, reason: null },
    container: { ran: false, observations: null, reason: null },
  }

  const skip = (name, reason) => { scans[name] = { ran: false, observations: null, reason } }
  const record = (name, out, normalize, ranWhat) => {
    if (out == null) {
      skip(name, `${ranWhat} produced no output at all`)
      return
    }
    const parsed = unwrapMcpContent(out)
    // Not JSON at all — the common failure, not an exotic one: an unauthenticated `snyk iac test
    // --json` prints a stack trace, and a disabled Snyk Code prints one English sentence.
    if (parsed == null) {
      skip(name, failureReason(out, null, ranWhat))
      return
    }
    let observations
    try { observations = normalize(parsed) } catch (e) {
      skip(name, `${ranWhat} output could not be normalised: ${String(e.message || e).slice(0, 120)}`)
      return
    }
    // null means the payload was not recognised. This is the branch that stops "Snyk errored" from
    // reaching the grader as "Snyk found nothing".
    if (observations === null) {
      const firstErr = Array.isArray(parsed)
        ? parsed.map(d => snykError(d)).find(Boolean) ?? null
        : snykError(parsed)
      skip(name, failureReason(out, firstErr, ranWhat))
      return
    }
    // A multi-target array can succeed for some targets and fail per-file for others (recorded:
    // Snyk IaC returns code 1022 for every GitHub Actions workflow it meets). The normaliser skips
    // those rather than losing the real results next to them — but a skipped file is a partial
    // limit that has to be VISIBLE, so it is carried alongside, never inferred from silence.
    const skippedTargets = Array.isArray(parsed)
      ? parsed.filter(d => snykError(d)).map(d => ({
        path: d.path ?? null,
        error: String(d.error ?? snykError(d)).slice(0, 120),
        code: d.code ?? null,
      }))
      : []
    scans[name] = { ran: true, observations, reason: null, skippedTargets }
  }

  // ---- an offline / captured run ------------------------------------------
  // `snyk mcp -t stdio --experimental` is how an agent talks to Snyk; its tool results can be
  // captured to a file and normalised here, so the grading path is identical either way.
  const fromMcp = valueOf('--from-mcp')
  if (fromMcp) {
    const captured = safeParse(readFileSync(fromMcp, 'utf8')) || {}
    if (captured.snyk_sca_scan !== undefined) record('sca', captured.snyk_sca_scan, normalizeSnykSca, 'snyk_sca_scan')
    if (captured.snyk_iac_scan !== undefined) record('iac', captured.snyk_iac_scan, normalizeSnykIac, 'snyk_iac_scan')
    if (captured.snyk_container_scan !== undefined) record('container', captured.snyk_container_scan, normalizeSnykContainer, 'snyk_container_scan')
    if (captured.snyk_code_scan !== undefined) {
      if (!consent.granted) {
        skip('code', 'a snyk_code_scan payload was supplied but source-upload consent was not recorded, so it was not read')
      } else {
        record('code', captured.snyk_code_scan, normalizeSnykCode, 'snyk_code_scan')
      }
    }
    // `snyk_iac_scan` and `snyk_container_scan` take no json parameter and have no output mapper, so
    // over MCP they answer in human-readable text. That is a real limit of the transport and it is
    // said out loud rather than left as an unexplained "unrecognised shape".
    for (const n of ['iac', 'container']) {
      if (!scans[n].ran && scans[n].reason && /does not recognise/.test(scans[n].reason)) {
        skip(n, `snyk_${n === 'iac' ? 'iac' : 'container'}_scan returns human-readable text over MCP, not JSON, so nothing structured could be read — run the Snyk CLI directly for this scan`)
      }
    }
    for (const [name, s] of Object.entries(scans)) {
      if (!s.ran && s.reason == null) skip(name, `no ${name} payload was present in ${fromMcp}`)
    }
  } else if (!available) {
    const why = 'the Snyk CLI is not installed, so no Snyk scan ran (install it with `npm i -g snyk`, then `snyk auth`)'
    for (const name of Object.keys(scans)) skip(name, why)
    if (!consent.granted) skip('code', `${why} — and Snyk Code would still be skipped, because it uploads your source to Snyk's cloud and consent was not given`)
  } else if (!authenticated) {
    // SNYK_TOKEN is the explicit grant to THIS automation. The CLI would also accept the session a
    // user created interactively with `snyk auth`, but a background audit silently spending that
    // session is its own consent problem — so the adapter only ever uses a token it was handed.
    const why = 'Snyk is installed but SNYK_TOKEN is not set, so the adapter did not run it (set SNYK_TOKEN; the adapter never borrows your interactive `snyk auth` session)'
    for (const name of Object.keys(scans)) skip(name, why)
    if (!consent.granted) skip('code', `${why} — and Snyk Code would still be skipped, because it uploads your source to Snyk's cloud and consent was not given`)
  } else if (trust.refused) {
    const why = `Snyk was not run because ${trust.refused}, so nothing was checked — point the scan at the repository directory itself`
    for (const name of Object.keys(scans)) skip(name, why)
  } else {
    // `snyk test --json --all-projects` returns an ARRAY of result documents in a monorepo and a
    // single document otherwise; the normaliser handles both.
    const sca = runSnyk(['test', '--json', '--all-projects'])
    record('sca', sca.out, normalizeSnykSca, 'snyk test')

    const iac = runSnyk(['iac', 'test', '--json', root])
    record('iac', iac.out, normalizeSnykIac, 'snyk iac test')

    // Container scanning needs an image reference, which a repository does not carry. Declared
    // rather than skipped silently — "we did not look" has to be readable.
    const image = valueOf('--image')
    if (image) {
      const c = runSnyk(['container', 'test', image, '--json'])
      record('container', c.out, normalizeSnykContainer, `snyk container test ${image}`)
    } else {
      skip('container', 'no image was named (`--image <ref>`), so no container image was scanned')
    }

    if (consent.granted) {
      const code = runSnyk(['code', 'test', '--json', root])
      record('code', code.out, normalizeSnykCode, 'snyk code test')
    } else {
      skip('code', 'Snyk Code (SAST) uploads your source to Snyk\'s cloud, and consent was not given, so no dataflow analysis ran (pass --code, or set snyk.code_scan_uploads_source: true in claudeguard.scope.yml)')
    }
  }

  // Rooted last, so every scan type gets it and no normalizer has to care where the repo lives.
  const observations = relativizeObservations(
    Object.values(scans).flatMap(s => s.observations || []), root)

  console.log(JSON.stringify({
    root,
    available,
    authenticated,
    // The exact folder an agent may hand to the MCP `snyk_trust` tool — the repo under scan and
    // never a parent. Null means trusting anything here would be too wide to be safe.
    trustPath: trust.path,
    codeConsent: consent,
    scans,
    observations,
    total: observations.length,
    note: 'advisorySeverity is Snyk\'s own label, and reachability / hasDataflow are facts, not grades. ' +
      'grader.mjs owns the P-level, derives confidence from evidence, and caps every Snyk finding below `confirmed` — ' +
      'an external tool\'s judgement is never a proof.',
  }, null, 2))
}
