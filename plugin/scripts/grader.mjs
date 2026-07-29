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
//
// Two rules that follow from the domain model:
//   - Confidence is a pure function of Evidence, so the same repo always grades the same way.
//   - Severity is impact-if-true and is NEVER reduced because we are unsure. Discounting twice
//     buries a catastrophic-but-unproven issue where nobody looks. The renderer compensates by
//     counting only `confirmed` Findings in the headline verdict.
//
// Usage:
//   node grader.mjs <repo-path> [--json]        # runs the engine, then grades
//   node project_model.mjs . | node grader.mjs  # grades a model on stdin
//   node grader.mjs <repo-path> --observations live.json
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

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

// LAW 1, made mechanical. A `pass` in these sets could only ever come from a token in the source
// (a route mentioning `getUser`, an LLM call mentioning an auth check) — and a token is not a
// proof, so a static pass here is exactly the false checkmark LAW 1 forbids. Every legitimate pass
// this grader emits is STRUCTURAL and lives in a different set (RLS proven by a migration, an
// anon-scoped client factory, a security-invoker function). So we can assert the rule outright:
// these sets are never allowed a `pass` row. A future rule that regressed into passing a route on
// a bare `getUser` would throw here instead of printing a green check nobody double-checks.
const NO_PASS_SETS = new Set(['routes', 'llmSites'])

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
    provenance = 'rule',
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
    tier,
    // Evidence is a single concept with a strength and the places that establish it. The
    // renderer shows `at` verbatim so a user can check our work in their own editor.
    evidence: { strength: evidence, nameOnly, why, at },
    exploit, impact, guard, cwe, owasp, autofixable,
    // What would have to be true for this to be a false positive. Stated because "likely" with
    // no named assumption is just hedging.
    assumption,
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
    const subject = `route:${r.file}`
    if (allow.has(subject)) { ledger.record('routes', subject, 'allowlisted', 'user allowlist'); continue }

    const urlPath = urlPathOf(r.file)
    const mwCovers = mwAuth && (matchers.length ? matchers.some(m => matcherCovers(m, urlPath)) : true)

    // Impact-if-true, decided once: a route holding the service-role key bypasses RLS entirely,
    // so an unauthenticated one is a total compromise rather than a scoped one.
    const severity = r.usesServiceRole ? 'P0' : r.mutating ? 'P1' : 'P2'

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
        at: firstAt(r.file),
        exploit: `Anyone sends ${r.methods.join('/')} to ${urlPath} without logging in.`,
        impact: r.usesServiceRole
          ? 'The handler holds the service-role key, which bypasses RLS, so an anonymous caller acts as database owner.'
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
        at: firstAt(r.file),
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
        at: firstAt(r.file),
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
    if (r.usesServiceRole && r.readsIdParam && !r.ownershipFilter) {
      findings.push(finding({
        id: 'CG-WEB-004', subject,
        title_en: `Route ${urlPath} looks up a record by id with no ownership check`,
        title_he: `הנתיב ${urlPath} מאחזר רשומה לפי מזהה ללא בדיקת בעלות`,
        severity: 'P1', evidence: 'weak',
        why: 'The handler reads an id from the request and holds a service-role client, which bypasses RLS, yet no ownership column is compared anywhere in the file.',
        at: firstAt(r.file),
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

function gradeMobile(model, ledger, findings, allow) {
  ledger.declare('mobileArtifacts')
  ledger.declare('exportedComponents')

  for (const man of model.mobile?.android || []) {
    const subject = `android-manifest:${man.file}`
    if (allow.has(subject)) { ledger.record('mobileArtifacts', subject, 'allowlisted', 'user allowlist'); continue }
    const problems = []

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
        guard: 'guard-recipes/network-security-config.md',
        cwe: 'CWE-489', owasp: 'M8', autofixable: true,
      }))
      problems.push('debuggable')
    }

    // Cleartext is only a problem when nothing scopes it. A network security config is exactly the
    // mechanism for allowing one legacy host without opening everything, so crediting it here is
    // what keeps a correctly-configured app quiet.
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
        guard: 'guard-recipes/network-security-config.md',
        cwe: 'CWE-319', owasp: 'M3', autofixable: true,
      }))
      problems.push('cleartext')
    }

    if (man.allowBackup?.value === 'true') {
      findings.push(finding({
        id: 'CG-AND-003', subject,
        title_en: 'App data can be extracted with adb backup',
        title_he: 'ניתן לחלץ את נתוני האפליקציה באמצעות adb backup',
        severity: 'P3', evidence: 'definitive',
        why: 'android:allowBackup="true" permits the platform backup agent to copy the app\'s private data.',
        at: firstAt(man.file, man.allowBackup.line, 'android:allowBackup="true"'),
        exploit: 'Someone with brief physical access to an unlocked device copies the app\'s private storage over USB.',
        impact: 'Stored tokens and local data leave the device without root.',
        guard: 'guard-recipes/network-security-config.md',
        cwe: 'CWE-530', owasp: 'M9', autofixable: true,
      }))
      problems.push('allowBackup')
    }

    ledger.record('mobileArtifacts', subject,
      problems.length ? 'fail' : 'pass',
      problems.length ? problems.join(', ') : 'no debuggable, cleartext or backup exposure declared')

    // Each exported component is separately enumerable, so each gets its own row — the mobile
    // equivalent of walking every route.
    for (const c of man.exportedComponents || []) {
      const cs = `android-component:${man.file}:${c.name}`
      if (allow.has(cs)) { ledger.record('exportedComponents', cs, 'allowlisted', 'user allowlist'); continue }
      if (c.hasPermission) {
        // A permission-guarded export is a deliberate, controlled interface. This is a structural
        // pass: the guard is declared in the manifest, not inferred from a token in code.
        ledger.record('exportedComponents', cs, 'pass', `${c.kind} exported behind a declared permission`)
        continue
      }
      // A content provider hands out data directly, so an unguarded one is worse than an activity.
      const severity = c.kind === 'provider' ? 'P1' : 'P2'
      findings.push(finding({
        id: 'CG-AND-004', subject: cs,
        title_en: `Exported ${c.kind} "${c.name}" has no permission guard`,
        title_he: `הרכיב המיוצא "${c.name}" מסוג ${c.kind} אינו מוגן בהרשאה`,
        severity, evidence: 'definitive',
        why: `android:exported="true" is set with no android:permission, so any app on the device may invoke it.`,
        at: firstAt(man.file, c.line),
        exploit: `A malicious app installed alongside yours invokes this ${c.kind} directly, with no user involvement.`,
        impact: c.kind === 'provider'
          ? 'Any installed app reads or writes the data this provider exposes.'
          : 'Any installed app drives this component, bypassing whatever your UI would have required.',
        guard: 'guard-recipes/network-security-config.md',
        cwe: 'CWE-926', owasp: 'M1',
      }))
      ledger.record('exportedComponents', cs, 'fail', `${c.kind} exported with no permission`)
    }
  }

  for (const pl of model.mobile?.ios || []) {
    const subject = `ios-plist:${pl.file}`
    if (allow.has(subject)) { ledger.record('mobileArtifacts', subject, 'allowlisted', 'user allowlist'); continue }

    if (pl.allowsArbitraryLoads?.value === true) {
      findings.push(finding({
        id: 'CG-IOS-001', subject,
        title_en: 'App Transport Security is disabled for all hosts',
        title_he: 'מנגנון App Transport Security מבוטל עבור כל השרתים',
        severity: 'P2', evidence: 'definitive',
        why: 'NSAllowsArbitraryLoads is true, which turns off the platform requirement for HTTPS.',
        at: firstAt(pl.file, pl.allowsArbitraryLoads.line, 'NSAllowsArbitraryLoads'),
        exploit: 'Anyone on the same network reads and rewrites the app\'s traffic, including tokens.',
        impact: 'Account takeover and content tampering on any untrusted network.',
        guard: 'guard-recipes/network-security-config.md',
        cwe: 'CWE-319', owasp: 'M3',
        assumption: pl.hasExceptionDomains
          ? 'That the NSExceptionDomains block does not already restrict this to hosts you control.'
          : null,
      }))
      ledger.record('mobileArtifacts', subject, 'fail', 'ATS disabled globally')
      continue
    }

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
        guard: 'guard-recipes/network-security-config.md',
        cwe: 'CWE-319', owasp: 'M3',
      }))
      ledger.record('mobileArtifacts', subject, 'fail', 'ATS disabled for web content')
      continue
    }

    // ATS is on by default, so a plist that never weakens it is structurally correct.
    ledger.record('mobileArtifacts', subject, 'pass',
      pl.hasAtsBlock ? 'ATS present and not globally disabled' : 'ATS left at the secure platform default')
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
}

function gradeObservations(observations, ledger, findings) {
  ledger.declare('liveObservations')
  for (const o of observations || []) {
    const subject = `observation:${o.tier}:${o.kind}:${o.subject || o.at || 'target'}`
    const p = OBSERVATION_POLICY[o.kind]
    if (!p) {
      ledger.record('liveObservations', subject, 'undeterminable', `no rule owns observation kind "${o.kind}"`)
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
          tier: 'static', autofixable: false,
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
      ledger.record('scanCoverage', 'scan:dependencies', 'undeterminable',
        'no dependency auditor was available — the lockfile was not checked against advisories')
    } else {
      ledger.record('scanCoverage', 'scan:dependencies', 'pass', 'a dependency auditor ran against the manifest')
      for (const res of dep.results || []) {
        for (const v of res.vulnerabilities || []) {
          const subject = `dependency:${res.ecosystem}:${v.name}`
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
            assumption: 'That the vulnerable code path is actually reached at runtime. Many dependency CVEs sit in code an app never calls.',
          }))
          ledger.record('dependencies', subject, 'fail', `${v.name} (${label})`)
        }
      }
    }
  }
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

function summarize(findings) {
  const confirmed = findings.filter(f => f.confidence === 'confirmed')
  return {
    verdict: {
      rule: 'counts only findings whose confidence is `confirmed`',
      confirmedP0: confirmed.filter(f => f.severity === 'P0').length,
      confirmedP1: confirmed.filter(f => f.severity === 'P1').length,
      level: confirmed.some(f => f.severity === 'P0') ? 'critical'
        : confirmed.some(f => f.severity === 'P1') ? 'high'
          : confirmed.some(f => f.severity === 'P2') ? 'medium'
            : confirmed.length ? 'low' : 'clean',
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
  const summary = summarize(merged)

  // THE KEYSTONE INVARIANT. Reviewer findings may never move the badge, because the verdict counts
  // only confirmed findings and a reviewer finding can never be confirmed. If this ever fails, the
  // cap has a hole and the whole "safe to let an LLM contribute" claim is void.
  if (summary.verdict.level !== graded.verdict.level ||
      summary.verdict.confirmedP0 !== graded.verdict.confirmedP0 ||
      summary.verdict.confirmedP1 !== graded.verdict.confirmedP1) {
    throw new Error('reviewer findings changed the confirmed verdict — the reviewer cap has a hole')
  }

  return {
    ...graded,
    findings: merged,
    ...summary,
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
 * @param {object} [opts.scanners]        { secrets, sast, dependencies } outputs from the adapters
 * @param {string[]} [opts.allowlist]     subject ids the user has accepted
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
  gradeObservations(opts.observations, ledger, findings)
  gradeScanners(opts.scanners, ledger, findings, allow)

  // ---- law enforcement -----------------------------------------------------
  for (const f of findings) {
    if (f.confidence !== CONFIDENCE_BY_EVIDENCE[f.evidence.strength]) {
      throw new Error(`${f.id}: confidence must be a pure function of evidence`)
    }
    if (f.evidence.nameOnly && f.severity === 'P0') {
      throw new Error(`LAW 3 violated by ${f.id}`)
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

  const sorted = sortFindings(findings)
  return {
    generatedBy: 'claudeguard/grader',
    // The verdict counts ONLY confirmed findings. Severity is uncapped precisely because this is
    // where uncertainty is paid for: an unproven P0 is reported, but it does not turn the badge
    // red. See CONTEXT.md, "Severity".
    ...summarize(sorted),
    findings: sorted,
    coverage,
    // DISCOVERY coverage travels alongside analysis coverage, as its own axis: what the engine
    // could and could not SEE, versus how it graded what it saw. The renderer prints them as two
    // separate blocks so a partial scan cannot pass for a complete one. See ADR/methodology.
    discovery: model.discovery || null,
    // Handed to the user verbatim when the schema could not be read, so they can answer the
    // question we could not.
    verifyQuery: model.database?.coverage?.verifyQuery || null,
    limits: model.limits || [],
  }
}

// ---- CLI --------------------------------------------------------------------
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  // Parse in one pass. An earlier version searched the array with indexOf, which silently picked
  // the wrong element whenever a flag value repeated a positional argument.
  const argv = process.argv.slice(2)
  const flags = new Map()
  const positional = []
  const TAKES_VALUE = new Set(['--model', '--observations', '--allowlist',
    '--scanners', '--secrets', '--sast', '--dependencies', '--reviewer'])
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
  }
  const anyScanner = scanners.secrets || scanners.sast || scanners.dependencies

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
}
