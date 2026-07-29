#!/usr/bin/env node
// SARIF 2.1.0 renderer — turns a ClaudeGuardIL graded report into a Static Analysis Results
// Interchange Format log that GitHub Code Scanning ingests natively (PR annotations, the Security
// tab, and "fail CI on NEW findings only" baselining, all for free).
//
// This file is STANDALONE and read-only toward the rest of the tool: it imports nothing from the
// grader and mutates nothing. It consumes the report shape `grade()` already emits — the finding
// schema in core/severity-model.md — and nothing else. Zero runtime dependencies (Node built-ins
// only), same as every other script here.
//
// Three mappings carry the tool's whole philosophy into SARIF, and each is deliberate:
//
//   level ← CONFIDENCE, not severity.  ClaudeGuardIL prints an unproven P0 loudly but never lets it
//     turn a gate red — severity is impact-if-true, confidence is how-sure-we-are, and SARIF `level`
//     is the how-sure axis. So `confirmed → error`, `likely → warning`, `needs-review → note`. A
//     wide-open-but-unproven route arrives as a `note`, exactly as the grader intends.
//
//   security-severity ← SEVERITY.  GitHub reads the `security-severity` property (a CVSS-like number,
//     as a STRING) to sort findings and to decide what blocks a branch. That is the impact axis, so it
//     is mapped from the P-level, independent of `level` above. A P0 sorts to the top even while its
//     `level` is `note`.
//
//   partialFingerprints ← a stable hash of `id::subject`.  This is what lets GitHub tell a NEW finding
//     from one it has already seen, so a CI gate can fire on new problems only. It must be stable
//     across runs and distinct per graded subject — both asserted in the tests.
//
// Determinism is a hard project rule (see the run-record section of severity-model.md): the same
// report must render byte-identical SARIF. So this file reads no clock and no RNG — results are
// sorted by (id, subject) and rules by id, and the one timestamp SARIF can carry is emitted only when
// the CALLER supplies `opts.now`, mirroring how the grader treats `runRecord.generatedAt`.
//
// Usage:
//   node sarif.mjs <cg-graded.json>            # prints the SARIF log to stdout
//   node grader.mjs <repo> --json | ...        # (produce cg-graded.json first)
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// ---------------------------------------------------------------------------
// Constants & policy tables
// ---------------------------------------------------------------------------

const TOOL_NAME = 'ClaudeGuardIL'
const INFORMATION_URI = 'https://github.com/Freespirits/claudeguard-il'
// Used only when a report carries no runRecord.toolVersion (an older or hand-built report). The real
// version rides on the report itself, so the renderer never needs to read package.json.
const TOOL_VERSION_FALLBACK = '0.0.0'
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json'

const SEVERITY_ORDER = ['P0', 'P1', 'P2', 'P3', 'P4']

// P-level → GitHub `security-severity`, a STRING on purpose (SARIF requires it; a number is silently
// dropped by the ingester). The numbers follow severity-model.md's CVSS-lite guidance: P0 ≈ 9–10,
// P1 ≈ 7–8.9, P2 ≈ 4–6.9, P3 ≈ 0.1–3.9, P4 = none.
const SECURITY_SEVERITY = { P0: '9.5', P1: '8.0', P2: '5.0', P3: '3.0', P4: '0.0' }

// Confidence → SARIF level. See the header: this is the load-bearing choice that keeps an unproven
// finding from screaming `error`.
const LEVEL_BY_CONFIDENCE = { confirmed: 'error', likely: 'warning', 'needs-review': 'note' }

const sevIndex = s => {
  const i = SEVERITY_ORDER.indexOf(s)
  return i === -1 ? SEVERITY_ORDER.length : i
}
const securitySeverityOf = sev => SECURITY_SEVERITY[sev] || '0.0'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * The baseline key. Stable per (rule, subject) so GitHub can carry it across runs and recognise a
 * finding it has already seen; distinct per subject so two routes flagged by the same rule are two
 * findings, not one. sha256 hex, first 16 chars — enough to not collide across a repo's findings,
 * short enough to read.
 */
function fingerprintOf(id, subject) {
  return createHash('sha256').update(`${id}::${subject}`).digest('hex').slice(0, 16)
}

/**
 * A finding's `guard` is a repo-relative doc path like `guard-recipes/rls-policies.md#enable-rls`.
 * SARIF `helpUri` wants a URI:
 *   - an already-absolute URL is used verbatim;
 *   - with `opts.helpUriBase` it becomes an absolute URL (e.g. a GitHub blob base), which is what a
 *     CI setup wanting clickable annotations should pass;
 *   - otherwise the relative help path is emitted as-is (a valid relative URI reference);
 *   - a missing guard yields null, and the caller omits the field.
 */
function helpUriFrom(guard, base) {
  if (typeof guard !== 'string') return null
  const g = guard.trim()
  if (!g) return null
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(g)) return g
  if (base) return String(base).replace(/\/+$/, '') + '/' + g.replace(/^\/+/, '')
  return g
}

/** SARIF artifact URIs use forward slashes; a model produced on Windows might carry backslashes. */
const uriOf = file => String(file).replace(/\\/g, '/')

/**
 * One `evidence.at` entry → one SARIF location, or null when there is nothing to point at. A null
 * line (the fact is file-level, e.g. "this route file has no auth") yields a location with an
 * artifact but no region, which is valid SARIF — a startLine must be a real 1-based line or absent.
 */
function locationOf(at) {
  if (!at || !at.file) return null
  const physicalLocation = { artifactLocation: { uri: uriOf(at.file) } }
  if (Number.isInteger(at.line) && at.line > 0) {
    physicalLocation.region = { startLine: at.line }
    // Carried verbatim so the annotation shows the exact line the grader read — the tool's whole
    // "check our work in your own editor" contract, surfaced in the PR.
    if (at.snippet) physicalLocation.region.snippet = { text: String(at.snippet) }
  }
  return { physicalLocation }
}

/** A concise one-liner for the annotation: the title, then the concrete exploit (or impact). */
function messageTextOf(f) {
  const title = String(f.title_en || '').trim()
  const detail = String(f.exploit || f.impact || '').trim()
  return detail ? `${title} — ${detail}` : title
}

// ---------------------------------------------------------------------------
// The renderer
// ---------------------------------------------------------------------------

/**
 * @param {object} report  the return value of grader.mjs `grade()` (or `mergeReviewerFindings`).
 * @param {object} [opts]
 * @param {string} [opts.helpUriBase]  prefix that turns a relative `guard` path into an absolute
 *                                     help URL (e.g. `https://github.com/<org>/<repo>/blob/main/core`).
 * @param {string} [opts.now]          caller-supplied ISO timestamp for the run's endTimeUtc. The
 *                                     renderer never reads a clock itself — determinism is a rule.
 * @returns {object} a SARIF 2.1.0 log object.
 */
export function toSarif(report, opts = {}) {
  const findings = Array.isArray(report?.findings) ? report.findings : []
  const helpBase = opts.helpUriBase || null

  // Deterministic order regardless of how the caller assembled the list: (id, subject), with the
  // title as a last-resort tiebreaker so the sort is a total order even if a pair ever repeats.
  const sorted = findings.slice().sort((a, b) =>
    String(a.id).localeCompare(String(b.id)) ||
    String(a.subject).localeCompare(String(b.subject)) ||
    String(a.title_en || '').localeCompare(String(b.title_en || '')))

  // --- rules: one reportingDescriptor per DISTINCT finding id ---------------
  const ruleById = new Map()
  for (const f of sorted) {
    const seen = ruleById.get(f.id)
    if (!seen) {
      ruleById.set(f.id, {
        id: f.id,
        title: String(f.title_en || f.id),
        guard: f.guard || null,
        pillar: f.pillar || 'security',
        sevIdx: sevIndex(f.severity),
      })
    } else {
      // A single rule id can fire at different severities (CG-WEB-001 is P0 on a service-role route,
      // P1 on an ordinary mutating one). The RULE advertises the worst case so GitHub never
      // under-ranks it; each RESULT still carries its own exact severity below.
      seen.sevIdx = Math.min(seen.sevIdx, sevIndex(f.severity))
      if (!seen.guard && f.guard) seen.guard = f.guard
    }
  }
  const rules = [...ruleById.values()]
    .sort((a, b) => String(a.id).localeCompare(String(b.id)))
    .map(r => {
      const rule = {
        id: r.id,
        name: r.title,
        shortDescription: { text: r.title },
        properties: {
          pillar: r.pillar,
          'security-severity': securitySeverityOf(SEVERITY_ORDER[r.sevIdx]),
        },
      }
      const helpUri = helpUriFrom(r.guard, helpBase)
      if (helpUri) rule.helpUri = helpUri
      return rule
    })

  // --- results: one per finding ---------------------------------------------
  const results = sorted.map(f => {
    const locations = (f.evidence?.at || []).map(locationOf).filter(Boolean)

    const result = {
      ruleId: f.id,
      // level is the CONFIDENCE axis. Unknown confidences fall back to `note`, never `error` — the
      // renderer must not be the thing that turns a badge red on an unrecognised value.
      level: LEVEL_BY_CONFIDENCE[f.confidence] || 'note',
      message: { text: messageTextOf(f) },
    }

    // A finding with an empty `at` is repo-level (e.g. CG-DB-COVERAGE — "RLS state unknown for N
    // tables"). It is a valid result with NO locations array, not a dropped one.
    if (locations.length) result.locations = locations

    // corroboration: another tool independently reported the SAME weakness at the SAME file:line
    // (reconciliation only ever merges same-location findings), so each corroborator shares this
    // finding's location. Surface them as relatedLocations carrying a describing message, so the
    // "two scanners agreed" signal survives into the PR.
    const related = (f.corroboration || []).map(c => {
      const loc = {}
      if (locations[0]) loc.physicalLocation = locations[0].physicalLocation
      const tag = [c.id, c.severity].filter(Boolean).join(' ')
      loc.message = {
        text: `Also reported by ${c.source || 'another tool'}` +
          `${tag ? ` (${tag})` : ''}${c.why ? `: ${c.why}` : ''}`,
      }
      return loc
    })
    if (related.length) result.relatedLocations = related

    result.partialFingerprints = { claudeguardId: fingerprintOf(f.id, f.subject) }
    // Everything a downstream consumer needs to split, filter and sort without re-parsing the
    // report. `pillar` in particular lets a consumer separate security from compliance (a breach
    // from a lawsuit) purely from the SARIF.
    result.properties = {
      pillar: f.pillar || 'security',
      severity: f.severity,
      confidence: f.confidence,
      cwe: f.cwe ?? null,
      owasp: f.owasp ?? null,
      tier: f.tier ?? null,
      subject: f.subject,
      'security-severity': securitySeverityOf(f.severity),
    }
    return result
  })

  const run = {
    tool: {
      driver: {
        name: TOOL_NAME,
        informationUri: INFORMATION_URI,
        version: report?.runRecord?.toolVersion || TOOL_VERSION_FALLBACK,
        rules,
      },
    },
    results,
  }
  // The only clock this renderer reads is the caller's. Present only when `opts.now` is supplied, so
  // default output stays byte-identical run to run — see the header on determinism.
  if (opts.now) run.invocations = [{ executionSuccessful: true, endTimeUtc: opts.now }]

  return {
    version: '2.1.0',
    $schema: SARIF_SCHEMA,
    runs: [run],
  }
}

// ---- CLI --------------------------------------------------------------------

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  const file = process.argv[2]
  if (!file) {
    console.error('usage: node sarif.mjs <cg-graded.json>')
    process.exit(2)
  }
  // A byte-order mark survives `grader.mjs > cg-graded.json` on Windows PowerShell, which is exactly
  // how this file is produced — strip it rather than fail on the common path.
  let report
  try {
    report = JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, ''))
  } catch (e) {
    console.error(`sarif: could not read ${file}: ${e.message}`)
    process.exit(2)
  }
  console.log(JSON.stringify(toSarif(report), null, 2))
}
