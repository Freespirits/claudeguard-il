import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { cweOf, owaspOf, normalizeSemgrep } from '../plugin/scripts/run_semgrep.mjs'
import { grade } from '../plugin/scripts/grader.mjs'
import { findingSites, findMatch, coveredWith, sastRan, COVERED, DELEGATED } from '../bench/wild.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ENGINE = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS — ERR-008.
//
// ADR 0007 delegates generic dataflow (rce, ssrf, injection-sql, xss) to semgrep instead of building
// `taint.mjs`. Everything needed to score that delegation existed, and one link was missing:
// `run_semgrep.mjs` dropped `extra.metadata.cwe`, so the grader stamped CG-SAST-001 with `cwe: null`.
// `bench/wild.mjs` establishes weakness by category OR CWE, and CG-SAST-001 has no `ID_CATEGORY`
// entry — so a semgrep hit on the exact labelled line agreed on PLACE and failed on WEAKNESS. The
// delegated arm scored zero no matter how good semgrep was, and every one of those labels printed as
// `○ GAP — no rule for this category`, which is the wrong sentence for a category the ADR covers.
//
// These tests are the bridge, asserted end to end. They use RECORDED semgrep payloads and never
// shell out: `semgrep --config auto` fetches rules from semgrep.dev, so a test that ran it would be
// measuring the network — and on a host that blocks that domain it would pass by being skipped,
// which is the failure mode this whole project is about.
// ---------------------------------------------------------------------------

// ---- the adapter -----------------------------------------------------------

test('cweOf pulls the bare id out of semgrep metadata, in every shape it writes it', () => {
  assert.equal(cweOf({ cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')" }), 'CWE-95')
  assert.equal(cweOf({ cwe: ['CWE-79: Cross-site Scripting'] }), 'CWE-79', 'array form')
  assert.equal(cweOf({ cwe: ['CWE-89: SQL Injection', 'CWE-943'] }), 'CWE-89', 'first wins, deterministically')
  assert.equal(cweOf({ cwe: 'cwe-918: SSRF' }), 'CWE-918', 'case-insensitive, normalised upper')
  assert.equal(cweOf({}), null, 'a rule with no CWE gets none — inventing one is worse than a miss')
  assert.equal(cweOf(undefined), null)
  assert.equal(cweOf({ cwe: 'no identifier here' }), null)
})

test('owaspOf normalises to the zero-padded form the grader already uses', () => {
  assert.equal(owaspOf({ owasp: 'A03:2021 - Injection' }), 'A03:2021')
  assert.equal(owaspOf({ owasp: ['A1:2017 - Injection'] }), 'A01:2017', 'padded so it compares')
  assert.equal(owaspOf({}), null)
})

test('normalizeSemgrep forwards weakness identity alongside the tool severity', () => {
  const out = normalizeSemgrep({
    results: [{
      path: 'app\\routes\\contributions.js',
      start: { line: 32 },
      check_id: 'javascript.lang.security.audit.eval-detected',
      extra: {
        severity: 'ERROR',
        message: 'Detected eval() on user input.',
        metadata: { cwe: ["CWE-95: Improper Neutralization of Directives ('Eval Injection')"], owasp: ['A03:2021 - Injection'] },
      },
    }],
  })
  assert.equal(out.length, 1)
  assert.deepEqual(out[0], {
    file: 'app/routes/contributions.js', // backslashes normalised, as run_gitleaks.mjs does
    line: 32,
    rule: 'javascript.lang.security.audit.eval-detected',
    engineSeverity: 'ERROR',
    message: 'Detected eval() on user input.',
    cwe: 'CWE-95',
    owasp: 'A03:2021',
  })
})

test('normalizeSemgrep tolerates an empty or malformed payload', () => {
  assert.deepEqual(normalizeSemgrep({}), [])
  assert.deepEqual(normalizeSemgrep(null), [])
  const [f] = normalizeSemgrep({ results: [{ check_id: 'r' }] })
  assert.equal(f.cwe, null)
  assert.equal(f.file, '')
})

// ---- the grader keeps owning severity -------------------------------------

test('the grader stamps the forwarded CWE on CG-SAST-001 without letting it touch severity', () => {
  const model = { database: { parserVersion: 2, tables: [] } }
  const sast = {
    engine: 'semgrep', available: true, count: 2,
    findings: [
      { file: 'a.js', line: 1, rule: 'r-error', engineSeverity: 'ERROR', message: 'm', cwe: 'CWE-95', owasp: 'A03:2021' },
      { file: 'b.js', line: 2, rule: 'r-warn', engineSeverity: 'WARNING', message: 'm', cwe: null },
    ],
  }
  const findings = grade(model, { scanners: { sast } }).findings.filter(f => f.id === 'CG-SAST-001')
  assert.equal(findings.length, 2)

  const err = findings.find(f => f.subject.endsWith('r-error'))
  assert.equal(err.cwe, 'CWE-95')
  assert.equal(err.owasp, 'A03:2021')
  // Severity still comes from SAST_POLICY[engineSeverity], not from the CWE (ADR 0001).
  assert.equal(err.severity, 'P2')
  assert.notEqual(err.confidence, 'confirmed', 'an external rule match is never auto-confirmed')

  const warn = findings.find(f => f.subject.endsWith('r-warn'))
  assert.equal(warn.cwe, null, 'no CWE in, no CWE out')
  assert.equal(warn.severity, 'P3')
})

// ---- coverage follows the outcome, never the flag -------------------------

test('sastRan is true only when the delegate actually produced results', () => {
  assert.equal(sastRan(null), false, 'not requested')
  assert.equal(sastRan({ engine: 'none', available: false }), false, 'semgrep not installed')
  assert.equal(sastRan({ engine: 'semgrep', available: true, error: 'proxy blocked semgrep.dev' }), false,
    'present but its rule registry was unreachable — asking is not running')
  assert.equal(sastRan({ engine: 'semgrep', available: true, count: 0, findings: [] }), true,
    'ran and found nothing is a real measurement, unlike the three above')
})

test('delegated categories enter recall scope only when the delegate ran', () => {
  for (const c of DELEGATED) {
    assert.equal(COVERED.has(c), false, `${c} has no rule of our own — ADR 0007 delegates it`)
    assert.equal(coveredWith(false).has(c), false, `${c} must not be scored when the delegate did not run`)
    assert.equal(coveredWith(true).has(c), true, `${c} is in scope once semgrep has actually run`)
  }
  // Own-rule categories are unaffected either way.
  assert.ok(coveredWith(false).has('rls-disabled'))
  assert.ok(coveredWith(true).has('rls-disabled'))
  // And a category with neither a rule nor a delegate stays out of scope in both modes.
  assert.equal(coveredWith(true).has('open-cors'), false)
})

// ---- end to end: the bridge actually credits a blind label ----------------

test('a semgrep hit at a labelled dataflow site now matches that label', () => {
  // OWASP NodeGoat holds four of the delegated labels. Real engine, real truth.json, synthetic
  // semgrep payload standing in for the registry fetch — so this asserts the WIRING, and makes no
  // claim about semgrep's real-world reach. That number needs a host that can read semgrep.dev.
  const caseDir = join(HERE, '..', 'bench', 'wild', 'owasp-nodegoat')
  const model = JSON.parse(execFileSync(process.execPath, [ENGINE, join(caseDir, 'repo')], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  }).replace(/^﻿/, ''))

  const sast = {
    engine: 'semgrep', available: true, count: 4,
    findings: [
      { file: 'app/routes/contributions.js', line: 32, rule: 'js.eval-detected', engineSeverity: 'ERROR', message: 'eval', cwe: 'CWE-95' },
      { file: 'app/routes/research.js', line: 15, rule: 'js.ssrf', engineSeverity: 'ERROR', message: 'ssrf', cwe: 'CWE-918' },
      { file: 'app/data/allocations-dao.js', line: 78, rule: 'js.nosql-injection', engineSeverity: 'ERROR', message: 'sqli', cwe: 'CWE-89' },
      { file: 'server.js', line: 137, rule: 'js.xss', engineSeverity: 'ERROR', message: 'xss', cwe: 'CWE-79' },
    ],
  }

  const sites = findingSites(grade(model, { scanners: { sast } }))
  const truth = JSON.parse(readFileSync(join(caseDir, 'truth.json'), 'utf8'))
  const byCategory = c => truth.labels.find(l => l.category === c)

  for (const category of ['rce', 'ssrf', 'injection-sql', 'xss']) {
    const label = byCategory(category)
    assert.ok(label, `truth.json should still carry a ${category} label`)
    const m = findMatch(label, sites)
    assert.ok(m, `the ${category} label at ${label.file}:${label.line} must now be credited to the delegate`)
    assert.equal(m.id, 'CG-SAST-001')
  }
})

test('without the CWE the same hit is invisible — the regression ERR-008 describes', () => {
  const caseDir = join(HERE, '..', 'bench', 'wild', 'owasp-nodegoat')
  const model = JSON.parse(execFileSync(process.execPath, [ENGINE, join(caseDir, 'repo')], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  }).replace(/^﻿/, ''))

  // Identical payload, CWE stripped — i.e. exactly what the adapter forwarded before this change.
  const sast = {
    engine: 'semgrep', available: true, count: 1,
    findings: [{ file: 'app/routes/contributions.js', line: 32, rule: 'js.eval-detected', engineSeverity: 'ERROR', message: 'eval', cwe: null }],
  }
  const sites = findingSites(grade(model, { scanners: { sast } }))
  const truth = JSON.parse(readFileSync(join(caseDir, 'truth.json'), 'utf8'))
  const label = truth.labels.find(l => l.category === 'rce')

  assert.equal(findMatch(label, sites), null,
    'place agreed and weakness did not, so the label went uncredited — this is the bug, pinned so it cannot return')
})
