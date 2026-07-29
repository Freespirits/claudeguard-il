import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { grade } from '../plugin/scripts/grader.mjs'

// The engine returns an empty-but-valid model for a repo with nothing in it. gradeScanners is
// independent of the model, so these tests feed a minimal model and vary only the scanner input.
const EMPTY_MODEL = { database: { parserVersion: 2, tables: [] } }

function withScanners(scanners, allowlist) {
  return grade(EMPTY_MODEL, { scanners, allowlist })
}

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS.
//
// gitleaks, semgrep and npm-audit each emitted their own JSON, and none of it entered the ledger.
// So LAW 2's promise — every enumerated subject accounted for — silently excluded the entire
// secret, SAST and dependency surface: a repo with a committed private key could still show "full
// coverage". Two of the adapters also passed a tool's OWN severity straight through, which is the
// duplicated severity policy the whole v2 refactor exists to delete.
//
// These tests pin three things: the detections become findings with OUR severity, the subjects
// enter the ledger so LAW 2 covers them, and — the honest part — a scanner that could not run
// properly shows up as a loud `undeterminable` coverage row rather than a silent gap.
// ---------------------------------------------------------------------------

test('a committed privileged secret is a confirmed P0 that reaches the verdict', () => {
  // A value match (not a name match) is exactly what LAW 3 permits to justify a P0. A committed
  // AWS key or private key is the textbook case.
  const r = withScanners({
    secrets: {
      engine: 'gitleaks', scannedGitHistory: true,
      findings: [{ file: '.env', line: 3, rule: 'aws-access-key', masked: 'AKIA…3X9Q' }],
    },
  })
  const f = r.findings.find(x => x.id === 'CG-SEC-001')
  assert.ok(f)
  assert.equal(f.severity, 'P0')
  assert.equal(f.confidence, 'confirmed')
  assert.equal(f.evidence.nameOnly, false, 'a value match is never name-only')
  assert.equal(r.verdict.level, 'critical')
  assert.match(f.assumption, /rotate/i, 'a committed secret must be treated as burned')
})

test('an often-public key (Google/Maps) is held to needs-review, not a P0', () => {
  // The classic scanner false positive. A Google API key is usually a Maps key that is meant to be
  // in the client. Firing a P0 here is the anon-key trust catastrophe with a new rule name.
  const r = withScanners({
    secrets: {
      engine: 'gitleaks', scannedGitHistory: true,
      findings: [{ file: 'src/map.ts', line: 10, rule: 'google-api-key', masked: 'AIza…0abc' }],
    },
  })
  const f = r.findings.find(x => x.id === 'CG-SEC-001')
  assert.notEqual(f.severity, 'P0')
  assert.equal(f.confidence, 'needs-review')
  assert.notEqual(r.verdict.level, 'critical', 'a maybe-public key must not turn the badge red')
})

test('a fallback (regex) secret scan is declared as NOT covering git history', () => {
  // The loud-limit rule. A fallback scan never reads history, so a secret rotated out of the tree
  // but alive in a past commit is invisible. That gap must be a countable coverage row, not silence.
  const r = withScanners({
    secrets: { engine: 'fallback-regex', scannedGitHistory: false, findings: [] },
  })
  const row = r.coverage.scanCoverage.undeterminable.find(s => s.subject === 'scan:secrets')
  assert.ok(row, 'a shallow scan must be recorded as undeterminable coverage')
  assert.match(row.note, /history/i)
})

test('semgrep results become findings with OUR severity, capped at likely', () => {
  // External SAST is a lead, not a proof. An ERROR maps to P2/likely; a WARNING is held lower.
  // Nothing from semgrep may ever be `confirmed`, or its noise would drive the verdict.
  const r = withScanners({
    sast: {
      engine: 'semgrep', available: true, count: 2,
      findings: [
        { file: 'a.ts', line: 1, rule: 'sql-injection', engineSeverity: 'ERROR', message: 'tainted' },
        { file: 'b.ts', line: 2, rule: 'weak-hash', engineSeverity: 'WARNING', message: 'md5' },
      ],
    },
  })
  const err = r.findings.find(f => f.id === 'CG-SAST-001' && f.evidence.at[0].file === 'a.ts')
  const warn = r.findings.find(f => f.id === 'CG-SAST-001' && f.evidence.at[0].file === 'b.ts')
  assert.equal(err.severity, 'P2')
  assert.equal(err.confidence, 'likely')
  assert.equal(warn.severity, 'P3')
  assert.equal(warn.confidence, 'needs-review')
  assert.ok(r.findings.every(f => f.confidence !== 'confirmed' || f.id !== 'CG-SAST-001'),
    'no semgrep finding may be confirmed')
})

test('semgrep not installed is undeterminable coverage, not an empty pass', () => {
  const r = withScanners({ sast: { engine: 'none', available: false, note: 'semgrep not installed' } })
  const row = r.coverage.scanCoverage.undeterminable.find(s => s.subject === 'scan:sast')
  assert.ok(row, 'a SAST pass that never ran must not read as clean')
})

test('a dependency CVE is needs-review because reachability was not checked', () => {
  // The unreachable-CVE false positive is explicitly in the methodology. The advisory severity is
  // the impact-if-true, but confidence stays down until someone confirms the path is reached.
  const r = withScanners({
    dependencies: {
      ran: true,
      results: [{ ecosystem: 'node', tool: 'npm', vulnerabilities: [
        { name: 'lodash', advisorySeverity: 'high', via: ['Prototype Pollution'] },
      ] }],
    },
  })
  const f = r.findings.find(x => x.id === 'CG-DEP-001')
  assert.equal(f.severity, 'P1', 'impact-if-true follows the advisory severity')
  assert.equal(f.confidence, 'needs-review', 'reachability is unverified')
  assert.match(f.assumption, /reached at runtime/i)
})

test('every scanner subject enters the ledger, so LAW 2 covers them', () => {
  const r = withScanners({
    secrets: { engine: 'gitleaks', scannedGitHistory: true, findings: [
      { file: '.env', line: 1, rule: 'stripe-secret', masked: 'sk_l…x' }] },
    sast: { engine: 'semgrep', available: true, count: 1, findings: [
      { file: 'a.ts', line: 1, rule: 'xss', engineSeverity: 'ERROR' }] },
    dependencies: { ran: true, results: [{ ecosystem: 'node', vulnerabilities: [
      { name: 'ws', advisorySeverity: 'moderate' }] }] },
  })
  for (const set of ['secrets', 'sast', 'dependencies', 'scanCoverage']) {
    assert.ok(r.coverage[set], `${set} must be a ledger set`)
  }
  for (const [name, set] of Object.entries(r.coverage)) {
    const c = set.counts
    assert.equal(c.pass + c.fail + c.undeterminable + c.allowlisted, set.enumerated,
      `LAW 2 broken in "${name}"`)
  }
})

test('a scanner subject can be allowlisted', () => {
  // A user who has confirmed their Google key is public, or a CVE is unreachable, accepts it once
  // and it moves out of the findings and into the allowlisted bucket.
  const scanners = {
    secrets: { engine: 'gitleaks', scannedGitHistory: true, findings: [
      { file: 'src/map.ts', line: 10, rule: 'google-api-key', masked: 'AIza…x' }] },
  }
  const subject = 'secret:src/map.ts:10:google-api-key'
  const r = withScanners(scanners, [subject])
  assert.ok(!r.findings.some(f => f.id === 'CG-SEC-001'))
  assert.equal(r.coverage.secrets.counts.allowlisted, 1)
  assert.equal(r.coverage.secrets.counts.fail, 0)
})

test('no scanner input means no scanner sets and no change to a clean verdict', () => {
  const r = grade(EMPTY_MODEL, {})
  assert.ok(!r.coverage.scanCoverage, 'scanCoverage only appears when a scanner ran')
  assert.equal(r.verdict.level, 'clean')
})

// ---------------------------------------------------------------------------
// THE SEAM. Every other test in this file hands `grade()` a hand-written scanner payload, so all of
// them would keep passing if the adapter's real output stopped matching that shape. This one runs
// the adapter as a subprocess and feeds its ACTUAL stdout to the grader — the join every /cg-scan
// run depends on and no test covered.
//
// The unauthenticated case is the right one to pin, because it is the failure that has to stay
// LOUD: an adapter which reported "nothing found" for a scan that never ran would let a project with
// eleven live CVEs print a clean dependency section. Four scans, four declared rows, no findings —
// and a verdict that does not move, because "we could not look" is not evidence of anything.
// ---------------------------------------------------------------------------

test('run_snyk with no token yields four declared coverage rows, no findings, and a clean verdict', () => {
  const HERE = dirname(fileURLToPath(import.meta.url))
  const ADAPTER = join(HERE, '..', 'plugin', 'scripts', 'run_snyk.mjs')
  const dir = mkdtempSync(join(tmpdir(), 'cg-snyk-'))
  try {
    writeFileSync(join(dir, 'package.json'), '{"name":"x","dependencies":{}}', 'utf8')

    // SNYK_TOKEN is the adapter's ONLY grant. Removing it is what makes this deterministic on any
    // machine: installed or not, authenticated interactively or not, the adapter refuses to run and
    // has to say so — it never borrows a `snyk auth` session it was not handed.
    const env = { ...process.env }
    delete env.SNYK_TOKEN

    const r = spawnSync(process.execPath, [ADAPTER, dir], {
      cwd: dir, env, encoding: 'utf8', input: '', timeout: 180000, maxBuffer: 64 * 1024 * 1024,
    })
    if (r.error) throw r.error
    assert.equal(r.status, 0, `the adapter must exit 0 and report the gap in JSON: ${r.stderr}`)

    const snyk = JSON.parse(r.stdout)
    assert.equal(snyk.authenticated, false)
    assert.deepEqual(snyk.observations, [], 'a scan that did not run reports nothing, not zero issues')

    const graded = grade(EMPTY_MODEL, { scanners: { snyk } })
    const rows = graded.coverage.scanCoverage.undeterminable
      .filter(s => s.subject.startsWith('scan:snyk-'))
    assert.deepEqual(rows.map(s => s.subject).sort(),
      ['scan:snyk-code', 'scan:snyk-container', 'scan:snyk-iac', 'scan:snyk-sca'],
      'all four Snyk scans must be declared, or a skipped scan reads as a clean one')
    for (const row of rows) {
      assert.ok(row.note && row.note.trim(), `${row.subject} was declared with no reason`)
    }
    assert.ok(!graded.findings.some(f => f.id.startsWith('CG-SNYK-')),
      'a scan that could not run must not manufacture findings')
    assert.equal(graded.verdict.level, 'clean',
      '"we could not look" must not move the badge in either direction')
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
