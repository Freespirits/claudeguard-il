#!/usr/bin/env node
// Independent benchmark harness for ClaudeGuardIL.
//
// WHY THIS EXISTS: no change to the engine or the grader may claim "improvement" without evidence.
// This harness measures the tool against a labeled ground-truth corpus (bench/corpus/), so a
// regression that silently stops detecting a planted vulnerability — or starts crying wolf at a
// correct app — fails a release gate instead of shipping.
//
// It imports grade() directly, exactly as the test suite does, and runs the real engine
// (project_model.mjs) as a subprocess. For cases that plant a committed secret it also runs the
// real secret scanner (run_gitleaks.mjs) and feeds it to grade() through the `scanners` option,
// mirroring how `/cg --secrets` wires them together.
//
// Ground truth is DERIVED FROM REALITY: expected.json for each case records what the grader
// actually produces today, asserted so it stays that way. The `notes` field states the INTENT
// first, so a future grader change that breaks a case is visible as a diff against a stated goal,
// not just against an opaque list of ids.
//
// Usage:
//   node bench/run.mjs           run every case, print the scorecard, exit non-zero on a gate fail
//   node bench/run.mjs --dump    print the grader's ACTUAL findings per variant (for authoring
//                                expected.json) and skip the gates
//
// Zero runtime dependencies — Node builtins only, a hard project constraint.
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { performance } from 'node:perf_hooks'
import { isDeepStrictEqual } from 'node:util'
import { grade } from '../plugin/scripts/grader.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const CORPUS = join(HERE, 'corpus')
const ENGINE = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')
const GITLEAKS = join(HERE, '..', 'plugin', 'scripts', 'run_gitleaks.mjs')

// The subdirectory names a case may carry. `vulnerable` is graded for RECALL (its planted findings
// must all appear); `fixed` and `clean` are graded for the FALSE-POSITIVE gate (no unexpected
// confirmed finding may appear on correct code). `clean` and `fixed` are treated identically.
const VARIANTS = ['vulnerable', 'fixed', 'clean']
const CLEAN_VARIANTS = new Set(['fixed', 'clean'])

const DUMP = process.argv.includes('--dump')

// ---------------------------------------------------------------------------
// Running the real tools
// ---------------------------------------------------------------------------

function runEngine(dir) {
  return JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  }))
}

// The secret scanner is a separate subprocess whose JSON is the exact shape grade() expects at
// `scanners.secrets` ({ engine, scannedGitHistory, findings: [{file,line,rule,masked}] }).
function runSecretScanner(dir) {
  return JSON.parse(execFileSync(process.execPath, [GITLEAKS, dir], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  }))
}

// ---------------------------------------------------------------------------
// Corpus discovery
// ---------------------------------------------------------------------------

function discoverCases() {
  if (!existsSync(CORPUS)) return []
  const cases = []
  for (const name of readdirSync(CORPUS).sort()) {
    const dir = join(CORPUS, name)
    if (!statSync(dir).isDirectory()) continue
    const variants = VARIANTS.filter(v => existsSync(join(dir, v)) && statSync(join(dir, v)).isDirectory())
    if (!variants.length) continue
    const expPath = join(dir, 'expected.json')
    const expected = existsSync(expPath) ? JSON.parse(readFileSync(expPath, 'utf8')) : null
    cases.push({ id: name, dir, variants, expected, expPath })
  }
  return cases
}

// ---------------------------------------------------------------------------
// Grading one variant
// ---------------------------------------------------------------------------

function evaluate(caseObj, variant) {
  const dir = join(caseObj.dir, variant)
  const wantSecrets = !!caseObj.expected?.scan?.secrets

  const t0 = performance.now()
  const model = runEngine(dir)
  const opts = {}
  let secretScan = null
  if (wantSecrets) {
    secretScan = runSecretScanner(dir)
    opts.scanners = { secrets: secretScan }
  }
  const result = grade(model, opts)
  const ms = performance.now() - t0

  // Stability: grading the SAME model+scanners twice must be byte-for-byte identical. Determinism
  // is what lets a user trust the diff after a fix; the Set/Map iteration inside the ledger is
  // exactly the kind of thing that can quietly reorder, so we pin it here.
  const again = grade(model, opts)
  const stable = isDeepStrictEqual(result, again)

  return { variant, dir, model, result, secretScan, ms, stable, discovery: model.discovery }
}

// ---------------------------------------------------------------------------
// Matching actual findings against the ground truth
// ---------------------------------------------------------------------------

const atOf = f => (f.evidence?.at?.[0]) || {}

/** Does an actual finding satisfy an `at` clause of the form "file" or "file:line"? */
function atMatches(expectedAt, f) {
  if (!expectedAt) return true
  const m = /^(.*):(\d+)$/.exec(expectedAt)
  const wantFile = m ? m[1] : expectedAt
  const wantLine = m ? Number(m[2]) : null
  const a = atOf(f)
  if (a.file !== wantFile) return false
  if (wantLine != null && a.line !== wantLine) return false
  return true
}

/**
 * Consume-matching so that N expected findings of the same id require N distinct actual findings.
 * A finding matches on id + severity + confidence, plus `subject` and `at` when the ground truth
 * pins them. Matching by shape (not by exact subject) keeps the secret cases stable whether the
 * scan came from gitleaks or the regex fallback, which use different rule ids in the subject.
 */
function matchMustFind(mustFind, actual) {
  const pool = actual.slice()
  const matched = []
  const missing = []
  for (const exp of mustFind) {
    const i = pool.findIndex(f =>
      f.id === exp.id &&
      f.severity === exp.severity &&
      f.confidence === exp.confidence &&
      (exp.subject ? f.subject === exp.subject : true) &&
      atMatches(exp.at, f))
    if (i === -1) missing.push(exp)
    else { matched.push(pool[i]); pool.splice(i, 1) }
  }
  return { matched, missing, leftover: pool }
}

// ---------------------------------------------------------------------------
// Per-variant scoring
// ---------------------------------------------------------------------------

function score(caseObj, ev) {
  const exp = caseObj.expected?.[ev.variant] || {}
  const findings = ev.result.findings
  const isClean = CLEAN_VARIANTS.has(ev.variant)

  const mustFind = exp.mustFind || []
  const allowedAlternates = new Set(exp.allowedAlternates || [])
  const expectConfirmed = new Set(exp.expectConfirmed || [])

  // THE VERDICT GATE. A case may pin the badge itself, not just the finding list. It exists for
  // one shape of defect the finding gates cannot see: a repository where every individual finding
  // is correct and the HEADLINE is still a lie — an open unproven P0/P1, or a scan that read too
  // little, printed as 🟢 clean. Only cases that declare `verdict` are checked, so the existing
  // corpus is untouched.
  const expectedVerdict = exp.verdict ?? null
  const actualVerdict = ev.result.verdict.level
  const verdictMismatch = expectedVerdict && expectedVerdict !== actualVerdict

  const { matched, missing } = matchMustFind(mustFind, findings)

  // The set of ids that are legitimately allowed to appear for this variant.
  const validIds = new Set([...allowedAlternates, ...expectConfirmed, ...mustFind.map(m => m.id)])
  const unexpected = findings.filter(f => !validIds.has(f.id))

  // False positives are UNEXPECTED CONFIRMED findings on a clean/fixed variant — the cry-wolf case
  // that makes this audience rotate live keys over nothing.
  const unexpectedConfirmed = isClean
    ? findings.filter(f => f.confidence === 'confirmed' && !expectConfirmed.has(f.id))
    : []

  // `filesParsed` counts source files; `configParsed` counts files a dedicated parser read instead
  // (workflows, Dockerfiles, Terraform, rules files, manifests, migrations). Both are files the
  // engine actually examined, so both belong in a coverage figure — counting only the first
  // understated coverage on exactly the cases whose whole content is configuration.
  const dc = ev.discovery?.counts || {}
  const disc = {
    filesParsed: (dc.filesParsed || 0) + (dc.configParsed || 0),
    filesDiscovered: dc.filesDiscovered || 0,
  }

  // DECISION RATE — `(pass + fail) / enumerated`, straight from the grader. It is the counter-
  // pressure against the architecture's cheapest exit: LAW 1 makes `undeterminable` the honest
  // answer whenever a token is all we have, which is right, and it is also how a rule can abstain
  // on everything while printing a full coverage table. Nothing else in this harness can tell
  // "we looked hard and could not settle it" apart from "we never tried".
  const dr = ev.result.decisionRate?.overall || { enumerated: 0, decided: 0 }

  return {
    variant: ev.variant,
    isClean,
    findings,
    mustFindCount: mustFind.length,
    matchedCount: matched.length,
    missing,
    valid: findings.length - unexpected.length,
    total: findings.length,
    unexpected,
    unexpectedConfirmed,
    expectedVerdict,
    actualVerdict,
    verdictMismatch,
    enumerated: dr.enumerated,
    decided: dr.decided,
    stable: ev.stable,
    ms: ev.ms,
    filesParsed: disc.filesParsed,
    filesDiscovered: disc.filesDiscovered,
    secretScan: ev.secretScan,
  }
}

// ---------------------------------------------------------------------------
// Dump mode — print the grader's real output so expected.json can be authored from it
// ---------------------------------------------------------------------------

function dump(cases) {
  for (const c of cases) {
    console.log(`\n=== ${c.id} ===`)
    for (const variant of c.variants) {
      const ev = evaluate(c, variant)
      const dc = ev.discovery?.counts || {}
      const dr = ev.result.decisionRate?.overall || {}
      console.log(`\n  [${variant}]  files ${(dc.filesParsed || 0) + (dc.configParsed || 0)}/${dc.filesDiscovered} parsed, ` +
        `verdict=${ev.result.verdict.level}, decided ${dr.decided}/${dr.enumerated}, stable=${ev.stable}, ${ev.ms.toFixed(0)}ms`)
      if (ev.secretScan) console.log(`  secret scan: engine=${ev.secretScan.engine} history=${ev.secretScan.scannedGitHistory} count=${ev.secretScan.count}`)
      if (!ev.result.findings.length) { console.log('    (no findings)'); continue }
      for (const f of ev.result.findings) {
        const a = atOf(f)
        const loc = a.file ? `${a.file}${a.line != null ? ':' + a.line : ''}` : '-'
        console.log(`    ${f.severity} ${f.confidence.padEnd(12)} ${f.id.padEnd(14)} ${f.subject}`)
        console.log(`        at ${loc}`)
      }
    }
  }
  console.log('\n(dump mode — gates not evaluated)')
}

// ---------------------------------------------------------------------------
// Scorecard + gates
// ---------------------------------------------------------------------------

const pct = (n, d) => (d === 0 ? '100.0%' : (100 * n / d).toFixed(1) + '%')

/**
 * THE DECISION-RATE FLOOR — the one gate that ratchets rather than merely holding.
 *
 * `(pass + fail) / enumerated` over the whole corpus: the share of enumerated subjects the grader
 * actually DECIDED, as opposed to abstaining via `undeterminable`. Every other gate here protects
 * against getting louder or wronger. This one protects against getting quieter: LAW 1 makes
 * `undeterminable` the correct answer whenever a token is all the evidence there is, and that same
 * correctness makes it the cheapest possible exit — a rule that abstains everywhere satisfies
 * LAW 2, prints a complete coverage table, and has decided nothing.
 *
 * The floor is the value MEASURED on the corpus as it stands — 41 of 181 subjects decided across
 * 17 variants, 22.65%, rounded down at the third decimal so the gate does not trip on its own
 * rounding. It may not decrease. Raising it after real work is welcome; lowering it is the change
 * this line exists to make somebody justify out loud.
 *
 * It is deliberately not a *target*: 22.65% is low, and it is low for a defensible reason (LAW 1
 * forbids buying a `pass` with a token, and most route/LLM subjects have nothing else to offer).
 * The number is here to be ratcheted upward by better evidence, never to be argued downward.
 */
const DECISION_RATE_FLOOR = 0.226

function run(cases) {
  const failures = []
  const rows = []

  // Aggregates.
  let totalMustFind = 0, totalMatched = 0
  let totalFindings = 0, totalValid = 0
  let cleanVariants = 0, unexpectedConfirmedTotal = 0
  let filesParsed = 0, filesDiscovered = 0
  let subjectsEnumerated = 0, subjectsDecided = 0
  let verdictsPinned = 0
  let allStable = true, totalMs = 0

  for (const c of cases) {
    if (!c.expected) {
      failures.push(`${c.id}: no expected.json — a case without ground truth cannot be graded`)
      continue
    }
    for (const variant of c.variants) {
      const ev = evaluate(c, variant)
      const s = score(c, ev)
      rows.push({ caseId: c.id, ...s })

      totalMustFind += s.mustFindCount
      totalMatched += s.matchedCount
      totalFindings += s.total
      totalValid += s.valid
      filesParsed += s.filesParsed
      filesDiscovered += s.filesDiscovered
      subjectsEnumerated += s.enumerated
      subjectsDecided += s.decided
      totalMs += s.ms
      if (!s.stable) allStable = false
      if (s.isClean) { cleanVariants++; unexpectedConfirmedTotal += s.unexpectedConfirmed.length }
      if (s.expectedVerdict) verdictsPinned++

      // ---- gates ----
      for (const m of s.missing) {
        failures.push(`${c.id}/${variant}: expected finding NOT produced — ${m.id} ${m.severity}/${m.confidence}` +
          `${m.subject ? ' ' + m.subject : ''} (recall gate)`)
      }
      for (const f of s.unexpectedConfirmed) {
        failures.push(`${c.id}/${variant}: UNEXPECTED confirmed finding on clean code — ${f.id} ${f.severity} ${f.subject} (false-positive gate)`)
      }
      if (s.verdictMismatch) {
        failures.push(`${c.id}/${variant}: the HEADLINE is wrong — expected verdict "${s.expectedVerdict}", got ` +
          `"${s.actualVerdict}". Every finding can be right while the badge still lies (verdict gate)`)
      }
      if (!s.stable) failures.push(`${c.id}/${variant}: grade() was not deterministic across two runs (stability gate)`)
    }
  }

  const decisionRate = subjectsEnumerated ? subjectsDecided / subjectsEnumerated : 0
  if (decisionRate < DECISION_RATE_FLOOR) {
    failures.push(`decision rate fell to ${pct(subjectsDecided, subjectsEnumerated)} ` +
      `(${subjectsDecided}/${subjectsEnumerated}); the floor is ${(100 * DECISION_RATE_FLOOR).toFixed(1)}%. ` +
      'The grader is abstaining more than it used to — `undeterminable` is honest, but it is not ' +
      'an answer (decision-rate gate)')
  }

  // ---- scorecard ----
  console.log('\nClaudeGuardIL benchmark scorecard')
  console.log('='.repeat(78))
  console.log(
    'case/variant'.padEnd(38) +
    'recall'.padEnd(9) +
    'prec'.padEnd(8) +
    'FP'.padEnd(5) +
    'verdict'.padEnd(10) +
    'dec'.padEnd(9) +
    'stable'.padEnd(8) +
    'ms')
  console.log('-'.repeat(90))
  for (const r of rows) {
    const name = `${r.caseId}/${r.variant}`
    const recall = r.mustFindCount ? pct(r.matchedCount, r.mustFindCount) : '  -  '
    const prec = r.total ? pct(r.valid, r.total) : '  -  '
    const fp = r.isClean ? String(r.unexpectedConfirmed.length) : '-'
    // A pinned verdict is marked with `=`, so a reader can tell an asserted badge from a reported one.
    const verdict = (r.expectedVerdict ? '=' : ' ') + r.actualVerdict
    const dec = `${r.decided}/${r.enumerated}`
    const bad = r.missing.length || r.unexpectedConfirmed.length || r.verdictMismatch || !r.stable
    console.log(
      (bad ? '! ' : '  ') + name.padEnd(36) +
      recall.padEnd(9) +
      prec.padEnd(8) +
      fp.padEnd(5) +
      verdict.padEnd(10) +
      dec.padEnd(9) +
      (r.stable ? 'yes' : 'NO').padEnd(8) +
      r.ms.toFixed(0))
  }
  console.log('-'.repeat(90))

  console.log('\nAggregate metrics')
  console.log(`  recall (planted vulns detected)   ${pct(totalMatched, totalMustFind)}  (${totalMatched}/${totalMustFind})`)
  console.log(`  precision (valid / all reported)  ${pct(totalValid, totalFindings)}  (${totalValid}/${totalFindings})`)
  console.log(`  false positives (confirmed on clean) ${unexpectedConfirmedTotal}  over ${cleanVariants} clean variant(s)  = ${pct(unexpectedConfirmedTotal, cleanVariants)}`)
  console.log(`  discovery coverage (parsed / found)  ${pct(filesParsed, filesDiscovered)}  (${filesParsed}/${filesDiscovered})`)
  console.log(`  decision rate ((pass+fail)/enumerated) ${pct(subjectsDecided, subjectsEnumerated)}  ` +
    `(${subjectsDecided}/${subjectsEnumerated})  floor ${(100 * DECISION_RATE_FLOOR).toFixed(1)}%` +
    `${decisionRate < DECISION_RATE_FLOOR ? '  ← BELOW FLOOR' : ''}`)
  console.log(`  verdicts pinned by ground truth      ${verdictsPinned} of ${rows.length} variant(s)`)
  console.log(`  stability (deterministic re-runs)    ${allStable ? 'all stable' : 'UNSTABLE'}`)
  console.log(`  runtime                              ${totalMs.toFixed(0)}ms total, ${(totalMs / Math.max(1, rows.length)).toFixed(0)}ms per variant`)

  // ---- verdict ----
  console.log('\n' + '='.repeat(90))
  if (failures.length) {
    console.error(`FAIL — ${failures.length} release gate(s) tripped:`)
    for (const f of failures) console.error('  - ' + f)
    process.exit(1)
  }
  console.log('PASS — all release gates green:')
  console.log('  - recall 100% on every planted vulnerability')
  console.log('  - zero unexpected confirmed findings on fixed/clean code')
  console.log('  - every pinned headline verdict matches (a right finding list can still print a wrong badge)')
  console.log(`  - decision rate ${pct(subjectsDecided, subjectsEnumerated)} at or above its ${(100 * DECISION_RATE_FLOOR).toFixed(1)}% floor`)
  console.log('  - output deterministic across re-runs')
  process.exit(0)
}

// ---------------------------------------------------------------------------
// Exports — so test/benchmark.test.mjs can assert the same gates in-process (no duplicated logic).
// ---------------------------------------------------------------------------

export { discoverCases, evaluate, score, CLEAN_VARIANTS, DECISION_RATE_FLOOR }

// Only take over the process when invoked directly; imported by the test, this file just exports.
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  const cases = discoverCases()
  if (!cases.length) {
    console.error('no cases found under bench/corpus/')
    process.exit(1)
  }
  if (DUMP) dump(cases)
  else run(cases)
}
