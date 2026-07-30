#!/usr/bin/env node
// The WILD benchmark — real-world detection against INDEPENDENT ground truth.
//
// WHY THIS EXISTS, and how it differs from bench/run.mjs. The regression harness (bench/run.mjs) is
// honest about what it is: `expected.json` records what the grader produces TODAY, asserted so it
// stays that way. That makes its recall 100% BY CONSTRUCTION — a vulnerability the grader misses never
// becomes a label, so the number cannot fall except by regression. It is a regression gate, not a
// detection rate, and the ROADMAP/ERRATA say so.
//
// This harness measures the thing that one cannot: real detection on code the tool was NOT tuned on,
// against labels authored INDEPENDENTLY of the tool. The corpus under bench/wild/ is real, fetched
// source (see each case's truth.json `source_url`), labelled by a reviewer who never saw ClaudeGuard's
// rules or output, using a neutral category/CWE vocabulary. So a MISS is visible here — which is the
// entire point. It is a MEASUREMENT, not a pass/fail gate: it always exits 0 (unless asked to gate),
// because a self-fulfilling green light is exactly what it exists to avoid.
//
// HONEST CAVEATS, stated in the scorecard too:
//   - "Recall" is recall against the blind labeller's labels, not against omniscient ground truth: a
//     human reviewer misses things, so the true denominator is at least this large, never smaller.
//   - An unmatched confirmed finding is a CANDIDATE false positive: it may be a real issue the
//     labeller missed. Both are printed for a human to adjudicate, never silently scored.
//   - Categories with no rule AND no delegate (open-cors, and the `other` bucket) are reported
//     separately as known COVERAGE GAPS, so "missed because no rule" is not blamed on detection
//     quality.
//   - Categories ADR 0007 DELEGATES to semgrep (rce, ssrf, injection-sql, xss) are a third state,
//     not a gap: `◍ DELEG` when the delegate did not run, a real ✗ MISS when it ran and came back
//     empty. They used to print as "no rule for this category", which was the wrong sentence about
//     a surface nothing had measured — ERR-008.
//   - Recall is printed over BOTH denominators, in-scope and all-labels, because printing only the
//     narrower one invites being quoted as a detection rate over everything the labeller found.
//
// Usage:
//   node bench/wild.mjs            measure and print the scorecard (exit 0)
//   node bench/wild.mjs --json     emit the raw per-case results as JSON
//   node bench/wild.mjs --sast     also run the delegated semgrep pass (ADR 0007). NOT the default:
//                                  `semgrep --config auto` fetches rules from semgrep.dev, so this
//                                  makes the run depend on a remote registry and stop being
//                                  reproducible. Requires semgrep on PATH and that host reachable;
//                                  when either is missing the delegated labels stay UNMEASURED
//                                  rather than being counted as misses.
//
// Zero runtime dependencies — Node builtins only.
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { grade } from '../plugin/scripts/grader.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const WILD = join(HERE, 'wild')
const ENGINE = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')
const SEMGREP = join(HERE, '..', 'plugin', 'scripts', 'run_semgrep.mjs')
const JSON_OUT = process.argv.includes('--json')
// Opt in to the delegated SAST arm (ADR 0007). Off by default because it reaches semgrep.dev for
// rules, which would make this harness's output depend on a remote registry — see sastFor().
const SAST = process.argv.includes('--sast')
const LINE_TOLERANCE = 6 // labels and findings reference the same real file; allow small drift

// ---------------------------------------------------------------------------
// The bridge between two taxonomies: the neutral label category (and its CWE) and a ClaudeGuardIL
// finding. A label matches a finding when they agree on the WEAKNESS and the PLACE. Weakness is
// established two ways, either sufficient: (1) the finding id maps to the label's category, or (2)
// they share a CWE. CWE is the robust cross-taxonomy key — both sides speak it.
// ---------------------------------------------------------------------------

// ClaudeGuardIL finding id (or id prefix) → neutral category. Best-effort; CWE is the backstop.
const ID_CATEGORY = [
  [/^CG-ENV-/, 'exposed-secret'],
  [/^CG-SECRET-|^CG-GITLEAKS-/, 'exposed-secret'],
  [/^CG-SB-001|^CG-DB-006/, 'privileged-key-client'],
  [/^CG-DB-001|^CG-DB-002|^CG-DB-COVERAGE|^CG-SB-RLS/, 'rls-disabled'],
  [/^CG-FB-00[1-3]/, 'firebase-open-rules'],
  [/^CG-WEB-001/, 'missing-auth'],
  [/^CG-WEB-004/, 'idor'],
  [/^CG-WEB-002/, 'missing-validation'],
  [/^CG-WEB-0(10|20|21|22)/, 'missing-security-headers'],
  [/^CG-LLM-001/, 'llm-key-client'],
  [/^CG-LLM-00[234]/, 'llm-no-limit'],
  [/^CG-PRIV-TLS/, 'cleartext-transit'],
  [/^CG-PRIV-COOKIE/, 'insecure-cookie'],
  [/^CG-DAST-/, 'missing-auth'],
]
function categoryOfFinding(id) {
  for (const [re, cat] of ID_CATEGORY) if (re.test(id)) return cat
  return null
}

// category → the CWE(s) that mean the same weakness. Used when the finding carries a CWE.
const CATEGORY_CWE = {
  'exposed-secret': ['CWE-200', 'CWE-798', 'CWE-312'],
  'privileged-key-client': ['CWE-200', 'CWE-522'],
  'rls-disabled': ['CWE-284', 'CWE-1220'],
  'firebase-open-rules': ['CWE-284', 'CWE-306'],
  'missing-auth': ['CWE-306', 'CWE-862'],
  'idor': ['CWE-639', 'CWE-284'],
  'missing-validation': ['CWE-20'],
  'ssrf': ['CWE-918'],
  'xss': ['CWE-79'],
  'injection-sql': ['CWE-89'],
  'rce': ['CWE-94', 'CWE-95', 'CWE-78'],
  'llm-key-client': ['CWE-200'],
  'llm-no-limit': ['CWE-770', 'CWE-400'],
  'cleartext-transit': ['CWE-319'],
  'insecure-cookie': ['CWE-1004', 'CWE-614'],
  'missing-security-headers': ['CWE-693'],
  'open-cors': ['CWE-942'],
}
// The categories ClaudeGuardIL has a rule OF ITS OWN for. A label outside this set that goes unfound is
// not straightforwardly a detection failure — but see DELEGATED below, because "no rule of our own" and
// "not covered" are not the same statement, and this file used to print them as if they were.
const COVERED = new Set(Object.keys(CATEGORY_CWE).filter(c =>
  ID_CATEGORY.some(([, cat]) => cat === c)))

// The categories ADR 0007 covers BY DELEGATION rather than by a rule of ours. `taint.mjs` was
// deliberately not built — generic interfile dataflow is the most false-positive-prone code in the
// design and mature tools maintain it as their whole product — so these four are semgrep's job,
// wired through the grader like any other observation source.
//
// WHY THIS SET HAS TO EXIST HERE. None of these appears in ID_CATEGORY, so `COVERED` excluded them
// and every one printed as `○ GAP — no rule for this category (known)`. That sentence is false in
// the way that matters: the project does claim to cover them, via a delegate. Worse, the delegate
// was never invoked by this harness at all, so the honest status was neither "covered" nor "no rule"
// but UNMEASURED — and an unmeasured surface printed as a known, accepted gap is precisely the
// silent-clean failure grade-or-declare exists to kill. Retracted as ERR-008 in ERRATA.md.
//
// So coverage of these four is now a FUNCTION of whether the delegate actually ran (`--sast`):
//   ran     → covered, and an unfound label is a real ✗ MISS attributable to semgrep's reach.
//   not run → `◍ DELEGATED (not run)`, an undeterminable, counted in neither recall nor gaps.
const DELEGATED = new Set(['rce', 'ssrf', 'injection-sql', 'xss'])

/**
 * Categories in scope for recall, given whether the delegated SAST arm ACTUALLY RAN.
 *
 * The argument is deliberately the outcome and never the `--sast` flag. Asking for the delegate and
 * getting it are different facts, and conflating them is how `--sast` on a machine with no semgrep
 * turned nine undeterminables into nine MISSES on the first run of this code — inflating the
 * denominator with labels nothing had even looked for. Coverage follows what happened.
 */
function coveredWith(sastRan) {
  return sastRan ? new Set([...COVERED, ...DELEGATED]) : COVERED
}

/** Did the delegated pass actually produce results? Not "was it requested". */
function sastRan(sast) {
  return !!(sast && sast.available && sast.engine !== 'none' && !sast.error)
}

// ---------------------------------------------------------------------------
// Running the tool on one wild case (its real files live in <case>/repo/).
// ---------------------------------------------------------------------------

/**
 * The delegated SAST pass for one case, or null when it was not requested.
 *
 * Opt-in, and deliberately NOT the default: `run_semgrep.mjs` shells out to `semgrep --config auto`,
 * which fetches its ruleset from semgrep.dev. That makes the result a function of a remote registry
 * at the moment of the run — so making it default-on would trade this harness's determinism for a
 * number that drifts when someone else edits a rule. Determinism is a hard project rule, so the
 * default run stays offline and reproducible and the delegated arm is asked for explicitly.
 *
 * A refusal to run is never silent: the return value distinguishes "not installed" from "ran and
 * produced N results", and `gradeScanners` files either into the coverage ledger.
 */
function sastFor(repoDir) {
  if (!SAST) return null
  try {
    const out = execFileSync(process.execPath, [SEMGREP, repoDir], {
      encoding: 'utf8', maxBuffer: 128 * 1024 * 1024,
    })
    return JSON.parse(out || 'null')
  } catch (e) {
    // The adapter is designed not to throw, so reaching here means it could not even be launched.
    return { engine: 'semgrep', available: true, error: `adapter failed to run: ${String(e.message || e).slice(0, 200)}` }
  }
}

/** Returns { report, sast } — the graded report, and what the delegated pass actually did (null if not asked). */
function gradeRepo(repoDir) {
  const model = JSON.parse(execFileSync(process.execPath, [ENGINE, repoDir], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  }).replace(/^﻿/, ''))
  const sast = sastFor(repoDir)
  return { report: sast ? grade(model, { scanners: { sast } }) : grade(model), sast }
}

/** One line describing the delegated pass, for the scorecard. Never silent about a refusal. */
function sastStatus(sast) {
  if (!sast) return 'not requested (default; pass --sast to run it)'
  if (sast.error) return `ERROR — ${String(sast.error).slice(0, 120)}`
  if (!sast.available || sast.engine === 'none') return 'semgrep NOT INSTALLED — delegated categories are undeterminable'
  return `semgrep ran, ${sast.count ?? (sast.findings || []).length} result(s)`
}

// A finding can carry several locations; flatten to {file, line, id, cwe, category, severity, confidence}.
function findingSites(report) {
  const sites = []
  for (const f of report.findings || []) {
    const cat = categoryOfFinding(f.id)
    const ats = (f.evidence?.at || [])
    if (!ats.length) sites.push({ file: null, line: null, id: f.id, cwe: f.cwe || null, category: cat, severity: f.severity, confidence: f.confidence, pillar: f.pillar })
    for (const at of ats) sites.push({ file: normFile(at.file), line: at.line ?? null, id: f.id, cwe: f.cwe || null, category: cat, severity: f.severity, confidence: f.confidence, pillar: f.pillar })
  }
  return sites
}

// Labels reference `repo/<path>`; the engine (run on <case>/repo) reports `<path>`. Normalise both to a
// forward-slash path with any leading `repo/` stripped, so they meet in the middle.
function normFile(p) {
  return String(p == null ? '' : p).replace(/\\/g, '/').replace(/^repo\//, '')
}

function fileMatch(a, b) {
  if (!a || !b) return false
  if (a === b) return true
  // fall back to basename equality — a fetched file may sit at a slightly different depth
  return a.split('/').pop() === b.split('/').pop()
}

function weaknessMatch(label, site) {
  if (site.category && site.category === label.category) return true
  if (site.cwe && label.cwe && site.cwe === label.cwe) return true
  if (site.cwe && (CATEGORY_CWE[label.category] || []).includes(site.cwe)) return true
  return false
}

// Weaknesses that are a property of a WHOLE FILE/CONFIG, not a point: a rules file being world-open,
// an app shipping no security headers. The tool reports one representative location (e.g. the first
// open rule) while the labeller may point at any instance in the same file, so matching these on line
// would undercount a real detection. Matched on file + weakness only.
// rls-disabled is a per-TABLE property, not a per-line one: the tool points at the `create table`
// while the labeller points at the `disable row level security` / `grant … to anon` line, often in a
// different setup script in the same repo. Matching it on line would score a real detection as a miss
// (the verdict is already `critical`). Same reasoning as the open-rules file.
const FILE_LEVEL_CATEGORY = new Set(['firebase-open-rules', 'missing-security-headers', 'rls-disabled'])

// Do this label and this finding site describe the same defect at the same place? A file-level
// weakness (or a file-level finding, line null) agrees on file+weakness; everything else also needs
// the line within tolerance.
function pairMatches(label, s) {
  if (!weaknessMatch(label, s)) return false
  if (!fileMatch(normFile(label.file), s.file)) return false
  if (FILE_LEVEL_CATEGORY.has(label.category) || s.line == null || label.line == null) return true
  return Math.abs(s.line - label.line) <= LINE_TOLERANCE
}

// Does any finding site match this label? (recall direction)
function findMatch(label, sites) {
  for (const s of sites) if (pairMatches(label, s)) return s
  return null
}

// Does this finding site match ANY label? (precision direction) — so a finding that correctly
// identifies a labelled bug is never counted a false positive, even when a SIBLING finding already
// matched the same label (two rules detecting one issue is not one-and-one-FP).
function siteMatchesAnyLabel(s, labels) {
  for (const label of labels) if (pairMatches(label, s)) return true
  return false
}

// ---------------------------------------------------------------------------
// Scoring one case.
// ---------------------------------------------------------------------------

function scoreCase(caseDir, id) {
  const truth = JSON.parse(readFileSync(join(caseDir, 'truth.json'), 'utf8'))
  const { report, sast } = gradeRepo(join(caseDir, 'repo'))
  const sites = findingSites(report)
  const labels = truth.labels || []

  // Recall: for each label, did the tool produce ANY finding (any confidence) at that weakness+place,
  // and separately did it produce a CONFIRMED one? Track misses, and whether the miss is a coverage gap.
  const ran = sastRan(sast)
  const inScope = coveredWith(ran)
  const found = [], foundConfirmed = [], missed = [], gaps = [], delegatedUnrun = []
  for (const label of labels) {
    const covered = inScope.has(label.category)
    const m = findMatch(label, sites)
    if (m) {
      found.push({ label, by: m.id, confidence: m.confidence })
      if (m.confidence === 'confirmed') foundConfirmed.push({ label, by: m.id })
      else {
        // matched but not confirmed — still a detection, noted at its confidence
      }
    } else if (!covered && DELEGATED.has(label.category)) {
      // ADR 0007 delegates this category and the delegate did not run. Neither a miss nor a known
      // gap — an UNDETERMINABLE, kept out of both numbers rather than quietly counted as either.
      delegatedUnrun.push(label)
    } else if (!covered) {
      gaps.push(label) // no rule and no delegate for this category — a known gap, not a detection failure
    } else {
      missed.push(label)
    }
  }

  // Candidate false positives: CONFIRMED security findings that match no label. (Compliance-pillar
  // findings and non-confirmed findings are excluded — the first is a different axis, the second the
  // tool itself flags as unproven.) A candidate FP may be a real issue the labeller missed.
  const candidateFP = []
  const seenFp = new Set()
  for (const s of sites) {
    if (s.pillar === 'compliance') continue
    if (s.confidence !== 'confirmed') continue
    if (s.severity === 'P4') continue // informational (e.g. "RLS on, no policies → deny-all") is not cry-wolf
    if (siteMatchesAnyLabel(s, labels)) continue // correctly identifies a labelled bug → not a false positive
    const key = s.id + '@' + s.file + ':' + s.line
    if (seenFp.has(key)) continue
    seenFp.add(key)
    candidateFP.push(s)
  }

  return {
    id, repo: truth.repo, source: truth.source_url, ref: truth.ref, expectClean: !!truth.expectClean,
    labelCount: labels.length,
    coveredLabelCount: labels.filter(l => inScope.has(l.category)).length,
    found, foundConfirmed, missed, gaps, delegatedUnrun, candidateFP,
    sast: sastStatus(sast), sastRan: ran,
    verdict: report.verdict.level,
  }
}

// ---------------------------------------------------------------------------
// Run.
// ---------------------------------------------------------------------------

function discover() {
  if (!existsSync(WILD)) return []
  return readdirSync(WILD).sort()
    .map(name => ({ name, dir: join(WILD, name) }))
    .filter(c => statSync(c.dir).isDirectory() && existsSync(join(c.dir, 'truth.json')) && existsSync(join(c.dir, 'repo')))
}

// Pure matching functions are exported so the measurement logic can be unit-tested without running
// the engine (test/wild_harness.test.mjs). CWE is the cross-taxonomy key; keep this honest.
export {
  categoryOfFinding, weaknessMatch, findMatch, normFile, fileMatch, findingSites,
  CATEGORY_CWE, COVERED, DELEGATED, coveredWith, sastRan,
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) runScorecard()

function runScorecard() {
const cases = discover()
if (!cases.length) {
  console.error('bench/wild: no cases found under bench/wild/<case>/{repo,truth.json}. The blind labeller populates them.')
  process.exit(0)
}

const results = cases.map(c => scoreCase(c.dir, c.name))

if (JSON_OUT) { console.log(JSON.stringify(results, null, 2)); process.exit(0) }

// --- the scorecard ---------------------------------------------------------
const pct = (n, d) => d ? `${(100 * n / d).toFixed(0)}%` : 'n/a'
// Per case, and from the OUTCOME — see coveredWith(). A run where semgrep was asked for but absent
// must score exactly like a run where it was never asked for.
const scopeOf = r => coveredWith(r.sastRan)
let L = 0, F = 0, Fc = 0, G = 0, FP = 0, D = 0, ALL = 0
console.log('\n════════ WILD BENCHMARK — real code, independent labels ════════\n')
console.log(`delegated SAST arm (ADR 0007): ${results[0]?.sast ?? 'n/a'}\n`)
for (const r of results) {
  ALL += r.labelCount
  L += r.coveredLabelCount
  F += r.found.filter(f => scopeOf(r).has(f.label.category)).length
  Fc += r.foundConfirmed.filter(f => scopeOf(r).has(f.label.category)).length
  G += r.gaps.length; D += r.delegatedUnrun.length; FP += r.candidateFP.length
  const tag = r.expectClean ? 'PRECISION' : 'RECALL   '
  console.log(`● ${tag}  ${r.id}  (${r.repo} @ ${r.ref || '?'})`)
  console.log(`    ${r.labelCount} labels (${r.coveredLabelCount} in covered categories) · verdict ${r.verdict}`)
  if (r.coveredLabelCount) console.log(`    detected: ${r.found.filter(f => scopeOf(r).has(f.label.category)).length}/${r.coveredLabelCount} (any) · ${r.foundConfirmed.filter(f => scopeOf(r).has(f.label.category)).length}/${r.coveredLabelCount} confirmed`)
  for (const m of r.missed) console.log(`    ✗ MISS   [${m.category}] ${m.file}:${m.line} — ${m.note || ''}`)
  for (const d of r.delegatedUnrun) console.log(`    ◍ DELEG  [${d.category}] ${d.file}:${d.line} — delegated to semgrep (ADR 0007); the delegate did not run, so UNMEASURED`)
  for (const g of r.gaps) console.log(`    ○ GAP    [${g.category}] ${g.file}:${g.line} — no rule and no delegate for this category (known)`)
  for (const fp of r.candidateFP) console.log(`    ? maybe-FP ${fp.id} ${fp.file}:${fp.line} (confirmed, unlabelled — adjudicate)`)
  console.log('')
}
console.log('──────── overall ────────')
// BOTH denominators, always. "Covered categories only" is a defensible scope, but printing it alone
// invites being quoted as the detection rate over everything a blind reviewer found — the same
// misreading ERR-006 retracted. So the all-labels figure sits next to it, and neither can travel
// without the other.
console.log(`  in-scope recall, detected at all : ${F}/${L}  (${pct(F, L)})   ← covered categories only`)
console.log(`  in-scope recall, CONFIRMED       : ${Fc}/${L}  (${pct(Fc, L)})`)
console.log(`  ALL-LABELS recall, detected      : ${F}/${ALL}  (${pct(F, ALL)})   ← every label the blind labeller wrote`)
console.log(`  candidate false positives (confirmed, unlabelled): ${FP}`)
console.log(`  labels delegated but UNMEASURED (delegate not run): ${D}`)
console.log(`  labels in categories with no rule and no delegate: ${G}`)
console.log('\n  Caveats: recall is vs a blind human labeller (a floor, not omniscient truth); a')
console.log('  candidate FP may be a real bug the labeller missed. This is a MEASUREMENT, not a gate.')
console.log('  The two recall figures differ only by which labels are in scope — quote both or neither.')
console.log('  Grow the corpus (bench/wild/) to tighten every number.\n')
}
