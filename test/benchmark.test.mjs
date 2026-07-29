import { test } from 'node:test'
import assert from 'node:assert/strict'
import { discoverCases, evaluate, score, CLEAN_VARIANTS, DECISION_RATE_FLOOR } from '../bench/run.mjs'

// ---------------------------------------------------------------------------
// THE BENCHMARK GATES, as CI enforces them.
//
// This is item #2 of the improvement workflow made mechanical: no change to the engine or the
// grader may claim "improvement" without evidence. The harness (bench/run.mjs) measures the tool
// against the labeled corpus (bench/corpus/); this file asserts the three release gates so a
// regression fails the build instead of shipping:
//
//   1. RECALL — every planted finding in a `vulnerable` variant must still be produced. A grader
//      change that silently stops detecting an RLS-off table or a committed key trips this.
//   2. FALSE POSITIVES — no `fixed`/`clean` variant may produce an UNEXPECTED confirmed finding.
//      For this non-expert audience a false P0 is the worst failure: it makes someone rotate live
//      keys over nothing. The clean-baseline case is the cry-wolf guard.
//   3. STABILITY — grading the same model twice must be byte-for-byte identical, or "re-run after a
//      fix and trust the diff" is a lie.
//   4. VERDICT — a case may pin the HEADLINE, not just the finding list. Gates 1-3 all pass on a
//      report whose every finding is right and whose badge is a lie: that is exactly the shape of
//      the unauthenticated-DELETE defect, where a correct P1 at `needs-review` printed 🟢 clean.
//   5. DECISION RATE — `(pass + fail) / enumerated` may not decrease. Gates 1-3 protect against the
//      tool getting louder or wronger; nothing protected against it getting quieter, and
//      `undeterminable` is the cheapest exit in the architecture.
//
// The corpus is graded ONCE here and the three gates read the same results, so a heavy engine
// subprocess runs a minimal number of times.
// ---------------------------------------------------------------------------

const CASES = discoverCases()
const GRADED = CASES.flatMap(c => c.variants.map(v => ({ caseId: c.id, variant: v, s: score(c, evaluate(c, v)) })))

test('the corpus is populated — an empty corpus must not pass vacuously', () => {
  const ids = new Set(CASES.map(c => c.id))
  for (const want of ['nextjs-supabase-rls', 'llm-denial-of-wallet', 'committed-secret', 'clean-baseline']) {
    assert.ok(ids.has(want), `starter case "${want}" is missing from bench/corpus/`)
  }
  assert.ok(GRADED.length >= 6, 'the corpus must exercise several variants for the gates to mean anything')
  assert.ok(CASES.every(c => c.expected), 'every case must carry an expected.json (ground truth)')
})

test('GATE 1 — recall is 100% on every planted vulnerability', () => {
  const vuln = GRADED.filter(g => !CLEAN_VARIANTS.has(g.variant))
  assert.ok(vuln.length, 'there must be at least one vulnerable variant to have recall')
  let planted = 0
  for (const { caseId, variant, s } of vuln) {
    planted += s.mustFindCount
    assert.equal(s.missing.length, 0,
      `${caseId}/${variant}: the grader no longer produces ${s.missing.map(m => `${m.id} ${m.severity}/${m.confidence}`).join(', ')}`)
    assert.equal(s.matchedCount, s.mustFindCount)
  }
  assert.ok(planted > 0, 'the vulnerable variants must actually plant findings')
})

test('GATE 2 — no unexpected confirmed finding on any fixed/clean variant (the cry-wolf gate)', () => {
  const clean = GRADED.filter(g => CLEAN_VARIANTS.has(g.variant))
  assert.ok(clean.length, 'there must be at least one clean/fixed variant to guard against false positives')
  for (const { caseId, variant, s } of clean) {
    assert.equal(s.unexpectedConfirmed.length, 0,
      `${caseId}/${variant}: false positive(s) — ${s.unexpectedConfirmed.map(f => `${f.id} ${f.severity} ${f.subject}`).join(', ')}`)
  }
})

test('GATE 3 — grading is deterministic on every variant', () => {
  for (const { caseId, variant, s } of GRADED) {
    assert.equal(s.stable, true, `${caseId}/${variant}: grade() produced different output across two runs`)
  }
})

test('GATE 4 — every pinned headline verdict matches', () => {
  const pinned = GRADED.filter(g => g.s.expectedVerdict)
  assert.ok(pinned.length, 'at least one case must pin its badge, or the gate is decoration')
  for (const { caseId, variant, s } of pinned) {
    assert.equal(s.actualVerdict, s.expectedVerdict,
      `${caseId}/${variant}: the finding list may be perfect and the badge still wrong — ` +
      `expected "${s.expectedVerdict}", got "${s.actualVerdict}"`)
  }
})

test('GATE 5 — the decision rate has not decreased', () => {
  // The ratchet. `undeterminable` is the honest answer whenever a token is all the evidence there
  // is (LAW 1), and that is precisely what makes it the cheapest way to stop deciding anything.
  const enumerated = GRADED.reduce((n, g) => n + g.s.enumerated, 0)
  const decided = GRADED.reduce((n, g) => n + g.s.decided, 0)
  assert.ok(enumerated > 0, 'no subjects enumerated — the rate would be vacuous')
  const rate = decided / enumerated
  assert.ok(rate >= DECISION_RATE_FLOOR,
    `decision rate fell to ${(100 * rate).toFixed(2)}% (${decided}/${enumerated}); ` +
    `the floor is ${(100 * DECISION_RATE_FLOOR).toFixed(2)}%. The grader is abstaining more than it did.`)
})

test('THE DEFECT ITSELF — a repo with an open unauthenticated DELETE is never `clean`', () => {
  // The regression this whole change exists for, asserted on the corpus rather than on a synthetic
  // model. `unauthenticated-delete/vulnerable` confirms NOTHING, so under the old rule it printed a
  // green badge over an endpoint any stranger could call to destroy data.
  const bad = GRADED.find(g => g.caseId === 'unauthenticated-delete' && g.variant === 'vulnerable')
  assert.ok(bad, 'the unauthenticated-delete case must be graded')
  assert.equal(bad.s.actualVerdict, 'unknown')

  // And its `fixed` twin proves the rule did not simply paint everything `unknown`: same shape,
  // same routes, authentication added — and the badge goes green.
  const good = GRADED.find(g => g.caseId === 'unauthenticated-delete' && g.variant === 'fixed')
  assert.ok(good)
  assert.equal(good.s.actualVerdict, 'clean')
})

test('clean-baseline is completely silent — every finding it produced would be a false positive', () => {
  const cb = GRADED.find(g => g.caseId === 'clean-baseline')
  assert.ok(cb, 'the clean-baseline case must be graded')
  assert.equal(cb.s.total, 0,
    `clean-baseline produced ${cb.s.total} finding(s); a correct app built only from recommended patterns must grade silent`)
})
