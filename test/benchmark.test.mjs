import { test } from 'node:test'
import assert from 'node:assert/strict'
import { discoverCases, evaluate, score, CLEAN_VARIANTS } from '../bench/run.mjs'

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

test('clean-baseline is completely silent — every finding it produced would be a false positive', () => {
  const cb = GRADED.find(g => g.caseId === 'clean-baseline')
  assert.ok(cb, 'the clean-baseline case must be graded')
  assert.equal(cb.s.total, 0,
    `clean-baseline produced ${cb.s.total} finding(s); a correct app built only from recommended patterns must grade silent`)
})
