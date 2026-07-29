import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { grade, mergeReviewerFindings } from '../plugin/scripts/grader.mjs'

const ENGINE = join(dirname(fileURLToPath(import.meta.url)), '..', 'plugin', 'scripts', 'project_model.mjs')

// A model with two routes: one that fails auth (a `fail` subject) and one whose auth is present but
// unverifiable (an `undeterminable` subject — the reviewer's actual work list). This gives the
// validator real coverage to anchor reviewer findings against.
const MODEL = {
  database: { parserVersion: 2, tables: [] },
  middleware: { providesAuth: false, matchers: [] },
  routes: [
    { file: 'app/api/open/route.ts', kind: 'app-route', methods: ['POST'], mutating: true,
      hasAuthCheck: false, hasValidation: true, readsBody: false },
    { file: 'app/api/guarded/route.ts', kind: 'app-route', methods: ['POST'], mutating: true,
      hasAuthCheck: true, hasValidation: true, readsBody: false },
  ],
}

const graded = () => grade(MODEL)

// A well-formed reviewer finding: a business-logic flaw on the guarded route, which is exactly the
// judgement-level work a rule cannot do (auth is present, but ownership is checked against the
// wrong column).
const goodFinding = (over = {}) => ({
  subject: 'route:app/api/guarded/route.ts',
  title_en: 'Ownership is checked against the wrong column',
  title_he: 'בדיקת הבעלות מתבצעת מול העמודה הלא נכונה',
  severity: 'P1',
  why: 'The handler filters by team_id, but records are owned per-user, so any team member reads any record.',
  at: [{ file: 'app/api/guarded/route.ts', line: 12, snippet: null }],
  exploit: 'A team member changes the id and reads a colleague\'s private record.',
  impact: 'Cross-user data exposure within a tenant.',
  ...over,
})

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS.
//
// The grader proves its OWN findings safe with the assertions in grade(). But the domain auditors
// are LLMs, and their findings land in the same report. Until this validator existed, nothing
// stopped an agent from emitting a `confirmed` P0 on a route that does not exist and turning the
// badge red with no rule behind it. This is the seam the whole "safe to let an LLM contribute to a
// security report" claim rests on, so it is tested adversarially: every law the grader enforces on
// itself must be enforced on agent output too.
// ---------------------------------------------------------------------------

test('a well-formed reviewer finding is accepted, as reviewer/judgement/likely', () => {
  const r = mergeReviewerFindings(graded(), [goodFinding()])
  const f = r.findings.find(x => x.provenance === 'reviewer')
  assert.ok(f)
  assert.equal(f.evidence.strength, 'judgement')
  assert.equal(f.confidence, 'likely', 'no amount of reading is a proof — a reviewer caps at likely')
  assert.equal(f.autofixable, false, 'a reviewer finding is never auto-fixable')
  assert.equal(r.reviewer.accepted, 1)
  assert.equal(r.reviewer.rejected, 0)
})

test('THE KEYSTONE: a reviewer can never move the verdict, even claiming a confirmed P0', () => {
  // The single most important property. An agent asserts the maximum — a confirmed P0 — and the
  // badge must not move, because the verdict counts only confirmed findings and a reviewer finding
  // can never be one. If this regresses, letting an LLM write to the report is unsafe.
  const before = graded()
  const r = mergeReviewerFindings(before, [
    goodFinding({ severity: 'P0', evidence: 'definitive', confidence: 'confirmed' }),
  ])
  assert.equal(r.verdict.level, before.verdict.level)
  assert.equal(r.verdict.confirmedP0, before.verdict.confirmedP0)
  const f = r.findings.find(x => x.provenance === 'reviewer')
  assert.equal(f.confidence, 'likely', 'the claimed confirmed was capped to likely')
  assert.equal(f.severity, 'P0', 'severity is impact-if-true and uncapped — the P0 label survives')
  assert.ok(r.reviewerNotes.some(n => /capped to "judgement"/.test(n)))
})

test('the keystone invariant holds across a fuzz of adversarial claims', () => {
  // Whatever an agent throws at it — every severity, every evidence, a stray confirmed — the
  // confirmed verdict computed from rules must be identical after the merge.
  const before = graded()
  const evils = []
  for (const severity of ['P0', 'P1', 'P2', 'P3', 'P4']) {
    for (const evidence of ['definitive', 'strong', 'weak', 'judgement']) {
      evils.push(goodFinding({ severity, evidence, confidence: 'confirmed' }))
    }
  }
  const r = mergeReviewerFindings(before, evils)
  assert.equal(r.verdict.level, before.verdict.level)
  assert.equal(r.verdict.confirmedP0, before.verdict.confirmedP0)
  assert.equal(r.verdict.confirmedP1, before.verdict.confirmedP1)
  assert.ok(r.findings.every(f => f.provenance !== 'reviewer' || f.confidence === 'likely'))
})

test('LAW 3: a name-only P0 from a reviewer is rejected', () => {
  const r = mergeReviewerFindings(graded(), [
    goodFinding({ severity: 'P0', nameOnly: true }),
  ])
  assert.equal(r.reviewer.accepted, 0)
  assert.equal(r.reviewer.rejected, 1)
  assert.match(r.rejected[0].reason, /LAW 3/)
})

test('a malformed finding is rejected with a specific reason, not merged', () => {
  const r = mergeReviewerFindings(graded(), [
    { subject: 'route:app/api/guarded/route.ts', title_en: 'x' }, // missing most fields
    { ...goodFinding(), severity: 'P9' }, // bad enum
    goodFinding(), // one good one, to prove the batch still processes
  ])
  assert.equal(r.reviewer.accepted, 1)
  assert.equal(r.reviewer.rejected, 2)
  assert.ok(r.rejected.some(x => /missing required field/.test(x.reason)))
  assert.ok(r.rejected.some(x => /invalid severity/.test(x.reason)))
})

test('provenance is set by the channel — a payload claiming rule is forced to reviewer', () => {
  // An agent must not be able to launder its finding into a deterministic-looking one.
  const r = mergeReviewerFindings(graded(), [goodFinding({ provenance: 'rule' })])
  const f = r.findings.find(x => x.title_en.startsWith('Ownership'))
  assert.equal(f.provenance, 'reviewer')
})

test('a finding about an un-enumerated subject is flagged unanchored, not silently trusted', () => {
  // A reviewer finding about a route the engine never saw is either a hallucination or proof the
  // enumeration missed something. Either way the user must be told, not shown a clean-looking
  // finding.
  const r = mergeReviewerFindings(graded(), [
    goodFinding({ subject: 'route:app/api/does-not-exist/route.ts' }),
  ])
  const f = r.findings.find(x => x.provenance === 'reviewer')
  assert.equal(f.unanchored, true)
  assert.equal(r.reviewer.unanchored, 1)
  assert.ok(r.reviewerNotes.some(n => /never enumerated/.test(n)))
})

test('a finding on an enumerated undeterminable subject is anchored and on the work list', () => {
  const r = mergeReviewerFindings(graded(), [goodFinding()])
  const f = r.findings.find(x => x.provenance === 'reviewer')
  assert.ok(!f.unanchored, 'the guarded route is enumerated')
  assert.ok(!f.offWorkList, 'and it is undeterminable — the reviewer\'s actual mandate')
})

test('confidence stays a pure function of evidence after merge; the merged set still sorts', () => {
  const r = mergeReviewerFindings(graded(), [goodFinding(), goodFinding({ severity: 'P3' })])
  for (const f of r.findings) {
    const expect = { definitive: 'confirmed', strong: 'likely', weak: 'needs-review', judgement: 'likely' }[f.evidence.strength]
    assert.equal(f.confidence, expect, `${f.id} confidence must match its evidence`)
  }
  // severity order is preserved across the merged (rule + reviewer) list
  const sev = r.findings.map(f => f.severity)
  const sorted = [...sev].sort((a, b) => Number(a[1]) - Number(b[1]))
  assert.deepEqual(sev, sorted)
})

test('empty reviewer input is a no-op that preserves the graded result', () => {
  const before = graded()
  const r = mergeReviewerFindings(before, [])
  assert.equal(r.findings.length, before.findings.length)
  assert.equal(r.verdict.level, before.verdict.level)
  assert.equal(r.reviewer.accepted, 0)
})

function modelOf(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-law1-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return JSON.parse(execFileSync(process.execPath, [ENGINE, dir], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

test('LAW 1 is mechanical: the routes and llmSites sets can never contain a pass', () => {
  // A route and an LLM site that mention every auth/rate-limit token there is. If a token could
  // earn a pass, this repo would produce one. LAW 1 forbids it — a token is not a proof — and the
  // grader now ASSERTS these sets are pass-free rather than trusting each rule to elect
  // `undeterminable`. This is the backstop against a future rule that regresses into a green check
  // on a bare `getUser`.
  const model = modelOf({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0","openai":"4.60.0","@upstash/ratelimit":"2.0.0"}}',
    'app/api/thing/route.ts': `import OpenAI from 'openai'
import { Ratelimit } from '@upstash/ratelimit'
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
export async function POST(req) {
  const { data: { user } } = await getUser()
  if (!user) return new Response('no', { status: 401 })
  const rl = new Ratelimit({})
  return Response.json(await openai.chat.completions.create({ max_tokens: 100, messages: [] }))
}`,
  })
  const g = grade(model)
  assert.equal(g.coverage.routes.counts.pass, 0, 'a route mentioning getUser() is never a pass')
  assert.equal((g.coverage.llmSites?.counts.pass) || 0, 0, 'an LLM site mentioning auth + rate limit is never a pass')
})
