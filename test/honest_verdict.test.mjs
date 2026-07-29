import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readdirSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  grade, mergeReviewerFindings, gateExitCode, CLI_FLAGS_TAKING_VALUE, CLI_ONLY_FLAGS,
} from '../plugin/scripts/grader.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = join(HERE, '..')
const ENGINE = join(REPO, 'plugin', 'scripts', 'project_model.mjs')
const GRADER = join(REPO, 'plugin', 'scripts', 'grader.mjs')

function modelOf(dir) {
  return JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
    encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
  }))
}

function gradeRepo(files, opts) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-verdict-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return grade(modelOf(dir), opts)
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

// ---------------------------------------------------------------------------
// LAW 4 — THE `clean` VERDICT MUST NOT LIE.
//
// THE DEFECT. The verdict counted `confirmed` findings and nothing else. An unauthenticated DELETE
// endpoint is graded P1 at `needs-review` — correctly, because the absence of an auth token is not
// proof that the route is unauthenticated (LAW 1) — and `needs-review` did not count. So a
// repository whose delete endpoint any stranger can call printed 🟢 CLEAN.
//
// That is the one failure this audience cannot detect for itself. A false positive costs a user an
// afternoon; a false all-clear costs them the database. The badge is now a function of
// COVERAGE × CONFIRMED, and `unknown` is what it says when it cannot say `clean` honestly.
// ---------------------------------------------------------------------------

const UNAUTH_DELETE = {
  'package.json': JSON.stringify({ name: 'x', dependencies: { next: '15.0.0' } }),
  // headers() present, so nothing here lands as a CONFIRMED finding — the whole point of the case
  // is a repo where every confirmed count is zero.
  'next.config.js': `module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: "default-src 'self'" }] }]
  },
}`,
  'app/api/projects/[id]/route.ts': `export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  await fetch('https://example.invalid/delete/' + params.id, { method: 'DELETE' })
  return new Response(null, { status: 204 })
}`,
}

test('LAW 4: an unauthenticated DELETE grades `unknown`, never `clean`', () => {
  const r = gradeRepo(UNAUTH_DELETE)

  assert.equal(r.verdict.confirmedP0, 0, 'nothing is confirmed here — that is the premise')
  assert.equal(r.verdict.confirmedP1, 0)
  assert.equal(r.verdict.confirmedLevel, null)
  assert.equal(r.verdict.unprovenP1, 1, 'the open DELETE is an unproven P1')

  assert.equal(r.verdict.level, 'unknown',
    'a wide-open DELETE endpoint may never be reported as a clean bill of health')

  // The clause that fires matters: this repo was read completely, so it is the OPEN FINDING that
  // costs it the green badge, not a thin scan. If this ever flips, the case stops testing LAW 4's
  // (c) clause and starts testing its (b) clause by accident.
  assert.equal(r.verdict.discoveryCoverage.adequate, true)
  assert.deepEqual(r.verdict.discoveryCoverage.reasons, [])

  const f = r.findings.find(x => x.id === 'CG-WEB-001')
  assert.equal(f.severity, 'P1')
  assert.equal(f.confidence, 'needs-review', 'severity is uncapped; the uncertainty is paid in confidence')
})

test('LAW 4 does NOT paint everything unknown — a correct, fully-read app is still `clean`', () => {
  // The counter-test, and the one that keeps this change honest. If the fix were to make every
  // report say "unknown", it would be worthless in exactly the same way `clean` was: a badge that
  // never varies carries no information.
  const r = gradeRepo({
    'package.json': JSON.stringify({ name: 'ok', dependencies: { next: '15.0.0', '@supabase/ssr': '0.5.0' } }),
    'next.config.js': `module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: [{ key: 'Content-Security-Policy', value: "default-src 'self'" }] }]
  },
}`,
    'middleware.ts': `import { createServerClient } from '@supabase/ssr'
export async function middleware(req) {
  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, { cookies: req.cookies })
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
}
export const config = { matcher: ['/api/:path*'] }`,
    'app/api/projects/[id]/route.ts': `import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'
export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  const db = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, { cookies })
  const { data: { user } } = await db.auth.getUser()
  if (!user) return new Response('unauthorized', { status: 401 })
  return new Response(null, { status: 204 })
}`,
  })

  assert.deepEqual(r.findings.map(f => `${f.severity} ${f.id}`), [],
    'a correct app must stay silent — anything here is a false positive')
  assert.equal(r.verdict.level, 'clean')
  assert.equal(r.verdict.unprovenP0 + r.verdict.unprovenP1, 0)
  assert.equal(r.verdict.discoveryCoverage.adequate, true)
  assert.equal(r.verdict.discoveryCoverage.ratio, 1)
})

test('LAW 4: a repo the engine could barely read is `unknown`, whatever the findings say', () => {
  // The (b) clause on its own. Discovery is the other half of an honest badge: accounting for
  // every subject you enumerated means nothing if you never opened half the repo.
  const base = { database: { parserVersion: 2, tables: [] } }
  const withDiscovery = counts => grade({ ...base, discovery: { counts, reconciles: true } })

  const thin = withDiscovery({ filesDiscovered: 10, filesParsed: 5, configParsed: 0, unsupported: 0, oversized: 4, readErrors: 1 })
  assert.equal(thin.verdict.level, 'unknown')
  assert.equal(thin.verdict.discoveryCoverage.adequate, false)
  assert.match(thin.verdict.discoveryCoverage.reasons[0], /files the engine set out to read/)

  // Deliberate, accounted-for exclusions are NOT a coverage hole. A repo that is mostly images and
  // lockfiles has not been under-read, and flipping it to `unknown` for owning a logo would be the
  // cry-wolf failure wearing a different hat.
  const mostlyAssets = withDiscovery({ filesDiscovered: 100, filesParsed: 4, configParsed: 0, unsupported: 96, oversized: 0, readErrors: 0 })
  assert.equal(mostlyAssets.verdict.discoveryCoverage.adequate, true)
  assert.equal(mostlyAssets.verdict.level, 'clean')

  // A ledger that does not add up cannot support any verdict at all.
  const broken = grade({ ...base, discovery: { counts: { filesDiscovered: 10, filesParsed: 10, configParsed: 0, unsupported: 0, oversized: 0, readErrors: 0 }, reconciles: false } })
  assert.equal(broken.verdict.level, 'unknown')
  assert.match(broken.verdict.discoveryCoverage.reasons.join(' '), /does not reconcile/)

  // No ledger at all is not neutral. If absence counted as adequate, deleting one key off the
  // model would be the cheapest way to buy a green badge.
  const noLedger = grade(base)
  assert.equal(noLedger.verdict.level, 'unknown')
  assert.match(noLedger.verdict.discoveryCoverage.reasons[0], /no discovery ledger/)
})

test('LAW 4 leaves every graded level alone — only `clean` can become `unknown`', () => {
  const r = grade(modelOf(join(REPO, 'sample-vulnerable-app')))
  assert.equal(r.verdict.level, 'critical', 'a repo with confirmed P0s keeps its badge')
  assert.equal(r.verdict.confirmedLevel, 'critical')
  assert.ok(r.verdict.unprovenP0 + r.verdict.unprovenP1 > 0,
    'and it has unproven P0/P1 too — which must not change the level it already earned')
})

test('a reviewer may cost a repo its green badge, but can never reach a graded level', () => {
  // THE KEYSTONE, restated for LAW 4. A reviewer finding is capped at `likely` and can never be
  // confirmed, so it can never redden the badge. It CAN move `clean` to `unknown` — an unsettled
  // P1 from someone who read the code is exactly a reason we cannot claim proven-safe — and that
  // is the only transition mergeReviewerFindings permits.
  const before = gradeRepo({
    'package.json': JSON.stringify({ name: 'q' }),
    'lib/util.ts': 'export const noop = () => {}',
  })
  assert.equal(before.verdict.level, 'clean')

  const subject = before.coverage.ungradedSurfaces?.undeterminable?.[0]?.subject ||
    Object.values(before.coverage).flatMap(s => [...s.pass, ...s.fail, ...s.undeterminable, ...s.allowlisted])[0]?.subject
  const after = mergeReviewerFindings(before, [{
    subject: subject ?? 'file:lib/util.ts',
    title_en: 'Ownership is checked against the wrong column',
    title_he: 'בדיקת הבעלות מתבצעת מול העמודה הלא נכונה',
    severity: 'P1',
    exploit: 'A signed-in user edits another account\'s row.',
    impact: 'Cross-tenant write.',
  }])

  assert.equal(after.verdict.confirmedLevel, null, 'a reviewer can never reach a graded level')
  assert.equal(after.verdict.confirmedP0, 0)
  assert.equal(after.verdict.confirmedP1, 0)
  assert.equal(after.verdict.level, 'unknown', 'but an unsettled reviewer P1 does cost the green badge')
  assert.equal(after.runRecord.verdict, 'unknown',
    'the run record must attest the badge that was actually printed, not the pre-merge one')
})

// ---------------------------------------------------------------------------
// The run record — a reproducible attestation of WHAT WAS RUN.
// ---------------------------------------------------------------------------

test('runRecord is byte-identical across two runs on the same model, except generatedAt', () => {
  const model = modelOf(join(REPO, 'sample-vulnerable-app'))
  const a = grade(model).runRecord
  const b = grade(model).runRecord
  assert.deepEqual(a, b, 'two runs on one model must produce one run record')
  assert.equal(a.generatedAt, null, 'the grader never reads a clock — a timestamp must be supplied')

  const stamped = grade(model, { now: '2026-07-29T00:00:00.000Z' }).runRecord
  assert.equal(stamped.generatedAt, '2026-07-29T00:00:00.000Z')
  assert.deepEqual({ ...stamped, generatedAt: null }, a,
    'the ONLY field a clock may touch is generatedAt')
})

test('runRecord attests what ran — version, commit, model identity, verdict', () => {
  const model = modelOf(join(REPO, 'sample-vulnerable-app'))
  const r = grade(model)
  const rec = r.runRecord

  assert.equal(rec.toolVersion, JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8')).version)
  assert.ok(rec.commit === null || /^[0-9a-f]{40}$/.test(rec.commit), 'a commit or an honest null')
  assert.match(rec.modelHash, /^sha256:[0-9a-f]{64}$/)
  assert.equal(rec.ledgerReconciles, true)
  assert.equal(rec.verdict, r.verdict.level)
  assert.equal(rec.confirmedP0, r.verdict.confirmedP0)
  assert.match(rec.note, /not a statement that this repository is secure/i,
    'it attests what was run — it must never read as a certificate of safety')

  // The hash is of the MODEL, so a different repo is a different hash and the same repo is not.
  const other = grade(modelOf(join(REPO, 'bench', 'corpus', 'unauthenticated-delete', 'vulnerable')))
  assert.notEqual(other.runRecord.modelHash, rec.modelHash)

  // Key ORDER is not identity: the same facts hash the same however the JSON was assembled.
  const reordered = JSON.parse(JSON.stringify(model))
  const shuffled = Object.fromEntries(Object.entries(reordered).reverse())
  assert.equal(grade(shuffled).runRecord.modelHash, rec.modelHash)
})

// ---------------------------------------------------------------------------
// --gate: the exit code IS the verdict.
// ---------------------------------------------------------------------------

const gateOn = dir => spawnSync(process.execPath, [GRADER, dir, '--gate'], { encoding: 'utf8' })

test('--gate exits 1 on a confirmed P0/P1, 2 on unknown, 0 on clean', () => {
  const bad = gateOn(join(REPO, 'sample-vulnerable-app'))
  assert.equal(bad.status, 1, 'a confirmed P0 must block a deploy')
  assert.match(bad.stderr, /CRITICAL/)

  const unproven = gateOn(join(REPO, 'bench', 'corpus', 'unauthenticated-delete', 'vulnerable'))
  assert.equal(unproven.status, 2, 'not proven safe is not the same as safe')
  assert.match(unproven.stderr, /UNKNOWN — NOT PROVEN SAFE/)

  const ok = gateOn(join(REPO, 'bench', 'corpus', 'unauthenticated-delete', 'fixed'))
  assert.equal(ok.status, 0)
  assert.match(ok.stderr, /CLEAN/)

  // The report still goes to stdout in every case, so the gate composes with a reporting step.
  for (const r of [bad, unproven, ok]) assert.ok(JSON.parse(r.stdout).verdict)
})

test('an agent cannot argue the gate green — a reviewer finding can only ever raise the exit code', () => {
  // The whole agent-deploy story in one assertion. Reviewer findings are capped at `likely`, so
  // they can never produce the `confirmed` count that a 0 depends on being zero; and an unsettled
  // reviewer P0/P1 pushes a `clean` repo to `unknown`, i.e. from 0 to 2. There is no path by which
  // more agent output lowers this number.
  assert.equal(gateExitCode({ level: 'critical', confirmedP0: 1, confirmedP1: 0 }), 1)
  assert.equal(gateExitCode({ level: 'high', confirmedP0: 0, confirmedP1: 2 }), 1)
  assert.equal(gateExitCode({ level: 'unknown', confirmedP0: 0, confirmedP1: 0 }), 2)
  assert.equal(gateExitCode({ level: 'clean', confirmedP0: 0, confirmedP1: 0 }), 0)
  // Confirmed hygiene findings do not block: a gate that fires on a missing Referrer-Policy is a
  // gate somebody switches off, and then it protects nothing at all.
  assert.equal(gateExitCode({ level: 'medium', confirmedP0: 0, confirmedP1: 0 }), 0)
  assert.equal(gateExitCode({ level: 'low', confirmedP0: 0, confirmedP1: 0 }), 0)
})

// ---------------------------------------------------------------------------
// Decision rate — the counter-pressure against a cheap `undeterminable`.
// ---------------------------------------------------------------------------

test('the grader publishes (pass + fail) / enumerated per subject set and overall', () => {
  const r = grade(modelOf(join(REPO, 'sample-vulnerable-app')))
  const d = r.decisionRate
  assert.ok(d, 'a coverage table full of `undeterminable` is a complete accounting of nothing')

  let enumerated = 0
  let decided = 0
  for (const [setName, set] of Object.entries(r.coverage)) {
    const row = d.bySet[setName]
    assert.ok(row, `every subject set needs a decision rate — ${setName} has none`)
    assert.equal(row.enumerated, set.enumerated)
    assert.equal(row.decided, set.counts.pass + set.counts.fail)
    assert.equal(row.abstained, set.counts.undeterminable)
    assert.equal(row.rate, set.enumerated ? row.decided / set.enumerated : null)
    enumerated += set.enumerated
    decided += row.decided
  }
  assert.equal(d.overall.enumerated, enumerated)
  assert.equal(d.overall.decided, decided)
  assert.equal(d.overall.rate, decided / enumerated)
  assert.ok(d.overall.rate > 0, 'a grader that decides nothing has abstained its way to silence')
})

// ---------------------------------------------------------------------------
// Ship or declare, turned inward on the CLI.
// ---------------------------------------------------------------------------

test('every value-taking grader flag is either shipped in a skill or declared CLI-only', () => {
  // The same assertion CI makes, run locally so a new flag is caught before it is pushed. A flag
  // nobody teaches and nobody declares keeps consuming its argv element long after the code behind
  // it has moved on, and the first person to notice is a user whose file was silently ignored.
  const skillsDir = join(REPO, 'plugin', 'skills')
  const named = new Set()
  for (const entry of readdirSync(skillsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const md = join(skillsDir, entry.name, 'SKILL.md')
    if (!existsSync(md)) continue
    for (const m of readFileSync(md, 'utf8').matchAll(/--[a-zA-Z][\w-]*/g)) named.add(m[0])
  }
  assert.ok(named.size, 'no SKILL.md was read — the check would pass vacuously')

  for (const flag of CLI_FLAGS_TAKING_VALUE) {
    assert.ok(named.has(flag) || CLI_ONLY_FLAGS.has(flag),
      `${flag} takes a value and is neither taught by a skill nor declared in CLI_ONLY_FLAGS`)
  }
  assert.ok(CLI_ONLY_FLAGS.has('--gate'), '--gate is CLI-only by design and must say so')
})

test('the ship-or-declare check FAILS when a flag is neither shipped nor declared', () => {
  // A gate nobody has seen fail is a gate nobody knows works. This runs the real CI script against
  // a grader copy carrying an extra, undeclared flag, and requires a non-zero exit.
  const dir = mkdtempSync(join(tmpdir(), 'cg-flags-'))
  try {
    mkdirSync(join(dir, 'plugin', 'scripts'), { recursive: true })
    mkdirSync(join(dir, 'plugin', 'skills'), { recursive: true })
    mkdirSync(join(dir, 'scripts'), { recursive: true })
    const src = readFileSync(join(REPO, 'plugin', 'scripts', 'grader.mjs'), 'utf8')
      .replace("new Set(['--model', '--observations'", "new Set(['--undeclared-flag', '--model', '--observations'")
    assert.match(src, /--undeclared-flag/, 'the fixture must actually inject an undeclared flag')
    writeFileSync(join(dir, 'plugin', 'scripts', 'grader.mjs'), src, 'utf8')
    for (const dep of ['business_logic.mjs']) {
      writeFileSync(join(dir, 'plugin', 'scripts', dep),
        readFileSync(join(REPO, 'plugin', 'scripts', dep), 'utf8'), 'utf8')
    }
    mkdirSync(join(dir, 'plugin', 'scripts', 'lib'), { recursive: true })
    writeFileSync(join(dir, 'plugin', 'scripts', 'lib', 'strip_comments.mjs'),
      readFileSync(join(REPO, 'plugin', 'scripts', 'lib', 'strip_comments.mjs'), 'utf8'), 'utf8')
    writeFileSync(join(dir, 'package.json'), '{"name":"t","version":"0.0.0","type":"module"}', 'utf8')
    writeFileSync(join(dir, 'scripts', 'assert_cli_flags.mjs'),
      readFileSync(join(REPO, 'scripts', 'assert_cli_flags.mjs'), 'utf8'), 'utf8')

    const out = spawnSync(process.execPath, [join(dir, 'scripts', 'assert_cli_flags.mjs')], { encoding: 'utf8' })
    assert.equal(out.status, 1, 'an undeclared value-taking flag must fail the build')
    assert.match(out.stderr, /--undeclared-flag/)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
