import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { grade } from '../plugin/scripts/grader.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const ENGINE = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')

// ---------------------------------------------------------------------------
// The vibecoder-hygiene gates, ENGINE → GRADER, end to end.
//
// test/hygiene_scan.test.mjs already pins the four scanners as pure functions. This file pins the
// half that commit 73a293c deferred: that the engine actually CALLS them, that the grader turns
// their facts into findings, and — the part worth the most — that the wiring did not import a new
// class of false positive into a tool whose whole argument is that it does not cry wolf.
//
// Four properties:
//   1. DETECTION — each of the four checks fires on its planted defect, at the right file:line.
//   2. CRY WOLF — an app doing all four things CORRECTLY produces zero hygiene findings. A theme in
//      localStorage, btoa on an image, a TODO about CSS, a placeholder in .env.example: all silent.
//   3. THE CEILING — no CG-HYG finding may EVER reach `confirmed`. These are greps; they can see the
//      sink but not whether it matters, so none of them may redden the badge on its own. Asserted
//      mechanically over whatever the rules produce, not per-rule, so a future fifth check inherits it.
//   4. GRADE OR DECLARE + LAW 2 — the four sets exist even when empty, and coverage adds up.
// ---------------------------------------------------------------------------

function build(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-hyg-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content)
    }
    const model = JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    }).replace(/^﻿/, ''))
    return { model, graded: grade(model) }
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const PKG = '{"name":"a","dependencies":{"next":"15.5.21","react":"18.2.0"}}'
const hyg = g => g.findings.filter(f => f.id.startsWith('CG-HYG'))
const ids = g => hyg(g).map(f => f.id).sort()
const one = (g, id) => {
  const f = hyg(g).filter(x => x.id === id)
  assert.equal(f.length, 1, `expected exactly one ${id}, got ${f.length}`)
  return f[0]
}
const HYGIENE_SETS = ['hygienePlaceholderSecrets', 'hygieneFakeCrypto', 'hygieneTokenStorage',
  'hygieneAuthTodos']

function law2(graded) {
  for (const [name, set] of Object.entries(graded.coverage)) {
    const c = set.counts
    assert.equal(c.pass + c.fail + c.undeterminable + c.allowlisted, set.enumerated,
      `LAW 2 broken in "${name}"`)
  }
}

// ---------------------------------------------------------------------------
// 1 · Detection — each check fires on its planted defect.
// ---------------------------------------------------------------------------

test('CG-HYG-001: a placeholder credential in real source is found, at its line', () => {
  const { graded } = build({
    'package.json': PKG,
    'lib/config.js': "export const ADMIN_PASSWORD = 'admin123'\n",
  })
  const f = one(graded, 'CG-HYG-001')
  assert.equal(f.severity, 'P2')
  assert.equal(f.pillar, 'security', 'a shipped default credential is a breach path, not a legal exposure')
  assert.equal(f.evidence.at[0].file, 'lib/config.js')
  assert.equal(f.evidence.at[0].line, 1)
  assert.match(f.title_en, /admin123/, 'the token belongs in the title — it is what the user searches for')
  law2(graded)
})

test('CG-HYG-001 reads .env too — `API_KEY=changeme` is the shape this check exists for', () => {
  // A .env file is not CODE_EXT, so without the explicit env pass in the engine the single most
  // common placement of a placeholder secret would have been invisible to the check.
  const { graded } = build({ 'package.json': PKG, '.env': 'OPENAI_API_KEY=changeme\n' })
  const f = one(graded, 'CG-HYG-001')
  assert.equal(f.evidence.at[0].file, '.env')
  law2(graded)
})

test('CG-HYG-002: btoa() on a password is fake crypto', () => {
  const { graded } = build({
    'package.json': PKG,
    'lib/save.js': 'export const store = password => btoa(password)\n',
  })
  const f = one(graded, 'CG-HYG-002')
  assert.equal(f.severity, 'P1', 'a secret encoded rather than encrypted is plaintext in practice')
  assert.equal(f.evidence.at[0].line, 1)
  law2(graded)
})

test('CG-HYG-003: a bearer token in localStorage is found, and names the key', () => {
  const { graded } = build({
    'package.json': PKG,
    'lib/session.js': "export const keep = s => localStorage.setItem('access_token', s.token)\n",
  })
  const f = one(graded, 'CG-HYG-003')
  assert.equal(f.severity, 'P2')
  assert.match(f.title_en, /access_token/)
  assert.match(f.title_en, /localStorage/)
  law2(graded)
})

test('CG-HYG-004: a TODO beside auth code is found, at needs-review', () => {
  const { graded } = build({
    'package.json': PKG,
    'lib/guard.js': '// TODO: add real auth before launch\nexport const check = () => true\n',
  })
  const f = one(graded, 'CG-HYG-004')
  assert.equal(f.severity, 'P3')
  assert.equal(f.confidence, 'needs-review',
    'the weakest of the four: a marker near an auth word is a pointer to read, not a proven defect')
  law2(graded)
})

test('several markers on ONE line collapse to one finding and one row', () => {
  // The subject is file:line, so duplicates would be swallowed SILENTLY — record() returns rather
  // than throwing when a subject repeats with the same disposition. That produced four findings
  // against one coverage row: a table that disagrees with the list it summarises.
  //
  // The leading-marker rule means the scanner can no longer emit two facts for one line, so this
  // drives the grader directly with the shape it must survive. The grouping is deliberately kept as
  // the place the invariant lives, rather than left resting on a property of the scanner.
  const { model } = build({
    'package.json': PKG,
    'lib/guard.js': '// TODO: check the session\nexport const check = () => true\n',
  })
  const first = model.hygiene.authTodos[0]
  assert.ok(first, 'the fixture must produce a marker fact to duplicate')
  model.hygiene.authTodos = [first, { ...first, marker: 'FIXME' }, { ...first, marker: 'TODO' }]

  const graded = grade(model)
  const f = one(graded, 'CG-HYG-004')
  assert.match(f.title_en, /TODO\/FIXME/, 'both distinct markers are named, and the repeat is dropped')
  assert.equal(graded.coverage.hygieneAuthTodos.enumerated, 1)
  assert.equal(graded.coverage.hygieneAuthTodos.counts.fail, 1)
  law2(graded)
})

test('the coverage table can never disagree with the finding list', () => {
  // The general form of the bug above: one `fail` row per finding, per set. LAW 2 alone would not
  // have caught it — the row count stayed internally consistent while the finding list ran ahead.
  const { graded } = build({
    'package.json': PKG,
    '.env': 'API_KEY=changeme\n',
    'lib/all.js': [
      "const ADMIN_PASSWORD = 'admin123'",
      "localStorage.setItem('access_token', t)",
      '// TODO: check the session',
      'export const enc = password => btoa(password)',
    ].join('\n') + '\n',
  })
  const BY_SET = {
    hygienePlaceholderSecrets: 'CG-HYG-001', hygieneFakeCrypto: 'CG-HYG-002',
    hygieneTokenStorage: 'CG-HYG-003', hygieneAuthTodos: 'CG-HYG-004',
  }
  for (const [set, id] of Object.entries(BY_SET)) {
    assert.equal(graded.coverage[set].counts.fail, hyg(graded).filter(f => f.id === id).length,
      `${set} rows disagree with ${id} findings`)
  }
  law2(graded)
})

test('CRY WOLF: ClaudeGuardIL gains no hygiene finding from its own source', () => {
  // The tool's own comments EXPLAIN these four checks — they say "TODO", "btoa", "localStorage" and
  // "changeme" beside auth words on purpose. Firing on them is the same failure the changelog
  // records as "quoted source is no longer source", and it is the most embarrassing possible
  // cry-wolf for this tool. Corpus code under bench/ is vendored third-party and may fire freely.
  const graded = grade(JSON.parse(execFileSync(process.execPath, [ENGINE, join(HERE, '..')], {
    encoding: 'utf8', maxBuffer: 128 * 1024 * 1024,
  }).replace(/^﻿/, '')))
  const ours = hyg(graded).filter(f => !(f.evidence.at[0]?.file || '').startsWith('bench/'))
  assert.deepEqual(ours.map(f => `${f.id} ${f.evidence.at[0]?.file}:${f.evidence.at[0]?.line}`), [],
    'the tool must not detect its own documentation')
})

test('all four coexist in one file without colliding on a subject', () => {
  // Each subject is keyed file:line, so four defects in one file must produce four distinct rows.
  // A collision would throw inside the ledger (LAW 2), not merely miscount.
  const { graded } = build({
    'package.json': PKG,
    '.env': 'API_KEY=changeme\n',
    'lib/all.js': [
      "const ADMIN_PASSWORD = 'admin123'",
      "localStorage.setItem('jwt', token)",
      '// TODO: verify the session properly',
      'export const enc = password => btoa(password)',
    ].join('\n') + '\n',
  })
  assert.deepEqual(ids(graded),
    ['CG-HYG-001', 'CG-HYG-001', 'CG-HYG-002', 'CG-HYG-003', 'CG-HYG-004'])
  law2(graded)
})

// ---------------------------------------------------------------------------
// 2 · CRY WOLF — the property that decides whether this wiring was worth shipping.
// ---------------------------------------------------------------------------

test('CRY WOLF: an app doing all four things correctly produces ZERO hygiene findings', () => {
  const { graded } = build({
    'package.json': PKG,
    // Placeholders BELONG in an example file — that is what it is for.
    '.env.example': 'OPENAI_API_KEY=your-api-key-here\nADMIN_PASSWORD=changeme\n',
    '.env.template': 'STRIPE_SECRET_KEY=sk-xxxxxxxx\n',
    // Non-sensitive web storage: a preference is not a credential.
    'lib/prefs.js': [
      "localStorage.setItem('theme', 'dark')",
      "localStorage.setItem('locale', 'he')",
      "sessionStorage.setItem('sidebarCollapsed', 'true')",
      // A csrf mirror is the standard double-submit-cookie defence, not a leaked bearer token.
      "localStorage.setItem('csrf_token', csrf)",
    ].join('\n') + '\n',
    // base64 as an ENCODING, which is correct and expected.
    'lib/img.js': [
      'export const toDataUri = bytes => `data:image/png;base64,${btoa(bytes)}`',
      'export const packed = obj => Buffer.from(JSON.stringify(obj)).toString(\'base64\')',
    ].join('\n') + '\n',
    // Markers far from anything auth-shaped are ordinary backlog noise.
    'lib/list.js': [
      '// TODO: virtualise this list when it gets long',
      '// FIXME: the spacing is off on mobile',
      'export const tokenizer = s => s.split(\' \')',
    ].join('\n') + '\n',
    // Real secrets read from the environment: the correct pattern, and silent.
    'lib/env.js': [
      "export const apiKey = process.env.OPENAI_API_KEY",
      "if (!apiKey) throw new Error('OPENAI_API_KEY is not set')",
    ].join('\n') + '\n',
  })
  assert.deepEqual(hyg(graded), [],
    `correct code must be silent; fired: ${JSON.stringify(ids(graded))}`)
  law2(graded)
})

test('CRY WOLF: an empty repo is silent and the sets are still declared', () => {
  // Grade or declare: the reader must be able to tell "the check ran and matched nothing" from
  // "the check does not exist". Zero findings, four rows.
  const { graded } = build({ 'package.json': PKG, 'index.js': 'export const x = 1\n' })
  assert.deepEqual(hyg(graded), [])
  for (const s of HYGIENE_SETS) {
    assert.ok(graded.coverage[s], `set "${s}" must be declared even when empty`)
    assert.equal(graded.coverage[s].enumerated, 0)
  }
  law2(graded)
})

// ---------------------------------------------------------------------------
// 3 · THE CEILING — mechanical, over whatever the rules produce.
// ---------------------------------------------------------------------------

test('a hygiene finding can NEVER be confirmed, and never a P0', () => {
  // The load-bearing constraint of the whole domain. These are four regex passes: they see the sink
  // but not whether it matters, so no amount of matching may reach proof. Asserted over the finding
  // list rather than rule by rule, so a fifth check added later inherits the ceiling for free.
  const { graded } = build({
    'package.json': PKG,
    '.env': 'API_KEY=changeme\n',
    'lib/all.js': [
      "const ADMIN_PASSWORD = 'admin123'",
      "localStorage.setItem('access_token', t)",
      '// TODO: check the session',
      'export const enc = password => btoa(password)',
    ].join('\n') + '\n',
  })
  const found = hyg(graded)
  assert.ok(found.length >= 4, 'the fixture must actually produce findings, or this proves nothing')
  for (const f of found) {
    assert.notEqual(f.confidence, 'confirmed', `${f.id} reached confirmed — a grep cannot prove this`)
    assert.notEqual(f.severity, 'P0', `${f.id} claimed P0`)
    assert.ok(f.assumption, `${f.id} must name what would make it a false positive`)
    assert.ok(f.guard && f.guard.startsWith('guard-recipes/vibecoder-hygiene.md#'),
      `${f.id} must link to a fix`)
  }
  // And the consequence that matters to a user: none of this reddens the security badge.
  assert.equal(graded.verdict.confirmedP0, 0)
})

// ---------------------------------------------------------------------------
// 4 · Plumbing — allowlist, determinism, and the pillar boundary.
// ---------------------------------------------------------------------------

test('a hygiene subject can be allowlisted, and then it is a row rather than a finding', () => {
  const files = {
    'package.json': PKG,
    'lib/session.js': "export const keep = s => localStorage.setItem('access_token', s.token)\n",
  }
  const { model } = build(files)
  const subject = 'hygiene:token-storage:lib/session.js:1'
  const graded = grade(model, { allowlist: [subject] })
  assert.deepEqual(hyg(graded), [], 'an allowlisted subject fires nothing')
  assert.equal(graded.coverage.hygieneTokenStorage.counts.allowlisted, 1,
    'but it is still enumerated — an allowlist hides a finding, never the subject')
  law2(graded)
})

test('hygiene findings are SECURITY pillar, not compliance', () => {
  // The pillar split is what keeps a missing alt out of the security badge. These four are the other
  // side of that line: they are breach paths, so they belong to security and must count there.
  const { graded } = build({
    'package.json': PKG,
    'lib/session.js': "localStorage.setItem('access_token', t)\n",
  })
  for (const f of hyg(graded)) assert.equal(f.pillar, 'security')
})

test('the facts are deterministic — same repo, same hygiene model', () => {
  const files = {
    'package.json': PKG,
    'lib/all.js': "const ADMIN_PASSWORD = 'admin123'\nlocalStorage.setItem('jwt', t)\n",
  }
  const a = JSON.stringify(build(files).model.hygiene)
  const b = JSON.stringify(build(files).model.hygiene)
  assert.equal(a, b, 'a fact list that moves between runs cannot be diffed after a fix')
})
