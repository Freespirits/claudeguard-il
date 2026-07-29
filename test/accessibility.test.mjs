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
// The accessibility (compliance pillar) end-to-end gates, engine → grader.
//
// Two properties this file exists to prove:
//   1. CRY-WOLF — a CORRECT app produces ZERO compliance findings. Correct markup must be silent, or
//      the pillar teaches its audience to ignore it. Empty alt="", decorative role, a resolved label,
//      captions present, a keyboard-operable clickable, lang set: all silent.
//   2. THE WALL — a compliance finding NEVER touches the security verdict. An inaccessible app with no
//      security holes still grades security `clean`; the accessibility findings live on their own axis.
// Plus a detection twin per rule (the bad markup DOES fire), and the web-surface gate.
// ---------------------------------------------------------------------------

function build(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-a11y-'))
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

const NEXT_PKG = '{"name":"a","dependencies":{"next":"14.0.0","react":"18.2.0"}}'
const comp = g => g.findings.filter(f => f.pillar === 'compliance')
const ids = g => comp(g).map(f => f.id).sort()
const hasId = (g, id) => comp(g).some(f => f.id === id)

// ---------------------------------------------------------------------------
// 1. CRY-WOLF — a correct, accessible app is completely silent on the compliance pillar.
// ---------------------------------------------------------------------------

const CORRECT_APP = {
  'package.json': NEXT_PKG,
  'app/layout.tsx': `export default function RootLayout({ children }) {
    return (<html lang="he" dir="rtl"><body>{children}</body></html>)
  }`,
  'app/accessibility/page.tsx': `export default function A11yStatement() {
    return (<main><h1>הצהרת נגישות</h1><p>האתר עומד בת"י 5568.</p></main>)
  }`,
  'components/Ui.tsx': `export function Ui({ caption, onSave }) {
    return (<section>
      <img src="/logo.png" alt="" />
      <img src="/cat.png" alt="A cat on a mat" />
      <img src="/deco.svg" role="presentation" />
      <input type="text" aria-label="Full name" />
      <input type="hidden" name="csrf" />
      <button onClick={onSave} aria-label="Save">{'✓'}</button>
      <button onClick={onSave}>Delete</button>
      <video src="/v.mp4"><track kind="captions" src="/c.vtt" /></video>
      <div onClick={onSave} role="button" tabIndex={0} onKeyDown={onSave}>Menu</div>
      <a href="/home">Home</a>
    </section>)
  }`,
}

test('CRY-WOLF: a correct accessible app produces ZERO compliance findings', () => {
  const { graded } = build(CORRECT_APP)
  assert.deepEqual(comp(graded).map(f => `${f.id} ${f.subject}`), [],
    'every compliance finding on correct markup is a false positive')
})

test('THE WALL: that same app grades security `clean` and its a11y sets are fully accounted for', () => {
  const { graded } = build(CORRECT_APP)
  assert.equal(graded.verdict.level, 'clean', 'no security issue, so the security badge is clean')
  assert.equal(graded.compliance.total, 0)
  // Grade-or-declare: the statement page is detected (pass), the rendered-DOM row is declared.
  assert.equal(graded.coverage.a11yStatement.counts.pass, 1, 'the הצהרת נגישות page is detected')
  assert.equal(graded.coverage.a11yRenderedDom.counts.undeterminable, 1, 'the rendered-DOM audit is declared')
})

// ---------------------------------------------------------------------------
// 2. DETECTION TWINS — the bad markup DOES fire, each on its own rule.
// ---------------------------------------------------------------------------

const BROKEN_APP = {
  'package.json': NEXT_PKG,
  'app/layout.tsx': `export default function L({ children }) { return (<html><body>{children}</body></html>) }`,
  'components/Bad.tsx': `export function Bad({ onGo }) {
    return (<section>
      <img src="/hero.png" />
      <input type="email" />
      <button onClick={onGo}><svg /></button>
      <video src="/v.mp4"></video>
      <div onClick={onGo} tabIndex={5}>Menu</div>
    </section>)
  }`,
}

test('DETECTION: each planted barrier produces its CG-A11Y finding', () => {
  const { graded } = build(BROKEN_APP)
  for (const id of ['CG-A11Y-001', 'CG-A11Y-002', 'CG-A11Y-003', 'CG-A11Y-004', 'CG-A11Y-005', 'CG-A11Y-006', 'CG-A11Y-007']) {
    assert.ok(hasId(graded, id), `${id} should fire — planted in Bad.tsx; got ${ids(graded).join(', ')}`)
  }
})

test('DETECTION: the unambiguous barriers are `confirmed` violations, the subtle ones are not', () => {
  const { graded } = build(BROKEN_APP)
  const byId = Object.fromEntries(comp(graded).map(f => [f.id, f]))
  // definitive → confirmed
  assert.equal(byId['CG-A11Y-001'].confidence, 'confirmed', 'a missing alt is definitive')
  assert.equal(byId['CG-A11Y-002'].confidence, 'confirmed', 'a missing lang is definitive')
  assert.equal(byId['CG-A11Y-006'].confidence, 'confirmed', 'a positive tabIndex is definitive')
  // weak/strong → needs-review / likely (never a confirmed "violation")
  assert.equal(byId['CG-A11Y-003'].confidence, 'needs-review')
  assert.equal(byId['CG-A11Y-004'].confidence, 'likely')
  assert.equal(byId['CG-A11Y-005'].confidence, 'likely')
  assert.equal(byId['CG-A11Y-007'].confidence, 'needs-review')
})

test('THE WALL holds under load: a broken-a11y app still grades security `clean`', () => {
  const { graded } = build(BROKEN_APP)
  assert.equal(graded.verdict.level, 'clean', 'accessibility findings must never redden or unknown the security badge')
  assert.equal(graded.verdict.confirmedP0, 0)
  assert.ok(graded.compliance.total >= 7, 'but the compliance pillar is loud about them')
  assert.ok(graded.compliance.violations >= 3, 'the definitive ones are counted as violations')
  // Every compliance finding carries the pillar tag, and no security finding leaks the other way.
  assert.ok(comp(graded).every(f => f.pillar === 'compliance'))
  assert.equal(graded.findings.filter(f => f.pillar === 'security').length, 0)
})

// ---------------------------------------------------------------------------
// 3. FALSE-POSITIVE TRAPS — the specific shapes that must NOT fire.
// ---------------------------------------------------------------------------

test('TRAP: a {...spread} on an <img> abstains (undeterminable), never a missing-alt finding', () => {
  const { graded } = build({ 'package.json': NEXT_PKG, 'c.tsx': `export const C = (p) => <img {...p} />` })
  assert.equal(hasId(graded, 'CG-A11Y-001'), false, 'a spread could supply alt — we must not claim it is missing')
  assert.equal(graded.coverage.a11yImages.counts.undeterminable, 1)
})

test('TRAP: a dynamic lang={locale} is undeterminable, not a missing-lang finding', () => {
  const { graded } = build({
    'package.json': NEXT_PKG,
    'app/layout.tsx': `export default function L({ children, locale }) { return <html lang={locale}><body>{children}</body></html> }`,
  })
  assert.equal(hasId(graded, 'CG-A11Y-002'), false, 'a dynamic lang is probably fine — do not cry wolf')
  assert.equal(graded.coverage.a11yDocument.counts.undeterminable, 1)
})

test('TRAP: an input with an id is undeterminable (a <label for> may target it), not a finding', () => {
  const { graded } = build({ 'package.json': NEXT_PKG, 'c.tsx': `export const C = () => (<><label htmlFor="e">Email</label><input id="e" type="email" /></>)` })
  assert.equal(hasId(graded, 'CG-A11Y-003'), false)
  assert.equal(graded.coverage.a11yFormControls.counts.undeterminable, 1)
})

// ---------------------------------------------------------------------------
// 4. THE WEB-SURFACE GATE — a non-web project is never asked for a web accessibility statement.
// ---------------------------------------------------------------------------

test('a React Native / backend project gets no statement or rendered-DOM row (not a web surface)', () => {
  const { graded } = build({
    'package.json': '{"name":"m","dependencies":{"react-native":"0.74.5","react":"18.2.0"}}',
    'App.tsx': `import { View, Text } from 'react-native'
      export default () => (<View><Text>Hi</Text></View>)`,
  })
  assert.equal(hasId(graded, 'CG-A11Y-STATEMENT'), false, 'the statement is never a finding anywhere')
  assert.equal(graded.coverage.a11yStatement.enumerated, 0, 'no web surface — no statement expectation')
  assert.equal(graded.coverage.a11yRenderedDom.enumerated, 0, 'no web surface — no rendered-DOM row')
})

test('the accessibility statement is NEVER a fireable finding, even on a web app with none', () => {
  const { graded } = build(BROKEN_APP) // web app, no statement page
  assert.equal(hasId(graded, 'CG-A11Y-STATEMENT'), false, 'absence of a statement is a declared row, not a red finding (cry-wolf)')
  assert.equal(graded.coverage.a11yStatement.counts.undeterminable, 1, 'it is declared undeterminable instead')
})
