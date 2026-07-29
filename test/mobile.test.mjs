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

function build(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-mob-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    const model = JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    }))
    return { model, graded: grade(model) }
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const PKG = '{"name":"m","dependencies":{"expo":"51.0.0"}}'

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS.
//
// Before these rules, the engine recorded mobile as a list of file PATHS and nothing more. Two
// consequences, both bad:
//
//   1. The Ledger had no mobile subject set, so LAW 2's accounting did not extend to mobile at
//      all. The report could state that every enumerated subject was accounted for while never
//      having opened a manifest — the exact "quiet report mistaken for a safe one" failure the
//      coverage rule exists to prevent.
//   2. Every mobile finding had to come from a reviewer, whose best available evidence is
//      `judgement`. That caps at `likely`, and the verdict counts only `confirmed` — so a
//      mobile-only repo ALWAYS rendered `clean`, no matter what was in the manifest.
//
// The second point is the sharper one. `android:debuggable="true"` is not a matter of opinion.
// It is a flag with exactly one meaning, and it deserves `definitive` like any other
// build-guaranteed fact.
// ---------------------------------------------------------------------------

const BAD_MANIFEST = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <!-- <uses-permission android:name="android.permission.COMMENTED_OUT"/> -->
  <application
      android:debuggable="true"
      android:allowBackup="true"
      android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true"/>
    <service android:name=".SyncService" android:exported="true" android:permission="com.x.PRIVATE"/>
    <provider android:name=".DataProvider" android:exported="true"/>
    <receiver android:name=".Internal" android:exported="false"/>
  </application>
</manifest>`

test('a debuggable manifest produces a CONFIRMED finding that reaches the verdict', () => {
  // The regression this guards: mobile findings that could only ever be `likely`, leaving a
  // mobile-only repo rendering `clean` with a debuggable app.
  const { graded } = build({ 'package.json': PKG, 'android/app/src/main/AndroidManifest.xml': BAD_MANIFEST })
  const f = graded.findings.find(x => x.id === 'CG-AND-001')
  assert.ok(f, 'debuggable must be graded by a rule, not left to a reviewer')
  assert.equal(f.evidence.strength, 'definitive', 'a build flag is not a judgement call')
  assert.equal(f.confidence, 'confirmed')
  assert.notEqual(graded.verdict.level, 'clean', 'a debuggable app must not render as clean')
})

test('mobile subjects enter the coverage ledger, so LAW 2 covers them', () => {
  const { graded } = build({ 'package.json': PKG, 'android/app/src/main/AndroidManifest.xml': BAD_MANIFEST })
  assert.ok(graded.coverage.mobileArtifacts, 'mobile needs its own subject set or it escapes the accounting')
  assert.equal(graded.coverage.mobileArtifacts.enumerated, 1)
  for (const [name, set] of Object.entries(graded.coverage)) {
    const c = set.counts
    assert.equal(c.pass + c.fail + c.undeterminable + c.allowlisted, set.enumerated,
      `LAW 2 broken in "${name}"`)
  }
})

test('every exported component is enumerated, and a permission guard is a structural pass', () => {
  // The mobile equivalent of walking every route. A permission-guarded export is a deliberate,
  // declared interface — crediting it is what keeps a correct app quiet.
  const { graded } = build({ 'package.json': PKG, 'android/app/src/main/AndroidManifest.xml': BAD_MANIFEST })
  const set = graded.coverage.exportedComponents
  assert.equal(set.enumerated, 3, 'the non-exported receiver is not a subject; the other three are')
  assert.equal(set.counts.pass, 1, 'the permission-guarded service passes')
  assert.equal(set.counts.fail, 2, 'the unguarded activity and provider fail')
  assert.ok(set.pass[0].subject.includes('SyncService'))
})

test('an unguarded content provider outranks an unguarded activity', () => {
  // A provider hands out data directly; an activity merely runs. Impact-if-true differs, so
  // severity must too.
  const { graded } = build({ 'package.json': PKG, 'android/app/src/main/AndroidManifest.xml': BAD_MANIFEST })
  const byName = n => graded.findings.find(f => f.id === 'CG-AND-004' && f.subject.includes(n))
  assert.equal(byName('DataProvider').severity, 'P1')
  assert.equal(byName('MainActivity').severity, 'P2')
})

test('a commented-out manifest line is not read as live configuration', () => {
  // The same class of bug that once made a commented-out `enable row level security` read as
  // enabled — a false negative that printed a checkmark over a P0.
  const { model } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <!-- <application android:debuggable="true"/> -->
  <application android:allowBackup="false"/>
</manifest>`,
  })
  assert.equal(model.mobile.android[0].debuggable, null,
    'a debuggable flag inside an XML comment is not set')
})

test('cleartext scoped by a network security config is not flagged', () => {
  // A networkSecurityConfig is exactly the mechanism for allowing one legacy host without opening
  // everything. Punishing the correct pattern is how the tool loses its audience.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:usesCleartextTraffic="true"
               android:networkSecurityConfig="@xml/network_security_config"/>
</manifest>`,
  })
  assert.ok(!graded.findings.some(f => f.id === 'CG-AND-002'))
})

test('a clean manifest passes with no findings', () => {
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false" android:usesCleartextTraffic="false">
    <activity android:name=".MainActivity" android:exported="false"/>
  </application>
</manifest>`,
  })
  assert.deepEqual(graded.findings, [])
  assert.equal(graded.coverage.mobileArtifacts.counts.pass, 1)
  assert.equal(graded.verdict.level, 'clean')
})

test('iOS: ATS disabled globally is confirmed; the secure default is a pass', () => {
  const off = build({
    'package.json': PKG,
    'ios/App/Info.plist': `<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict><key>NSAllowsArbitraryLoads</key><true/></dict>
</dict></plist>`,
  })
  const f = off.graded.findings.find(x => x.id === 'CG-IOS-001')
  assert.ok(f)
  assert.equal(f.confidence, 'confirmed')

  const on = build({
    'package.json': PKG,
    'ios/App/Info.plist': '<plist version="1.0"><dict><key>CFBundleName</key><string>x</string></dict></plist>',
  })
  assert.deepEqual(on.graded.findings, [], 'ATS is on by default — a plist that never weakens it is correct')
  assert.equal(on.graded.coverage.mobileArtifacts.counts.pass, 1)
})
