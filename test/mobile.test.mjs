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
      writeFileSync(abs, content)
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
//
// AND THE OTHER HALF, which this file used to have backwards. It asserted that a launcher activity
// with `android:exported="true"` is a P2 `fail`, and its "clean manifest" fixture put
// `android:exported="false"` on the launcher — a manifest that CANNOT occur in a shipping app.
// So 210 tests passed while four untouched framework templates graded `medium`. A test that
// encodes a false positive as desired behaviour is worse than no test: it defends the defect.
// The stock-template baseline at the bottom of this file is the guard that was missing.
// ---------------------------------------------------------------------------

// A manifest with real defects, shaped like a manifest that could actually ship: the launcher
// activity is exported (it has to be), and the problems are elsewhere.
const BAD_MANIFEST = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <!-- <uses-permission android:name="android.permission.COMMENTED_OUT"/> -->
  <application
      android:debuggable="true"
      android:allowBackup="false"
      android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".AdminActivity" android:exported="true"/>
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

test('every reachable component is enumerated, and a permission guard is a structural pass', () => {
  // The mobile equivalent of walking every route. A permission-guarded export is a deliberate,
  // declared interface — crediting it is what keeps a correct app quiet.
  const { graded } = build({ 'package.json': PKG, 'android/app/src/main/AndroidManifest.xml': BAD_MANIFEST })
  const set = graded.coverage.exportedComponents
  assert.equal(set.enumerated, 4, 'the non-exported receiver is not a subject; the other four are')
  assert.equal(set.counts.pass, 1, 'the permission-guarded service passes')
  assert.equal(set.counts.fail, 2, 'the unguarded admin activity and provider fail')
  assert.equal(set.counts.allowlisted, 1, 'the launcher activity is allowlisted, not failed')
  assert.ok(set.pass[0].subject.includes('SyncService'))
})

test('THE LAUNCHER ACTIVITY IS NEVER A FINDING', () => {
  // This test replaces an assertion that demanded the OPPOSITE. Every Android app that exists has
  // a MAIN/LAUNCHER activity and the platform requires it to be exported — so the old rule fired
  // on React Native, Flutter, Android Studio's "Empty Activity" and Capacitor alike, and the
  // remediation it printed ("set exported=false or require a permission") makes the app
  // UNLAUNCHABLE. A security tool whose advice bricks the app is worse than no tool.
  const { graded } = build({ 'package.json': PKG, 'android/app/src/main/AndroidManifest.xml': BAD_MANIFEST })
  const launcher = graded.coverage.exportedComponents.allowlisted
    .find(r => r.subject.includes('MainActivity'))
  assert.ok(launcher, 'the launcher activity must still be ENUMERATED — silence is not the fix')
  assert.match(launcher.note, /LAUNCHER|launcher/)
  assert.ok(!graded.findings.some(f => f.subject.includes('MainActivity')),
    'no finding may name the launcher activity')
})

test('an unguarded content provider outranks an unguarded activity', () => {
  // A provider hands out data directly; an activity merely runs. Impact-if-true differs, so
  // severity must too.
  const { graded } = build({ 'package.json': PKG, 'android/app/src/main/AndroidManifest.xml': BAD_MANIFEST })
  const byName = n => graded.findings.find(f => f.id === 'CG-AND-004' && f.subject.includes(n))
  assert.equal(byName('DataProvider').severity, 'P1')
  assert.equal(byName('AdminActivity').severity, 'P2')
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

test('a manifest with no defects passes with no findings', () => {
  // The old version of this fixture put `android:exported="false"` on the launcher activity, which
  // cannot happen in a shipping app — it "proved" the clean path only by using an impossible input.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false" android:usesCleartextTraffic="false">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".SettingsActivity" android:exported="false"/>
  </application>
</manifest>`,
  })
  assert.deepEqual(graded.findings, [])
  assert.equal(graded.coverage.mobileArtifacts.counts.pass, 1)
  assert.equal(graded.verdict.level, 'clean')
})

// ---------------------------------------------------------------------------
// Source sets — a manifest no release build compiles is not a release finding
// ---------------------------------------------------------------------------

test('debug and test source sets are allowlisted, not graded as if they shipped', () => {
  // `npx react-native init` ships src/debug/AndroidManifest.xml with usesCleartextTraffic="true"
  // so Metro can reach the device. Grading it put `CG-AND-002 confirmed` and a `medium` verdict on
  // a verbatim template. Neither file exists in a release build.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:allowBackup="false"/></manifest>',
    'android/app/src/debug/AndroidManifest.xml': '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:debuggable="true" android:usesCleartextTraffic="true"/></manifest>',
    'android/app/src/androidTest/AndroidManifest.xml': '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:usesCleartextTraffic="true"/></manifest>',
  })
  assert.deepEqual(graded.findings, [], 'a debug-only source set may not produce a release finding')
  assert.equal(graded.verdict.level, 'clean')
  const allowed = graded.coverage.mobileArtifacts.allowlisted.map(r => r.subject)
  assert.equal(allowed.length, 2, 'both non-release manifests are still enumerated and accounted for')
  for (const row of graded.coverage.mobileArtifacts.allowlisted) {
    assert.match(row.note, /release build/, 'the allowlist reason must say why it does not apply')
  }
})

test('the SAME flags in the main source set are still confirmed findings', () => {
  // The source-set fix must not become a blanket exemption. This is the control for it.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:debuggable="true" android:usesCleartextTraffic="true" android:allowBackup="false"/></manifest>',
  })
  assert.ok(graded.findings.some(f => f.id === 'CG-AND-001' && f.confidence === 'confirmed'))
  assert.ok(graded.findings.some(f => f.id === 'CG-AND-002' && f.confidence === 'confirmed'))
  assert.equal(graded.verdict.level, 'high')
})

// ---------------------------------------------------------------------------
// LAW 1 — the network security config is READ, not credited for existing
// ---------------------------------------------------------------------------

test('LAW 1: a permissive network_security_config.xml is graded, not passed on presence', () => {
  // The rule used to credit the mere PRESENCE of android:networkSecurityConfig with scoping
  // cleartext and print `pass` — "no debuggable, cleartext or backup exposure declared" — over a
  // config that permits cleartext to EVERY host and trusts any CA the phone's owner installs.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false" android:usesCleartextTraffic="true"
               android:networkSecurityConfig="@xml/network_security_config"/>
</manifest>`,
    'android/app/src/main/res/xml/network_security_config.xml': `<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors>
  </base-config>
</network-security-config>`,
  })
  const ids = graded.findings.map(f => f.id).sort()
  assert.deepEqual(ids, ['CG-AND-002', 'CG-AND-005'])
  for (const f of graded.findings) assert.equal(f.confidence, 'confirmed')
  const row = graded.coverage.mobileArtifacts.fail.find(r => r.subject.startsWith('android-network-config:'))
  assert.ok(row, 'the config file is its own enumerated subject')
})

test('a CORRECT network security config stays quiet, including a debug-overrides user anchor', () => {
  // Scoping cleartext to one legacy host and putting the user trust anchor inside <debug-overrides>
  // is exactly what the guard recipe tells people to do. Punishing it is how the tool loses its
  // audience.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false" android:usesCleartextTraffic="true"
               android:networkSecurityConfig="@xml/network_security_config"/>
</manifest>`,
    'android/app/src/main/res/xml/network_security_config.xml': `<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system"/></trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">legacy.example.com</domain>
  </domain-config>
  <debug-overrides>
    <trust-anchors><certificates src="user"/></trust-anchors>
  </debug-overrides>
</network-security-config>`,
  })
  assert.deepEqual(graded.findings, [])
  assert.equal(graded.verdict.level, 'clean')
  const row = graded.coverage.mobileArtifacts.pass.find(r => r.subject.startsWith('android-network-config:'))
  assert.match(row.note, /legacy\.example\.com/, 'the pass must name what the cleartext is scoped to')
})

test('a networkSecurityConfig naming a file this repo does not contain is undeterminable', () => {
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false" android:usesCleartextTraffic="true"
               android:networkSecurityConfig="@xml/nsc"/>
</manifest>`,
  })
  assert.deepEqual(graded.findings, [], 'an unreadable reference is a question, not a finding')
  const row = graded.coverage.mobileArtifacts.undeterminable[0]
  assert.match(row.note, /open it and confirm/, 'an undeterminable row without an instruction is an apology')
})

// ---------------------------------------------------------------------------
// LAW 2 — subject ids
// ---------------------------------------------------------------------------

test('LAW 2: two components the name regex cannot read do not collide', () => {
  // The id was `android-component:${file}:${name}`, and `name` falls back to '(unnamed)'. Two such
  // components with DIFFERENT dispositions threw LAW 2 — and a throw means NO REPORT AT ALL, which
  // is the worst outcome the pipeline has. The id is positional now.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false">
    <service android:exported="true"/>
    <service android:exported="true" android:permission="com.x.P"/>
  </application>
</manifest>`,
  })
  const set = graded.coverage.exportedComponents
  assert.equal(set.enumerated, 2, 'both components are enumerated; neither is swallowed')
  assert.equal(set.counts.fail + set.counts.pass, 2)
})

// ---------------------------------------------------------------------------
// The XML reader
// ---------------------------------------------------------------------------

test('single-quoted attributes are read — they are legal XML', () => {
  // Every attribute regex hardcoded a double quote, so a single-quoted manifest read as every flag
  // null and zero components: `verdict: clean` on an app declaring debuggable='true'.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android='http://schemas.android.com/apk/res/android'>
  <application android:debuggable='true' android:usesCleartextTraffic='true' android:allowBackup='false'>
    <provider android:name='.P' android:exported='true'/>
  </application>
</manifest>`,
  })
  const ids = graded.findings.map(f => f.id).sort()
  assert.deepEqual(ids, ['CG-AND-001', 'CG-AND-002', 'CG-AND-004'])
  assert.equal(graded.verdict.level, 'high')
})

test('a > inside an attribute value does not truncate the element', () => {
  // Only < and & must be escaped in an XML attribute value, so this is legal input. The old
  // `[^>]*` window stopped at the > inside the label, android:exported fell outside it, and the
  // element was dropped entirely — a silent miss.
  const { model, graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false">
    <activity android:label="Settings > Advanced" android:name=".AdminActivity" android:exported="true"/>
  </application>
</manifest>`,
  })
  assert.equal(model.mobile.android[0].exportedComponents.length, 1)
  assert.equal(model.mobile.android[0].exportedComponents[0].name, '.AdminActivity')
  assert.ok(graded.findings.some(f => f.id === 'CG-AND-004'))
})

test('activity-alias reports its own kind, not "activity"', () => {
  const { model } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false">
    <activity-alias android:name=".Alias" android:targetActivity=".A" android:exported="true"/>
  </application>
</manifest>`,
  })
  assert.equal(model.mobile.android[0].exportedComponents[0].kind, 'activity-alias')
})

test('an EMPTY android:permission does not buy a structural pass', () => {
  // `android:permission=""` satisfied a presence test while enforcing nothing — a checkmark over
  // an unguarded export.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false">
    <service android:name=".S" android:exported="true" android:permission=""/>
  </application>
</manifest>`,
  })
  assert.ok(graded.findings.some(f => f.id === 'CG-AND-004'))
  assert.equal(graded.coverage.exportedComponents.counts.pass, 0)
})

test('a permission whose protectionLevel is not signature is not a guard', () => {
  // checks/android.md requires a SIGNATURE permission. `normal` — Android's default when the
  // attribute is omitted — is granted to every app at install with no prompt, so a component
  // behind one is exactly as reachable as an unguarded one.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <permission android:name="com.x.OPEN" android:protectionLevel="normal"/>
  <permission android:name="com.x.SIG" android:protectionLevel="signature"/>
  <application android:allowBackup="false">
    <service android:name=".Open" android:exported="true" android:permission="com.x.OPEN"/>
    <service android:name=".Sig" android:exported="true" android:permission="com.x.SIG"/>
  </application>
</manifest>`,
  })
  const set = graded.coverage.exportedComponents
  assert.equal(set.counts.fail, 1)
  assert.equal(set.counts.pass, 1)
  assert.ok(set.pass[0].subject.includes('.Sig'))
  assert.match(set.fail[0].note, /protectionLevel="normal"/)
})

test('a resource-backed flag is undeterminable, never a silent pass', () => {
  // `android:usesCleartextTraffic="@bool/cleartext"` resolves per build variant. Reading it as
  // absent printed "no cleartext declared" over a manifest that declares it conditionally.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:usesCleartextTraffic="@bool/cleartext" android:allowBackup="false"/>
</manifest>`,
  })
  assert.deepEqual(graded.findings, [], 'an unresolved value is a question, not a finding')
  assert.equal(graded.coverage.mobileArtifacts.counts.undeterminable, 1)
  assert.match(graded.coverage.mobileArtifacts.undeterminable[0].note, /build variant/)
})

test('the manifest row says what happened to its own components', () => {
  // The note "no debuggable, cleartext or backup exposure declared" was printed verbatim even when
  // that manifest's own components failed in the other set, and read as an all-clear.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false"><provider android:name=".P" android:exported="true"/></application>
</manifest>`,
  })
  const row = graded.coverage.mobileArtifacts.pass[0]
  assert.match(row.note, /1 reachable component: 1 fail/)
})

// ---------------------------------------------------------------------------
// Exported by default, and deep links
// ---------------------------------------------------------------------------

test('a component exported by DEFAULT through an intent-filter is enumerated', () => {
  // checks/android.md has always required "(or an intent-filter and no explicit exported)", and
  // the engine could not see it because the old component window stopped before the children.
  // Android 12 makes the missing attribute a build error, so without a stated targetSdk the honest
  // disposition is undeterminable — enumerated and handed to a human, not silently dropped.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="false">
    <receiver android:name=".AdminReceiver">
      <intent-filter><action android:name="com.example.WIPE_ALL_USER_DATA"/></intent-filter>
    </receiver>
  </application>
</manifest>`,
  })
  const set = graded.coverage.exportedComponents
  assert.equal(set.enumerated, 1, 'it used to be invisible: exportedComponents was []')
  assert.equal(set.counts.undeterminable, 1)
  assert.match(set.undeterminable[0].note, /targetSdk 30 and below/)
})

test('with targetSdk 30 stated in the manifest, exported-by-default becomes a finding', () => {
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-sdk android:targetSdkVersion="30"/>
  <application android:allowBackup="false">
    <receiver android:name=".AdminReceiver">
      <intent-filter><action android:name="com.example.WIPE_ALL_USER_DATA"/></intent-filter>
    </receiver>
  </application>
</manifest>`,
  })
  const f = graded.findings.find(x => x.id === 'CG-AND-004')
  assert.ok(f)
  assert.equal(f.confidence, 'confirmed')
  assert.match(f.evidence.why, /targets SDK 30/)
})

test('deep links and declared permissions are declared, never silent', () => {
  // GRADE OR DECLARE. Neither has a rule; both must appear as an undeterminable row with an
  // instruction, or a reader cannot tell "not graded" from "nothing there".
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-permission android:name="android.permission.READ_SMS"/>
  <uses-permission android:name="android.permission.RECORD_AUDIO"/>
  <application android:allowBackup="false">
    <activity android:name=".PayActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp" android:host="pay"/>
      </intent-filter>
    </activity>
  </application>
</manifest>`,
  })
  const notes = graded.coverage.ungradedSurfaces.undeterminable
  assert.ok(notes.some(r => r.subject.startsWith('android-permissions:') && /READ_SMS/.test(r.note)))
  assert.ok(notes.some(r => r.subject.startsWith('android-deep-links:') && /myapp:\/\/pay/.test(r.note)))
})

// ---------------------------------------------------------------------------
// Native source and framework gaps — the two grade-or-declare holes
// ---------------------------------------------------------------------------

test('native and Dart source the parser cannot read is DECLARED, not silent', () => {
  // The largest hole in the mobile arm: an app whose live keys, WebView bridge and token logging
  // all sat in MainActivity.kt and AppDelegate.swift produced findings: [], verdict: clean,
  // ungradedSurfaces: 0 — a report that reads as an examined-and-clean mobile app.
  const { graded } = build({
    'package.json': PKG,
    'android/app/src/main/AndroidManifest.xml': '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:allowBackup="false"/></manifest>',
    'android/app/src/main/java/com/x/MainActivity.kt': 'val k = "sk_live_x"',
    'ios/App/AppDelegate.swift': 'let k = "sk-proj-x"',
    'android/app/src/main/res/values/strings.xml': '<resources><string name="api">x</string></resources>',
    'gradle.properties': 'STORE_PASSWORD=x',
  })
  const subjects = graded.coverage.ungradedSurfaces.undeterminable.map(r => r.subject)
  for (const s of ['native-source:kotlinJava', 'native-source:swiftObjc',
    'native-source:androidResValues', 'native-source:gradleConfig']) {
    assert.ok(subjects.includes(s), `${s} must be declared`)
  }
  for (const row of graded.coverage.ungradedSurfaces.undeterminable) {
    assert.match(row.note, /review against/, 'every declaration must say what to review it against')
  }
})

test('a managed Expo app declares its mobile surface instead of reporting a confident zero', () => {
  // The modal shape for this audience: no android/ or ios/ directory at all until `expo prebuild`.
  // Every mobile set reported 0, which renders as `mobileArtifacts | 0 | 0 | 0 | 0 | 0` — the same
  // row a repo with no mobile surface produces.
  const { model, graded } = build({
    'package.json': '{"name":"x","dependencies":{"expo":"~51.0.0","react-native":"0.74.5"}}',
    'app.json': JSON.stringify({ expo: { scheme: 'myapp', android: { usesCleartextTraffic: true } } }),
    'App.js': 'export default function App() { return null }',
  })
  assert.equal(model.framework.expo, '~51.0.0')
  assert.equal(model.framework.reactNative, '0.74.5')
  const rows = graded.coverage.ungradedSurfaces.undeterminable
  assert.ok(rows.some(r => r.subject === 'mobile-framework:expo' && /app\.json/.test(r.note)))
})

test('flutter and capacitor are detected at all', () => {
  const flutter = build({
    'pubspec.yaml': 'name: a\ndependencies:\n  flutter:\n    sdk: flutter\nflutter:\n  uses-material-design: true\n',
    'lib/main.dart': 'void main() {}',
  })
  assert.ok(flutter.model.framework.flutter, 'a pubspec with a flutter section is a Flutter app')
  const cap = build({ 'package.json': '{"name":"c","dependencies":{"@capacitor/core":"5.5.1"}}' })
  assert.equal(cap.model.framework.capacitor, '5.5.1')
})

// ---------------------------------------------------------------------------
// iOS
// ---------------------------------------------------------------------------

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

test('iOS: a binary plist is undeterminable, never a pass', () => {
  // bplist00 is what Xcode writes for several target types and what ships inside an IPA. The
  // textual reader finds nothing in one, so every ATS fact came back null and the file earned
  // "ATS left at the secure platform default" — a checkmark bought by being unreadable.
  const { graded } = build({
    'package.json': PKG,
    'ios/App/Info.plist': Buffer.from('bplist00\xd4\x01\x02\x03', 'binary'),
  })
  assert.equal(graded.coverage.mobileArtifacts.counts.pass, 0)
  assert.equal(graded.coverage.mobileArtifacts.counts.undeterminable, 1)
  assert.match(graded.coverage.mobileArtifacts.undeterminable[0].note, /plutil -convert xml1/)
})

test('iOS: NSAllowsArbitraryLoads beside an override key is needs-review, and names why', () => {
  // From iOS 10 onward NSAllowsArbitraryLoads is IGNORED when NSAllowsArbitraryLoadsInWebContent /
  // ForMedia / NSAllowsLocalNetworking is present — the narrower key governs. Claiming "ATS is off
  // for all hosts" as `confirmed` there is a false statement about every device made in a decade.
  // Severity is unchanged (impact-if-true is the same); the uncertainty is paid in evidence.
  const { graded } = build({
    'package.json': PKG,
    'ios/App/Info.plist': `<plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict>
  <key>NSAllowsArbitraryLoads</key><true/>
  <key>NSAllowsArbitraryLoadsInWebContent</key><true/>
</dict></dict></plist>`,
  })
  const global = graded.findings.find(f => f.id === 'CG-IOS-001')
  assert.equal(global.severity, 'P2', 'severity is impact-if-true and is never discounted for doubt')
  assert.equal(global.confidence, 'needs-review')
  assert.match(global.assumption, /iOS 10/)
  const web = graded.findings.find(f => f.id === 'CG-IOS-002')
  assert.ok(web, 'the key iOS actually honours must still be reported')
  assert.equal(web.confidence, 'confirmed')
})

test('iOS: custom URL schemes are declared', () => {
  const { graded } = build({
    'package.json': PKG,
    'ios/Runner/Info.plist': `<plist version="1.0"><dict>
  <key>CFBundleURLTypes</key><array><dict>
    <key>CFBundleURLSchemes</key><array><string>myapp</string></array>
  </dict></array>
</dict></plist>`,
  })
  const row = graded.coverage.ungradedSurfaces.undeterminable
    .find(r => r.subject.startsWith('ios-url-schemes:'))
  assert.ok(row, 'a claimable URL scheme may not be silent')
  assert.match(row.note, /myapp/)
})

test('vendored CocoaPods are skipped, as methodology/enumerate.md has always claimed', () => {
  // 'ios/Pods' sat in SKIP_DIRS, which is tested against a single directory NAME, so the entry was
  // dead. Pod plists became graded subjects the user cannot edit, and their pass rows inflated
  // coverage.
  const { model, graded } = build({
    'package.json': PKG,
    'ios/App/Info.plist': '<plist version="1.0"><dict/></plist>',
    'ios/Pods/Target Support Files/FirebaseCore/FirebaseCore-Info.plist': `<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>`,
  })
  assert.deepEqual(model.artifacts.infoPlist, ['ios/App/Info.plist'])
  assert.deepEqual(graded.findings, [], 'a vendored pod is not the user\'s code to fix')
  assert.ok(model.discovery.skippedDirs.some(d => d.dir === 'ios/Pods'),
    'the skip must be RECORDED — a silent skip is the thing the discovery ledger exists to prevent')
})

// ---------------------------------------------------------------------------
// THE STOCK-TEMPLATE CRY-WOLF BASELINE
//
// Every finding produced against an untouched framework template is a false positive BY
// CONSTRUCTION: nobody has written a line of app code yet, so there is nothing to be wrong. This
// audience cannot tell a false P2 from a real one — a wrong finding makes people rotate live keys
// and announce breaches that never happened — so a template that grades anything but `clean` is a
// release-blocking defect, not a tuning issue.
//
// These four fixtures are shaped verbatim after `npx react-native init`, `flutter create`, Android
// Studio's "Empty Activity" and `npx cap add android`, INCLUDING React Native's real
// src/debug/AndroidManifest.xml with usesCleartextTraffic="true". Before the fixes above, all four
// graded `medium` and React Native graded `medium` twice over.
//
// Modelled on test/clean_app.test.mjs, which does exactly this for the web arm.
// ---------------------------------------------------------------------------

const STOCK_TEMPLATES = {
  'npx react-native init': {
    'package.json': '{"name":"rn","dependencies":{"react":"18.2.0","react-native":"0.73.6"}}',
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <uses-permission android:name="android.permission.INTERNET" />

    <application
      android:name=".MainApplication"
      android:label="@string/app_name"
      android:icon="@mipmap/ic_launcher"
      android:roundIcon="@mipmap/ic_launcher_round"
      android:allowBackup="false"
      android:theme="@style/AppTheme"
      android:supportsRtl="true">
      <activity
        android:name=".MainActivity"
        android:label="@string/app_name"
        android:configChanges="keyboard|keyboardHidden|orientation|screenLayout|screenSize|smallestScreenSize|uiMode"
        android:launchMode="singleTask"
        android:windowSoftInputMode="adjustResize"
        android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN" />
            <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>
      </activity>
    </application>
</manifest>`,
    // The real file, verbatim. This alone used to produce CG-AND-002 confirmed → verdict medium.
    'android/app/src/debug/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <application
      android:usesCleartextTraffic="true"
      tools:targetApi="28"
      tools:ignore="GoogleAppIndexingWarning"
      tools:replace="android:usesCleartextTraffic" />
</manifest>`,
    'App.tsx': 'export default function App() { return null }',
  },

  'flutter create': {
    'pubspec.yaml': "name: myapp\nenvironment:\n  sdk: '>=3.3.0 <4.0.0'\ndependencies:\n  flutter:\n    sdk: flutter\nflutter:\n  uses-material-design: true\n",
    'android/app/src/main/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:label="myapp"
        android:name="\${applicationName}"
        android:icon="@mipmap/ic_launcher">
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:launchMode="singleTop"
            android:theme="@style/LaunchTheme"
            android:configChanges="orientation|keyboardHidden|keyboard|screenSize|smallestScreenSize|locale|layoutDirection|fontScale|screenLayout|density|uiMode"
            android:hardwareAccelerated="true"
            android:windowSoftInputMode="adjustResize">
            <meta-data
              android:name="io.flutter.embedding.android.NormalTheme"
              android:resource="@style/NormalTheme"
              />
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <meta-data
            android:name="flutterEmbedding"
            android:value="2" />
    </application>
    <queries>
        <intent>
            <action android:name="android.intent.action.PROCESS_TEXT"/>
            <data android:mimeType="text/plain"/>
        </intent>
    </queries>
</manifest>`,
    'android/app/src/debug/AndroidManifest.xml': `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET"/>
</manifest>`,
    'ios/Runner/Info.plist': `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>$(DEVELOPMENT_LANGUAGE)</string>
	<key>UIApplicationSupportsIndirectInputEvents</key>
	<true/>
</dict>
</plist>`,
    'lib/main.dart': 'void main() {}',
  },

  'Android Studio Empty Activity': {
    'app/src/main/AndroidManifest.xml': `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <application
        android:allowBackup="true"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:fullBackupContent="@xml/backup_rules"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.MyApplication"
        tools:targetApi="31">
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:label="@string/app_name"
            android:theme="@style/Theme.MyApplication">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>

</manifest>`,
    'app/src/main/res/xml/data_extraction_rules.xml': '<data-extraction-rules><cloud-backup></cloud-backup></data-extraction-rules>',
    'app/src/main/res/values/strings.xml': '<resources><string name="app_name">My Application</string></resources>',
    'app/src/main/java/com/example/myapplication/MainActivity.kt': 'class MainActivity',
    'gradle.properties': 'org.gradle.jvmargs=-Xmx2048m',
  },

  'npx cap add android': {
    'package.json': '{"name":"cap","dependencies":{"@capacitor/core":"5.5.1","@capacitor/android":"5.5.1"}}',
    'android/app/src/main/AndroidManifest.xml': `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme">

        <activity
            android:configChanges="orientation|keyboardHidden|keyboard|screenSize|locale|smallestScreenSize|screenLayout|uiMode"
            android:name="com.example.app.MainActivity"
            android:label="@string/title_activity_main"
            android:theme="@style/AppTheme.NoActionBarLaunch"
            android:launchMode="singleTask"
            android:exported="true">

            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>

        </activity>

        <provider
            android:name="androidx.core.content.FileProvider"
            android:authorities="\${applicationId}.fileprovider"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/file_paths" />
        </provider>
    </application>

    <uses-permission android:name="android.permission.INTERNET" />
</manifest>`,
    'ios/App/App/Info.plist': '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleDisplayName</key><string>cap</string></dict></plist>',
  },
}

for (const [name, files] of Object.entries(STOCK_TEMPLATES)) {
  test(`CRY-WOLF: an untouched \`${name}\` project produces NO findings`, () => {
    const { graded } = build(files)
    assert.deepEqual(graded.findings.map(f => `${f.severity} ${f.id} ${f.subject}`), [],
      'every finding listed here is a false positive against a template nobody has edited yet')
    assert.equal(graded.verdict.level, 'clean')
  })

  test(`CRY-WOLF: \`${name}\` is still fully ACCOUNTED FOR, not merely quiet`, () => {
    // Silence is not the fix for a false positive — a template must be enumerated and dispositioned
    // exactly like anything else, or "no findings" starts meaning "we looked nowhere".
    const { graded } = build(files)
    for (const [setName, set] of Object.entries(graded.coverage)) {
      const c = set.counts
      assert.equal(c.pass + c.fail + c.undeterminable + c.allowlisted, set.enumerated,
        `LAW 2 broken in "${setName}"`)
    }
    assert.ok(graded.coverage.mobileArtifacts.enumerated > 0,
      'the manifests must be enumerated; a zero here would mean we stopped reading them')
    for (const row of [...graded.coverage.mobileArtifacts.undeterminable,
      ...graded.coverage.exportedComponents.undeterminable,
      ...graded.coverage.ungradedSurfaces.undeterminable]) {
      assert.ok(row.note && row.note.length > 20,
        `an undeterminable row without an instruction is an apology: ${row.subject}`)
    }
  })
}
