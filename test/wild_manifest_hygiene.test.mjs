import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  FRAMEWORK_PACKAGES, SERVER_FRAMEWORK_PACKAGES, OBSERVABLE_PACKAGES,
} from '../bench/wild/observable-packages.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const WILD = join(HERE, '..', 'bench', 'wild')
const ENGINE_SRC = readFileSync(join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs'), 'utf8')

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS.
//
// The wild corpus vendors real third-party source. A vendored `package.json` enters GitHub's
// dependency graph, and Dependabot then raises an alert for every stale dependency of a fixture
// that is never installed, built, run or shipped. That reached ~120 alerts — a repository whose own
// alert list is almost entirely noise, on a project whose entire argument is that a clean scan and
// a noisy scan must both mean something. Retracted and explained as ERR-007 in ERRATA.md.
//
// The fix was to keep, at their upstream-pinned versions, exactly the dependencies the engine can
// OBSERVE — and drop the rest, which no pass can read. These two tests are what keep that true:
// the first stops a newly-added case from re-importing a 90-dependency manifest, the second stops
// the allowlist from silently narrowing if the engine renames what it looks for.
//
// Neither test asserts anything about VERSIONS. Fidelity to upstream is the point of the corpus, so
// a dependency that survives the trim keeps the real pin — including a vulnerable one, which is why
// this repository still carries a small, genuine, fixture-only alert count rather than zero.
// ---------------------------------------------------------------------------

/** Every vendored wild manifest, as [caseName, parsedPkg]. */
function vendoredManifests() {
  const out = []
  for (const e of readdirSync(WILD, { withFileTypes: true })) {
    if (!e.isDirectory()) continue
    const p = join(WILD, e.name, 'repo', 'package.json')
    if (existsSync(p)) out.push([e.name, JSON.parse(readFileSync(p, 'utf8'))])
  }
  return out
}

test('the wild corpus vendors at least one manifest to guard', () => {
  assert.ok(vendoredManifests().length > 0, 'no bench/wild/*/repo/package.json found — has the corpus moved?')
})

test('no vendored wild manifest declares a dependency the engine cannot observe', () => {
  const offenders = []
  for (const [name, pkg] of vendoredManifests()) {
    for (const key of ['dependencies', 'devDependencies']) {
      for (const dep of Object.keys(pkg[key] || {})) {
        if (!OBSERVABLE_PACKAGES.has(dep)) offenders.push(`${name}: ${key}.${dep}`)
      }
    }
  }
  assert.deepEqual(offenders, [],
    'These dependencies are invisible to every engine pass, so they buy no detection — and each one ' +
    'can raise a Dependabot alert against a fixture that is never installed. Remove them, or add the ' +
    'name to bench/wild/observable-packages.mjs if the engine really does read it now.')
})

test('every allowlisted package name still appears in the engine source', () => {
  // Guards the other direction: if project_model.mjs stops reading `@supabase/ssr` (rename, refactor,
  // deletion), the allowlist would keep permitting it and the corpus would quietly stop exercising a
  // detector nobody noticed had moved.
  const missing = [...FRAMEWORK_PACKAGES, ...SERVER_FRAMEWORK_PACKAGES]
    .filter(n => !ENGINE_SRC.includes(`'${n}'`))
  assert.deepEqual(missing, [],
    'These names are allowlisted for vendored manifests but project_model.mjs no longer mentions them. ' +
    'Either the engine renamed what it looks for, or the allowlist has stale entries.')
})

test('the trim preserved the framework signal each wild case is labelled against', () => {
  // The corpus measures detection on Next.js/Supabase/Firebase/AI code. If the trim had removed the
  // dependency that makes a case detectable as such, the wild scorecard would silently drop — so
  // spot-check the signal per case rather than trusting the scorecard alone.
  const EXPECTED_SIGNAL = {
    'chartgpt-service-role-client': ['next', '@supabase/supabase-js', 'openai'],
    'chordmini-firebase-open-rules': ['next', 'firebase', 'firebase-admin'],
    'lyrictor-firebase-clean': ['firebase'],
    'nextjs-subscription-payments': ['next', '@supabase/ssr', '@supabase/supabase-js'],
    'nextjs-with-supabase': ['next', '@supabase/ssr', '@supabase/supabase-js'],
    'owasp-nodegoat': ['express'],
    'promptos-forgeable-admin-session': ['next', '@supabase/ssr', 'openai'],
    'react-openai-client-key': ['openai', 'react'],
    'vocabtest-rls-disabled': ['next', '@supabase/ssr', '@supabase/supabase-js'],
  }
  for (const [name, pkg] of vendoredManifests()) {
    const expected = EXPECTED_SIGNAL[name]
    if (!expected) continue // a case added later; the allowlist test still covers it
    const declared = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) }
    for (const dep of expected) {
      assert.ok(Object.prototype.hasOwnProperty.call(declared, dep),
        `${name} lost '${dep}' — the framework signal the blind labels were matched against`)
    }
  }
})
