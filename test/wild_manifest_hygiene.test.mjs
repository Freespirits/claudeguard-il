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
// OBSERVE — and drop the rest, which no pass can read. The name tests below keep that true:
// one stops a newly-added case from re-importing a 90-dependency manifest, another stops
// the allowlist from silently narrowing if the engine renames what it looks for.
//
// Those name tests assert nothing about VERSIONS. Fidelity to upstream is the point of the corpus,
// so a dependency that survives the trim keeps the real pin — including a vulnerable one, which is
// why this repository still carries a small, genuine, fixture-only alert count rather than zero.
// But "any version is allowed" left one door open: Dependabot SECURITY-update PRs against these
// manifests keep appearing (dependabot.yml explains why the limit cannot stop them), and a merged
// bump would move a pin the blind labels were written against — falsifying the corpus while every
// test stayed green. So the pins are snapshotted in EXPECTED_VERSION_PINS below: a version that
// MOVES fails loudly, and a human decides — close the Dependabot PR, or bless an intentional
// corpus change by updating the snapshot and the case's truth.json notes.
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

// ---------------------------------------------------------------------------
// The upstream pin every vendored wild manifest held at the ERR-007 trim (0.3.1). A Dependabot
// security-update PR merged against bench/wild changes exactly one of these — and fails here.
// ---------------------------------------------------------------------------
const EXPECTED_VERSION_PINS = {
  'chartgpt-service-role-client': {
    dependencies: {
      '@supabase/supabase-js': '^2.21.0',
      'ajv': '^8.12.0',
      'express': '^4.18.2',
      'express-rate-limit': '^6.7.0',
      'next': 'latest',
      'openai': '^3.2.1',
      'react': '^18.2.0',
    },
  },
  'chordmini-firebase-open-rules': {
    dependencies: {
      'firebase': '^11.10.0',
      'firebase-admin': '^13.8.0',
      'next': '^16.2.12',
      'react': '^19.0.0',
    },
  },
  'lyrictor-firebase-clean': {
    dependencies: { 'firebase': '^12.10.0', 'react': '^19' },
    devDependencies: { 'electron': '^36.0.0', 'vite': '^6.2.2' },
  },
  'nextjs-subscription-payments': {
    dependencies: {
      '@supabase/ssr': '^0.1.0',
      '@supabase/supabase-js': '^2.43.4',
      'next': '14.2.3',
      'react': '^18.3.1',
    },
  },
  'nextjs-with-supabase': {
    dependencies: {
      '@supabase/ssr': 'latest',
      '@supabase/supabase-js': 'latest',
      'next': 'latest',
      'react': '^19.0.0',
    },
  },
  'owasp-nodegoat': {
    dependencies: { 'express': '^4.13.4' },
  },
  'promptos-forgeable-admin-session': {
    dependencies: {
      '@ai-sdk/openai': '^4.0.8',
      '@google/generative-ai': '^0.24.0',
      '@supabase/ssr': '^0.7.0',
      '@supabase/supabase-js': '^2.49.4',
      'ai': '^4.3.9',
      'next': '15.5.9',
      'openai': '^5.19.1',
      'react': '^19.0.0',
      'zod': '^3.25.76',
    },
  },
  'react-openai-client-key': {
    dependencies: { 'openai': '^5.20.0', 'react': '^19.1.1' },
    devDependencies: { 'vite': '^7.1.2' },
  },
  'vocabtest-rls-disabled': {
    dependencies: {
      '@supabase/ssr': '^0.7.0',
      '@supabase/supabase-js': '^2.57.4',
      'next': '15.5.3',
      'react': '19.1.0',
    },
  },
}

test('vendored wild manifests hold their recorded upstream version pins', () => {
  for (const [name, pkg] of vendoredManifests()) {
    const expected = EXPECTED_VERSION_PINS[name]
    assert.ok(expected,
      `${name} has no recorded version pins — a new case? Record its upstream pins in EXPECTED_VERSION_PINS.`)
    for (const key of ['dependencies', 'devDependencies']) {
      assert.deepEqual(pkg[key] || {}, expected[key] || {},
        `${name}: ${key} moved. bench/wild pins must NEVER move (ERR-007, dependabot.yml): each is pinned ` +
        `to the third-party commit the blind labels were written against, so a bump falsifies the corpus. ` +
        `If this is a Dependabot security-update PR, close it unmerged. If it is an intentional corpus ` +
        `change, update EXPECTED_VERSION_PINS and record the reason in ${name}/truth.json.`)
    }
  }
})
