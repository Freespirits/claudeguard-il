import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const SCRIPT = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')

function modelOf(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-ig-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return JSON.parse(execFileSync(process.execPath, [SCRIPT, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    }))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const NEXT_PKG = '{"name":"x","dependencies":{"next":"15.0.0"}}'
const strengthOf = (m, file) => m.boundary.clientReachableDetail.find(d => d.file === file)?.strength

// ---------------------------------------------------------------------------
// FALSE-POSITIVE BLOCKER: barrel files must not fabricate a P0.
//
// `import { cn } from '@/lib'` in a client component pulls the barrel's ENTIRE re-export
// closure into the graph. If that counted as strong evidence, a correct app would be told its
// service-role key is in the browser — and people rotate keys and announce breaches over that.
// ---------------------------------------------------------------------------

test('reachability THROUGH a barrel is weak, not strong', () => {
  const m = modelOf({
    'package.json': NEXT_PKG,
    'lib/index.ts': "export * from './utils'\nexport * from './db'\n",
    'lib/utils.ts': 'export const cn = (...a) => a.join(" ")',
    'lib/db.ts': 'export const admin = process.env.SUPABASE_SERVICE_ROLE_KEY',
    'app/page.tsx': "'use client'\nimport { cn } from '../lib'\nexport default function P(){ return cn('a') }",
  })
  assert.ok(m.boundary.barrels.includes('lib/index.ts'), 'lib/index.ts must be detected as a barrel')
  assert.equal(strengthOf(m, 'lib/db.ts'), 'weak',
    'tree-shaking may well drop this; claiming a definite P0 here would be a false positive')

  const v = m.envVars.find(x => x.name === 'SUPABASE_SERVICE_ROLE_KEY')
  assert.equal(v.clientGraphStrength, 'weak', 'weak graph evidence must cap severity below P0')
  assert.notEqual(v.exposureStrength, 'definitive',
    'no public prefix, so nothing is inlined into client output — this is not a leak')
})

test('a DIRECT import into a client component is strong evidence', () => {
  const m = modelOf({
    'package.json': NEXT_PKG,
    'lib/db.ts': 'export const admin = process.env.SUPABASE_SERVICE_ROLE_KEY',
    'app/page.tsx': "'use client'\nimport { admin } from '../lib/db'\nexport default function P(){ return admin }",
  })
  assert.equal(strengthOf(m, 'lib/db.ts'), 'strong')
  const v = m.envVars.find(x => x.name === 'SUPABASE_SERVICE_ROLE_KEY')
  assert.equal(v.clientGraphStrength, 'strong')
  // Still not a leak: without a public prefix the bundler does not inline the value.
  // The graph fact drives a "this is undefined in the browser" correctness rule, not a P0.
  assert.equal(v.exposure, 'referenced-in-client-module')
})

test("a public bundler prefix is DEFINITIVE and needs no graph inference", () => {
  const m = modelOf({
    'package.json': NEXT_PKG,
    'lib/db.ts': 'export const k = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY',
  })
  const v = m.envVars.find(x => x.name.includes('SERVICE_ROLE'))
  assert.equal(v.exposureStrength, 'definitive',
    'the bundler inlines this value into client output regardless of who imports it')
})

test("'server-only' hard-stops a client chain", () => {
  // Importing a server-only module from the client is a BUILD ERROR, so the chain cannot exist.
  // Reporting it would be a finding about code that cannot compile.
  const m = modelOf({
    'package.json': NEXT_PKG,
    'lib/db.ts': "import 'server-only'\nexport const admin = process.env.SUPABASE_SERVICE_ROLE_KEY",
    'lib/index.ts': "export * from './db'\n",
    'app/page.tsx': "'use client'\nimport { admin } from '../lib'\nexport default function P(){ return null }",
  })
  assert.ok(m.boundary.serverOnlyModules.includes('lib/db.ts'))
  assert.ok(!m.boundary.clientReachable.includes('lib/db.ts'),
    'a server-only module can never be in the client bundle')
})

// ---------------------------------------------------------------------------
// Monorepo resolution — where cross-file recall used to die silently.
// ---------------------------------------------------------------------------

test('workspace package imports resolve across packages', () => {
  const m = modelOf({
    'package.json': '{"name":"root","private":true,"workspaces":["apps/*","packages/*"]}',
    'packages/db/package.json': '{"name":"@repo/db","main":"index.ts"}',
    'packages/db/index.ts': 'export const admin = process.env.SUPABASE_SERVICE_ROLE_KEY',
    'apps/web/package.json': '{"name":"web","dependencies":{"next":"15.0.0"}}',
    'apps/web/app/page.tsx': "'use client'\nimport { admin } from '@repo/db'\nexport default function P(){ return admin }",
  })
  const names = m.graphCoverage.workspacePackages.map(w => w.name)
  assert.ok(names.includes('@repo/db'), 'workspace packages must be discovered from package.json workspaces')
  assert.ok(m.boundary.clientReachable.includes('packages/db/index.ts'),
    'the cross-package edge must not be lost — this is exactly the multi-file case we claim to handle')
})

test('pnpm-workspace.yaml packages are discovered too', () => {
  const m = modelOf({
    'package.json': '{"name":"root","private":true}',
    'pnpm-workspace.yaml': "packages:\n  - 'packages/*'\n",
    'packages/ui/package.json': '{"name":"@acme/ui"}',
    'packages/ui/index.ts': 'export const Button = () => null',
    'app/page.tsx': "import { Button } from '@acme/ui'\nexport default Button",
  })
  const names = m.graphCoverage.workspacePackages.map(w => w.name)
  assert.ok(names.includes('@acme/ui'))
})

test('a genuine third-party package is not reported as an unresolved workspace import', () => {
  const m = modelOf({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}',
    'app/page.tsx': "import React from 'react'\nexport default () => null",
  })
  assert.equal(m.graphCoverage.unresolvedWorkspaceImports.length, 0,
    'react is a dependency, not a coverage hole')
})
