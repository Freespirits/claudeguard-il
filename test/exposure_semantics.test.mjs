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
  const dir = mkdtempSync(join(tmpdir(), 'cg-ex-'))
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

// ---------------------------------------------------------------------------
// REGRESSION — found by running the engine against a real 184-star repo.
//
// The engine reported STRIPE_SECRET_KEY, S3_SECRET_ACCESS_KEY, DATABASE_URL and two more as
// client-exposed, because a `'use client'` provider imported the module that references them.
// That was WRONG: Next.js statically inlines ONLY NEXT_PUBLIC_* into client output. A bare
// process.env.SECRET is absent from the browser bundle and evaluates to undefined.
//
// Worse, the repo was using t3-env — the recommended guard AGAINST leaking server vars. The tool
// would have fired five confident P0s at a correctly-built app. That is how a security tool
// loses its users.
// ---------------------------------------------------------------------------

test('REGRESSION: a non-prefixed secret referenced in a client-imported module is NOT exposed', () => {
  const m = modelOf({
    'package.json': NEXT_PKG,
    'src/env.mjs': `export const env = createEnv({
  server: { STRIPE_SECRET_KEY: z.string() },
  client: { NEXT_PUBLIC_SITE_URL: z.string() },
  runtimeEnv: {
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
    NEXT_PUBLIC_SITE_URL: process.env.NEXT_PUBLIC_SITE_URL,
  },
})`,
    'src/providers/Provider.tsx': "'use client'\nimport { env } from '../env.mjs'\nexport default function P(){ return env.NEXT_PUBLIC_SITE_URL }",
  })

  const stripe = m.envVars.find(v => v.name === 'STRIPE_SECRET_KEY')
  assert.equal(stripe.exposure, 'referenced-in-client-module',
    'must NOT be classified as an inlined/leaked secret')
  assert.notEqual(stripe.exposureStrength, 'definitive')
  assert.notEqual(stripe.exposureStrength, 'strong',
    'bundlers do not inline non-prefixed vars — claiming exposure here fires a P0 at correct code')
})

test('a NEXT_PUBLIC_ secret IS definitively exposed (the real leak path)', () => {
  const m = modelOf({
    'package.json': NEXT_PKG,
    'lib/x.ts': 'export const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY',
  })
  const v = m.envVars.find(x => x.name === 'NEXT_PUBLIC_STRIPE_SECRET_KEY')
  assert.equal(v.exposure, 'bundler-inlined-public-prefix')
  assert.equal(v.exposureStrength, 'definitive',
    'the prefix is what makes it definitive — no graph reasoning required')
})

test('the t3-env guard pattern is recognised as protective, not suspicious', () => {
  const m = modelOf({
    'package.json': '{"name":"x","dependencies":{"@t3-oss/env-nextjs":"0.11.0","next":"15.0.0"}}',
    'src/env.mjs': `import { createEnv } from '@t3-oss/env-nextjs'
export const env = createEnv({
  server: { DATABASE_URL: z.string() },
  client: { NEXT_PUBLIC_URL: z.string() },
  runtimeEnv: { DATABASE_URL: process.env.DATABASE_URL, NEXT_PUBLIC_URL: process.env.NEXT_PUBLIC_URL },
})`,
  })
  assert.equal(m.envGuards.length, 1)
  assert.equal(m.envGuards[0].library, 't3-env')
  assert.equal(m.envGuards[0].protectsServerVars, true,
    'a project using t3-env is doing the right thing and must be credited, not punished')
})

test('a var named only in .env.example, with no value and no usage, is not a live exposure', () => {
  // Found on a real repo: NEXT_PUBLIC_..._AUTH_TOKEN existed ONLY as an empty placeholder in
  // .env.example and was referenced nowhere. There is no secret to leak. Reporting a P0 there
  // manufactures a critical finding out of documentation.
  const m = modelOf({
    'package.json': NEXT_PKG,
    '.env.example': 'NEXT_PUBLIC_GITHUB_AUTH_TOKEN=\nNEXT_PUBLIC_SITE_URL=\n',
  })
  const v = m.envVars.find(x => x.name === 'NEXT_PUBLIC_GITHUB_AUTH_TOKEN')
  assert.equal(v.exampleOnly, true)
  assert.equal(v.exposure, 'example-only')
  assert.equal(v.exposureStrength, 'n/a', 'nothing exists yet, so nothing is exposed')
})

test('a REAL value committed in .env is still a live exposure', () => {
  // The tightening above must not suppress the genuine case.
  const m = modelOf({
    'package.json': NEXT_PKG,
    '.env': 'NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_realvaluehere123456\n',
  })
  const v = m.envVars.find(x => x.name === 'NEXT_PUBLIC_STRIPE_SECRET_KEY')
  assert.equal(v.exampleOnly, false)
  assert.equal(v.exposureStrength, 'definitive', 'a real value behind a public prefix IS inlined')
})

test('the client-graph signal is retained separately for correctness bugs', () => {
  // Referencing a server var from client code is still a real (minor) bug: it is undefined at
  // runtime. We keep the signal — we just refuse to call it a leaked secret.
  const m = modelOf({
    'package.json': NEXT_PKG,
    'lib/cfg.ts': 'export const k = process.env.MY_API_SECRET',
    'app/page.tsx': "'use client'\nimport { k } from '../lib/cfg'\nexport default () => k",
  })
  const v = m.envVars.find(x => x.name === 'MY_API_SECRET')
  assert.equal(v.exposure, 'referenced-in-client-module')
  assert.equal(v.clientGraphStrength, 'strong', 'the graph fact is preserved for a P3-level rule')
})
