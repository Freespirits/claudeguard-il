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
// Privacy / data-security (compliance pillar) end-to-end gates, engine → grader.
// The regulation (תקנות הגנת הפרטיות (אבטחת מידע)) is mostly process, so the graded slice is thin
// (cleartext transit, session-cookie flags) and the rest is declared. Two properties proven here:
//   1. CRY-WOLF — a correct app (https, secure cookies) produces ZERO privacy findings, and the
//      classic cleartext-detector FPs (xmlns/schema namespaces, localhost, env-conditional secure)
//      never fire.
//   2. THE WALL — a privacy finding never touches the security verdict.
// ---------------------------------------------------------------------------

function build(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-priv-'))
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

const PKG = '{"name":"p","dependencies":{"@supabase/supabase-js":"2.0.0"}}'
const priv = g => g.findings.filter(f => f.id.startsWith('CG-PRIV'))
const hasId = (g, id) => priv(g).some(f => f.id === id)

test('DETECTION: a cleartext http:// request and an insecure session cookie fire CG-PRIV-*', () => {
  const { graded } = build({
    'package.json': PKG,
    'api.ts': `export async function h(req, res) {
      const r = await fetch('http://api.example.com/users')
      res.cookie('session', 'v', { httpOnly: false })
      return r
    }`,
  })
  assert.ok(hasId(graded, 'CG-PRIV-TLS'), 'cleartext http:// request target')
  assert.ok(hasId(graded, 'CG-PRIV-COOKIE'), 'session cookie missing httpOnly')
})

test('THE WALL: those privacy findings never touch the security verdict', () => {
  const { graded } = build({
    'package.json': PKG,
    'api.ts': `export async function h(req, res) {
      await fetch('http://api.example.com/users')
      res.cookie('session', 'v', { httpOnly: false, secure: false })
    }`,
  })
  assert.equal(graded.verdict.level, 'clean', 'a privacy exposure must not redden or unknown the security badge')
  assert.ok(graded.compliance.total >= 2, 'but the compliance pillar reports them')
  assert.ok(priv(graded).every(f => f.pillar === 'compliance'))
  assert.equal(graded.findings.filter(f => f.pillar === 'security').length, 0)
})

test('CRY-WOLF: a correct app (https, secure cookie) produces ZERO privacy findings', () => {
  const { graded } = build({
    'package.json': PKG,
    'api.ts': `export async function h(req, res) {
      await fetch('https://api.example.com/users')
      res.cookie('session', 'v', { httpOnly: true, secure: true, sameSite: 'lax' })
    }`,
  })
  assert.deepEqual(priv(graded).map(f => f.id), [], 'correct transport + cookies = silent')
})

test('TRAP: xmlns/schema namespace URLs, localhost, and env-conditional secure never fire', () => {
  const { graded } = build({
    'package.json': PKG,
    'app.tsx': `export const S = () => <svg xmlns="http://www.w3.org/2000/svg"/>
      const ctx = { '@context': 'http://schema.org' }`,
    'dev.ts': `export const ping = () => fetch('http://localhost:3000/health')`,
    'cookie.ts': `export const set = (res) => res.cookie('session', 'v', { httpOnly: true, secure: process.env.NODE_ENV === 'production' })`,
  })
  assert.equal(hasId(graded, 'CG-PRIV-TLS'), false, 'namespaces and localhost are not cleartext transmissions')
  assert.equal(hasId(graded, 'CG-PRIV-COOKIE'), false, 'env-conditional secure is the correct pattern')
})

test('the ~20 declared obligation rows appear for a data-holding app, all undeterminable (grade-or-declare)', () => {
  const { graded } = build({
    'package.json': PKG,
    'api.ts': `export const h = () => fetch('https://api.example.com/x')`,
  })
  const ob = graded.coverage.privacyObligations
  assert.ok(ob, 'the obligations set is declared')
  assert.ok(ob.counts.undeterminable >= 19, 'every obligation is declared, never asserted as a violation')
  assert.equal(ob.counts.fail, 0, 'a process obligation is never a fail from source')
})

test('a static site with NO data layer is not handed the data-security obligations', () => {
  const { graded } = build({
    'package.json': '{"name":"s","dependencies":{"next":"14.0.0"}}',
    'page.tsx': `export default () => <main>hello</main>`,
  })
  assert.equal(graded.coverage.privacyObligations.enumerated, 0, 'no personal-data database → the regulation does not bind')
})
