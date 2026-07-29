import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ENGINE = join(HERE, '..', 'plugin', 'scripts', 'project_model.mjs')

function modelOf(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-disc-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
      encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    }))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

// ---------------------------------------------------------------------------
// DISCOVERY coverage is a different axis from analysis coverage. Analysis coverage accounts for
// every subject the engine ENUMERATED; discovery coverage accounts for what it FAILED to see —
// files it could not parse, routes it could only partially model, imports it could not resolve.
//
// A report that shows only analysis coverage can look complete while the engine silently skipped
// half the repo. These tests hold the line the whole axis exists to hold: nothing is skipped
// without a reason, and the file ledger always adds up.
// ---------------------------------------------------------------------------

test('the file ledger always reconciles: discovered = parsed + configParsed + unsupported + oversized + readErrors', () => {
  const m = modelOf({
    'package.json': '{"name":"x"}',              // unsupported (not code)
    'src/a.ts': 'export const a = 1',            // parsed
    'src/b.tsx': 'export const B = () => null',  // parsed
    'README.md': '# hi',                         // unsupported
    'data.json': '{}',                           // unsupported
    'big.ts': 'x'.repeat(1.6 * 1024 * 1024),     // oversized (> 1.5MB cap)
  })
  const c = m.discovery.counts
  assert.equal(c.filesParsed + c.configParsed + c.unsupported + c.oversized + c.readErrors, c.filesDiscovered,
    'the five categories must sum to the discovered count, or the ledger is lying')
  assert.equal(m.discovery.reconciles, true)
  assert.equal(c.oversized, 1, 'the 1.6MB file is over the cap')
})

test('a file read by a dedicated parser is counted as parsed, not as unsupported', () => {
  // The ledger's only job is to be accurate about what was read. Once workflows, Dockerfiles and
  // rules files have parsers, reporting them as "unsupported" says the engine ignored files it in
  // fact examined — an understatement, but still a false one, in the section a reader consults to
  // find out how much of their repo was actually looked at.
  const m = modelOf({
    'package.json': '{"name":"x"}',
    '.github/workflows/ci.yml': 'on: push\njobs:\n  a:\n    steps:\n      - run: echo hi\n',
    'Dockerfile': 'FROM node:22-alpine\nUSER node\n',
    'firestore.rules': 'match /a/{x} { allow read: if false; }\n',
    'README.md': '# genuinely unsupported\n',
  })
  const c = m.discovery.counts
  assert.ok(c.configParsed >= 3, 'the workflow, Dockerfile and rules file were each read by a parser')
  assert.equal(c.filesParsed + c.configParsed + c.unsupported + c.oversized + c.readErrors, c.filesDiscovered)
  assert.equal(m.discovery.reconciles, true)
})

test('an oversized file is recorded as a notable skip WITH a reason, never silently dropped', () => {
  const m = modelOf({
    'package.json': '{"name":"x"}',
    'huge.ts': 'y'.repeat(1.7 * 1024 * 1024),
  })
  const skip = m.discovery.notableSkips.find(s => s.file === 'huge.ts')
  assert.ok(skip, 'the oversized file must appear in notableSkips')
  assert.match(skip.reason, /oversized/, 'the reason must say why it was skipped')
})

test('skipped directories are listed with reasons (build/vendor and dotfiles)', () => {
  const m = modelOf({
    'package.json': '{"name":"x"}',
    'src/app.ts': 'export const x = 1',
    'node_modules/dep/index.js': 'module.exports = {}',
    'dist/bundle.js': 'console.log(1)',
  })
  const skipped = Object.fromEntries(m.discovery.skippedDirs.map(s => [s.dir, s.reason]))
  assert.ok('node_modules' in skipped, 'node_modules must be recorded as skipped, not silently ignored')
  assert.match(skipped['node_modules'], /vendor|build|ignored/i)
  // and nothing from a skipped dir was parsed
  assert.ok(!m.discovery.notableSkips.some(s => s.file.startsWith('node_modules/')))
})

test('a route whose HTTP methods could not be read is modeled-but-partial, and counted', () => {
  // A pages-API default-export handler with no explicit method check: the engine models the route
  // but cannot read its methods. That is a partial model, and hiding it would let a rule that keys
  // on the method silently under-fire.
  const m = modelOf({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}',
    'pages/api/thing.ts': 'export default function handler(req, res) { res.json({ ok: true }) }',
  })
  assert.equal(m.discovery.routes.foundByFilesystem, 1)
  assert.equal(m.discovery.routes.modeled, 1)
  assert.equal(m.discovery.routes.withUnknownMethods, 1,
    'the route is modeled, but its methods are unread — discovery must say so')
})

test('rlsVerifiable is true with migrations and false without — the key Supabase discovery fact', () => {
  const withMig = modelOf({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"2.45.0"}}',
    'supabase/migrations/001.sql': 'create table public.t (id uuid primary key);',
  })
  assert.equal(withMig.discovery.schema.rlsVerifiable, true)

  const noMig = modelOf({
    'package.json': '{"name":"x","dependencies":{"@supabase/supabase-js":"2.45.0"}}',
    'lib/db.ts': "import { createClient } from '@supabase/supabase-js'\nexport const s = createClient(u, k)\nawait s.from('orders').select()",
  })
  assert.equal(noMig.discovery.schema.rlsVerifiable, false,
    'no migrations means RLS state is NOT discoverable from the repo — every RLS row is really unknown')
})

test('the discovery ledger is present on the real fixtures and reconciles', () => {
  // A release gate in spirit: a scan must always emit a reconciling discovery ledger. A missing or
  // broken ledger means a parser failure or skip could be hidden.
  const repo = join(HERE, '..', 'sample-vulnerable-app')
  const m = JSON.parse(execFileSync(process.execPath, [ENGINE, repo], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  }))
  assert.ok(m.discovery, 'the engine must always emit a discovery ledger')
  assert.equal(m.discovery.reconciles, true)
  assert.equal(typeof m.discovery.schema.rlsVerifiable, 'boolean')
})
