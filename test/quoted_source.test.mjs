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
  const dir = mkdtempSync(join(tmpdir(), 'cg-quoted-'))
  try {
    for (const [rel, content] of Object.entries(files)) {
      const abs = join(dir, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content, 'utf8')
    }
    return JSON.parse(execFileSync(process.execPath, [ENGINE, dir], {
      encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    }))
  } finally { rmSync(dir, { recursive: true, force: true }) }
}

const PKG = '{"name":"x","dependencies":{"next":"15.0.0","openai":"4.60.0"}}'
const sites = m => m.llmSites.map(s => s.file)

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS
//
// Source code quoted INSIDE source code is not source code. A test fixture in a template literal, a
// documentation snippet, a code generator's output — the engine read all of it as live code,
// because two of its scanners matched RAW text and rejected only COMMENT, never STRING.
//
// Run against its own repository the tool reported eleven LLM call sites, seven of them invented.
// The worst was `plugin/scripts/_scope.mjs`, whose only mention of a provider is `api.openai.com`
// inside DEFAULT_BLOCKED — the list of hosts the live-probe gate REFUSES to touch. A security
// control was reported as an ungoverned LLM call site. That is precisely the cry-wolf failure this
// project exists to prevent, committed by the project against itself.
//
// The rule these tests pin: a fact may be read out of a string ONLY when the payload genuinely
// lives in a string — a URL, a module specifier, a route path. Executable syntax — a call
// expression, an import keyword — must be CODE. Every test here has a matching control asserting
// the real thing is still detected, because the cheap way to pass a false-positive suite is to
// stop detecting anything.
// ---------------------------------------------------------------------------

test('a call expression inside quoted source is not an LLM call site', () => {
  // The fixture holds a complete, correct-looking OpenAI client. Both signals the engine uses are
  // present in the text — the provider IMPORT and the CALL — and both are inside a template
  // literal, so neither is real.
  const m = modelOf({
    'package.json': PKG,
    'test/app.spec.ts': `const FIXTURE = \`
import OpenAI from 'openai'
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
await client.chat.completions.create({ model: 'gpt-4o-mini', messages: [] })
\`
export default FIXTURE`,
  })
  assert.deepEqual(sites(m), [], 'quoted source must not be enumerated as a live call site')
})

test('a regex that MATCHES provider call syntax is not a call site', () => {
  // This is the engine's own shape. `stripJs` masks a regex literal as STRING, so the detector
  // matched its own source and reported `plugin/scripts/project_model.mjs` as an LLM call site.
  const m = modelOf({
    'package.json': PKG,
    'lib/detect.ts': `export const CALL_RE = /(chat\\.completions\\.create|messages\\.create|generateText)/
export const isCall = (s) => CALL_RE.test(s)`,
  })
  assert.deepEqual(sites(m), [], 'a detector is not an instance of the thing it detects')
})

test('a provider host on a BLOCKLIST is not a call site', () => {
  // The `_scope.mjs` case. A bare hostname is a host being NAMED; being named on a refuse-to-touch
  // list is the opposite of being called.
  const m = modelOf({
    'package.json': PKG,
    'lib/blocked.ts': `export const NEVER_TOUCH = ['api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com']`,
  })
  assert.deepEqual(sites(m), [], 'a blocklist entry is not a call site')
})

test('a commented-out provider endpoint is not a call site', () => {
  const m = modelOf({
    'package.json': PKG,
    'lib/notes.ts': `// we used to call https://api.openai.com/v1/completions from here
export const migrated = true`,
  })
  assert.deepEqual(sites(m), [], 'a comment describes the past, not the running code')
})

test('CONTROL: a hand-rolled fetch client with a real endpoint IS a call site', () => {
  // The reason the host class exists at all: this file imports no SDK, so the import signal cannot
  // find it. The URL lives in a string, which is exactly where a URL belongs — scheme present.
  const m = modelOf({
    'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}',
    'lib/ask.ts': `export async function ask(prompt) {
  const r = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    body: JSON.stringify({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: prompt }] }),
  })
  return r.json()
}`,
  })
  assert.deepEqual(sites(m), ['lib/ask.ts'], 'a real endpoint call must still be enumerated')
})

test('CONTROL: a real SDK call is still a call site', () => {
  const m = modelOf({
    'package.json': PKG,
    'app/api/chat/route.ts': `import OpenAI from 'openai'
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
export async function POST() {
  return Response.json(await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [] }))
}`,
  })
  assert.deepEqual(sites(m), ['app/api/chat/route.ts'])
})

// ---------------------------------------------------------------------------
// The import graph — the same defect, and the one with the longer blast radius.
//
// A module specifier is itself a string, so an import cannot be read off stripped code at all. The
// discriminator has to be the mask at the `import` KEYWORD. Without it, quoted source adds edges to
// the graph, and the graph decides client/server reachability — so a phantom edge does not stay
// local, it manufactures an EXPOSURE finding about code that was never imported.
// ---------------------------------------------------------------------------

const NEXT_PKG = '{"name":"x","dependencies":{"next":"15.0.0"}}'
const ADMIN = `import { createClient } from '@supabase/supabase-js'
export const adminDb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)`

test('an import inside quoted source does not create a graph edge', () => {
  // The page renders an EXAMPLE of how to use the admin client. It does not use it. Without the
  // mask check the quoted specifier becomes a real edge, and the admin module — which holds a
  // service-role key — is reported as reachable from the browser: a P0 about code that is a string.
  const m = modelOf({
    'package.json': NEXT_PKG,
    'app/page.tsx': `'use client'
const EXAMPLE = \`
import { adminDb } from '../lib/admin'
\`
export default function Page() { return EXAMPLE }`,
    'lib/admin.ts': ADMIN,
  })
  assert.ok(!m.boundary.clientReachable.includes('lib/admin.ts'),
    'a module quoted inside an example must not be reported as reaching the client')
})

test('CONTROL: a real import does create the edge', () => {
  // Same two files, the import unquoted. This is a genuine client/server boundary violation and it
  // must still be found — a false-positive suite that passes by detecting nothing is worthless.
  const m = modelOf({
    'package.json': NEXT_PKG,
    'app/page.tsx': `'use client'
import { adminDb } from '../lib/admin'
export default function Page() { return adminDb }`,
    'lib/admin.ts': ADMIN,
  })
  assert.ok(m.boundary.clientReachable.includes('lib/admin.ts'),
    'the real edge must survive the fix')
})
