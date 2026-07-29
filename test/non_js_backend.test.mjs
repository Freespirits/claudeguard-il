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
const REPO = join(HERE, '..')

function build(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cg-nonjs-'))
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

const declared = graded => graded.coverage.ungradedSurfaces.undeterminable
const subjects = graded => declared(graded).map(r => r.subject)
const rowFor = (graded, lang) => declared(graded).find(r => r.subject === `route-framework:${lang}`)

/** LAW 2, asserted over every set the grader produced. */
function law2(graded) {
  for (const [name, set] of Object.entries(graded.coverage)) {
    const c = set.counts
    assert.equal(c.pass + c.fail + c.undeterminable + c.allowlisted, set.enumerated,
      `LAW 2 broken in "${name}"`)
  }
}

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS.
//
// `CODE_EXT` is `.js/.jsx/.ts/.tsx/.mjs/.cjs/.svelte/.vue`, and `SERVER_FRAMEWORKS` is keyed on npm
// package names. Between them, a Python, Go, Ruby or PHP server was invisible twice over: its files
// went into `discovery.counts.unsupported`, and no dependency the route pass looks for existed. The
// report rendered `routes | 0 | 0 | 0 | 0 | 0` with NO declared row anywhere — so a repository whose
// whole HTTP surface, every auth decorator and every hand-built SQL string went unread printed
// exactly like a repository that has no server at all.
//
// That is the silent-clean failure `core/methodology/grade-or-declare.md` exists to kill, and it is
// fatal in a security gate: the reader cannot tell an unexamined backend from a safe one. Mobile got
// its declaration path (`artifacts.nativeSource` → `ungradedSurfaces`); backend languages got
// nothing. These tests pin the fix AND its two boundaries — the declaration is `undeterminable`, it
// never becomes a finding, it never moves the verdict, and a repo with no non-JS backend gains not
// one row from it.
// ---------------------------------------------------------------------------

const FLASK_APP = `from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/admin/users')
def users():
    name = request.args.get('name')
    q = "select * from users where name = '%s'" % name
    return sqlite3.connect('app.db').execute(q).fetchall()
`

const PY_REPO = {
  'requirements.txt': 'flask==3.0.0\n',
  'app.py': FLASK_APP,
  'api/auth.py': "def login(user, pw):\n    return user == 'admin'\n",
}

// The control: the same repo with its Python removed. Every assertion about "does not change the
// verdict" is a comparison against this, not against a hardcoded guess.
const JS_ONLY = {
  'package.json': JSON.stringify({ name: 'web', dependencies: { next: '15.0.0' } }),
  'app/page.tsx': "export default function P(){ return null }\n",
}

test('a Python backend is DECLARED, naming the language and the file count', () => {
  const { graded } = build({ ...JS_ONLY, ...PY_REPO })
  const row = rowFor(graded, 'python')
  assert.ok(row, 'a Flask app must produce a declared row — silence here reads as "no server"')
  assert.equal(row.disposition, 'undeterminable', 'seen and not graded is the honest disposition')
  assert.match(row.note, /Python/, 'the row must name the language')
  assert.match(row.note, /^2 Python files/, 'the row must state how many files went unread')
  assert.match(row.note, /app\.py/, 'and point at real paths')
  assert.match(row.note, /declared by requirements\.txt/, 'the manifest that proves it is a Python project')
  // What the static tier does NOT read — the reviewer instruction is the whole point of the row.
  assert.match(row.note, /route/i)
  assert.match(row.note, /auth/i)
  assert.match(row.note, /injection/i)
  assert.match(row.note, /checks\/web\.md/, 'an undeterminable row without an instruction is an apology')
})

test('the declaration is undeterminable, NEVER a finding', () => {
  // A non-JS backend is not a vulnerability; it is an unexamined surface. Emitting a finding here
  // would be the cry-wolf mirror of the defect — reporting a P-level for the tool's own blind spot.
  const { graded } = build({ ...JS_ONLY, ...PY_REPO })
  const row = rowFor(graded, 'python')
  assert.ok(graded.coverage.ungradedSurfaces.undeterminable.includes(row))
  for (const bucket of ['pass', 'fail', 'allowlisted']) {
    assert.equal(graded.coverage.ungradedSurfaces[bucket].filter(r => r.subject === 'route-framework:python').length, 0,
      `the declaration must not land in "${bucket}"`)
  }
  for (const f of graded.findings) {
    assert.ok(!/\.py(:|$)/.test(f.subject || ''), `no finding may be raised on unread Python: ${f.id} ${f.subject}`)
    assert.ok(!/non-js|python/i.test(f.id), `no finding id may be invented for the declaration: ${f.id}`)
  }
})

test('the declaration does NOT change the verdict', () => {
  const withPy = build({ ...JS_ONLY, ...PY_REPO }).graded
  const without = build(JS_ONLY).graded
  assert.equal(withPy.verdict.level, without.verdict.level, 'an unread surface must not move the verdict')
  assert.equal(withPy.verdict.confirmedP0, without.verdict.confirmedP0)
  assert.equal(withPy.verdict.confirmedP1, without.verdict.confirmedP1)
  assert.equal(withPy.counts.total, without.counts.total, 'and must not add a finding of any confidence')
  assert.equal(withPy.verdict.level, 'clean',
    'the control repo is clean — the point is that the Python rows are visible IN a clean report')
})

test('CRY WOLF: a JS-only repo gains no declared row at all', () => {
  const { graded } = build(JS_ONLY)
  for (const lang of ['python', 'go', 'ruby', 'php']) {
    assert.equal(rowFor(graded, lang), undefined, `${lang} must not be declared in a repo that has none`)
  }
  assert.equal(graded.coverage.ungradedSurfaces.enumerated, 0,
    'a plain Next.js app must gain nothing from this change')
})

test('LAW 2 still reconciles with the declaration present', () => {
  const { model, graded } = build({ ...JS_ONLY, ...PY_REPO })
  law2(graded)
  const set = graded.coverage.ungradedSurfaces
  assert.equal(set.enumerated, 1, 'exactly one row: one language, one declaration')
  assert.equal(set.counts.undeterminable, 1)
  // The other ledger, on the other axis: declaring a file is not reading it. The .py files must
  // stay in `unsupported`, and the discovery arithmetic must still add up. If a future change adds
  // a real Python parser, this is the line that says the counts have to move with it.
  assert.equal(model.discovery.reconciles, true, 'the discovery ledger must still add up')
  assert.ok(model.discovery.counts.unsupported >= 3,
    'requirements.txt and both .py files are still unparsed — the declaration claims nothing else')
})

test('vendored dependencies do not inflate the count', () => {
  // composer installs into `vendor/`, which the walk skips. Counting thousands of dependency files
  // as "your unread backend" would make the row meaningless the first time anyone read it.
  const { model } = build({
    'composer.json': '{"require":{"laravel/framework":"^11.0"}}',
    'public/index.php': "<?php echo 'hi';\n",
    'vendor/laravel/framework/src/Foo.php': "<?php class Foo {}\n",
  })
  const php = model.discovery.routes.frameworkGaps.find(g => g.framework === 'php')
  assert.equal(php.fileCount, 1, 'only the application file counts')
  assert.deepEqual(php.files, ['public/index.php'])
})

test('one row per language, and no duplicate subject ids (LAW 2 throws on a dup)', () => {
  const { model, graded } = build({
    'requirements.txt': 'fastapi\n',
    'svc/main.py': "from fastapi import FastAPI\napp = FastAPI()\n",
    'go.mod': 'module example.com/api\n\ngo 1.22\n',
    'cmd/server/main.go': 'package main\n\nfunc main() {}\n',
    'Gemfile': "source 'https://rubygems.org'\ngem 'rails'\n",
    'app/controllers/users_controller.rb': 'class UsersController < ApplicationController\nend\n',
    'composer.json': '{"require":{"laravel/framework":"^11.0"}}',
    'public/index.php': "<?php echo 'hi';\n",
  })
  const got = subjects(graded).filter(s => s.startsWith('route-framework:')).sort()
  assert.deepEqual(got, ['route-framework:go', 'route-framework:php', 'route-framework:python', 'route-framework:ruby'])
  assert.equal(graded.coverage.ungradedSurfaces.enumerated, 4)
  law2(graded)
  // The facts behind the rows travel in the model, so a report can print them without re-deriving.
  const byLang = Object.fromEntries(model.discovery.routes.frameworkGaps.map(g => [g.framework, g]))
  assert.equal(byLang.go.language, 'Go')
  assert.equal(byLang.go.fileCount, 1)
  assert.equal(byLang.ruby.manifests[0], 'Gemfile')
  assert.equal(byLang.php.declaredIn, 'composer.json')
})

test('a JS server framework gap and a language gap coexist without colliding', () => {
  // Both ride `discovery.routes.frameworkGaps`. Their name spaces are disjoint by construction
  // (npm package names vs language names); if that ever stops being true LAW 2 throws, so this test
  // is the guard that the shared channel stays safe.
  const { graded } = build({
    'package.json': JSON.stringify({ dependencies: { express: '4.19.2' } }),
    'src/index.ts': "export const handler = () => 'not a route'\n",
    'worker/tasks.py': "def run():\n    pass\n",
  })
  assert.ok(rowFor(graded, 'express'), 'the express gap must survive')
  assert.ok(rowFor(graded, 'python'), 'the python gap must be filed alongside it')
  assert.equal(graded.coverage.ungradedSurfaces.enumerated, 2)
  law2(graded)
})

test('source alone is enough — no manifest required', () => {
  const { graded } = build({ 'package.json': '{}', 'scripts/etl.py': 'print(1)\n' })
  const row = rowFor(graded, 'python')
  assert.ok(row, 'a .py file this pass cannot read is unread whether or not a manifest names it')
  assert.match(row.note, /^1 Python file /, 'singular, and honest about the size of the hole')
})

test('a manifest alone is enough — the source may live in another repo', () => {
  // The modal shape for a split deployment: the API is a submodule or a separate service, and all
  // that is left here is the dependency list. A confident 0 would be the same lie in miniature.
  const { graded } = build({ 'package.json': '{}', 'services/api/pyproject.toml': '[project]\nname = "api"\n' })
  const row = rowFor(graded, 'python')
  assert.ok(row, 'a manifest with no source is a declared component whose code we never saw')
  assert.match(row.note, /no \.py file was enumerated/)
  assert.match(row.note, /outside this repository/)
})

test('CRY WOLF: ClaudeGuardIL itself gains no declared backend row', () => {
  // The tool must not detect a backend in its own tree. This repo is JS/TS end to end; a row here
  // would mean the detector fires on incidental files, which is how a coverage table stops being read.
  const model = JSON.parse(execFileSync(process.execPath, [ENGINE, REPO], {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  }))
  const langs = model.discovery.routes.frameworkGaps.filter(g => g.language)
  assert.deepEqual(langs, [], `self-scan declared a non-JS backend: ${JSON.stringify(langs.map(g => g.framework))}`)
})

test('the model stays deterministic with the declaration in it', () => {
  const files = { ...JS_ONLY, ...PY_REPO }
  const a = JSON.stringify(build(files).model.discovery.routes.frameworkGaps)
  const b = JSON.stringify(build(files).model.discovery.routes.frameworkGaps)
  assert.equal(a, b, 'same repo, same declaration — a coverage row that moves cannot be diffed')
})
