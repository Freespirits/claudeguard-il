#!/usr/bin/env node
// Project Security Model — deterministic ground truth about a codebase.
//
// Why this exists: an LLM reading files one at a time has to GUESS whether a secret
// reaches the browser, whether a table has RLS, or which routes lack auth. This script
// COMPUTES those facts: it builds the import graph, classifies the client/server
// boundary, traces env-var flow, and inventories routes, DB tables and LLM call sites.
// The model then reasons over facts instead of impressions.
//
// Heuristic but deterministic: regex/lightweight parsing, not a full type-aware AST.
// Same input always yields the same model. Limits are reported in `limits`.
//
// Usage: node project_model.mjs [path] [--json]
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, extname, dirname, resolve, sep } from 'node:path'
import { stripSql, stripJs, stripHash, CODE, COMMENT } from './lib/strip_comments.mjs'

const ROOT = resolve(process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : '.')

// Directory NAMES skipped anywhere in the tree.
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', 'coverage',
  'vendor', '.venv', '__pycache__', '.turbo', '.cache'])
// Directory PATHS skipped, matched as a suffix of the repo-relative path. These two lived in
// SKIP_DIRS, where they were dead: the walk tests `e.name`, a single path segment, which a
// two-segment string can never equal. `build` happened to catch `android/build` by name; nothing
// caught `Pods`, so vendored CocoaPods sources — which the user cannot edit — became graded
// subjects, and every pod's Info.plist added a `pass` row that inflated coverage.
// `methodology/enumerate.md` has documented both as skipped the whole time.
const SKIP_DIR_PATHS = ['android/build', 'ios/Pods']
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.svelte', '.vue'])
const MAX_FILE = 1.5 * 1024 * 1024

// Env prefixes that a bundler inlines into client output — definitive public exposure.
const PUBLIC_PREFIXES = ['NEXT_PUBLIC_', 'VITE_', 'PUBLIC_', 'EXPO_PUBLIC_', 'REACT_APP_', 'GATSBY_', 'NUXT_PUBLIC_']

// Secret-name classification, TIERED on purpose. The tier is a FACT about how much the name alone
// establishes; the grader is what refuses to raise a P0 on a name-only basis. Keeping the tiers
// here and the policy there means a rule change never requires re-reading the engine.
//
//   high  — the name alone is near-conclusive that this grants privileged access.
//   weak  — looks secret-ish, but is very often a publishable key
//           (NEXT_PUBLIC_GOOGLE_MAPS_KEY, PUSHER_APP_KEY, IDEMPOTENCY_KEY, CACHE_KEY...).
//           Reporting these as P0 is the anon-key trust catastrophe with a new variable name.
const SECRET_NAME_HIGH = /(SERVICE_ROLE|_SECRET$|^SECRET_|SECRET_KEY|PRIVATE_KEY|PASSWORD|PASSWD|ACCESS_KEY_ID|SECRET_ACCESS_KEY|_TOKEN$|SESSION_KEY|ENCRYPTION_KEY|SIGNING_KEY|WEBHOOK_SECRET|DATABASE_URL|DB_URL|CONNECTION_STRING|DSN$)/i
// Named LLM/payment provider keys are unambiguous: they are billable, privileged credentials.
// Without this they fall into the WEAK tier, which caps severity at P2 — and an LLM key inlined
// into the browser bundle (NEXT_PUBLIC_OPENAI_API_KEY) is a P0, not a P2. Denial-of-wallet is
// the single most common expensive mistake in this community.
const SECRET_NAME_PROVIDER = /^(?:NEXT_PUBLIC_|VITE_|PUBLIC_|EXPO_PUBLIC_|REACT_APP_|GATSBY_|NUXT_PUBLIC_)?(OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GROQ|MISTRAL|COHERE|REPLICATE|HUGGINGFACE|HF|TOGETHER|PERPLEXITY|DEEPSEEK|XAI|FIREWORKS|OPENROUTER|ELEVENLABS|STRIPE|TWILIO|SENDGRID|RESEND|POSTMARK|CLOUDINARY|AWS|GCP|AZURE)_(?:API_)?(?:KEY|SECRET|TOKEN)/i
const SECRET_NAME_WEAK = /(API_KEY|APIKEY|TOKEN|CREDENTIAL|_KEY$|AUTH)/i
// Public identifiers by design — never a "leaked secret". This list is the single most
// important false-positive guard in the tool for this audience.
const PUBLIC_BY_DESIGN = /(SUPABASE_ANON_KEY|SUPABASE_URL|FIREBASE_API_KEY|FIREBASE_APP_ID|FIREBASE_PROJECT_ID|FIREBASE_AUTH_DOMAIN|FIREBASE_STORAGE_BUCKET|MESSAGING_SENDER_ID|MEASUREMENT_ID|SENTRY_DSN|POSTHOG_KEY|POSTHOG_HOST|STRIPE_PUBLISHABLE|PUBLISHABLE_KEY|MAPBOX|GOOGLE_MAPS|RECAPTCHA_SITE_KEY|PUSHER_APP_KEY|ALGOLIA_SEARCH_KEY|VAPID_PUBLIC)/i

/** @returns {'high'|'weak'|'public-by-design'|'none'} */
function classifySecretName(name) {
  if (PUBLIC_BY_DESIGN.test(name)) return 'public-by-design'
  if (SECRET_NAME_PROVIDER.test(name)) return 'high'
  if (SECRET_NAME_HIGH.test(name)) return 'high'
  if (SECRET_NAME_WEAK.test(name)) return 'weak'
  return 'none'
}

const rel = p => relative(ROOT, p).split(sep).join('/')

// DISCOVERY LEDGER — what the engine could and could NOT see, tracked as it walks. This is a
// DIFFERENT axis from the coverage ledger the grader builds: coverage accounts for every subject we
// ENUMERATED; discovery accounts for what we FAILED to enumerate. A silently skipped directory or an
// unparsed file is invisible to coverage — a clean-looking report can hide the fact that we never
// opened half the repo. Every skip below carries a reason, so "we found nothing" can be told apart
// from "we looked nowhere".
const discovery = {
  skippedDirs: [],   // directories not descended into, with why
  notableSkips: [],  // files we wanted to parse but could not, with why
  // `filesParsed` counts SOURCE files that went through the code parser. `configParsed` counts
  // files a dedicated parser read instead — workflows, Dockerfiles, Terraform, Firebase rules,
  // manifests, migrations. They are tracked apart because they arrive through the walk as
  // "unsupported" (their extension is not code) and would otherwise be reported as files the
  // engine ignored, which stopped being true once those parsers existed. Under-claiming coverage
  // is safer than over-claiming it, but it is still wrong, and the discovery ledger is the one
  // place in the tool whose entire job is to be accurate about what was and was not read.
  counts: { filesDiscovered: 0, filesParsed: 0, configParsed: 0, unsupported: 0, oversized: 0, readErrors: 0 },
}
// Relative paths a non-code parser successfully read. Reconciled into the counts at the end.
const configParsedPaths = new Set()

/**
 * Read a file for one of the dedicated (non-code) parsers, recording that it was read.
 *
 * Every such parser goes through here so the discovery ledger cannot drift from reality: adding a
 * parser and forgetting to record it would leave its files counted as `unsupported`, i.e. reported
 * as ignored when they were in fact examined. Returns null when the file cannot be read, and the
 * caller skips it — the failure is already visible in `readErrors`.
 */
function readParsedConfig(p) {
  let text
  try { text = readFileSync(join(ROOT, p), 'utf8') } catch { return null }
  configParsedPaths.add(p)
  return text
}
const MAX_LEDGER_ROWS = 200 // cap the detail lists so a huge repo cannot balloon the model

function* walk(dir) {
  let entries
  try { entries = readdirSync(dir, { withFileTypes: true }) }
  catch { if (discovery.skippedDirs.length < MAX_LEDGER_ROWS) discovery.skippedDirs.push({ dir: rel(dir), reason: 'read-error' }); return }
  for (const e of entries) {
    const full = join(dir, e.name)
    if (e.isDirectory()) {
      const relDir = rel(full)
      if (SKIP_DIRS.has(e.name) || SKIP_DIR_PATHS.some(s => relDir === s || relDir.endsWith('/' + s))) {
        if (discovery.skippedDirs.length < MAX_LEDGER_ROWS) discovery.skippedDirs.push({ dir: relDir, reason: 'ignored build/vendor dir' }); continue }
      if (e.name.startsWith('.') && e.name !== '.github') { if (discovery.skippedDirs.length < MAX_LEDGER_ROWS) discovery.skippedDirs.push({ dir: rel(full), reason: 'dotfile dir' }); continue }
      yield* walk(full)
    } else if (e.isFile()) yield full
  }
}

// ---------- collect files ----------
const files = new Map() // rel -> record
const allPaths = []
for (const abs of walk(ROOT)) {
  const r = rel(abs)
  allPaths.push(r)
  discovery.counts.filesDiscovered++
  const ext = extname(abs).toLowerCase()
  // Not source we model (images, json, lockfiles, …). Not a failure — just outside the parser.
  if (!CODE_EXT.has(ext)) { discovery.counts.unsupported++; continue }
  let size = 0
  try { size = statSync(abs).size } catch { discovery.counts.readErrors++; if (discovery.notableSkips.length < MAX_LEDGER_ROWS) discovery.notableSkips.push({ file: r, reason: 'stat failed' }); continue }
  if (size > MAX_FILE) { discovery.counts.oversized++; if (discovery.notableSkips.length < MAX_LEDGER_ROWS) discovery.notableSkips.push({ file: r, reason: `oversized: ${Math.round(size / 1024)}KB > ${Math.round(MAX_FILE / 1024)}KB cap` }); continue }
  let text
  try { text = readFileSync(abs, 'utf8') } catch { discovery.counts.readErrors++; if (discovery.notableSkips.length < MAX_LEDGER_ROWS) discovery.notableSkips.push({ file: r, reason: 'read failed (not valid UTF-8?)' }); continue }
  discovery.counts.filesParsed++
  files.set(r, { path: r, abs, ext, text, lines: text.split(/\r?\n/) })
}

// ---------- framework detection ----------
function readJson(p) { try { return JSON.parse(readFileSync(join(ROOT, p), 'utf8')) } catch { return null } }
const pkg = readJson('package.json')
const deps = { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) }
const has = n => Object.prototype.hasOwnProperty.call(deps, n)
const framework = {
  next: has('next') ? deps.next : null,
  react: has('react') ? deps.react : null,
  vue: has('vue') ? deps.vue : null,
  svelte: has('svelte') ? deps.svelte : null,
  vite: has('vite') ? deps.vite : null,
  expo: has('expo') ? deps.expo : null,
  // The four mobile frameworks this audience actually ships. None of them was detected before, so
  // nothing could key the "mobile framework declared but no manifest enumerated" declaration —
  // which is the shape of every managed Expo app — and the mobile-auditor agent's own invocation
  // condition ("the repo has React Native / Flutter / Capacitor project files") had no fact behind
  // it. Flutter is not an npm package, so it is read from pubspec.yaml.
  reactNative: has('react-native') ? deps['react-native'] : null,
  capacitor: has('@capacitor/core') || has('@capacitor/cli')
    ? (deps['@capacitor/core'] || deps['@capacitor/cli']) : null,
  cordova: ['cordova', 'cordova-android', 'cordova-ios'].some(has)
    ? (deps.cordova || deps['cordova-android'] || deps['cordova-ios']) : null,
  flutter: (() => {
    let y
    try { y = readFileSync(join(ROOT, 'pubspec.yaml'), 'utf8') } catch { return null }
    if (!/^\s*flutter\s*:/m.test(y)) return null
    const sdk = /^\s*flutter\s*:\s*["']?([^"'\n]+)["']?\s*$/m.exec(y)
    return sdk && sdk[1].trim() ? sdk[1].trim() : true
  })(),
  electron: has('electron') ? deps.electron : null,
  supabase: has('@supabase/supabase-js') || has('@supabase/ssr') ? (deps['@supabase/supabase-js'] || deps['@supabase/ssr']) : null,
  firebase: has('firebase') || has('firebase-admin') ? (deps.firebase || deps['firebase-admin']) : null,
  llm: ['openai', '@anthropic-ai/sdk', '@google/generative-ai', 'ai', '@ai-sdk/openai', 'cohere-ai', 'replicate']
    .filter(has).reduce((a, k) => (a[k] = deps[k], a), {}),
  validators: ['zod', 'yup', 'joi', 'valibot', 'superstruct', 'ajv'].filter(has),
  ratelimit: ['@upstash/ratelimit', 'express-rate-limit', 'rate-limiter-flexible', 'p-ratelimit'].filter(has),
}

// ---------- import graph ----------
const IMPORT_RE = /(?:^|\n)\s*(?:import\s[^'"]*?from\s*|import\s*|export\s[^'"]*?from\s*)['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)|import\(\s*['"]([^'"]+)['"]\s*\)/g
const RESOLVE_EXT = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.vue', '.svelte',
  '/index.ts', '/index.tsx', '/index.js', '/index.jsx']

// tsconfig path aliases (common: "@/*")
let aliasRoots = []
const tsconf = readJson('tsconfig.json') || readJson('jsconfig.json')
if (tsconf?.compilerOptions?.paths) {
  for (const [k, v] of Object.entries(tsconf.compilerOptions.paths)) {
    const baseUrl = tsconf.compilerOptions.baseUrl || '.'
    aliasRoots.push({ prefix: k.replace(/\*$/, ''), targets: v.map(t => join(baseUrl, t.replace(/\*$/, ''))) })
  }
}
if (!aliasRoots.length) aliasRoots.push({ prefix: '@/', targets: ['src/', './'] })

// ---------- workspace packages (Turborepo / pnpm workspaces) ----------
//
// Scaffolds emitted by v0/Cursor are frequently monorepos where apps/web imports `@repo/db`.
// A bare specifier previously resolved to null, so EVERY cross-package edge was lost — meaning
// client reachability and helper-closure analysis silently under-reported in exactly the
// multi-file repos where we claim an advantage over reading one file at a time.
const workspaceGlobs = []
if (Array.isArray(pkg?.workspaces)) workspaceGlobs.push(...pkg.workspaces)
else if (Array.isArray(pkg?.workspaces?.packages)) workspaceGlobs.push(...pkg.workspaces.packages)
try {
  const ws = readFileSync(join(ROOT, 'pnpm-workspace.yaml'), 'utf8')
  for (const m of ws.matchAll(/^\s*-\s*['"]?([^'"\n]+)['"]?\s*$/gm)) workspaceGlobs.push(m[1].trim())
} catch { /* no pnpm workspace */ }

// name -> package directory (repo-relative). Resolved by reading each candidate package.json.
const workspacePackages = new Map()
for (const g of workspaceGlobs) {
  const base = g.replace(/\/\*+$/, '')
  let entries = []
  try { entries = readdirSync(join(ROOT, base), { withFileTypes: true }) } catch { continue }
  for (const e of entries) {
    if (!e.isDirectory()) continue
    const dir = `${base}/${e.name}`.replace(/^\.\//, '')
    const wp = readJson(`${dir}/package.json`)
    if (wp?.name) workspacePackages.set(wp.name, dir)
  }
}
const unresolvedWorkspaceImports = []

function resolveImport(fromRel, spec) {
  if (!spec) return null
  let candidates = []
  if (spec.startsWith('.')) {
    candidates.push(join(dirname(fromRel), spec).split(sep).join('/'))
  } else {
    for (const a of aliasRoots) {
      if (spec.startsWith(a.prefix)) {
        const tail = spec.slice(a.prefix.length)
        for (const t of a.targets) candidates.push(join(t, tail).split(sep).join('/'))
      }
    }
    // Workspace package: `@repo/db` or `@repo/db/client` -> packages/db[/client]
    for (const [name, dir] of workspacePackages) {
      if (spec === name || spec.startsWith(name + '/')) {
        const tail = spec.slice(name.length).replace(/^\//, '')
        candidates.push(tail ? `${dir}/${tail}` : dir)
        candidates.push(tail ? `${dir}/src/${tail}` : `${dir}/src`)
      }
    }
    if (!candidates.length) return null // genuine third-party package
  }
  for (const c of candidates) {
    const norm = c.replace(/^\.\//, '')
    for (const ext of RESOLVE_EXT) {
      const cand = (norm + ext).replace(/\/+/g, '/')
      if (files.has(cand)) return cand
    }
  }
  return null
}

const imports = new Map()   // rel -> Set(rel)
const importedBy = new Map()
const bareImports = new Map() // rel -> Set(pkg)
for (const [r, f] of files) {
  const set = new Set(), bare = new Set()
  // The module SPECIFIER is a string literal, so stripping erases it and an import cannot be read
  // off stripped code at all — the same shape as a route path. The discriminator is the mask at the
  // `import`/`require` KEYWORD, which is the code half of the statement. A keyword sitting inside a
  // template literal is QUOTED SOURCE: a test fixture, a docs snippet, a generator's output.
  //
  // Reading those as real imports gave this repo 18 dependencies it does not have — `rxjs` and
  // `@supabase/supabase-js` among them, out of test fixtures — and on a user's repo it is any file
  // that embeds an example, which for this audience is common. The import graph feeds framework
  // detection, client/server reachability and the LLM-site scan, so a phantom edge does not stay
  // local: it propagates into findings about code that does not exist.
  const { mask } = stripJs(f.text)
  let m
  IMPORT_RE.lastIndex = 0
  while ((m = IMPORT_RE.exec(f.text))) {
    const spec = m[1] || m[2] || m[3]
    if (!spec) continue
    // `(?:^|\n)\s*` can precede the keyword, so step over the leading whitespace to land on it.
    if (mask[m.index + (m[0].length - m[0].trimStart().length)] !== CODE) continue
    const target = resolveImport(r, spec)
    if (target && target !== r) set.add(target)
    else if (!spec.startsWith('.')) {
      bare.add(spec.split('/').slice(0, spec.startsWith('@') ? 2 : 1).join('/'))
      // A workspace package we know about but could NOT resolve to a file is a coverage hole,
      // not a third-party dependency. Surface it rather than losing the edge silently.
      for (const name of workspacePackages.keys()) {
        if (spec === name || spec.startsWith(name + '/')) unresolvedWorkspaceImports.push({ file: r, spec })
      }
    }
  }
  imports.set(r, set); bareImports.set(r, bare)
  for (const t of set) {
    if (!importedBy.has(t)) importedBy.set(t, new Set())
    importedBy.get(t).add(r)
  }
}

// ---------- client / server classification ----------
// Decisive client signals (a secret referenced here ships to the browser).
function directClientSignal(r, f) {
  const head = f.text.slice(0, 400)
  if (/^\s*(['"])use client\1/m.test(head)) return 'use-client-directive'
  if (/^pages\//.test(r) && !/^pages\/api\//.test(r)) return 'pages-router-page'
  if (/^src\/(main|index|App)\.(t|j)sx?$/.test(r) && (framework.vite || framework.react)) return 'spa-entry'
  if (framework.vite && /^src\//.test(r) && !/\.server\./.test(r)) return 'vite-src'
  return null
}
function directServerSignal(r, f) {
  const head = f.text.slice(0, 400)
  if (/^\s*(['"])use server\1/m.test(head)) return 'use-server-directive'
  if (/^pages\/api\//.test(r)) return 'pages-api-route'
  if (/^(app|src\/app)\/.*\/route\.(t|j)sx?$/.test(r)) return 'app-route-handler'
  if (/(^|\/)(middleware)\.(t|j)s$/.test(r)) return 'middleware'
  if (/\.server\.(t|j)sx?$/.test(r)) return 'server-suffix'
  if (/^(server|api|functions|netlify\/functions|supabase\/functions|scripts)\//.test(r)) return 'server-dir'
  return null
}

const clientSeed = new Map(), serverSeed = new Map()
for (const [r, f] of files) {
  const c = directClientSignal(r, f); if (c) clientSeed.set(r, c)
  const s = directServerSignal(r, f); if (s) serverSeed.set(r, s)
}
// A "barrel" is a pure re-export hub (lib/index.ts). Reachability THROUGH one is weak evidence:
// importing { cn } from '@/lib' does not mean the bundler ships lib/db.ts's service-role client,
// because tree-shaking drops unused re-exports. Treating it as strong evidence fabricates a P0
// on a correct app — and a wrong P0 makes people rotate keys and announce breaches.
function isBarrel(rel) {
  const f = files.get(rel)
  if (!f) return false
  const { code } = stripJs(f.text)
  const lines = code.split(/\r?\n/).map(l => l.trim()).filter(Boolean)
  if (!lines.length) return false
  const reexport = lines.filter(l => /^export\s+(\*|\{)[^=]*\bfrom\b/.test(l)).length
  return reexport / lines.length >= 0.6
}
const serverOnlyCache = new Map()
// `import 'server-only'` makes a client import a BUILD ERROR, so a chain through it cannot exist.
// It must be an actual import STATEMENT, not any textual mention: a comment like
// `// we deliberately do NOT use 'server-only' here` used to match and prune the reachability
// graph, burying a real client-side leak (an adversarial-audit bypass). Matched on raw text (the
// module specifier is a string) but rejected inside comments via the mask.
function hasServerOnly(rel) {
  if (serverOnlyCache.has(rel)) return serverOnlyCache.get(rel)
  const f = files.get(rel)
  let yes = false
  if (f) {
    const { mask } = stripJs(f.text)
    const re = /import\s*['"]server-only['"]|require\(\s*['"]server-only['"]\s*\)/g
    let m
    while ((m = re.exec(f.text))) { if (mask[m.index] === CODE) { yes = true; break } }
  }
  serverOnlyCache.set(rel, yes)
  return yes
}

const barrelCache = new Map()
const isBarrelCached = r => (barrelCache.has(r) ? barrelCache.get(r) : (barrelCache.set(r, isBarrel(r)), barrelCache.get(r)))

/**
 * BFS over the import graph, recording HOW strong each reachability claim is.
 *   strong — the file itself is a client entrypoint, or is directly imported by one.
 *   weak   — reached only transitively, or through a re-export barrel, where tree-shaking may
 *            drop the module entirely so the chain might not exist in the shipped bundle.
 * This strength is Evidence, and the grader maps Evidence to confidence. The engine states how
 * solid the observation is; it does not decide what to do about it.
 */
function propagate(seed) {
  const out = new Map()
  for (const [k, why] of seed) out.set(k, { why, strength: 'strong', depth: 0, viaBarrel: false })
  const q = [...seed.keys()]
  while (q.length) {
    const cur = q.shift()
    const curInfo = out.get(cur)
    for (const dep of imports.get(cur) || []) {
      if (out.has(dep)) continue
      // A module marked server-only can never be in the client bundle — stop the chain.
      if (hasServerOnly(dep)) continue
      const depth = curInfo.depth + 1
      const viaBarrel = curInfo.viaBarrel || isBarrelCached(cur)
      out.set(dep, {
        why: `imported-by:${cur}`,
        strength: depth <= 1 && !viaBarrel ? 'strong' : 'weak',
        depth,
        viaBarrel,
      })
      q.push(dep)
    }
  }
  return out
}
const clientReachable = propagate(clientSeed)
const serverReachable = propagate(serverSeed)

// ---------- env var flow ----------
const ENV_RE = /process\.env\.([A-Z0-9_]+)|process\.env\[\s*['"]([A-Z0-9_]+)['"]\s*\]|import\.meta\.env\.([A-Z0-9_]+)/g
const envUsage = new Map() // NAME -> [{file,line}]
for (const [r, f] of files) {
  for (let i = 0; i < f.lines.length; i++) {
    let m; ENV_RE.lastIndex = 0
    while ((m = ENV_RE.exec(f.lines[i]))) {
      const name = m[1] || m[2] || m[3]
      if (!envUsage.has(name)) envUsage.set(name, [])
      envUsage.get(name).push({ file: r, line: i + 1 })
    }
  }
}
// declared env files
const envFiles = allPaths.filter(p => /(^|\/)\.env(\.|$)/.test(p) && !/\.example$/.test(p))
const envDeclared = new Map() // NAME -> {file,line,hasValue}
for (const p of allPaths.filter(x => /(^|\/)\.env/.test(x))) {
  const text = readParsedConfig(p); if (text == null) continue
  text.split(/\r?\n/).forEach((ln, i) => {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)$/.exec(ln)
    if (m) envDeclared.set(m[1], { file: p, line: i + 1, hasValue: m[2].trim().length > 2, example: /\.example$/.test(p) })
  })
}

const envVars = []
for (const name of new Set([...envUsage.keys(), ...envDeclared.keys()])) {
  const publicPrefix = PUBLIC_PREFIXES.find(p => name.startsWith(p)) || null
  const usages = envUsage.get(name) || []
  const clientUses = usages.filter(u => clientReachable.has(u.file))
  const secretClass = classifySecretName(name)
  const decl = envDeclared.get(name) || null
  // A name that appears only in .env.example, carries no value, and is never read by any code
  // describes a variable that does not exist yet. There is no secret to leak. Treating it as a
  // live exposure manufactures a P0 out of documentation.
  const exampleOnly = !!decl && decl.example === true && !decl.hasValue && usages.length === 0
  envVars.push({
    name, publicPrefix, secretClass,
    // `secretish` retained for compatibility, but consumers should prefer secretClass, which
    // distinguishes a near-conclusive name from one that is merely credential-shaped.
    secretish: secretClass === 'high' || secretClass === 'weak',
    publicByDesign: secretClass === 'public-by-design',
    declared: decl,
    usages,
    clientReachableUsages: clientUses.map(u => ({ ...u, strength: clientReachable.get(u.file)?.strength || 'weak' })),
    // EXPOSURE SEMANTICS — corrected after testing against real repos.
    //
    // A bare `process.env.SECRET` inside a module that a client component imports is NOT a leak.
    // Bundlers statically replace ONLY allowlisted prefixes (NEXT_PUBLIC_, VITE_, REACT_APP_...).
    // Everything else is simply absent from client output and evaluates to undefined in the
    // browser. Calling that "exposed" produced five confident P0s against a correctly-built repo
    // that uses t3-env — the textbook guard AGAINST this very mistake. Reporting a best-practice
    // pattern as a critical vulnerability is exactly how a security tool loses its audience.
    //
    //   bundler-inlined-public-prefix — DEFINITIVE. The value is compiled into client output.
    //   next-config-inlined           — DEFINITIVE. next.config env:/publicRuntimeConfig, no prefix needed.
    //   referenced-in-client-module   — NOT a leak. Usually a runtime-undefined bug instead.
    //   server-only                   — not reachable from the client at all.
    //   example-only                  — named in .env.example with no value and never used in
    //                                   code. Nothing is exposed because nothing exists yet; at
    //                                   most the TEMPLATE teaches an unsafe pattern (advisory).
    exposure: exampleOnly ? 'example-only'
      : publicPrefix ? 'bundler-inlined-public-prefix'
        : clientUses.length ? 'referenced-in-client-module' : 'server-only',
    // Evidence strength for the exposure claim. `definitive` because the bundler substitutes the
    // value textually — no inference is involved, so no link in the chain can break.
    exposureStrength: (publicPrefix && !exampleOnly) ? 'definitive' : 'n/a',
    exampleOnly,
    // Kept so a later rule can flag "this will be undefined in the browser" as a correctness
    // bug (P3/P4), which is what it actually is — never as a leaked secret.
    clientGraphStrength: clientUses.length
      ? (clientUses.some(u => clientReachable.get(u.file)?.strength === 'strong') ? 'strong' : 'weak')
      : 'n/a',
  })
}

// ---------- route inventory ----------
const AUTH_HINT = /(getUser|getSession|auth\(\)|requireUser|requireAuth|currentUser|verifyToken|jwt\.verify|getServerSession|clerkClient|withApiAuth|authenticate|isAuthenticated|session\?\.user|verifyIdToken)/
const RATE_HINT = /(ratelimit|rateLimit|limiter\.|rate_limit|Ratelimit|throttle)/
const VALIDATE_HINT = /(\.safeParse\(|\.parse\(|zod|yup|joi|valibot|superstruct|ajv|validateSync)/
const METHOD_RE = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b|req\.method\s*===?\s*['"](GET|POST|PUT|PATCH|DELETE)['"]/g

// ---------- business-logic facts, per route ----------
//
// These say what a handler MANIPULATES — which table, which column it compares, which body fields
// it reads, which literal it writes. They make no claim about what the app is supposed to PERMIT;
// that is the intent model's job, and only the app's author can state it
// (core/methodology/business-logic.md).
//
// Modelled only for FILE-routed handlers (Next pages/app routes, serverless functions), where the
// file IS the route so a file-level read is exact. An Express/Fastify/Hono file declares many
// handlers, and attributing `.from('orders')` to one of them would be a guess — so those routes get
// `null` and the business-logic layer DECLARES the gap instead of inventing a link.
const BODY_SOURCE = String.raw`req(?:uest)?\s*\.\s*body|req(?:uest)?\s*\.\s*json\s*\(\s*\)`
const FILTER_METHODS = 'eq|neq|gt|gte|lt|lte|like|ilike|is|in|contains|containedBy|filter'
const WRITE_CALL = /\.\s*(?:insert|update|upsert|create|createMany|updateMany|save)\s*\(/

function businessFactsForRouteFile(code, rawText, inCode) {
  // Table references and body-field names live inside STRING literals for the first, and are plain
  // identifiers for the rest. So table names are read from RAW text with the mask rejecting
  // comments; identifiers are read from the stripped copy, where a name inside a string cannot
  // masquerade as code.
  const tablesTouched = []
  {
    const re = /\.from\(\s*['"]([A-Za-z0-9_]+)['"]\s*\)/g
    let m
    while ((m = re.exec(rawText))) {
      if (!inCode(m.index)) continue
      const t = m[1].toLowerCase()
      if (!tablesTouched.includes(t)) tablesTouched.push(t)
    }
  }

  // Columns the handler actually COMPARES. `ownershipFilter` answers "is any ownership-ish token
  // present"; this answers "which column", which is what a wrong-owner-column check needs.
  const eqColumns = []
  {
    const re = new RegExp(String.raw`\.\s*(?:${FILTER_METHODS})\s*\(\s*['"]([A-Za-z0-9_]+)['"]`, 'g')
    let m
    while ((m = re.exec(rawText))) {
      if (!inCode(m.index)) continue
      const c = m[1].toLowerCase()
      if (!eqColumns.includes(c)) eqColumns.push(c)
    }
  }

  // Variables that hold the request body, so `const { price } = body` is read as a body field and
  // `const { price } = defaults` is not.
  const bodyVars = new Set()
  {
    const re = new RegExp(String.raw`(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:${BODY_SOURCE})`, 'g')
    let m
    while ((m = re.exec(code))) bodyVars.add(m[1])
  }
  const bodyAlt = [`(?:${BODY_SOURCE})`, ...[...bodyVars].map(v => `${v}\\b`)].join('|')

  const bodyFields = []
  const addField = raw => {
    const name = raw.replace(/^\s*\.\.\./, '').split(/[:=]/)[0].trim().toLowerCase()
    if (/^[a-z_][\w$]*$/.test(name) && !bodyFields.includes(name)) bodyFields.push(name)
  }
  {
    const destructRe = new RegExp(String.raw`(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:${bodyAlt})`, 'g')
    let m
    while ((m = destructRe.exec(code))) for (const part of m[1].split(',')) addField(part)
    const memberRe = new RegExp(String.raw`(?:${bodyAlt})\s*\.\s*([A-Za-z_$][\w$]*)`, 'g')
    while ((m = memberRe.exec(code))) addField(m[1])
  }

  // `status: 'paid'` — the literal a handler writes. Matched on RAW text because the VALUE is a
  // string, and rejected by the mask when the whole pair sits inside a comment or another string.
  const literalAssignments = []
  {
    const re = /(?:^|[{,(\s])([A-Za-z_$][\w$]*)\s*:\s*(['"])([^'"\n]{0,64})\2/g
    let m
    while ((m = re.exec(rawText)) && literalAssignments.length < 60) {
      const keyIdx = m.index + m[0].indexOf(m[1])
      if (!inCode(keyIdx)) continue
      literalAssignments.push({ key: m[1].toLowerCase(), value: m[3] })
    }
  }

  // Mass assignment's tell: the whole request body handed to a write with no allowlist in between.
  const spreadRe = new RegExp(String.raw`\.\.\.\s*(?:${bodyAlt})`)
  const wholeBodyRe = new RegExp(String.raw`\.\s*(?:insert|update|upsert|create)\s*\(\s*(?:${bodyAlt})\s*[,)]`)
  const spreadsBodyIntoWrite = (spreadRe.test(code) && WRITE_CALL.test(code)) || wholeBodyRe.test(code)

  return { tablesTouched, eqColumns, bodyFields, literalAssignments, spreadsBodyIntoWrite }
}

const routes = []
for (const [r, f] of files) {
  const kind = /^pages\/api\//.test(r) ? 'pages-api'
    : /^(app|src\/app)\/.*\/route\.(t|j)sx?$/.test(r) ? 'app-route'
      : /^(supabase\/functions|netlify\/functions|api)\//.test(r) ? 'serverless-fn' : null
  if (!kind) continue
  // Security hints run on comment/string-STRIPPED code. A decoy comment mentioning `service_role`
  // must not inflate a correct route to a false P0, and a comment mentioning `user_id`/`auth.uid()`
  // must not silence a real IDOR — both were adversarial-audit bypasses. METHOD_RE stays on raw
  // text because `req.method === 'GET'` reads a method-name string literal.
  const { code, mask } = stripJs(f.text)
  const inCode = idx => mask[idx] === CODE
  const methods = new Set(); let m; METHOD_RE.lastIndex = 0
  while ((m = METHOD_RE.exec(f.text))) methods.add(m[1] || m[2])
  const mutating = [...methods].some(x => x !== 'GET') || methods.size === 0
  routes.push({
    file: r, kind,
    methods: [...methods].length ? [...methods] : ['UNKNOWN'],
    mutating,
    hasAuthCheck: AUTH_HINT.test(code),
    hasRateLimit: RATE_HINT.test(code),
    hasValidation: VALIDATE_HINT.test(code),
    usesServiceRole: /SERVICE_ROLE|service_role/.test(code),
    readsIdParam: /(params|query)\s*[.\[]\s*['"]?\w*id/i.test(code) || /\[\w*id\w*\]/i.test(r),
    // Whether the handler consumes a request body at all. Without this, "no schema validation"
    // fires on handlers that take no input, which is noise on correct code — and noise is what
    // makes people stop reading the report.
    readsBody: /\breq(uest)?\.json\s*\(|\breq(uest)?\.body\b|\.formData\s*\(|await\s+\w+\.json\s*\(/.test(code),
    ownershipFilter: /(user_id|userId|owner_id|ownerId|auth\.uid\(\)|session\.user\.id|user\.id)/.test(code),
    businessFacts: 'file-scoped',
    ...businessFactsForRouteFile(code, f.text, inCode),
  })
}
// ---------- non-Next route inventory (Express / Fastify / Hono / Koa / NestJS) ----------
//
// AUDIT FIX C. The block above only recognises routes that are FILES: Next.js pages/app routes and
// serverless function directories. Every other Node server declares its routes as CALLS —
// `app.get('/admin', h)` — so an Express or Fastify app enumerated ZERO routes. LAW 2 was still
// satisfied (0 === 0) and the report rendered a full green coverage row for `routes`, while the
// entire HTTP surface was invisible. "We found nothing" meant "we looked nowhere", which is the
// exact failure the ledger exists to prevent.
//
// Precision matters more than reach here: `api.get('/users')` in a React component is an axios
// CALL, not a route DEFINITION, and inventing routes out of client fetches would be worse than
// missing them. So a file is only searched when it imports a server framework, and only variables
// actually assigned from that framework's constructors are treated as routers.
const SERVER_FRAMEWORKS = {
  express: { pkgs: ['express'], ctors: ['express', 'Router'] },
  fastify: { pkgs: ['fastify'], ctors: ['fastify', 'Fastify'] },
  hono: { pkgs: ['hono'], ctors: ['Hono'] },
  koa: { pkgs: ['koa', '@koa/router', 'koa-router'], ctors: ['Koa', 'Router'] },
  nest: { pkgs: ['@nestjs/common', '@nestjs/core'], ctors: [] },
  hapi: { pkgs: ['@hapi/hapi'], ctors: ['server', 'Server'] },
}
const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'all', 'options', 'head']

/** Text of a call's argument list, from the `(` at `openIdx` to its balanced `)`. */
function callArgs(text, openIdx, cap = 4000) {
  let depth = 0
  for (let i = openIdx; i < text.length && i - openIdx < cap; i++) {
    const c = text[i]
    if (c === '(') depth++
    else if (c === ')') { depth--; if (depth === 0) return text.slice(openIdx + 1, i) }
  }
  return text.slice(openIdx + 1, Math.min(text.length, openIdx + cap))
}

const frameworkRoutesByPkg = new Map() // framework name -> route count, for the declare-gap check
for (const [r, f] of files) {
  const bare = bareImports.get(r) || new Set()
  const fw = Object.entries(SERVER_FRAMEWORKS)
    .find(([, def]) => def.pkgs.some(p => bare.has(p)))
  if (!fw) continue
  const [fwName, fwDef] = fw
  const { code, mask } = stripJs(f.text)
  const inCode = idx => mask[idx] === CODE

  // Router-holding variables: `const app = express()`, `= new Hono()`, `= express.Router()`,
  // `= fastify({...})`. Plus the framework binding itself, since `fastify.get(...)` is idiomatic.
  const routerVars = new Set()
  const ctorAlt = fwDef.ctors.length ? fwDef.ctors.join('|') : '\\0'
  const ctorRe = new RegExp(
    `(?:const|let|var)\\s+(\\w+)\\s*(?::[^=]+)?=\\s*(?:await\\s+)?(?:new\\s+)?(?:\\w+\\s*\\.\\s*)?(?:${ctorAlt})\\s*[(<]`, 'g')
  let cm
  while ((cm = ctorRe.exec(code))) routerVars.add(cm[1])
  for (const p of fwDef.pkgs) {
    // Default import binding: `import express from 'express'` / `import Fastify from 'fastify'`.
    const impRe = new RegExp(`import\\s+(\\w+)\\s*(?:,\\s*\\{[^}]*\\})?\\s*from\\s*['"]${p.replace(/[/@]/g, '\\$&')}['"]`, 'g')
    let im
    while ((im = impRe.exec(f.text))) routerVars.add(im[1])
  }
  if (!routerVars.size && fwName !== 'nest') continue

  // App-level auth middleware (`app.use(requireAuth)`) protects everything registered after it,
  // exactly like Next's middleware.ts. Recorded so a correctly-guarded Express app is not reported
  // as a wall of unauthenticated routes. It still only reaches `undeterminable` — LAW 1 applies to
  // a token here as much as anywhere.
  let appLevelAuth = false
  {
    const useRe = new RegExp(`\\b(?:${[...routerVars].join('|') || '\\0'})\\s*\\.\\s*use\\s*\\(`, 'g')
    let um
    while ((um = useRe.exec(code))) {
      if (!inCode(um.index)) continue
      if (AUTH_HINT.test(callArgs(code, code.indexOf('(', um.index), 600))) { appLevelAuth = true; break }
    }
  }

  // Registering the same method+path twice in one file is a bug in the app, not two subjects. It
  // must be collapsed HERE: two ledger rows with the same subject is a LAW 2 violation, and LAW 2
  // is a throw — so without this, a duplicate `app.get('/x')` would crash the whole grade instead
  // of producing a report.
  const seenKeys = new Set()
  const push = (method, urlPath, idx, handlerText) => {
    const key = `${method.toUpperCase()} ${urlPath}`
    if (seenKeys.has(key)) return
    seenKeys.add(key)
    const line = code.slice(0, idx).split(/\r?\n/).length
    routes.push({
      file: r,
      kind: `${fwName}-route`,
      // The join key that keeps subjects unique: one file legitimately declares many routes, and
      // two rows with the same subject is a LAW 2 violation, not a duplicate to silently drop.
      routeKey: `${method.toUpperCase()} ${urlPath}`,
      urlPath,
      line,
      methods: [method.toUpperCase()],
      mutating: method !== 'get' && method !== 'head' && method !== 'options',
      hasAuthCheck: AUTH_HINT.test(handlerText) || appLevelAuth,
      authVia: AUTH_HINT.test(handlerText) ? 'handler' : appLevelAuth ? 'app-level-middleware' : null,
      hasRateLimit: RATE_HINT.test(handlerText) || RATE_HINT.test(code.slice(0, idx)),
      hasValidation: VALIDATE_HINT.test(handlerText),
      usesServiceRole: /SERVICE_ROLE|service_role/.test(handlerText),
      readsIdParam: /(params|query)\s*[.[]\s*['"]?\w*id/i.test(handlerText) || /:\w*id\w*/i.test(urlPath),
      // Must not match `res.json(...)` — that WRITES a response. A bare `.json(` matched it, so
      // every handler that replies with JSON was asked to validate a body it never read, which is
      // the noise-on-correct-code failure that makes a report stop being read.
      readsBody: /\breq(uest)?\.body\b|\breq(uest)?\.json\s*\(|c\.req\.(json|parseBody|valid)\s*\(|ctx\.request\.body/.test(handlerText),
      ownershipFilter: /(user_id|userId|owner_id|ownerId|auth\.uid\(\)|session\.user\.id|user\.id|req\.user)/.test(handlerText),
      // One file declares many handlers here, and the handler text this pass keeps is the STRIPPED
      // copy — table names and body-field literals live in strings, which stripping blanks. So the
      // route→resource link is not modelled for call-declared routes, and the business-logic layer
      // DECLARES that gap rather than attributing a `.from('orders')` to a handler by proximity.
      businessFacts: 'not-modelled',
      tablesTouched: null,
      eqColumns: null,
      bodyFields: null,
      literalAssignments: null,
      spreadsBodyIntoWrite: null,
    })
    frameworkRoutesByPkg.set(fwName, (frameworkRoutesByPkg.get(fwName) || 0) + 1)
  }

  // The route PATH lives inside a string literal, and stripJs blanks strings — so `app.get('/x')`
  // reads as `app.get(   )` in the stripped copy and every path vanishes. So: match on RAW text and
  // use the mask to reject a match that sits in a comment (a commented-out route must not be
  // enumerated). The HANDLER is then read from the stripped copy at the same offsets, because
  // stripJs preserves length and line breaks 1:1 — which matters, since running AUTH_HINT over raw
  // text would let `const msg = "TODO: add requireAuth"` mark an unauthenticated route as guarded.
  if (routerVars.size) {
    const varAlt = [...routerVars].join('|')
    const routeRe = new RegExp(
      `\\b(?:${varAlt})\\s*\\.\\s*(${HTTP_METHODS.join('|')})\\s*\\(\\s*(['"\`])([^'"\`]+)\\2`, 'g')
    let rm
    while ((rm = routeRe.exec(f.text))) {
      if (!inCode(rm.index)) continue
      push(rm[1], rm[3], rm.index, callArgs(code, code.indexOf('(', rm.index)))
    }
    // `app.route('/x').get(h).post(h)` — the path is on route(), the methods chain off it.
    const chainRe = new RegExp(`\\b(?:${varAlt})\\s*\\.\\s*route\\s*\\(\\s*(['"\`])([^'"\`]+)\\1\\s*\\)`, 'g')
    while ((rm = chainRe.exec(f.text))) {
      if (!inCode(rm.index)) continue
      const tail = code.slice(rm.index, rm.index + 2000)
      const methRe = new RegExp(`\\.\\s*(${HTTP_METHODS.join('|')})\\s*\\(`, 'g')
      let mm
      while ((mm = methRe.exec(tail))) push(mm[1], rm[2], rm.index + mm.index, callArgs(tail, mm.index + mm[0].length - 1))
    }
  }

  // NestJS declares routes with decorators. The controller prefix and the method path combine.
  if (fwName === 'nest') {
    const prefix = (/@Controller\s*\(\s*['"]([^'"]*)['"]/.exec(f.text) || [, ''])[1]
    const decRe = /@(Get|Post|Put|Patch|Delete|All|Options|Head)\s*\(\s*(?:['"]([^'"]*)['"])?\s*\)/g
    let dm
    while ((dm = decRe.exec(f.text))) {
      if (!inCode(dm.index)) continue
      const urlPath = ('/' + [prefix, dm[2] || ''].filter(Boolean).join('/')).replace(/\/+/g, '/')
      // The decorated method body follows the decorator; take a bounded slice of it.
      push(dm[1].toLowerCase(), urlPath, dm.index, code.slice(dm.index, dm.index + 1500))
    }
  }
}

// A server framework in package.json with ZERO routes enumerated is the loud version of the bug
// above: either the app declares its routes somewhere this pass cannot see, or it genuinely has
// none. We cannot tell which, so it becomes a declared coverage hole rather than a silent zero.
const routeFrameworkGaps = []
for (const [name, def] of Object.entries(SERVER_FRAMEWORKS)) {
  if (!def.pkgs.some(has)) continue
  if (!frameworkRoutesByPkg.get(name)) {
    routeFrameworkGaps.push({
      framework: name,
      declaredIn: 'package.json',
      reason: `${name} is a dependency but no route definitions were enumerated from it — its HTTP surface may be declared in a way this pass cannot follow (dynamic registration, a route file loader, or a generated router)`,
    })
  }
}

// ---------- non-JS backends ----------
//
// THE SAME DEFECT, ONE LANGUAGE OVER. `SERVER_FRAMEWORKS` above is keyed on npm package names, and
// `CODE_EXT` has no `.py`, `.go`, `.rb` or `.php` — so a Flask, FastAPI, Django, Gin, Rails or
// Laravel server is invisible TWICE: every one of its files falls into
// `discovery.counts.unsupported`, and no framework this pass knows how to look for is a dependency.
// The report then renders `routes | 0 | 0 | 0 | 0 | 0` with NOT ONE declared row, so a repository
// whose entire HTTP surface, every auth decorator and every hand-built SQL string went unread
// prints exactly like a repository that has no server at all. Mobile got its declaration path
// (`artifacts.nativeSource`); backend languages got nothing — and for a security gate, silence
// about the server is the precise silent-clean failure grade-or-declare exists to kill.
//
// Detected by manifest AND/OR source extension, either alone being enough: a service whose sources
// live in a submodule still declares its dependencies here, and a directory of `.py` files with no
// manifest is still a Python codebase this pass cannot read.
//
// These are DECLARATIONS, never findings. A non-JS backend is not a vulnerability, it is an
// unexamined surface, and nothing here may move the verdict. They ride the existing `frameworkGaps`
// channel, which `declareUngradedSurfaces` already files as `undeterminable` rows under
// `ungradedSurfaces` — being the net for exactly this case is what that channel is for.
const NON_JS_BACKENDS = [
  {
    name: 'python', label: 'Python', ext: '.py', extRe: /\.py$/,
    manifests: new Set(['requirements.txt', 'pyproject.toml', 'Pipfile']),
    review: 'routes declared with @app.route / @router.get / urls.py, endpoints with no auth decorator, SQL built by f-string or %-formatting, and os.system / subprocess(…, shell=True) reached from request data',
  },
  {
    name: 'go', label: 'Go', ext: '.go', extRe: /\.go$/,
    manifests: new Set(['go.mod']),
    review: 'handlers registered on net/http, gin, chi or echo with no auth middleware on their group, SQL built with fmt.Sprintf instead of placeholders, and os/exec calls reached from request data',
  },
  {
    name: 'ruby', label: 'Ruby', ext: '.rb', extRe: /\.rb$/,
    manifests: new Set(['Gemfile']),
    review: 'controller actions with no before_action authorisation filter, routes.rb entries nobody guards, string-interpolated ActiveRecord `where` clauses, and system / backtick calls reached from params',
  },
  {
    name: 'php', label: 'PHP', ext: '.php', extRe: /\.php$/,
    manifests: new Set(['composer.json']),
    review: 'endpoints with no session or permission check, SQL concatenated from $_GET/$_POST instead of a prepared statement, and shell_exec / include of a request-controlled path',
  },
]

const nonJsBackendGaps = []
for (const b of NON_JS_BACKENDS) {
  const src = allPaths.filter(p => b.extRe.test(p))
  const mans = allPaths.filter(p => b.manifests.has(p.split('/').pop()))
  if (!src.length && !mans.length) continue
  const n = src.length
  const reason = n
    // What the row must give the reader is the size of the hole and the work it implies, so the
    // count and three real paths lead — an undeterminable row without an instruction is an apology.
    ? `${n} ${b.label} file${n === 1 ? '' : 's'} (e.g. ${src.slice(0, 3).join(', ')})${mans.length ? `, declared by ${mans.slice(0, 2).join(', ')}` : ''} — the static tier parses JavaScript and TypeScript only, so it read NONE of them: no ${b.label} route, auth check or injection sink is counted anywhere in this report, and a 0 in the routes or tables rows describes the JavaScript half of this repo alone. Review this backend by hand for ${b.review} (checks/web.md — "Authentication & authorization", "API routes / IDOR / mass assignment", "Injection & XSS")`
    : `${mans.slice(0, 3).join(', ')} declares a ${b.label} component but no ${b.ext} file was enumerated — its source is outside this repository (a submodule, a separate service, or generated at build time), so nothing about its routes, auth or injection surface could be read here; audit that service on its own against checks/web.md`
  nonJsBackendGaps.push({
    framework: b.name,
    language: b.label,
    declaredIn: mans.length ? mans.slice(0, 3).join(', ') : `${b.ext} source files`,
    fileCount: n,
    files: src.slice(0, MAX_LEDGER_ROWS),
    manifests: mans.slice(0, MAX_LEDGER_ROWS),
    reason,
  })
}

// middleware-based auth (a route may be protected centrally — avoids false "no auth")
const middlewareFiles = [...files.keys()].filter(r => /(^|\/)middleware\.(t|j)s$/.test(r))
const middlewareAuth = middlewareFiles.some(r => AUTH_HINT.test(files.get(r).text))
const middlewareMatcher = middlewareFiles.map(r => {
  const mm = /matcher\s*:\s*\[([^\]]+)\]|matcher\s*:\s*['"]([^'"]+)['"]/.exec(files.get(r).text)
  return { file: r, matcher: mm ? (mm[1] || mm[2]).replace(/\s+/g, ' ').trim() : null }
})

// ---------- SQL column lists ----------
//
// WHY: the business-logic layer's intent proposer has to read `user_id` / `org_id` / `status` off
// the schema, and until now the engine knew a table's NAME and nothing else. Columns are Facts in
// the strictest sense — a name and a type. That `user_id` *means* ownership is an INTENT statement,
// which only the app's author can make (core/methodology/business-logic.md); the engine says only
// that the column exists.
//
// Table-level constraints share the parenthesised list with the columns, so they are skipped by
// their leading keyword. Missing that would invent a column named `primary` on half the schemas in
// the wild, and the proposer would then offer the user a schema that does not exist.
const TABLE_CONSTRAINT_KW = /^(primary|unique|foreign|check|exclude|constraint|like|inherits|partition|deferrable|initially)\b/i
// Where a column's TYPE stops and its constraints begin. The cut is made at the first CONSTRAINT
// word rather than at the first space, so multi-word types (`double precision`,
// `timestamp with time zone`, `character varying`) survive whole.
const COLUMN_CONSTRAINT_KW = /\b(?:primary\s+key|references|not\s+null|null|default|unique|check|generated|collate|constraint|deferrable|storage|compression)\b/i

/** Split on commas at paren depth 0 — `numeric(10,2)` must not split into two columns. */
function splitTopLevel(s) {
  const out = []
  let depth = 0, start = 0
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (c === '(') depth++
    else if (c === ')') depth--
    else if (c === ',' && depth === 0) { out.push(s.slice(start, i)); start = i + 1 }
  }
  out.push(s.slice(start))
  return out
}

/**
 * The contents of the balanced `( … )` that starts at or after `from`, or null when the next
 * non-space token is not `(`. Returning null is what keeps `create table x as select …` — which has
 * no column list at all — from parsing a subquery's parentheses as columns.
 */
function balancedParen(text, from) {
  let i = from
  while (i < text.length && /\s/.test(text[i])) i++
  if (text[i] !== '(') return null
  let depth = 0
  for (let j = i; j < text.length; j++) {
    if (text[j] === '(') depth++
    else if (text[j] === ')') { depth--; if (depth === 0) return text.slice(i + 1, j) }
  }
  return null
}

/** `id uuid primary key default gen_random_uuid()` -> { name: 'id', type: 'uuid' } */
function parseColumnDef(part) {
  const s = part.trim()
  if (!s || TABLE_CONSTRAINT_KW.test(s)) return null
  const m = /^(?:"([^"]+)"|`([^`]+)`|([A-Za-z_][\w$]*))\s*([\s\S]*)$/.exec(s)
  if (!m) return null
  const name = (m[1] || m[2] || m[3]).toLowerCase()
  let rest = m[4] || ''
  const cut = COLUMN_CONSTRAINT_KW.exec(rest)
  if (cut) rest = rest.slice(0, cut.index)
  const type = rest.trim().replace(/\s+/g, ' ').replace(/[,;]+$/, '')
  return { name, type: type ? type.toLowerCase() : null }
}

/** Every column definition in a `create table … ( … )` statement. */
function parseCreateTableColumns(stmt, afterNameIdx) {
  const inner = balancedParen(stmt, afterNameIdx)
  if (inner == null) return []
  const out = []
  const seen = new Set()
  for (const part of splitTopLevel(inner)) {
    const def = parseColumnDef(part)
    if (!def || seen.has(def.name)) continue
    seen.add(def.name)
    out.push(def)
  }
  return out
}

// ---------- database model (Supabase/Postgres migrations) ----------
const sqlFiles = allPaths.filter(p => /\.sql$/i.test(p))
const tables = new Map()
const sqlFunctions = []
for (const p of sqlFiles) {
  const raw = readParsedConfig(p); if (raw == null) continue

  // CRITICAL: never match against raw SQL. A commented-out
  //   -- alter table public.orders enable row level security;
  // previously made this report RLS as ENABLED on an unprotected table — a false negative
  // that hid a P0. stripSql blanks comments/strings while preserving every offset and line
  // number, so `file:line` evidence stays exact.
  const { code: text, dollarBodies } = stripSql(raw)

  // `create function ... security definer` bodies are dollar-quoted, so they are blanked above.
  // Capture them here: a SECURITY DEFINER function without `set search_path` and without an
  // internal auth check bypasses RLS entirely and is callable by anon via supabase.rpc().
  // Stripping and forgetting them would trade one blind spot for a worse one.
  {
    const fnRe = /create\s+(?:or\s+replace\s+)?function\s+(?:(\w+)\.)?["']?(\w+)["']?/gi
    let fm
    while ((fm = fnRe.exec(text))) {
      const at = text.slice(0, fm.index).split(/\r?\n/).length
      const tail = text.slice(fm.index, fm.index + 2000)
      const body = dollarBodies.find(b => b.start > fm.index) || null
      sqlFunctions.push({
        schema: (fm[1] || 'public').toLowerCase(),
        name: fm[2].toLowerCase(),
        at: `${p}:${at}`,
        securityDefiner: /security\s+definer/i.test(tail),
        setsSearchPath: /set\s+search_path/i.test(tail),
        // Scan the comment-stripped body: a `-- enforced by auth.uid() elsewhere` comment inside a
        // SECURITY DEFINER body used to silence the no-auth-check finding (an audit bypass).
        bodyChecksAuth: body ? /auth\.uid\(\)|auth\.jwt\(\)/i.test(stripSql(body.text).code) : null,
      })
    }
  }

  // Parse by complete STATEMENT, not by physical line or a fixed look-ahead window. Reading the
  // whole statement is what makes multi-line CREATE TABLE / CREATE POLICY parse (the Supabase docs
  // format policies across several lines), and — the audit's single worst defect — it stops an
  // adjacent policy's `using (true)` from bleeding into a *correct* owner-scoped policy and firing a
  // CONFIRMED false P0 on production SQL. `text` is comment/string-stripped and dollar-quoted bodies
  // are blanked, so a `;` inside a comment, a string, or a function body can never split falsely.
  const lineOf = off => text.slice(0, off).split(/\r?\n/).length
  const parseStatement = (stmt, absStart) => {
    let m
    if ((m = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:(\w+)\.)?["']?(\w+)["']?/i.exec(stmt))) {
      const schema = (m[1] || 'public').toLowerCase(), name = m[2].toLowerCase()
      if (schema === 'public') {
        if (!tables.has(name)) {
          tables.set(name, { name, definedIn: `${p}:${lineOf(absStart + m.index)}`, rlsEnabled: false, rlsAt: null, policies: [], columns: [] })
        }
        const cols = parseCreateTableColumns(stmt, m.index + m[0].length)
        if (cols.length) tables.get(name).columns = cols
      }
    }
    // `alter table … add column` / `drop column`. Migrations use these constantly, and a schema
    // read only from the original CREATE would hand the intent proposer a table without the very
    // `user_id` a later migration added.
    //
    // Deliberately attaches ONLY to a table this parser already knows. Creating a stub here would
    // enter a table into the enumerated set with `rlsEnabled: false` and `rlsCertainty:
    // from-migrations` — a CONFIRMED P0 invented out of an ALTER whose CREATE lives in the Supabase
    // dashboard. A missing column is a coverage gap; a fabricated P0 is a breach announcement.
    if (/\balter\s+table\b/i.test(stmt)) {
      const at = /alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:(\w+)\.)?["']?(\w+)["']?/i.exec(stmt)
      const tName = at ? at[2].toLowerCase() : null
      if (at && (at[1] || 'public').toLowerCase() === 'public' && tName && tables.has(tName)) {
        const t = tables.get(tName)
        t.columns = t.columns || []
        const addRe = /\badd\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(?!constraint\b|primary\b|foreign\b|unique\b|check\b|exclude\b)(?:"([^"]+)"|([A-Za-z_][\w$]*))\s+([^,;]*)/gi
        let am2
        while ((am2 = addRe.exec(stmt))) {
          const raw = am2[1] ? `"${am2[1]}" ${am2[3] || ''}` : `${am2[2]} ${am2[3] || ''}`
          const def = parseColumnDef(raw)
          if (def && !t.columns.some(c => c.name === def.name)) t.columns.push(def)
        }
        // `drop column` requires the keyword: a bare `drop constraint fk_x` must not delete a column
        // named `constraint`, and `drop` without `column` is not a column operation.
        const dropRe = /\bdrop\s+column\s+(?:if\s+exists\s+)?(?:"([^"]+)"|([A-Za-z_][\w$]*))/gi
        let dm2
        while ((dm2 = dropRe.exec(stmt))) {
          const gone = (dm2[1] || dm2[2]).toLowerCase()
          t.columns = t.columns.filter(c => c.name !== gone)
        }
      }
    }
    if ((m = /alter\s+table\s+(?:(\w+)\.)?["']?(\w+)["']?\s+enable\s+row\s+level\s+security/i.exec(stmt))) {
      const schema = (m[1] || 'public').toLowerCase(), name = m[2].toLowerCase()
      if (schema === 'public') {
        const t = tables.get(name) || { name, definedIn: null, rlsEnabled: false, rlsAt: null, policies: [] }
        t.rlsEnabled = true; t.rlsAt = `${p}:${lineOf(absStart + m.index)}`; tables.set(name, t)
      }
    }
    if ((m = /create\s+policy\s+["']?([^"'\n]+?)["']?\s+on\s+(?:(\w+)\.)?["']?(\w+)["']?/i.exec(stmt))) {
      const schema = (m[2] || 'public').toLowerCase(), name = m[3].toLowerCase()
      // storage.objects / auth.* are Supabase-managed system tables, not the user's — a policy on
      // one must not register a phantom `objects` table (an audit false positive).
      if (schema !== 'public') return
      const t = tables.get(name) || { name, definedIn: null, rlsEnabled: false, rlsAt: null, policies: [] }
      const cmd = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(stmt) || [, 'all'])[1].toLowerCase()
      // Permissive = the row predicate does NOT constrain to the caller: literal `true`, or the
      // blanket "any authenticated user" forms (`auth.uid() is not null`, `auth.role()='authenticated'`),
      // which grant every row to every logged-in user — a cross-tenant leak the old bare-substring
      // scopedToUid test passed as "safe".
      const permissive =
        /using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(stmt)
        || /auth\.uid\(\)\s+is\s+not\s+null/i.test(stmt)
        || /auth\.role\(\)\s*=\s*'authenticated'/i.test(stmt)
      // Scoped only when auth.uid() is actually COMPARED to a column — a bare mention is not a scope.
      const scopedToUid = !permissive
        && /auth\.uid\(\)\s*=\s*[\w".]+|[\w".]+\s*=\s*auth\.uid\(\)/i.test(stmt)
      t.policies.push({ name: m[1].trim(), cmd, at: `${p}:${lineOf(absStart + m.index)}`, permissive, scopedToUid })
      tables.set(name, t)
    }
  }
  let stmtStart = 0
  for (let i = 0; i < text.length; i++) {
    if (text[i] === ';') { const s = text.slice(stmtStart, i); if (s.trim()) parseStatement(s, stmtStart); stmtStart = i + 1 }
  }
  { const s = text.slice(stmtStart); if (s.trim()) parseStatement(s, stmtStart) }
}
// Snapshot which tables migrations actually proved, BEFORE other sources add more. RLS state is
// only verifiable for these; provenance from a later source must not overwrite it.
const tablesFromMigrations = new Set(tables.keys())

// tables referenced from code (catches tables used but never seen in migrations)
const TABLE_REF_RE = /\.from\(\s*['"]([a-zA-Z0-9_]+)['"]\s*\)/g
const tablesUsedInCode = new Map()
// Non-literal .from(x) — the table set cannot be enumerated from a generic CRUD helper.
// This must be VISIBLE, never a silent skip, or we would claim complete coverage while blind.
const DYNAMIC_TABLE_REF_RE = /\.from\(\s*(?!['"])([A-Za-z_$][\w$.]*)\s*\)/g
const dynamicTableRefs = []
// The Supabase client factories, used to prove that a bare `from(...)` is a table query and not,
// say, RxJS's `from`. A .from('x') is only a table reference when the thing before the dot is a
// Supabase client; a bare from('x') only when `from` was destructured off one.
const SUPA_FACTORY_NAMES = new Set(['createServerClient', 'createBrowserClient',
  'createRouteHandlerClient', 'createServerComponentClient', 'createClientComponentClient',
  'createMiddlewareClient', 'createPagesBrowserClient', 'createPagesServerClient', 'createClient'])
for (const [r, f] of files) {
  // Scan RAW text — a table name and an import path both LIVE inside string literals, so blanking
  // strings would erase the very data we read. Instead use the stripper's MASK to reject any match
  // whose `.from` / `from` token sits inside a comment or a string: real code is CODE at that
  // offset, a commented-out `.from('ghost')` is COMMENT. This kills the "table named only in a
  // comment" false positive without losing the table name.
  const { mask } = stripJs(f.text)
  const inCode = idx => mask[idx] === CODE

  let m; TABLE_REF_RE.lastIndex = 0
  while ((m = TABLE_REF_RE.exec(f.text))) {
    if (!inCode(m.index)) continue
    const t = m[1].toLowerCase()
    if (!tablesUsedInCode.has(t)) tablesUsedInCode.set(t, [])
    if (!tablesUsedInCode.get(t).includes(r)) tablesUsedInCode.get(t).push(r)
  }
  DYNAMIC_TABLE_REF_RE.lastIndex = 0
  while ((m = DYNAMIC_TABLE_REF_RE.exec(f.text))) {
    if (!inCode(m.index)) continue
    const line = f.text.slice(0, m.index).split(/\r?\n/).length
    dynamicTableRefs.push({ file: r, line, expr: m[1] })
  }

  // Destructured access: `const supabase = createServerClient(...); const { from } = supabase;
  // from('orders')`. The dotted scan above needs a leading dot, so the destructured call is
  // invisible to it. Enumerate it ONLY when `from` is destructured from something that actually
  // holds a Supabase client — a client variable assigned from a factory, or a factory call
  // directly. Without this scoping, an unrelated `const { from } = rxjs` (RxJS's Observable
  // factory) invents phantom tables on genuinely clean code — a false positive the adversarial
  // pass caught.
  const clientVars = new Set()
  const assignRe = /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(\w+)\s*[(<]/g
  let am
  while ((am = assignRe.exec(f.text))) {
    if (inCode(am.index) && SUPA_FACTORY_NAMES.has(am[2])) clientVars.add(am[1])
  }
  const rhsAlts = []
  if (clientVars.size) rhsAlts.push(`(?:${[...clientVars].join('|')})\\b`)
  rhsAlts.push(`(?:${[...SUPA_FACTORY_NAMES].join('|')})\\s*[(<]`)
  const destructRe = new RegExp(
    `(?:const|let|var)\\s*\\{[^}]*\\bfrom\\b[^}]*\\}\\s*=\\s*(?:${rhsAlts.join('|')})`, 'g')
  let destructInCode = false, dm
  while ((dm = destructRe.exec(f.text))) { if (inCode(dm.index)) { destructInCode = true; break } }
  if (destructInCode) {
    const BARE_FROM_RE = /(?<!\.)\bfrom\s*\(\s*['"]([a-zA-Z0-9_]+)['"]\s*\)/g
    while ((m = BARE_FROM_RE.exec(f.text))) {
      if (!inCode(m.index)) continue
      const t = m[1].toLowerCase()
      if (!tablesUsedInCode.has(t)) tablesUsedInCode.set(t, [])
      if (!tablesUsedInCode.get(t).includes(r)) tablesUsedInCode.get(t).push(r)
    }
  }
}

// ---------- schema population from EVERY available source ----------
//
// WHY: the modal vibecoder creates tables in the Supabase DASHBOARD and has no
// supabase/migrations/ at all. Enumerating tables only from .sql files finds 0-3 of them, so the
// flagship "table has no RLS" detector silently produces nothing — while a coverage row implies
// completeness. Worse is the partial case: 6 tables in migrations pass and the 7th, added in the
// dashboard, never appears. "The LLM misses the 7th table" is exactly what we would do.
//
// database.types.ts (generated by `supabase gen types`) is the authoritative list because it is
// produced FROM the live database, so it includes dashboard-created tables.
const schemaSources = []
if (sqlFiles.length) schemaSources.push('migrations')

/** Extract the direct child keys of a `Tables: { ... }` block in generated Supabase types. */
function tablesFromSupabaseTypes(text) {
  const out = []
  const anchor = /public\s*:\s*\{/.exec(text)
  const start = anchor ? anchor.index : 0
  const tIdx = text.indexOf('Tables:', start)
  if (tIdx === -1) return out
  const open = text.indexOf('{', tIdx)
  if (open === -1) return out
  let depth = 0
  for (let i = open; i < text.length; i++) {
    const c = text[i]
    if (c === '{') {
      depth++
      if (depth === 2) {
        // a direct child of Tables: capture the identifier preceding this brace
        const head = text.slice(Math.max(0, i - 120), i)
        const km = /([A-Za-z_][\w]*)\s*:\s*$/.exec(head)
        if (km) out.push(km[1].toLowerCase())
      }
    } else if (c === '}') {
      depth--
      if (depth === 0) break
    }
  }
  return out
}

const typeFiles = allPaths.filter(p =>
  /(^|\/)(database|supabase)\.types\.ts$|(^|\/)types\/(supabase|database)\.ts$|(^|\/)supabase\/types\.ts$/i.test(p))
for (const p of typeFiles) {
  const text = readParsedConfig(p); if (text == null) continue
  const names = tablesFromSupabaseTypes(text)
  if (!names.length) continue
  if (!schemaSources.includes('supabase-types')) schemaSources.push('supabase-types')
  for (const name of names) {
    const t = tables.get(name) || { name, definedIn: null, rlsEnabled: false, rlsAt: null, policies: [] }
    t.knownFrom = [...new Set([...(t.knownFrom || []), 'supabase-types'])]
    if (!t.definedIn) t.definedIn = p
    tables.set(name, t)
  }
}

// Prisma / Drizzle projects manage schema in code, and have no Postgres RLS layer at all.
for (const p of allPaths.filter(x => /schema\.prisma$/i.test(x))) {
  const text = readParsedConfig(p); if (text == null) continue
  let m; const re = /^\s*model\s+(\w+)\s*\{/gm
  while ((m = re.exec(text))) {
    if (!schemaSources.includes('prisma')) schemaSources.push('prisma')
    const name = m[1].toLowerCase()
    const t = tables.get(name) || { name, definedIn: p, rlsEnabled: false, rlsAt: null, policies: [] }
    t.knownFrom = [...new Set([...(t.knownFrom || []), 'prisma'])]
    tables.set(name, t)
  }
}
for (const [r, f] of files) {
  let m; const re = /pgTable\(\s*['"]([\w]+)['"]/g
  while ((m = re.exec(f.text))) {
    if (!schemaSources.includes('drizzle')) schemaSources.push('drizzle')
    const name = m[1].toLowerCase()
    const t = tables.get(name) || { name, definedIn: r, rlsEnabled: false, rlsAt: null, policies: [] }
    t.knownFrom = [...new Set([...(t.knownFrom || []), 'drizzle'])]
    tables.set(name, t)
  }
}
// Tables seen only in code still count as enumerated subjects.
for (const [name, usedIn] of tablesUsedInCode) {
  const t = tables.get(name) || { name, definedIn: null, rlsEnabled: false, rlsAt: null, policies: [] }
  t.knownFrom = [...new Set([...(t.knownFrom || []), 'code-reference'])]
  t.usedIn = usedIn
  tables.set(name, t)
}
if (tablesUsedInCode.size && !schemaSources.includes('code-reference')) schemaSources.push('code-reference')
for (const t of tables.values()) {
  if (tablesFromMigrations.has(t.name)) {
    t.knownFrom = [...new Set(['migrations', ...(t.knownFrom || [])])]
  } else if (!t.knownFrom) {
    t.knownFrom = ['migrations']
  }
  // RLS state is only KNOWN when a migration proves it. A table discovered from generated types
  // or a code reference says nothing about whether RLS is on — claiming `false` there would be a
  // false positive, and claiming `true` would be a false negative. So: unknown.
  t.rlsCertainty = tablesFromMigrations.has(t.name) ? 'from-migrations' : 'unknown-no-migration'
  // Same discipline for COLUMNS: only a migration's column list establishes them. A table known
  // from generated types, Prisma or a bare `.from('x')` has an unknown shape, and `[]` must be
  // readable as "unknown", not as "this table has no columns" — hence the separate certainty field.
  t.columns = t.columns || []
  t.columnsKnownFrom = t.columns.length ? 'migrations' : null
}

// If no schema source exists at all, that is ONE loud blocking unknown — not N quiet ones.
const schemaCoverage = {
  sources: schemaSources,
  tablesEnumerated: tables.size,
  dynamicTableRefs,
  rlsVerifiable: schemaSources.includes('migrations'),
  // Handed to the user verbatim when we cannot see the schema, so they can answer it themselves.
  verifyQuery: `select c.relname,
       c.relrowsecurity as rls_enabled,
       (select count(*) from pg_policy p where p.polrelid = c.oid) as policies
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r'
order by 1;`,
  note: schemaSources.length
    ? null
    : 'No schema source found (no migrations, no generated types, no Prisma/Drizzle schema). RLS state CANNOT be determined from this repo — run verifyQuery against your database.',
}

// ---------- env-guard libraries ----------
//
// t3-env (`createEnv({ server, client, runtimeEnv })`) is the recommended way to keep server
// secrets out of client bundles: it throws if client code touches a server var. A project using
// it is doing the RIGHT thing, and its `runtimeEnv` block necessarily names every server var —
// so a naive reader sees "secrets referenced in a client-imported file" and cries wolf.
// Recording the pattern lets downstream rules credit it instead of punishing it.
const envGuards = []
for (const [r, f] of files) {
  if (!/createEnv\s*\(/.test(f.text)) continue
  const { code } = stripJs(f.text)
  envGuards.push({
    file: r,
    library: /@t3-oss\/env/.test(f.text) ? 't3-env' : 'createEnv-like',
    declaresServerBlock: /\bserver\s*:\s*\{/.test(code),
    declaresClientBlock: /\bclient\s*:\s*\{/.test(code),
    // The whole point of the library: server vars are unreachable from client code.
    protectsServerVars: /\bserver\s*:\s*\{/.test(code),
  })
}

// ---------- Supabase client identity ----------
//
// WHY THIS EXISTS (false-positive blocker): `@supabase/ssr`'s createServerClient(url, ANON_KEY,
// { cookies }) is the OFFICIALLY RECOMMENDED pattern and produces a USER-SCOPED client where RLS
// with auth.uid() is the correct and sufficient control. Without recognising it, every
// `.eq('id', id)` in a correct app looks like an IDOR, and we would flood the idiomatic Supabase
// app with false P1s. Volume is what destroys trust — not any single finding.
const SUPABASE_FACTORIES = [
  // factory name                          identity
  ['createServerClient', 'anon-user-scoped'],
  ['createBrowserClient', 'anon-user-scoped'],
  ['createRouteHandlerClient', 'anon-user-scoped'],
  ['createServerComponentClient', 'anon-user-scoped'],
  ['createClientComponentClient', 'anon-user-scoped'],
  ['createMiddlewareClient', 'anon-user-scoped'],
  ['createPagesBrowserClient', 'anon-user-scoped'],
  ['createPagesServerClient', 'anon-user-scoped'],
]
const FACTORY_IDENTITY = new Map(SUPABASE_FACTORIES)
const FACTORY_NAMES = new Set([...FACTORY_IDENTITY.keys(), 'createClient'])

// Resolve import aliases for the known factory names, so `import { createClient as cc }` followed by
// `cc(...)` is still recognised. Without this, a one-line alias — a semantics-preserving edit —
// silently hides a service-role client entirely: the subject never enters the model and CG-DB-006
// vanishes. Scoped to `@supabase/*` imports so a `createClient` from some other library is not
// mistaken for a Supabase factory.
function factoryAliasesFor(text) {
  const aliases = new Map() // localName -> canonicalFactory
  const impRe = /import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*['"](@supabase\/[^'"]+)['"]/g
  let im
  while ((im = impRe.exec(text))) {
    for (const part of im[1].split(',')) {
      const mm = /^\s*([A-Za-z_$][\w$]*)\s*(?:as\s+([A-Za-z_$][\w$]*))?\s*$/.exec(part)
      if (!mm) continue
      const orig = mm[1], local = mm[2] || mm[1]
      if (FACTORY_NAMES.has(orig) && local !== orig) aliases.set(local, orig)
    }
  }
  return aliases
}

const supabaseClients = []
for (const [r, f] of files) {
  // Reject factory calls that sit in a comment: a `createClient(url, SERVICE_ROLE_KEY)` written in
  // a doc example must never manufacture a service-role client (and a P0). The import specifier is
  // a STRING, so aliases are read from raw text; the CALL sites are checked against the mask.
  const { mask } = stripJs(f.text)
  const inCode = idx => mask[idx] === CODE
  const aliases = factoryAliasesFor(f.text)

  // The ssr/auth-helpers factories, under their canonical names AND any local alias.
  const namedFactories = new Map() // localName -> { canonical, identity }
  for (const [fn, identity] of SUPABASE_FACTORIES) namedFactories.set(fn, { canonical: fn, identity })
  for (const [local, orig] of aliases) {
    if (orig !== 'createClient') namedFactories.set(local, { canonical: orig, identity: FACTORY_IDENTITY.get(orig) })
  }
  for (const [localName, { canonical, identity }] of namedFactories) {
    const re = new RegExp(`\\b${localName}\\s*[(<]`, 'g')
    let m
    while ((m = re.exec(f.text))) {
      if (!inCode(m.index)) continue
      supabaseClients.push({
        file: r,
        line: f.text.slice(0, m.index).split(/\r?\n/).length,
        factory: canonical,
        identity,
        // RLS is the correct control for this identity; IDOR must never be `confirmed` here.
        rlsIsTheControl: true,
      })
    }
  }

  // Plain createClient(url, KEY) — identity depends entirely on WHICH key — plus its aliases.
  const createClientLocals = new Set(['createClient'])
  for (const [local, orig] of aliases) if (orig === 'createClient') createClientLocals.add(local)
  for (const localName of createClientLocals) {
    const re = new RegExp(`\\b${localName}\\s*(?:<[^>]*>)?\\s*\\(([^)]{0,400})\\)`, 'gs')
    let m
    while ((m = re.exec(f.text))) {
      if (!inCode(m.index)) continue
      const args = m[1]
      const usesServiceRole = /SERVICE_ROLE/i.test(args)
      const usesAnon = /ANON/i.test(args)
      supabaseClients.push({
        file: r,
        line: f.text.slice(0, m.index).split(/\r?\n/).length,
        factory: 'createClient',
        identity: usesServiceRole ? 'service-role' : usesAnon ? 'anon-public' : 'unknown-key',
        // service_role BYPASSES RLS entirely, so RLS is not a control for it.
        rlsIsTheControl: !usesServiceRole,
      })
    }
  }
}

// ---------- route reachability to a service-role client ----------
//
// AUDIT #6 (the worst reproduced finding): the flagship IDOR/auth findings vanished the moment the
// privileged client moved one import away — the universal real pattern is a route that imports
// `lib/db.ts`, where a `createClient(url, SERVICE_ROLE_KEY)` lives. The route-file text scan
// (`usesServiceRole`) can't see it, but the import graph and `supabaseClients` already do. This
// post-pass marks a route as reaching a service-role client when any module it transitively imports
// builds one, so `gradeRoutes` can treat "no auth" as a P0 and detect the IDOR.
{
  /** Does `from` reach any file in `targets` through the import graph (including itself)? */
  const reaches = (from, targets) => {
    if (targets.has(from)) return true
    const seen = new Set([from]); const q = [from]
    while (q.length) {
      for (const dep of imports.get(q.shift()) || []) {
        if (seen.has(dep)) continue
        if (targets.has(dep)) return true
        seen.add(dep); q.push(dep)
      }
    }
    return false
  }
  const serviceRoleFiles = new Set(
    supabaseClients.filter(c => c.identity === 'service-role').map(c => c.file))
  // The mirror fact, and the one the business-logic layer's false-positive guard turns on: an anon,
  // USER-SCOPED client means RLS with auth.uid() is the control, so `.eq('id', id)` there is the
  // officially recommended Supabase pattern and not an IDOR (FP-03). Without this fact the
  // business-logic pass would flag the correct app — the worst possible false positive here.
  const anonScopedFiles = new Set(
    supabaseClients.filter(c => c.identity === 'anon-user-scoped').map(c => c.file))
  for (const route of routes) {
    route.reachesServiceRoleClient = route.usesServiceRole || reaches(route.file, serviceRoleFiles)
    route.reachesAnonScopedClient = reaches(route.file, anonScopedFiles)
  }
}

// ---------- next.config.js ----------
//
// `env:` and `publicRuntimeConfig` INLINE arbitrary server env vars into the client bundle with NO
// public prefix required, which defeats the entire prefix-based model. Enumerable, high-value, and
// previously invisible to the engine.
//
// These are FACTS, not Findings: each one records that a key is set and what setting it does, and
// says nothing about how bad that is. Severity for every key below lives in grader.mjs and nowhere
// else — the engine holding a `severityHint` was the last place the policy was duplicated, and a
// duplicated policy is one that drifts. Whether `env:` is a P0 or a P2 depends on whether this repo
// has anything privileged to inline, which is a judgement about the whole model rather than about
// this file, so only the grader is in a position to make it.
const nextConfigFacts = []
for (const p of allPaths.filter(x => /(^|\/)next\.config\.(m|c)?[jt]s$/.test(x))) {
  const raw = readParsedConfig(p); if (raw == null) continue
  const { code } = stripJs(raw)
  const at = re => {
    const m = re.exec(code)
    return m ? { line: code.slice(0, m.index).split(/\r?\n/).length, match: m[0].slice(0, 80) } : null
  }
  const add = (key, hit, why) => { if (hit) nextConfigFacts.push({ file: p, key, ...hit, why }) }
  add('env', at(/\benv\s*:\s*\{/),
    'next.config env: inlines these values into the CLIENT bundle regardless of prefix')
  add('publicRuntimeConfig', at(/\bpublicRuntimeConfig\s*:\s*\{/),
    'publicRuntimeConfig is shipped to the browser')
  add('productionBrowserSourceMaps', at(/productionBrowserSourceMaps\s*:\s*true/),
    'source maps published to production')
  add('ignoreBuildErrors', at(/ignoreBuildErrors\s*:\s*true/),
    'TypeScript errors suppressed at build time')
  add('ignoreDuringBuilds', at(/ignoreDuringBuilds\s*:\s*true/),
    'ESLint suppressed at build time')
  add('remotePatternsWildcard', at(/hostname\s*:\s*['"]\*\*?['"]/),
    'image remotePatterns allows any host')
  const hasHeaders = /\bheaders\s*\(\s*\)/.test(code) || /\bheaders\s*:\s*async/.test(code)
  nextConfigFacts.push({ file: p, key: 'securityHeadersConfigured', present: hasHeaders })
}

// ---------- LLM surface ----------
//
// An LLM call site is a file that IMPORTS a provider SDK or CALLS one — not merely any file that
// mentions a provider's name. The earlier substring test matched `OPENAI_API_KEY`, so a t3-env
// schema declaring that variable was classified as a call site and then reported for having no
// rate limit. That is the recommended env pattern earning a finding, which is the exact failure
// mode this project exists to avoid: the tool punishing correct code teaches people to ignore it.
const LLM_PKGS = new Set(['openai', '@anthropic-ai/sdk', '@google/generative-ai', 'ai',
  'cohere-ai', 'replicate', '@mistralai/mistralai', 'groq-sdk', '@huggingface/inference'])
// A direct call into a provider API. Kept as an independent signal so a hand-rolled fetch client,
// which imports nothing, is still enumerated.
//
// TWO CLASSES, because they live in different places and only one of them is executable. Reading
// both off raw text — rejecting only COMMENT — is what made this detector cry wolf at its own
// project: it reported seven phantom call sites, `plugin/scripts/_scope.mjs` among them.
//
// A CALL EXPRESSION is code, so it is read from STRIPPED code. `openai.chat.completions.create(…)`
// inside a string is not a call, it is QUOTED SOURCE — a test fixture, a doc snippet, or this very
// file's own detection regex, since stripJs masks regex literals as STRING.
const LLM_CALL_RE = /(chat\.completions\.create|messages\.create|generateText|streamText|generateObject|streamObject|getGenerativeModel|embeddings\.create)/
// A provider ENDPOINT is a URL, and a URL lives inside the string literal that stripping blanks, so
// this class must be matched on RAW text. It requires a scheme or a path: `https://api.openai.com`
// and `api.openai.com/v1/…` are a host being CALLED. A BARE hostname is a host being NAMED, and the
// difference is the whole finding — `_scope.mjs` lists `api.openai.com` in DEFAULT_BLOCKED, the
// providers the live-probe gate refuses to touch. Being on a refuse-to-touch list is the opposite
// of being called, and reporting that as an ungoverned LLM call site is the precise failure this
// project exists to avoid.
const LLM_HOST = '(?:api\\.(?:openai|anthropic)\\.com|generativelanguage\\.googleapis\\.com)'
const LLM_HOST_RE = new RegExp(`https?://${LLM_HOST}|${LLM_HOST}/\\w`)

const llmSites = []
for (const [r, f] of files) {
  const importsProvider = [...(bareImports.get(r) || [])]
    .some(p => LLM_PKGS.has(p) || p.startsWith('@ai-sdk/'))
  const { code, mask } = stripJs(f.text)
  // Template-literal `${…}` expressions survive stripping as code, so an interpolated call still
  // counts. The endpoint pass rejects a COMMENT hit, so a commented-out URL invents nothing.
  let llmCall = LLM_CALL_RE.test(code)
  if (!llmCall) {
    const re = new RegExp(LLM_HOST_RE.source, 'g'); let m
    while ((m = re.exec(f.text))) { if (mask[m.index] !== COMMENT) { llmCall = true; break } }
  }
  if (!importsProvider && !llmCall) continue
  llmSites.push({
    file: r,
    clientReachable: clientReachable.has(r),
    serverReachable: serverReachable.has(r),
    browserFlag: /dangerouslyAllowBrowser\s*:\s*true/.test(code),
    hasMaxTokens: /max_tokens|maxTokens|maxOutputTokens/.test(code),
    hasRateLimit: RATE_HINT.test(code),
    hasAuth: AUTH_HINT.test(code),
    // User input reaching the prompt, via template interpolation OR string concatenation, case-
    // insensitive. The concat form (`'…' + req.body.x`) defeated the template-only regex — an
    // adversarial-audit bypass of the only prompt-injection detector.
    buildsPromptFromInput:
      /\$\{[^}]*(req\.body|req\.query|message|input|prompt|user(?:Message|Input)|query)[^}]*\}/i.test(code)
      || /(req\.body|req\.query|user(?:Message|Input))\s*(?:\.\w+)?\s*\+|\+\s*(req\.body|req\.query|user(?:Message|Input))/i.test(code),
    // Tools passed by explicit key `tools:`, object shorthand `tools,` / `tools }`, or a call form.
    definesTools: /\btools\s*[:,}]|\btool\(|function_call|functionDeclarations|toolChoice/.test(code),
  })
}

// ---------- mobile / desktop / infra presence ----------
const artifacts = {
  androidManifest: allPaths.filter(p => /AndroidManifest\.xml$/.test(p)),
  infoPlist: allPaths.filter(p => /Info\.plist$/.test(p)),
  dockerfiles: allPaths.filter(p => /(^|\/)Dockerfile(\.|$)/i.test(p)),
  compose: allPaths.filter(p => /docker-compose.*\.ya?ml$/i.test(p)),
  terraform: allPaths.filter(p => /\.tf$/.test(p)),
  workflows: allPaths.filter(p => /^\.github\/workflows\/.*\.ya?ml$/.test(p)),
  firebaseRules: allPaths.filter(p => /(firestore|database|storage)\.rules$|\.rules\.json$/.test(p)),
  // Matched on STRIPPED code, not raw text. `BrowserWindow` appearing inside a string or a regex
  // literal is a file that MENTIONS Electron — a detector, a doc example, a test fixture — not one
  // that configures a window. Reading raw text here made this engine detect ITSELF as an Electron
  // app, which then produced a confidently wrong coverage row.
  electronMain: [...files.keys()].filter(r => {
    const { code } = stripJs(files.get(r).text)
    return /\bnew\s+BrowserWindow\b|\bwebPreferences\s*:/.test(code)
  }),
  migrations: sqlFiles,
  envFiles,
  lockfiles: allPaths.filter(p => /(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|requirements\.txt)$/.test(p)),
  // Source and build config the code parser cannot read: CODE_EXT has no `.kt`, `.java`, `.swift`,
  // `.m`, `.dart`, so these files landed in `discovery.counts.unsupported` with no artifact class
  // and no declaration. An app whose live Stripe key, WebView bridge, plaintext token store and
  // token-logging all live in MainActivity.kt and AppDelegate.swift rendered as `findings: []`,
  // `verdict: clean`, `ungradedSurfaces: 0` — a report that reads as examined-and-clean. Listed as
  // CLASSES so grade-or-declare can file one honest row each instead of staying silent.
  nativeSource: {
    kotlinJava: allPaths.filter(p => /\.(kt|kts|java)$/.test(p) && !/\.gradle\.kts$/.test(p)),
    swiftObjc: allPaths.filter(p => /\.(swift|m|mm)$/.test(p)),
    dart: allPaths.filter(p => /\.dart$/.test(p)),
    // String resources are where an Android app's hardcoded API keys actually live.
    androidResValues: allPaths.filter(p => /(^|\/)res\/values(-[^/]+)?\/[^/]+\.xml$/.test(p)),
    // Signing passwords and release config. `gradle.properties` is the classic committed-secret
    // location on Android, and no secret-name rule is shaped to find it.
    gradleConfig: allPaths.filter(p => /(^|\/)(build|settings)\.gradle(\.kts)?$|(^|\/)gradle\.properties$/.test(p)),
  },
}

// ---------- mobile manifests ----------
//
// WHY THIS EXISTS: until now the engine recorded mobile only as a list of file PATHS, so no rule
// could grade anything on a phone app and the coverage ledger had no mobile subject set at all.
// That meant the whole mobile domain fell outside the completeness guarantee — the report could
// say "everything accounted for" while never having opened a manifest.
//
// It also cost severity. A reviewer reading a manifest can only ever produce `judgement` evidence,
// which caps at `likely` and can never reach the verdict. But `android:debuggable="true"` in a
// shipped app is not a judgement call: it is a flag with one meaning, and it belongs at
// `definitive` like any other compiler-guaranteed fact.
//
// These are attribute reads on XML/plist text, not a full parser. Each records its own line so the
// finding can point at it exactly.
function lineOf(text, index) { return text.slice(0, index).split(/\r?\n/).length }

// Blank XML comments, preserving every byte offset (and therefore every line number) so lineOf()
// stays exact. A commented-out flag that still matched would misreport the manifest — the same
// class of bug that once made a commented-out `enable row level security` read as enabled.
const blankXmlComments = t => t.replace(/<!--[\s\S]*?-->/g, m => m.replace(/[^\n]/g, ' '))

/**
 * Tokenise one element's attribute list.
 *
 * Every attribute read here used to be its own regex with a hardcoded `"`. Single quotes are
 * equally legal XML, and a single-quoted manifest therefore read as EVERY FLAG NULL and ZERO
 * components — `verdict: clean` on an app declaring `android:debuggable='true'`. Tokenising once
 * also stops one attribute's regex from matching inside another attribute's VALUE, and gives each
 * attribute its own offset so a finding can point at the attribute rather than the element.
 */
function parseXmlAttrs(src, base = 0) {
  const out = new Map()
  const re = /([A-Za-z_][\w.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g
  let m
  while ((m = re.exec(src))) {
    if (out.has(m[1])) continue
    out.set(m[1], { value: m[2] !== undefined ? m[2] : m[3], index: base + m.index })
  }
  return out
}

// An element's opening tag, with its attribute VALUES consumed properly.
//
// The old window was `[^>]*`, which ended at the first `>` in the text. Two defects followed, and
// they pull in opposite directions:
//   - Only `<` and `&` must be escaped in an XML attribute value, so `android:label="Settings >
//     Advanced"` is legal and truncated the window — `android:exported` fell outside it and the
//     element was DROPPED (a miss).
//   - The window stopped at the element's own `>`, so its CHILDREN were structurally invisible. No
//     rule could tell a MAIN/LAUNCHER entry point from an internal component, which is why the
//     launcher activity of every Android app that exists was reported as an exposed component.
const XML_ELEMENT_OPEN = /<([A-Za-z][\w.-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g

const COMPONENT_KINDS = new Set(['activity', 'activity-alias', 'service', 'receiver', 'provider'])
const LAUNCHER_CATEGORIES = new Set([
  'android.intent.category.LAUNCHER',
  'android.intent.category.LEANBACK_LAUNCHER',
  'android.intent.category.CAR_LAUNCHER',
])

/** Read one element's body: '' when self-closing, else the text up to its matching close tag. */
function elementBody(code, tag, attrsText, endOfOpenTag) {
  if (/\/\s*$/.test(attrsText)) return ''
  const close = code.toLowerCase().indexOf(`</${tag.toLowerCase()}`, endOfOpenTag)
  return close === -1 ? code.slice(endOfOpenTag) : code.slice(endOfOpenTag, close)
}

/** Every `<intent-filter>` inside a component body, with its actions, categories and data. */
function parseIntentFilters(body, base) {
  const filters = []
  const re = /<intent-filter\b((?:[^>"']|"[^"]*"|'[^']*')*)>([\s\S]*?)<\/intent-filter\s*>/gi
  let m
  while ((m = re.exec(body))) {
    const own = parseXmlAttrs(m[1])
    const inner = m[2]
    const names = tag => [...inner.matchAll(new RegExp(`<${tag}\\b((?:[^>"']|"[^"]*"|'[^']*')*)>`, 'gi'))]
      .map(x => parseXmlAttrs(x[1]).get('android:name')?.value).filter(Boolean)
    const data = [...inner.matchAll(/<data\b((?:[^>"']|"[^"]*"|'[^']*')*)>/gi)].map(x => {
      const a = parseXmlAttrs(x[1])
      return {
        scheme: a.get('android:scheme')?.value ?? null,
        host: a.get('android:host')?.value ?? null,
        path: a.get('android:path')?.value ?? a.get('android:pathPrefix')?.value ?? a.get('android:pathPattern')?.value ?? null,
      }
    })
    filters.push({
      line: lineOf(body, m.index) + base - 1,
      autoVerify: own.get('android:autoVerify')?.value === 'true',
      actions: names('action'),
      categories: names('category'),
      data: data.filter(d => d.scheme || d.host),
    })
  }
  return filters
}

/**
 * Resolve `@xml/name` to the resource file it names, so the file can actually be READ.
 *
 * The grader used to credit the mere PRESENCE of `android:networkSecurityConfig` with scoping
 * cleartext and print a `pass` over it — LAW 1 exactly: a checkmark bought by a token. The file it
 * pointed at was never in `artifacts`, never opened, never declared, and could permit cleartext to
 * every host AND trust any CA the phone's owner installs.
 */
function resolveXmlResource(manifestPath, ref) {
  const m = /^@xml\/([\w.]+)$/.exec(String(ref || ''))
  if (!m) return null
  const re = new RegExp(`(^|/)res/xml(-[^/]+)?/${m[1].replace(/\./g, '\\.')}\\.xml$`)
  const candidates = allPaths.filter(p => re.test(p))
  if (!candidates.length) return null
  // Prefer a file in the manifest's own source set; a library module may define the same name.
  const base = manifestPath.replace(/AndroidManifest\.xml$/, '')
  return candidates.find(p => p.startsWith(base)) || candidates[0]
}

/** Facts about a `res/xml/network_security_config.xml`. What any of them is worth is the grader's. */
function readNetworkSecurityConfig(p) {
  const text = readParsedConfig(p)
  if (text == null) return { file: p, readable: false }
  const code = blankXmlComments(text)
  // `<debug-overrides>` applies ONLY to a build with android:debuggable set, so a user trust anchor
  // inside it is deliberate and is not a release exposure. Blank the block (offsets preserved)
  // before reading the release configuration, or the correct pattern would be reported.
  const hasDebugOverrides = /<debug-overrides\b/i.test(code)
  const release = code.replace(/<debug-overrides\b[\s\S]*?<\/debug-overrides\s*>/gi, m => m.replace(/[^\n]/g, ' '))

  const configAt = (tag, wantCleartext) => {
    const re = new RegExp(`<${tag}\\b((?:[^>"']|"[^"]*"|'[^']*')*)>`, 'gi')
    const hits = []
    let m
    while ((m = re.exec(release))) {
      const a = parseXmlAttrs(m[1])
      const v = a.get('cleartextTrafficPermitted')?.value
      if (wantCleartext && v !== 'true') continue
      const body = elementBody(release, tag, m[1], m.index + m[0].length)
      hits.push({
        line: lineOf(release, m.index),
        cleartextTrafficPermitted: v ?? null,
        domains: [...body.matchAll(/<domain\b((?:[^>"']|"[^"]*"|'[^']*')*)>([^<]*)</gi)].map(d => d[2].trim()).filter(Boolean),
      })
    }
    return hits
  }

  // A `user` trust anchor means the app trusts any CA the phone's owner installs — which is every
  // intercepting proxy on earth, and defeats HTTPS without any of the traffic looking wrong.
  const userAnchor = /<certificates\b(?:[^>"']|"[^"]*"|'[^']*')*src\s*=\s*(?:"user"|'user')/i.exec(release)

  return {
    file: p,
    readable: true,
    hasDebugOverrides,
    baseCleartext: configAt('base-config', true)[0] || null,
    domainCleartext: configAt('domain-config', true),
    trustsUserCas: userAnchor ? { line: lineOf(release, userAnchor.index) } : null,
  }
}

const androidManifests = []
const networkSecurityConfigs = []
const seenNsc = new Set()
for (const p of artifacts.androidManifest) {
  const text = readParsedConfig(p); if (text == null) continue
  const code = blankXmlComments(text)

  // Which Gradle source set this manifest belongs to. `src/debug`, `src/androidTest`, `src/test`
  // and `src/benchmark` are NOT compiled into a release build — and the stock `npx react-native
  // init` output ships `src/debug/AndroidManifest.xml` with `usesCleartextTraffic="true"` so Metro
  // works. Grading those as if they shipped put a confirmed P1/P2 and a `high`/`medium` verdict on
  // a verbatim framework template. The path is the fact; which sets ship is the grader's call.
  const sourceSet = (/(^|\/)src\/([^/]+)\//.exec(p) || [, , null])[2]

  // The release flags live on `<application>`. Scanning the whole file for them could pick a value
  // out of an unrelated element.
  let appAttrs = new Map()
  {
    XML_ELEMENT_OPEN.lastIndex = 0
    let m
    while ((m = XML_ELEMENT_OPEN.exec(code))) {
      if (m[1].toLowerCase() !== 'application') continue
      appAttrs = parseXmlAttrs(m[2], m.index)
      break
    }
  }
  // A manifest value may be a resource reference (`@bool/cleartext`, `${placeholder}`) resolved per
  // build variant. That is a normal pattern and it is NOT `false` — reading it as absent printed a
  // `pass` note saying no cleartext was declared, over a manifest that declares it conditionally.
  const flag = name => {
    const a = appAttrs.get('android:' + name)
    if (!a) return null
    const literal = /^(true|false)$/i.test(a.value)
    return {
      value: literal ? a.value.toLowerCase() : a.value,
      line: lineOf(code, a.index),
      resolved: literal,
    }
  }
  const strAttr = name => {
    const a = appAttrs.get('android:' + name)
    return a ? { value: a.value, line: lineOf(code, a.index) } : null
  }

  // Permissions this manifest DECLARES (not the ones it requests). A component "guarded" by a
  // permission whose protectionLevel is `normal` is not guarded at all: Android grants normal
  // permissions to any app at install with no prompt.
  const declaredPermissions = []
  const usesPermissions = []
  let targetSdkVersion = null
  XML_ELEMENT_OPEN.lastIndex = 0
  {
    let m
    while ((m = XML_ELEMENT_OPEN.exec(code))) {
      const tag = m[1].toLowerCase()
      const a = parseXmlAttrs(m[2], m.index)
      if (tag === 'permission') {
        declaredPermissions.push({
          name: a.get('android:name')?.value ?? null,
          // Android's own default when the attribute is omitted.
          protectionLevel: a.get('android:protectionLevel')?.value ?? 'normal',
          line: lineOf(code, m.index),
        })
      } else if (tag === 'uses-permission' || tag === 'uses-permission-sdk-23') {
        const n = a.get('android:name')?.value
        if (n) usesPermissions.push({ name: n, line: lineOf(code, m.index) })
      } else if (tag === 'uses-sdk') {
        targetSdkVersion = a.get('android:targetSdkVersion')?.value ?? targetSdkVersion
      }
    }
  }

  // Every component another app on the device can reach. `exported` without a permission is the
  // mobile equivalent of an unauthenticated route — but a MAIN/LAUNCHER activity is exported
  // because the platform requires it to be, and telling a user to set `exported="false"` there
  // makes their app unlaunchable.
  const exported = []
  XML_ELEMENT_OPEN.lastIndex = 0
  {
    let m
    while ((m = XML_ELEMENT_OPEN.exec(code))) {
      const kind = m[1].toLowerCase()
      if (!COMPONENT_KINDS.has(kind)) continue
      const attrs = parseXmlAttrs(m[2], m.index)
      const openEnd = m.index + m[0].length
      const filters = parseIntentFilters(
        elementBody(code, kind, m[2], openEnd), lineOf(code, openEnd))

      const exportedAttr = attrs.get('android:exported')?.value ?? null
      const exportState =
        exportedAttr == null ? (filters.length ? 'default-exported' : 'not-exported')
          : /^true$/i.test(exportedAttr) ? 'exported'
            : /^false$/i.test(exportedAttr) ? 'not-exported'
              : 'unresolved'
      if (exportState === 'not-exported') continue

      // An EMPTY permission value satisfied the old `android:permission\s*=` presence test, so
      // `android:permission=""` bought a structural `pass` while enforcing nothing.
      const permission = ['android:permission', 'android:readPermission', 'android:writePermission']
        .map(k => attrs.get(k)?.value).find(v => v != null && v.trim() !== '') ?? null

      exported.push({
        kind,
        name: attrs.get('android:name')?.value ?? '(unnamed)',
        line: lineOf(code, m.index),
        exportState,
        exportedAttr,
        permission,
        hasPermission: permission != null,
        // MAIN + LAUNCHER is the home-screen entry point. The platform requires it to be exported.
        isLauncher: filters.some(f =>
          f.actions.includes('android.intent.action.MAIN') &&
          f.categories.some(c => LAUNCHER_CATEGORIES.has(c))),
        intentFilters: filters.length,
        // `checks/android.md` documents a P1 for deep-link / intent redirection. There was no model
        // field for it at all, so the check could not exist and nothing declared its absence.
        deepLinks: filters.flatMap(f => f.data.map(d => ({
          scheme: d.scheme, host: d.host, path: d.path, autoVerify: f.autoVerify, line: f.line,
        }))),
      })
    }
  }

  const nscRef = strAttr('networkSecurityConfig')
  const nscFile = nscRef ? resolveXmlResource(p, nscRef.value) : null
  if (nscFile && !seenNsc.has(nscFile)) {
    seenNsc.add(nscFile)
    networkSecurityConfigs.push({ ...readNetworkSecurityConfig(nscFile), sourceSet })
  }

  androidManifests.push({
    file: p,
    sourceSet,
    targetSdkVersion,
    debuggable: flag('debuggable'),
    allowBackup: flag('allowBackup'),
    usesCleartextTraffic: flag('usesCleartextTraffic'),
    networkSecurityConfig: nscRef,
    // Null when the attribute is absent, and null WITH a reference present when `@xml/name` names
    // no file in this repo — two different states the grader must not conflate.
    networkSecurityConfigFile: nscFile,
    // Either of these scopes the backup set. `allowBackup="true"` is the platform DEFAULT, so
    // reporting it flat is reporting boilerplate; what matters is what the backup set contains.
    dataExtractionRules: strAttr('dataExtractionRules'),
    fullBackupContent: strAttr('fullBackupContent'),
    declaredPermissions,
    usesPermissions,
    exportedComponents: exported,
  })
}

const iosPlists = []
for (const p of artifacts.infoPlist) {
  const text = readParsedConfig(p); if (text == null) continue
  // A BINARY plist (`bplist00`) is what Xcode writes for several target types and what ships
  // inside an IPA. The textual `<key>X</key><true/>` reader finds nothing in one, which read as
  // "ATS is at the secure platform default" and printed a `pass` — a checkmark bought by the file
  // being unreadable, which is the worst possible reason to print one.
  const format = /^bplist\d/.test(text) ? 'binary'
    : /<\s*plist\b|<\?xml/i.test(text) ? 'xml' : 'unknown'
  if (format !== 'xml') {
    iosPlists.push({
      file: p, format,
      allowsArbitraryLoads: null, allowsArbitraryLoadsInWebContent: null,
      allowsArbitraryLoadsForMedia: null, allowsLocalNetworking: null,
      hasAtsBlock: false, hasExceptionDomains: false, insecureHttpExceptions: 0, urlSchemes: [],
    })
    continue
  }
  const code = blankXmlComments(text)
  // In a plist, `<key>X</key><true/>` is the shape. Match the key and the value that follows it.
  const boolKey = name => {
    const m = new RegExp(`<key>\\s*${name}\\s*</key>\\s*<(true|false)\\s*/>`, 'i').exec(code)
    return m ? { value: m[1] === 'true', line: lineOf(code, m.index) } : null
  }
  // A custom URL scheme is claimable by any other app on the device, so a handler that acts on its
  // parameters is an unauthenticated entry point (`checks/ios.md`, P1). No model field existed.
  const urlSchemes = []
  for (const sm of code.matchAll(/<key>\s*CFBundleURLSchemes\s*<\/key>\s*<array>([\s\S]*?)<\/array>/gi)) {
    for (const s of sm[1].matchAll(/<string>\s*([^<]*?)\s*<\/string>/g)) if (s[1]) urlSchemes.push(s[1])
  }
  iosPlists.push({
    file: p,
    format,
    // ATS off globally means the app will talk plaintext HTTP to anywhere.
    allowsArbitraryLoads: boolKey('NSAllowsArbitraryLoads'),
    allowsArbitraryLoadsInWebContent: boolKey('NSAllowsArbitraryLoadsInWebContent'),
    // On iOS 10+ the presence of ANY of these makes NSAllowsArbitraryLoads inert, so they are the
    // difference between "ATS is off everywhere" and "ATS is off in one narrow place".
    allowsArbitraryLoadsForMedia: boolKey('NSAllowsArbitraryLoadsForMedia'),
    allowsLocalNetworking: boolKey('NSAllowsLocalNetworking'),
    hasAtsBlock: /<key>\s*NSAppTransportSecurity\s*<\/key>/i.test(code),
    // Domain-scoped exceptions are the correct way to allow one legacy host.
    hasExceptionDomains: /<key>\s*NSExceptionDomains\s*<\/key>/i.test(code),
    insecureHttpExceptions:
      [...code.matchAll(/<key>\s*NSExceptionAllowsInsecureHTTPLoads\s*<\/key>\s*<true\s*\/>/gi)].length,
    urlSchemes,
  })
}

// A mobile framework declared in the project with ZERO manifests and ZERO plists enumerated. This
// is the MODAL shape for this audience: a managed Expo app has no `android/` or `ios/` directory
// at all until `expo prebuild`, so every mobile subject set reported a confident 0 — which the
// report renders as `mobileArtifacts | 0 | 0 | 0 | 0 | 0`, indistinguishable from "there is no
// mobile surface here". Same precedent, same fix as `discovery.routes.frameworkGaps`.
const mobileFrameworkGaps = []
if (!androidManifests.length && !iosPlists.length) {
  const declared = [
    ['expo', framework.expo, 'package.json', 'app.json / app.config.js (`expo.android`, `expo.ios.infoPlist`, `expo.scheme`, `expo.*.permissions`)'],
    ['react-native', framework.reactNative, 'package.json', 'the native projects this app generates'],
    ['flutter', framework.flutter, 'pubspec.yaml', 'the `android/` and `ios/` projects this app generates'],
    ['capacitor', framework.capacitor, 'package.json', 'capacitor.config.* and the native projects it generates'],
    ['cordova', framework.cordova, 'package.json', 'config.xml and the native projects it generates'],
  ].filter(([, v]) => v)
  for (const [name, , declaredIn, where] of declared) {
    mobileFrameworkGaps.push({
      framework: name,
      declaredIn,
      reason: `${name} is declared in ${declaredIn} but no AndroidManifest.xml or Info.plist was enumerated — the mobile configuration lives in ${where}, which the static tier does not grade; review it against checks/android.md and checks/ios.md`,
    })
  }
}

// ---------- CI/CD workflows ----------
//
// AUDIT FIX C, and the same defect as mobile before it: `artifacts.workflows` was a list of PATHS.
// Nothing graded them and no ledger set covered them, so a workflow that hands repo secrets to a
// forked pull request rendered as a clean report. Discovering a file and never reading it is
// indistinguishable, in the output, from the file not existing.
//
// These are FACTS — which trigger is declared, whether a ref is a SHA, where an expression is
// interpolated. What any of it is worth lives in the grader.
//
// The `${{ }}` fields an attacker can write into. GitHub's own hardening guidance singles these
// out: interpolating one into a `run:` shell is command injection with no exploit chain, because
// the expression is substituted BEFORE the shell ever sees it. Deliberately an allowlist and not
// a broad `github.event.*` match — `github.event.pull_request.number` is an integer nobody can
// inject through, and flagging it would be the kind of noise that gets a whole report ignored.
const INJECTABLE_CONTEXT = new RegExp([
  'github\\.event\\.issue\\.(title|body)',
  'github\\.event\\.pull_request\\.(title|body)',
  'github\\.event\\.pull_request\\.head\\.(ref|label)',
  'github\\.event\\.pull_request\\.head\\.repo\\.default_branch',
  'github\\.event\\.(comment|review|review_comment)\\.body',
  'github\\.event\\.discussion\\.(title|body)',
  'github\\.event\\.(head_commit|commits\\[[^\\]]*\\])\\.(message|author\\.(name|email))',
  'github\\.event\\.workflow_run\\.(head_branch|head_commit\\.message)',
  'github\\.event\\.pages\\[[^\\]]*\\]\\.page_name',
  'github\\.head_ref',
].join('|'))

// A ref an attacker controls the contents of. Checking one out under `pull_request_target` is the
// single most dangerous pattern in GitHub Actions.
const UNTRUSTED_REF = /github\.event\.pull_request\.(head\.(sha|ref)|merge_commit_sha)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch)/

// Orgs whose action tags we do NOT report as unpinned. Not because a tag is immutable there — it
// is not — but because the realistic supply-chain attack is a compromised third-party maintainer
// (the tj-actions/changed-files incident is exactly this shape), and flagging `actions/checkout@v4`
// in every repo on earth would bury the one line that matters under one that never does.
const FIRST_PARTY_ACTION_ORGS = new Set(['actions', 'github', 'docker'])

const ciWorkflows = []
for (const p of artifacts.workflows) {
  const raw = readParsedConfig(p); if (raw == null) continue
  const { code } = stripHash(raw)
  const lines = code.split(/\r?\n/)
  const indentOf = ln => { const m = /^(\s*)/.exec(ln); return m[1].length }

  // Triggers. All three YAML spellings: `on: push`, `on: [a, b]`, and a nested block. The key is
  // often written `"on":` or `'on':` because YAML 1.1 reads a bare `on` as the boolean true, and
  // missing those spellings would make a pull_request_target workflow look like it has no trigger
  // at all — which is the difference between a P0 and silence.
  const triggers = new Set()
  for (let i = 0; i < lines.length; i++) {
    const m = /^['"]?on['"]?\s*:\s*(.*)$/.exec(lines[i])
    if (!m) continue
    const inline = m[1].trim()
    if (inline && inline !== '|' && inline !== '>') {
      for (const t of inline.replace(/[[\]]/g, '').split(',')) if (t.trim()) triggers.add(t.trim())
    }
    // Nested block. Only keys at the block's OWN indent are triggers — a deeper key is a trigger's
    // option (`types:`, `branches:`), and collecting those would put `types` in the trigger list.
    // The indent is read from the first child rather than assumed, so 2- and 4-space files both work.
    let childIndent = null
    for (let j = i + 1; j < lines.length; j++) {
      if (!lines[j].trim()) continue
      const ind = indentOf(lines[j])
      if (ind === 0) break
      if (childIndent === null) childIndent = ind
      if (ind !== childIndent) continue
      const tm = /^\s*([a-z_]+)\s*:/.exec(lines[j])
      if (tm) triggers.add(tm[1])
    }
    break
  }

  // Job boundaries, so a step can be attributed to the job it is actually in. Without this, a
  // harmless `run:` in a LATER job counted as execution of an earlier job's untrusted checkout —
  // which would upgrade that finding's evidence from strong to definitive, and a definitive P0 is
  // what turns the badge red. A wrong confirmed is the one error this project cannot afford.
  const jobs = []
  {
    const jobsLine = lines.findIndex(l => /^jobs\s*:/.test(l))
    if (jobsLine !== -1) {
      let jobIndent = null
      for (let i = jobsLine + 1; i < lines.length; i++) {
        if (!lines[i].trim()) continue
        const ind = indentOf(lines[i])
        if (ind === 0) break
        if (jobIndent === null) jobIndent = ind
        if (ind !== jobIndent || !/^\s*[\w-]+\s*:/.test(lines[i])) continue
        if (jobs.length) jobs[jobs.length - 1].end = i
        jobs.push({ start: i + 1, end: lines.length })
      }
    }
  }
  /** The 1-based line range of the job containing `line`, or the whole file if none is found. */
  const jobRangeOf = line => jobs.find(j => line >= j.start && line <= j.end) || { start: 1, end: lines.length }

  // `run:` blocks, with their body, so an interpolation can be attributed to a shell rather than to
  // a `with:` input (where it is a string, not code).
  const runBlocks = []
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)(?:-\s+)?run\s*:\s*(.*)$/.exec(lines[i])
    if (!m) continue
    const keyIndent = lines[i].indexOf('run:')
    let body = m[2].replace(/^[|>][-+\d]*\s*$/, '')
    let end = i
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() && lines[j].indexOf(lines[j].trim()) <= keyIndent) break
      body += '\n' + lines[j]
      end = j
    }
    runBlocks.push({ startLine: i + 1, body })
    i = end
  }

  const scriptInjections = []
  for (const b of runBlocks) {
    const re = /\$\{\{\s*([^}]+?)\s*\}\}/g
    let m
    while ((m = re.exec(b.body))) {
      if (INJECTABLE_CONTEXT.test(m[1])) {
        scriptInjections.push({
          line: b.startLine + b.body.slice(0, m.index).split('\n').length - 1,
          expr: m[1].trim(),
        })
      }
    }
  }
  const secretsInRunScript = runBlocks
    .filter(b => /\$\{\{\s*secrets\./.test(b.body))
    .map(b => ({ line: b.startLine }))

  // Actions used, and whether each is pinned to a full commit SHA.
  const usesSteps = []
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*(?:-\s+)?uses\s*:\s*['"]?([^'"\s]+)['"]?/.exec(lines[i])
    if (!m) continue
    const spec = m[1]
    if (spec.startsWith('./') || spec.startsWith('docker://')) continue // local / image, not a tag
    const at = spec.lastIndexOf('@')
    const ref = at === -1 ? null : spec.slice(at + 1)
    const name = at === -1 ? spec : spec.slice(0, at)
    usesSteps.push({
      line: i + 1, action: name, ref,
      pinnedToSha: !!ref && /^[0-9a-f]{40}$/i.test(ref),
      firstParty: FIRST_PARTY_ACTION_ORGS.has(name.split('/')[0]),
    })
  }

  // Checkout of an attacker-controlled ref, and whether anything runs afterwards. A checkout alone
  // writes files; a `run:` after it is what executes them — and `npm ci` alone is enough, because
  // an install script in the PR's package.json runs at that moment.
  let untrustedCheckout = null
  for (let i = 0; i < lines.length; i++) {
    if (!/uses\s*:\s*['"]?actions\/checkout/.test(lines[i])) continue
    // Read to the end of THIS step, not a fixed number of lines. A `ref:` belonging to the next
    // step would otherwise be attributed to the checkout and manufacture a P0 — the same
    // window-bleed defect the SQL parser was rewritten to eliminate, in a different format.
    const stepIndent = lines[i].indexOf('-') >= 0 && /^\s*-\s/.test(lines[i])
      ? lines[i].indexOf('-') : lines[i].search(/\S/)
    let ref = null
    for (let j = i + 1; j < lines.length; j++) {
      if (!lines[j].trim()) continue
      const ind = lines[j].search(/\S/)
      if (ind <= stepIndent) break // next step, or the end of the steps list
      const rm = /\bref\s*:\s*(.+)/.exec(lines[j])
      if (rm) { ref = rm[1].trim(); break }
    }
    if (ref && UNTRUSTED_REF.test(ref)) { untrustedCheckout = { line: i + 1, ref }; break }
  }
  // Scoped to the job the checkout is in — a `run:` in a different job never touches this job's
  // working copy, so counting it would manufacture the stronger claim.
  const executesAfterCheckout = !!untrustedCheckout && (() => {
    const { end } = jobRangeOf(untrustedCheckout.line)
    const after = x => x > untrustedCheckout.line && x <= end
    return runBlocks.some(b => after(b.startLine)) ||
      usesSteps.some(u => after(u.line) && !/^actions\/(checkout|setup-|cache)/.test(u.action))
  })()

  const selfHostedLine = lines.findIndex(l => /runs-on\s*:.*self-hosted/.test(l))

  ciWorkflows.push({
    file: p,
    triggers: [...triggers],
    // A workflow with no `permissions:` block inherits a repo/org default that is NOT readable from
    // the repo — it may be read-all or write-all. That ambiguity is the grader's to express.
    declaresPermissions: lines.some(l => /^permissions\s*:/.test(l)),
    declaresJobPermissions: lines.some(l => /^\s+permissions\s*:/.test(l)),
    untrustedCheckout,
    executesAfterCheckout,
    scriptInjections,
    secretsInRunScript,
    unpinnedActions: usesSteps.filter(u => !u.pinnedToSha),
    actionsTotal: usesSteps.length,
    selfHosted: selfHostedLine === -1 ? null : { line: selfHostedLine + 1 },
  })
}

// ---------- infrastructure as code ----------
//
// Same defect class, same fix. A Dockerfile with a baked credential, a compose file mounting the
// Docker socket, or a Terraform security group open to the world were all discovered and none was
// read.
//
// A value assigned in a committed file is a VALUE match, which is what LAW 3 requires before
// severity may go high — but only if it is a real value. Placeholders and variable references are
// the whole content of a well-written template, so mistaking one for a secret would fire on exactly
// the files that are done right.
const PLACEHOLDER_VALUE = /^(?:changeme|change_me|your[-_ ]?\w*|xxx+|<[^>]*>|\.\.\.|todo|example|placeholder|secret|password|test|dummy|\$\{[^}]*\}|\$\w+|""|'')$/i
function looksLikeRealSecretValue(v) {
  const s = String(v).trim().replace(/^['"]|['"]$/g, '')
  if (s.length < 12) return false
  if (PLACEHOLDER_VALUE.test(s)) return false
  if (/^\$|\{\{|\$\{/.test(s)) return false // interpolated from a real secret store
  return true
}

const iac = { dockerfiles: [], compose: [], terraform: [] }

for (const p of artifacts.dockerfiles) {
  const raw = readParsedConfig(p); if (raw == null) continue
  const { code } = stripHash(raw)
  const lines = code.split(/\r?\n/)
  const bakedSecrets = []
  let setsUser = null, baseImage = null, remoteScript = null
  lines.forEach((ln, i) => {
    let m
    if ((m = /^\s*FROM\s+(\S+)/i.exec(ln)) && !baseImage) {
      const ref = m[1]
      baseImage = {
        line: i + 1, ref,
        // A digest is immutable; a tag is not, and `latest` is not even stable across a rebuild.
        pinned: /@sha256:[0-9a-f]{64}/i.test(ref),
        latest: /:latest$/i.test(ref) || !/[:@]/.test(ref.replace(/^[^/]*\//, '')),
      }
    }
    // A numeric-or-named USER that is not root. `USER root` is not a mitigation.
    if ((m = /^\s*USER\s+(\S+)/i.exec(ln)) && !/^(root|0)$/i.test(m[1])) setsUser = { line: i + 1, user: m[1] }
    if ((m = /^\s*(ENV|ARG)\s+([A-Z0-9_]+)\s*[= ]\s*(.+)$/i.exec(ln))) {
      const name = m[2], value = m[3].trim()
      const cls = classifySecretName(name)
      if ((cls === 'high' || cls === 'weak') && looksLikeRealSecretValue(value)) {
        bakedSecrets.push({ line: i + 1, name, secretClass: cls, directive: m[1].toUpperCase() })
      }
    }
    if (/^\s*RUN\b/i.test(ln) && /(curl|wget)[^|]*\|\s*(sudo\s+)?(ba)?sh/i.test(ln) && !remoteScript) {
      remoteScript = { line: i + 1 }
    }
  })
  iac.dockerfiles.push({ file: p, baseImage, setsUser, bakedSecrets, remoteScript })
}

for (const p of artifacts.compose) {
  const raw = readParsedConfig(p); if (raw == null) continue
  const { code } = stripHash(raw)
  const lines = code.split(/\r?\n/)
  const at = re => { const i = lines.findIndex(l => re.test(l)); return i === -1 ? null : { line: i + 1 } }
  // A published port binds 0.0.0.0 by default. For a database that means the internet, on a host
  // with no firewall — which is how an unauthenticated Redis or Mongo ends up in a ransom note.
  const DB_PORTS = { 5432: 'postgres', 3306: 'mysql', 27017: 'mongodb', 6379: 'redis', 9200: 'elasticsearch', 5984: 'couchdb', 11211: 'memcached', 1433: 'mssql' }
  const exposedDbPorts = []
  const bakedSecrets = []
  lines.forEach((ln, i) => {
    let m
    if ((m = /^\s*-\s*['"]?(?:(\d{1,3}(?:\.\d{1,3}){3}):)?(\d{2,5}):(\d{2,5})['"]?\s*$/.exec(ln))) {
      const host = m[1] || '0.0.0.0'
      const container = Number(m[3])
      if (DB_PORTS[container] && host !== '127.0.0.1' && host !== 'localhost') {
        exposedDbPorts.push({ line: i + 1, port: container, service: DB_PORTS[container], bind: host })
      }
    }
    if ((m = /^\s*-?\s*([A-Z0-9_]+)\s*[:=]\s*(.+)$/.exec(ln))) {
      const cls = classifySecretName(m[1])
      if ((cls === 'high' || cls === 'weak') && looksLikeRealSecretValue(m[2])) {
        bakedSecrets.push({ line: i + 1, name: m[1], secretClass: cls })
      }
    }
  })
  iac.compose.push({
    file: p,
    privileged: at(/privileged\s*:\s*true/),
    dockerSocket: at(/\/var\/run\/docker\.sock/),
    hostNetwork: at(/network_mode\s*:\s*['"]?host/),
    exposedDbPorts,
    bakedSecrets,
  })
}

for (const p of artifacts.terraform) {
  const raw = readParsedConfig(p); if (raw == null) continue
  const { code } = stripHash(raw)
  const lineAt = idx => code.slice(0, idx).split(/\r?\n/).length

  // The innermost `{ ... }` block containing an offset. Used instead of a fixed look-ahead window
  // for the same reason the SQL parser reads whole statements: a window bleeds one resource's
  // attributes into its neighbour, and that produced a confident false P0 in the audit.
  //
  // Returns the block body AND its header — the text before the opening brace. The header is what
  // names the block (`egress {`), and it lives OUTSIDE the braces, so a body-only slice cannot tell
  // an ingress rule from an egress one.
  const enclosingBlock = idx => {
    let depth = 0, start = -1
    for (let i = idx; i >= 0; i--) {
      if (code[i] === '}') depth++
      else if (code[i] === '{') { if (depth === 0) { start = i; break } depth-- }
    }
    if (start === -1) return { body: code.slice(Math.max(0, idx - 200), idx + 200), header: '' }
    const header = code.slice(Math.max(0, start - 80), start)
    let d = 0
    for (let i = start; i < code.length; i++) {
      if (code[i] === '{') d++
      else if (code[i] === '}') { d--; if (d === 0) return { body: code.slice(start, i + 1), header } }
    }
    return { body: code.slice(start), header }
  }

  const openIngress = []
  {
    const re = /['"]0\.0\.0\.0\/0['"]/g
    let m
    while ((m = re.exec(code))) {
      const { body, header } = enclosingBlock(m.index)
      // Outbound traffic to the world is normal and near-universal; inbound is the exposure.
      // Written two ways in HCL: a nested `egress { … }` block, whose name is in the HEADER, and
      // `aws_security_group_rule` with `type = "egress"`, which is inside the body.
      if (/\begress\s*$|\begress\s*\{/.test(header.trimEnd()) || /\btype\s*=\s*"egress"/.test(body)) continue
      const from = Number((/from_port\s*=\s*(\d+)/.exec(body) || [, NaN])[1])
      const to = Number((/to_port\s*=\s*(\d+)/.exec(body) || [, NaN])[1])
      // Public HTTP/HTTPS is what a web server is FOR. Only a wider range is a finding.
      const webOnly = Number.isFinite(from) && Number.isFinite(to) &&
        ((from === 80 && to === 80) || (from === 443 && to === 443) || (from === 80 && to === 443))
      if (webOnly) continue
      openIngress.push({
        line: lineAt(m.index),
        portRange: Number.isFinite(from) ? `${from}-${to}` : 'unspecified',
      })
    }
  }
  const at = re => { const m = re.exec(code); return m ? { line: lineAt(m.index), match: m[0].slice(0, 60) } : null }
  const literalSecrets = []
  {
    const re = /^\s*([a-z0-9_]*(?:password|secret|token|private_key|access_key)[a-z0-9_]*)\s*=\s*(.+)$/gim
    let m
    while ((m = re.exec(code))) {
      const value = m[2].trim()
      if (!/^['"]/.test(value)) continue // a variable/reference, which is the correct pattern
      if (looksLikeRealSecretValue(value)) literalSecrets.push({ line: lineAt(m.index), name: m[1] })
    }
  }
  iac.terraform.push({
    file: p,
    openIngress,
    publicAcl: at(/acl\s*=\s*['"]public-read(-write)?['"]/),
    publiclyAccessible: at(/publicly_accessible\s*=\s*true/),
    literalSecrets,
  })
}

// Kubernetes manifests. DETECTED but not parsed — identified by content rather than by path,
// because `deploy/app.yaml` and `k8s/prod/web.yml` are equally common and neither name is reliable.
// They are deliberately NOT recorded as parsed: the engine has no rules for them, and the point of
// finding them is to DECLARE the gap in the coverage ledger rather than to let a repository whose
// entire deployment lives in Kubernetes read as fully examined.
const k8sManifests = []
for (const p of allPaths) {
  if (!/\.ya?ml$/i.test(p)) continue
  if (artifacts.workflows.includes(p) || artifacts.compose.includes(p)) continue
  let head
  try { head = readFileSync(join(ROOT, p), 'utf8').slice(0, 2000) } catch { continue }
  if (/^apiVersion\s*:/m.test(head) && /^kind\s*:/m.test(head)) k8sManifests.push(p)
}

// State files hold every attribute of every resource IN PLAINTEXT, including generated passwords
// and private keys. Committing one is a credential leak that no secret scanner rule is shaped to
// catch, because the value has no recognisable prefix.
const terraformState = allPaths.filter(p => /\.tfstate(\.backup)?$/.test(p))

// ---------- Firebase security rules ----------
//
// The Supabase half of this audience gets RLS grading; the Firebase half got nothing. `allow read,
// write: if true` is the exact Firebase equivalent of RLS disabled — the whole database readable
// and writable by anyone with the config object that ships in every client bundle by design.
const firebaseRules = []
for (const p of artifacts.firebaseRules) {
  const raw = readParsedConfig(p); if (raw == null) continue
  if (/\.json$/i.test(p)) {
    // Realtime Database rules are JSON: `".read": true` grants the whole subtree.
    const open = []
    const re = /"\.(read|write)"\s*:\s*(true|"auth != null"|"true")/g
    let m
    while ((m = re.exec(raw))) {
      open.push({ line: raw.slice(0, m.index).split(/\r?\n/).length, op: m[1], value: m[2] })
    }
    firebaseRules.push({ file: p, dialect: 'rtdb-json', openRules: open.filter(o => o.value !== '"auth != null"'), authOnlyRules: open.filter(o => o.value === '"auth != null"') })
    continue
  }
  // Firestore / Storage rules language. Comments use `//`, which stripHash blanks.
  const { code } = stripHash(raw)
  const openRules = [], authOnlyRules = []
  const re = /allow\s+([a-z, ]+?)\s*(?::\s*if\s+([^;{]+))?;/gi
  let m
  while ((m = re.exec(code))) {
    const ops = m[1].split(',').map(s => s.trim()).filter(Boolean)
    const cond = (m[2] || 'true').trim()
    const line = code.slice(0, m.index).split(/\r?\n/).length
    if (/^true$/i.test(cond)) openRules.push({ line, ops, condition: cond })
    // `if request.auth != null` means ANY signed-in user, including one who just self-registered.
    // Not open to the world, but not owner-scoped either — the cross-tenant case.
    else if (/^request\.auth\s*!=\s*null$/i.test(cond)) authOnlyRules.push({ line, ops, condition: cond })
  }
  firebaseRules.push({ file: p, dialect: /storage/i.test(p) ? 'storage' : 'firestore', openRules, authOnlyRules })
}

// ---------- finish the discovery ledger ----------
//
// The counts above cover files. These cover the higher-level subjects, and — critically — where
// the engine MODELLED a subject but only partially: a route whose HTTP methods it could not read,
// an import it could not resolve, a `.from(x)` it could not follow. Those are not failures to
// enumerate (they ARE enumerated), but they are failures to fully MODEL, and hiding them would let
// a partial analysis pass for a complete one.
const routeLikeFiles = allPaths.filter(p =>
  /^pages\/api\//.test(p) ||
  /^(app|src\/app)\/.*\/route\.(t|j)sx?$/.test(p) ||
  /^(supabase\/functions|netlify\/functions|api)\/.*\.(t|j)sx?$/.test(p))
const thirdPartyPkgs = new Set()
for (const set of bareImports.values()) for (const p of set) thirdPartyPkgs.add(p)
let importEdges = 0
for (const set of imports.values()) importEdges += set.size

discovery.routes = {
  // Every route-kind FILE becomes a modeled route, so found === modeled by construction for the
  // file-routed frameworks; the real signal is how many we could only PARTIALLY model.
  foundByFilesystem: routeLikeFiles.length,
  modeled: routes.length,
  withUnknownMethods: routes.filter(r => r.methods.length === 1 && r.methods[0] === 'UNKNOWN').length,
  // Call-declared routes (Express/Fastify/Hono/Koa/Nest) are counted separately because they are
  // found by reading calls, not by listing files — so there is no filesystem number to compare
  // them against, and a zero here on a repo that depends on such a framework is a coverage hole
  // rather than a fact. That case is what `frameworkGaps` states out loud.
  fromFrameworkCalls: routes.filter(r => r.routeKey).length,
  // Two kinds of gap, one channel, because the consequence is identical: a route count of 0 that
  // means "we looked nowhere" rather than "there is nothing". The first kind is a JS server
  // framework whose routes this pass could not follow; the second is a backend written in a
  // language the parser does not read at all. Both are `undeterminable` rows under
  // `ungradedSurfaces`, never findings. The two name spaces cannot collide — the first is keyed on
  // SERVER_FRAMEWORKS' npm names, the second on language names — and LAW 2 throws if that ever
  // stops being true, which is the guard we want.
  frameworkGaps: [...routeFrameworkGaps, ...nonJsBackendGaps],
}
discovery.mobile = {
  androidManifests: androidManifests.length,
  iosPlists: iosPlists.length,
  networkSecurityConfigs: networkSecurityConfigs.length,
  frameworkGaps: mobileFrameworkGaps,
}
discovery.imports = {
  edgesResolvedToFiles: importEdges,
  thirdPartyPackages: thirdPartyPkgs.size,
  unresolvedWorkspaceImports: unresolvedWorkspaceImports.length,
  // Non-literal table refs behind a generic CRUD helper: enumerated as a hole, never followed.
  dynamicTableRefs: dynamicTableRefs.length,
}
discovery.schema = {
  sources: schemaSources,
  tablesEnumerated: tables.size,
  // The single most consequential discovery fact for a Supabase app: if this is false, RLS state
  // was NOT discoverable from the repo at all, and every RLS pass/fail is really "unknown".
  rlsVerifiable: schemaSources.includes('migrations'),
}
// The ledger must add up, or it is lying: everything discovered is either parsed, unsupported,
// oversized, or a read error. Asserted here so a future change to the collect loop that forgets to
// count a branch fails loudly instead of silently under-reporting.
{
  const c = discovery.counts
  // Move every file a dedicated parser actually read out of `unsupported`. Only paths that were
  // counted there in the first place move — a next.config.js is source and is already in
  // filesParsed, so counting it again would break the equation in the other direction.
  for (const p of configParsedPaths) {
    if (!files.has(p)) { c.configParsed++; c.unsupported-- }
  }
  const accounted = c.filesParsed + c.configParsed + c.unsupported + c.oversized + c.readErrors
  discovery.reconciles = accounted === c.filesDiscovered
  if (!discovery.reconciles) {
    discovery.discrepancy = `filesDiscovered=${c.filesDiscovered} but parsed+configParsed+unsupported+oversized+readErrors=${accounted}`
  }
}

const model = {
  root: ROOT.split(sep).join('/'),
  generatedBy: 'claudeguard/project_model',
  counts: {
    filesTotal: allPaths.length, codeFiles: files.size,
    clientReachable: clientReachable.size, serverReachable: serverReachable.size,
    routes: routes.length, tables: tables.size, envVars: envVars.length, llmSites: llmSites.length,
  },
  framework, artifacts,
  // DISCOVERY coverage — a first-class output, and a DIFFERENT axis from the grader's analysis
  // coverage. This says what the engine could and could not SEE; the grader's ledger says how it
  // GRADED what it saw. A report that shows only analysis coverage can look complete while the
  // engine silently skipped half the repo. See core/methodology/discovery.md.
  discovery,
  // Coverage is a first-class output: what we could NOT analyze must be as visible as what we
  // could, or a clean report reads as "safe" when it is really "unexamined".
  graphCoverage: {
    workspacePackages: [...workspacePackages].map(([name, dir]) => ({ name, dir })),
    unresolvedWorkspaceImports,
    barrelCount: [...files.keys()].filter(isBarrelCached).length,
  },
  boundary: {
    clientSeeds: [...clientSeed].map(([f, why]) => ({ file: f, why })),
    serverSeeds: [...serverSeed].map(([f, why]) => ({ file: f, why })),
    clientReachable: [...clientReachable.keys()],
    clientReachableDetail: [...clientReachable].map(([file, i]) => ({ file, ...i })),
    barrels: [...files.keys()].filter(isBarrelCached),
    serverOnlyModules: [...files.keys()].filter(hasServerOnly),
  },
  envVars: envVars.sort((a, b) => a.name.localeCompare(b.name)),
  routes,
  middleware: { files: middlewareFiles, providesAuth: middlewareAuth, matchers: middlewareMatcher },
  database: {
    // parserVersion 2 = SQL is comment/string-stripped before matching. Consumers MUST refuse to
    // trust `rlsEnabled === true` from parserVersion < 2: v1 matched commented-out statements and
    // could report RLS as on when it was off.
    parserVersion: 2,
    coverage: schemaCoverage,
    schemaSources,
    tables: [...tables.values()],
    functions: sqlFunctions,
    tablesUsedInCodeOnly: [...tablesUsedInCode.keys()].filter(t => !tables.has(t))
      .map(t => ({ table: t, usedIn: tablesUsedInCode.get(t) })),
  },
  supabaseClients,
  envGuards,
  nextConfig: nextConfigFacts,
  llmSites,
  mobile: { android: androidManifests, ios: iosPlists, networkSecurityConfigs },
  // Audit fix C: three artifact classes the engine used to discover and never read. Each is now a
  // graded subject set, so silence about them is no longer indistinguishable from safety.
  ci: ciWorkflows,
  iac: { ...iac, stateFiles: terraformState, k8sManifests },
  firebaseRules,
  limits: [
    'Heuristic parsing (regex + import resolution), not a type-aware AST. May miss dynamic requires, re-exports through barrels, and monorepo aliases.',
    'Client/server classification is decisive for public env prefixes and "use client" chains; other cases are reported as weaker signals.',
    'Database model reflects migrations in the repo, not the live database. Applied state is the ground truth.',
  ],
}

console.log(JSON.stringify(model, null, 2))
