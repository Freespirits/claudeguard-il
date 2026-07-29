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
import { stripSql, stripJs } from './lib/strip_comments.mjs'

const ROOT = resolve(process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : '.')

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', 'coverage',
  'vendor', '.venv', '__pycache__', '.turbo', '.cache', 'android/build', 'ios/Pods'])
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

function* walk(dir) {
  let entries
  try { entries = readdirSync(dir, { withFileTypes: true }) } catch { return }
  for (const e of entries) {
    const full = join(dir, e.name)
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue
      if (e.name.startsWith('.') && e.name !== '.github') continue
      yield* walk(full)
    } else if (e.isFile()) yield full
  }
}

const rel = p => relative(ROOT, p).split(sep).join('/')

// ---------- collect files ----------
const files = new Map() // rel -> record
const allPaths = []
for (const abs of walk(ROOT)) {
  const r = rel(abs)
  allPaths.push(r)
  const ext = extname(abs).toLowerCase()
  if (!CODE_EXT.has(ext)) continue
  let size = 0
  try { size = statSync(abs).size } catch { continue }
  if (size > MAX_FILE) continue
  let text
  try { text = readFileSync(abs, 'utf8') } catch { continue }
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
  let m
  IMPORT_RE.lastIndex = 0
  while ((m = IMPORT_RE.exec(f.text))) {
    const spec = m[1] || m[2] || m[3]
    if (!spec) continue
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
// `import 'server-only'` makes a client import a BUILD ERROR, so a chain through it cannot exist.
function hasServerOnly(rel) {
  const f = files.get(rel)
  return !!f && /['"]server-only['"]/.test(f.text)
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
  let text; try { text = readFileSync(join(ROOT, p), 'utf8') } catch { continue }
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

const routes = []
for (const [r, f] of files) {
  const kind = /^pages\/api\//.test(r) ? 'pages-api'
    : /^(app|src\/app)\/.*\/route\.(t|j)sx?$/.test(r) ? 'app-route'
      : /^(supabase\/functions|netlify\/functions|api)\//.test(r) ? 'serverless-fn' : null
  if (!kind) continue
  const methods = new Set(); let m; METHOD_RE.lastIndex = 0
  while ((m = METHOD_RE.exec(f.text))) methods.add(m[1] || m[2])
  const mutating = [...methods].some(x => x !== 'GET') || methods.size === 0
  routes.push({
    file: r, kind,
    methods: [...methods].length ? [...methods] : ['UNKNOWN'],
    mutating,
    hasAuthCheck: AUTH_HINT.test(f.text),
    hasRateLimit: RATE_HINT.test(f.text),
    hasValidation: VALIDATE_HINT.test(f.text),
    usesServiceRole: /SERVICE_ROLE|service_role/.test(f.text),
    readsIdParam: /(params|query)\s*[.\[]\s*['"]?\w*id/i.test(f.text) || /\[\w*id\w*\]/i.test(r),
    // Whether the handler consumes a request body at all. Without this, "no schema validation"
    // fires on handlers that take no input, which is noise on correct code — and noise is what
    // makes people stop reading the report.
    readsBody: /\breq(uest)?\.json\s*\(|\breq(uest)?\.body\b|\.formData\s*\(|await\s+\w+\.json\s*\(/.test(f.text),
    ownershipFilter: /(user_id|userId|owner_id|ownerId|auth\.uid\(\)|session\.user\.id|user\.id)/.test(f.text),
  })
}
// middleware-based auth (a route may be protected centrally — avoids false "no auth")
const middlewareFiles = [...files.keys()].filter(r => /(^|\/)middleware\.(t|j)s$/.test(r))
const middlewareAuth = middlewareFiles.some(r => AUTH_HINT.test(files.get(r).text))
const middlewareMatcher = middlewareFiles.map(r => {
  const mm = /matcher\s*:\s*\[([^\]]+)\]|matcher\s*:\s*['"]([^'"]+)['"]/.exec(files.get(r).text)
  return { file: r, matcher: mm ? (mm[1] || mm[2]).replace(/\s+/g, ' ').trim() : null }
})

// ---------- database model (Supabase/Postgres migrations) ----------
const sqlFiles = allPaths.filter(p => /\.sql$/i.test(p))
const tables = new Map()
const sqlFunctions = []
for (const p of sqlFiles) {
  let raw; try { raw = readFileSync(join(ROOT, p), 'utf8') } catch { continue }

  // CRITICAL: never match against raw SQL. A commented-out
  //   -- alter table public.orders enable row level security;
  // previously made this report RLS as ENABLED on an unprotected table — a false negative
  // that hid a P0. stripSql blanks comments/strings while preserving every offset and line
  // number, so `file:line` evidence stays exact.
  const { code: text, dollarBodies } = stripSql(raw)
  const lines = text.split(/\r?\n/)

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
        bodyChecksAuth: body ? /auth\.uid\(\)|auth\.jwt\(\)/i.test(body.text) : null,
      })
    }
  }

  lines.forEach((ln, i) => {
    let m
    if ((m = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:(\w+)\.)?["']?(\w+)["']?/i.exec(ln))) {
      const schema = (m[1] || 'public').toLowerCase(), name = m[2].toLowerCase()
      if (schema !== 'public') return
      if (!tables.has(name)) tables.set(name, { name, definedIn: `${p}:${i + 1}`, rlsEnabled: false, rlsAt: null, policies: [] })
    }
    if ((m = /alter\s+table\s+(?:(\w+)\.)?["']?(\w+)["']?\s+enable\s+row\s+level\s+security/i.exec(ln))) {
      const name = m[2].toLowerCase()
      const t = tables.get(name) || { name, definedIn: null, rlsEnabled: false, rlsAt: null, policies: [] }
      t.rlsEnabled = true; t.rlsAt = `${p}:${i + 1}`; tables.set(name, t)
    }
    if ((m = /create\s+policy\s+["']?([^"'\n]+?)["']?\s+on\s+(?:(\w+)\.)?["']?(\w+)["']?/i.exec(ln))) {
      const name = m[3].toLowerCase()
      const t = tables.get(name) || { name, definedIn: null, rlsEnabled: false, rlsAt: null, policies: [] }
      // look ahead a few lines for the command + predicate
      const ctx = lines.slice(i, i + 6).join(' ')
      const cmd = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(ctx) || [, 'all'])[1].toLowerCase()
      t.policies.push({
        name: m[1].trim(), cmd, at: `${p}:${i + 1}`,
        permissive: /using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(ctx),
        scopedToUid: /auth\.uid\(\)/i.test(ctx),
      })
      tables.set(name, t)
    }
  })
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
for (const [r, f] of files) {
  let m; TABLE_REF_RE.lastIndex = 0
  while ((m = TABLE_REF_RE.exec(f.text))) {
    const t = m[1].toLowerCase()
    if (!tablesUsedInCode.has(t)) tablesUsedInCode.set(t, [])
    tablesUsedInCode.get(t).push(r)
  }
  DYNAMIC_TABLE_REF_RE.lastIndex = 0
  while ((m = DYNAMIC_TABLE_REF_RE.exec(f.text))) {
    const line = f.text.slice(0, m.index).split(/\r?\n/).length
    dynamicTableRefs.push({ file: r, line, expr: m[1] })
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
  let text; try { text = readFileSync(join(ROOT, p), 'utf8') } catch { continue }
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
  let text; try { text = readFileSync(join(ROOT, p), 'utf8') } catch { continue }
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
const supabaseClients = []
for (const [r, f] of files) {
  for (const [fn, identity] of SUPABASE_FACTORIES) {
    const re = new RegExp(`\\b${fn}\\s*[(<]`, 'g')
    let m
    while ((m = re.exec(f.text))) {
      supabaseClients.push({
        file: r,
        line: f.text.slice(0, m.index).split(/\r?\n/).length,
        factory: fn,
        identity,
        // RLS is the correct control for this identity; IDOR must never be `confirmed` here.
        rlsIsTheControl: true,
      })
    }
  }
  // Plain createClient(url, KEY) — identity depends entirely on WHICH key.
  const re = /\bcreateClient\s*(?:<[^>]*>)?\s*\(([^)]{0,400})\)/gs
  let m
  while ((m = re.exec(f.text))) {
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
  let raw; try { raw = readFileSync(join(ROOT, p), 'utf8') } catch { continue }
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
const LLM_CALL_RE = /(chat\.completions\.create|messages\.create|generateText|streamText|generateObject|streamObject|getGenerativeModel|embeddings\.create|api\.(?:openai|anthropic)\.com|generativelanguage\.googleapis\.com)/

const llmSites = []
for (const [r, f] of files) {
  const importsProvider = [...(bareImports.get(r) || [])]
    .some(p => LLM_PKGS.has(p) || p.startsWith('@ai-sdk/'))
  if (!importsProvider && !LLM_CALL_RE.test(f.text)) continue
  llmSites.push({
    file: r,
    clientReachable: clientReachable.has(r),
    serverReachable: serverReachable.has(r),
    browserFlag: /dangerouslyAllowBrowser\s*:\s*true/.test(f.text),
    hasMaxTokens: /max_tokens|maxTokens|maxOutputTokens/.test(f.text),
    hasRateLimit: RATE_HINT.test(f.text),
    hasAuth: AUTH_HINT.test(f.text),
    buildsPromptFromInput: /`[^`]*\$\{[^}]*(req\.body|req\.query|message|input|prompt|userMessage|query)[^}]*\}[^`]*`/.test(f.text),
    definesTools: /(tools\s*:|tool\(|function_call|functionDeclarations|toolChoice)/.test(f.text),
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
  electronMain: [...files.keys()].filter(r => /BrowserWindow|webPreferences/.test(files.get(r).text)),
  migrations: sqlFiles,
  envFiles,
  lockfiles: allPaths.filter(p => /(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|requirements\.txt)$/.test(p)),
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

const androidManifests = []
for (const p of artifacts.androidManifest) {
  let text; try { text = readFileSync(join(ROOT, p), 'utf8') } catch { continue }
  // Blank XML comments first. A commented-out permission that still matched would misreport the
  // manifest, which is the same class of bug that once made a commented-out `enable row level
  // security` read as enabled.
  const code = text.replace(/<!--[\s\S]*?-->/g, m => m.replace(/[^\n]/g, ' '))
  const attr = re => { const m = re.exec(code); return m ? { value: m[1], line: lineOf(code, m.index) } : null }

  // Every component that is reachable by another app on the device. `exported` without a
  // permission is the mobile equivalent of an unauthenticated route.
  const exported = []
  const COMPONENT_RE = /<(activity|activity-alias|service|receiver|provider)\b([^>]*)>/gi
  let cm
  while ((cm = COMPONENT_RE.exec(code))) {
    const [, kind, attrs] = cm
    const isExported = /android:exported\s*=\s*"true"/i.test(attrs)
    if (!isExported) continue
    const nameM = /android:name\s*=\s*"([^"]+)"/i.exec(attrs)
    exported.push({
      kind,
      name: nameM ? nameM[1] : '(unnamed)',
      line: lineOf(code, cm.index),
      // A permission-guarded export is a deliberate, controlled interface.
      hasPermission: /android:(permission|readPermission|writePermission)\s*=/i.test(attrs),
    })
  }

  androidManifests.push({
    file: p,
    debuggable: attr(/android:debuggable\s*=\s*"(true|false)"/i),
    allowBackup: attr(/android:allowBackup\s*=\s*"(true|false)"/i),
    usesCleartextTraffic: attr(/android:usesCleartextTraffic\s*=\s*"(true|false)"/i),
    // Its PRESENCE is what matters: a network security config is how cleartext gets scoped to
    // named domains instead of allowed globally.
    networkSecurityConfig: attr(/android:networkSecurityConfig\s*=\s*"([^"]+)"/i),
    exportedComponents: exported,
  })
}

const iosPlists = []
for (const p of artifacts.infoPlist) {
  let text; try { text = readFileSync(join(ROOT, p), 'utf8') } catch { continue }
  const code = text.replace(/<!--[\s\S]*?-->/g, m => m.replace(/[^\n]/g, ' '))
  // In a plist, `<key>X</key><true/>` is the shape. Match the key and the value that follows it.
  const boolKey = name => {
    const m = new RegExp(`<key>\\s*${name}\\s*</key>\\s*<(true|false)\\s*/>`, 'i').exec(code)
    return m ? { value: m[1] === 'true', line: lineOf(code, m.index) } : null
  }
  iosPlists.push({
    file: p,
    // ATS off globally means the app will talk plaintext HTTP to anywhere.
    allowsArbitraryLoads: boolKey('NSAllowsArbitraryLoads'),
    allowsArbitraryLoadsInWebContent: boolKey('NSAllowsArbitraryLoadsInWebContent'),
    hasAtsBlock: /<key>\s*NSAppTransportSecurity\s*<\/key>/i.test(code),
    // Domain-scoped exceptions are the correct way to allow one legacy host.
    hasExceptionDomains: /<key>\s*NSExceptionDomains\s*<\/key>/i.test(code),
  })
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
  mobile: { android: androidManifests, ios: iosPlists },
  limits: [
    'Heuristic parsing (regex + import resolution), not a type-aware AST. May miss dynamic requires, re-exports through barrels, and monorepo aliases.',
    'Client/server classification is decisive for public env prefixes and "use client" chains; other cases are reported as weaker signals.',
    'Database model reflects migrations in the repo, not the live database. Applied state is the ground truth.',
  ],
}

console.log(JSON.stringify(model, null, 2))
