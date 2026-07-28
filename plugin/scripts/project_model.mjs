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
import { stripSql } from './lib/strip_comments.mjs'

const ROOT = resolve(process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : '.')

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', 'coverage',
  'vendor', '.venv', '__pycache__', '.turbo', '.cache', 'android/build', 'ios/Pods'])
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.svelte', '.vue'])
const MAX_FILE = 1.5 * 1024 * 1024

// Env prefixes that a bundler inlines into client output — definitive public exposure.
const PUBLIC_PREFIXES = ['NEXT_PUBLIC_', 'VITE_', 'PUBLIC_', 'EXPO_PUBLIC_', 'REACT_APP_', 'GATSBY_', 'NUXT_PUBLIC_']

// Secret-name classification, TIERED on purpose (severity Law 3: a NAME alone may never justify
// a P0 — only a value, or a name from the small high-confidence set, may).
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
    if (!candidates.length) return null // bare package
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
    else if (!spec.startsWith('.')) bare.add(spec.split('/').slice(0, spec.startsWith('@') ? 2 : 1).join('/'))
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
// Anything imported (transitively) by a client module is in the client bundle.
function propagate(seed) {
  const out = new Map(seed)
  const q = [...seed.keys()]
  while (q.length) {
    const cur = q.shift()
    for (const dep of imports.get(cur) || []) {
      if (!out.has(dep)) { out.set(dep, `imported-by:${cur}`); q.push(dep) }
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
  envVars.push({
    name, publicPrefix, secretClass,
    // `secretish` retained for compatibility, but consumers should prefer secretClass:
    // only 'high' may drive a P0 from the name alone (severity Law 3).
    secretish: secretClass === 'high' || secretClass === 'weak',
    publicByDesign: secretClass === 'public-by-design',
    declared: envDeclared.get(name) || null,
    usages,
    clientReachableUsages: clientUses,
    // The two decisive exposure paths, kept separate so severity/confidence stay honest.
    exposure: publicPrefix ? 'bundler-inlined-public-prefix'
      : clientUses.length ? 'imported-into-client-bundle' : 'server-only',
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
// tables referenced from code (catches tables used but never seen in migrations)
const TABLE_REF_RE = /\.from\(\s*['"]([a-zA-Z0-9_]+)['"]\s*\)/g
const tablesUsedInCode = new Map()
for (const [r, f] of files) {
  let m; TABLE_REF_RE.lastIndex = 0
  while ((m = TABLE_REF_RE.exec(f.text))) {
    const t = m[1].toLowerCase()
    if (!tablesUsedInCode.has(t)) tablesUsedInCode.set(t, [])
    tablesUsedInCode.get(t).push(r)
  }
}

// ---------- LLM surface ----------
const llmSites = []
for (const [r, f] of files) {
  const isLLM = /(openai|anthropic|generative-ai|@ai-sdk|generateText|streamText|chat\.completions|messages\.create|getGenerativeModel)/i.test(f.text)
  if (!isLLM) continue
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

const model = {
  root: ROOT.split(sep).join('/'),
  generatedBy: 'claudeguard/project_model',
  counts: {
    filesTotal: allPaths.length, codeFiles: files.size,
    clientReachable: clientReachable.size, serverReachable: serverReachable.size,
    routes: routes.length, tables: tables.size, envVars: envVars.length, llmSites: llmSites.length,
  },
  framework, artifacts,
  boundary: {
    clientSeeds: [...clientSeed].map(([f, why]) => ({ file: f, why })),
    serverSeeds: [...serverSeed].map(([f, why]) => ({ file: f, why })),
    clientReachable: [...clientReachable.keys()],
  },
  envVars: envVars.sort((a, b) => a.name.localeCompare(b.name)),
  routes,
  middleware: { files: middlewareFiles, providesAuth: middlewareAuth, matchers: middlewareMatcher },
  database: {
    // parserVersion 2 = SQL is comment/string-stripped before matching. Consumers MUST refuse to
    // trust `rlsEnabled === true` from parserVersion < 2: v1 matched commented-out statements and
    // could report RLS as on when it was off.
    parserVersion: 2,
    schemaSources: sqlFiles.length ? ['migrations'] : [],
    tables: [...tables.values()],
    functions: sqlFunctions,
    tablesUsedInCodeOnly: [...tablesUsedInCode.keys()].filter(t => !tables.has(t))
      .map(t => ({ table: t, usedIn: tablesUsedInCode.get(t) })),
  },
  llmSites,
  limits: [
    'Heuristic parsing (regex + import resolution), not a type-aware AST. May miss dynamic requires, re-exports through barrels, and monorepo aliases.',
    'Client/server classification is decisive for public env prefixes and "use client" chains; other cases are reported as weaker signals.',
    'Database model reflects migrations in the repo, not the live database. Applied state is the ground truth.',
  ],
}

console.log(JSON.stringify(model, null, 2))
