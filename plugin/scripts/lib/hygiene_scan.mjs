// The "vibecoder hygiene" scanner — the cheap, high-signal grep checks the cross-model poll
// converged on (SYNTHESIS.md, "Genuinely new, worth building": placeholder secrets shipped in real
// code, btoa/atob used AS encryption, a bearer token parked in localStorage, and a TODO left sitting
// inside auth code). These are SECURITY-pillar FACTS, not compliance.
//
// Like a11y_scan.mjs this is a PURE, deterministic, side-effect-free ENGINE that EMITS FACTS — plain
// objects carrying a line number and the matched token — and NEVER a severity, confidence, or verdict.
// The grader owns all policy. Same text in, same facts out: no Date.now, no Math.random, no I/O, no
// shared mutable state (every /g regex is built fresh per call so a retained lastIndex can never make
// the second call disagree with the first).
//
// Each check anchors on a concrete SINK — a placeholder value, a base64 call, a storage write, a TODO
// marker — and inspects the immediate SOURCE around it. That sink-to-source shape is the no-AST,
// zero-FP compromise the reviewers endorsed. Every false-positive trap a check must survive is encoded
// as DATA (an exempt-path test, a word-level sensitivity set, a benign-attribute exclusion) and
// documented in a comment right beside the code that enforces it.
//
// Comment/string handling reuses the ONE shared stripper (strip_comments.mjs, stripJs). A placeholder
// or a marker written inside a `//` comment is a note, not shipped code, and must never fire. Where a
// check needs the VALUE that lives inside a string literal (a secret value, a storage key) it reads
// the RAW text but consults stripJs's parallel `mask` to reject comment regions — strings are in play
// (a secret value lives in one), comments are not. project_model.mjs is deliberately NOT imported: it
// runs whole-repo scan code at module load. The one FP guard worth copying — its PUBLIC_BY_DESIGN set
// — is mirrored below so this library respects "public by design" without pulling in that side effect.

import { stripJs, CODE, COMMENT } from './strip_comments.mjs'

// ---------------------------------------------------------------------------
// Shared, deterministic helpers
// ---------------------------------------------------------------------------

// Map a character offset to a 1-based line number via binary search over the line starts.
function lineIndexer(text) {
  const starts = [0]
  for (let k = 0; k < text.length; k++) if (text[k] === '\n') starts.push(k + 1)
  return idx => {
    let lo = 0, hi = starts.length - 1
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= idx) lo = mid; else hi = mid - 1 }
    return lo + 1
  }
}

// The raw source line containing `idx`, trimmed and length-capped — human-readable evidence only.
function snippetAt(text, idx, cap = 200) {
  let s = idx, e = idx
  while (s > 0 && text[s - 1] !== '\n') s--
  while (e < text.length && text[e] !== '\n' && text[e] !== '\r') e++
  return text.slice(s, e).trim().slice(0, cap)
}

// Split an identifier / key into lowercase word tokens, breaking BOTH camelCase and separators, so
// `accessToken` and `access_token` both become [access, token] while `author` stays [author]. This is
// what lets a check key on a WHOLE word ("token") without the substring "token" firing on "tokenizer"
// — the difference between a real finding and a cry-wolf.
function wordTokens(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
}

// ===========================================================================
// 1) PLACEHOLDER SECRETS — a clearly-FAKE secret VALUE shipped in real source.
//    scanPlaceholderSecrets(text, path) -> [{ at:{line}, kind:'placeholder-secret', token, snippet }]
// ===========================================================================

// FP TRAP #1 (path). Placeholders BELONG in these files, so the WHOLE file is exempt before a single
// value is read. `.env.example` is covered by the `.example` arm; docs, samples, templates, stories
// and every flavour of test/fixture are exactly where a `changeme` is correct, not a finding.
function isPlaceholderExemptPath(path) {
  const p = String(path || '').replace(/\\/g, '/')
  const base = p.slice(p.lastIndexOf('/') + 1).toLowerCase()
  const segs = base.split('.')     // config.sample.ts -> [config, sample, ts]; .env.example -> ['', env, example]
  // A sample/example/template/test/spec token as ANY dot segment — the convention is usually infix
  // (`config.example.ts`, `db.sample.js`, `next.config.template.mjs`) as well as suffix (`.env.example`).
  if (segs.some(s => /^(?:example|sample|dist|template|tmpl|mock|stub|test|spec|stories|fixture)$/.test(s))) return true
  // Docs / plaintext.
  if (/\.(?:md|mdx|markdown|rst|txt)$/.test(base)) return true
  if (/(?:^|\.)(?:readme|changelog|contributing|license|notice|authors)\b/.test(base)) return true
  // Test / fixture / mock / docs / examples DIRECTORIES anywhere on the path.
  if (/(?:^|\/)(?:__tests__|__mocks__|__fixtures__|tests?|fixtures?|mocks?|e2e|cypress|examples?|samples?|docs?|stories)(?:\/|$)/.test(p)) return true
  return false
}

// FP TRAP #2 (shape). A self-evident FAKE credential fires WITHOUT needing a secret-ish variable name,
// because the token itself IS a credential by shape or wording. A REAL key never matches — every arm
// is a constant run of x/0 or a literal "your-…-key" phrase, the opposite of a high-entropy secret.
// Returned fresh each call so the global lastIndex is never shared between invocations.
function selfEvidentSecretRes() {
  return [
    // Fake OpenAI-style key: sk- (optionally sk-proj-/sk-ant-/…) followed by an obviously fake run.
    /\bsk-(?:proj-|ant-|live-|test-)?(?:x{4,}|0{4,}|(?:x0){3,})\b/gi,
    // Fake GitHub token (ghp_/gho_/ghu_/ghs_/ghr_ or github_pat_) + a fake run.
    /\b(?:gh[opusr]_|github_pat_)(?:x{4,}|0{4,})\w*/gi,
    // Fake AWS access key id: AKIA/ASIA + a run of X or 0 (a real one is 16 mixed base32 chars).
    /\b(?:AKIA|ASIA)(?:X{6,}|0{6,}|(?:X0){4,})\b/g,
    // Fake Slack bot/user token.
    /\bxox[baprs]-(?:x{4,}|0{4,})\w*/gi,
    // Fake Google API key.
    /\bAIza(?:X{6,}|0{6,}|x{6,})\w*/g,
    // "your-…-key/secret/token": the possessive "your" makes it a fill-in placeholder, never real
    // code. The [-_] joins are REQUIRED so UI PROSE like the label "Enter your API key" (spaces, no
    // joins) can never match — that is copy, not a shipped secret.
    /\byour[-_](?:own[-_])?(?:api[-_]?key|apikey|api[-_]?secret|secret[-_]?key|secret|access[-_]?token|token|password|client[-_]?secret)(?:[-_]here)?\b/gi,
    // insert/paste/replace/…-…-here: the trailing "-here"/"goes-here" is the placeholder tell, so
    // `enterKey` / `hotkey` (no "-here") never match, but "insert-your-key-here" does.
    /\b(?:insert|paste|replace|put|add|enter|set|use)[-_](?:your[-_])?(?:api[-_]?key|apikey|secret|token|password|value|credentials?)?[-_]?(?:goes[-_])?here\b/gi,
  ]
}

// FP TRAP #3 (generic value + context). These GENERIC placeholder values are a finding ONLY when
// assigned to a secret-ish name — a bare `changeme`/`xxxxxxxx` in an ordinary string is not (that is
// the exact "a xxxx inside a non-secret string is not a finding" trap). Anchored `^…$` so it matches
// a WHOLE value, never a substring of a real one.
const GENERIC_PLACEHOLDER_VALUE = /^(?:change[-_]?me|change[-_]?this|changeit|replace[-_]?me|replace[-_]?this|fill[-_]?me[-_]?in|password123|passw0rd|admin123|secret123|letmein123?|test123|x{4,}|0{16,})$/i

// The word-level names a generic placeholder must be assigned to. Via wordTokens so `KEY`, `apiKey`,
// `DB_PASSWORD` qualify but `monkey` / `keyboard` (which merely contain "key") do NOT.
const SECRETISH_NAME_WORDS = new Set([
  'key', 'apikey', 'secret', 'secrets', 'token', 'tokens', 'password', 'passwd', 'pwd', 'passphrase',
  'credential', 'credentials', 'auth', 'bearer', 'dsn', 'salt',
])

// FP TRAP #4 (public by design). Mirrors project_model.mjs's PUBLIC_BY_DESIGN — "the single most
// important false-positive guard in the tool for this audience". A key that is publishable by design
// is never a leaked secret, so a placeholder under such a name is not worth a security fact either.
const PUBLIC_BY_DESIGN_LOCAL = /(?:SUPABASE_ANON_KEY|SUPABASE_URL|FIREBASE_API_KEY|FIREBASE_APP_ID|FIREBASE_PROJECT_ID|FIREBASE_AUTH_DOMAIN|FIREBASE_STORAGE_BUCKET|MESSAGING_SENDER_ID|MEASUREMENT_ID|SENTRY_DSN|POSTHOG_KEY|POSTHOG_HOST|STRIPE_PUBLISHABLE|PUBLISHABLE_KEY|MAPBOX|GOOGLE_MAPS|RECAPTCHA_SITE_KEY|PUSHER_APP_KEY|ALGOLIA_SEARCH_KEY|VAPID_PUBLIC)/i

function isSecretishName(name) {
  if (!name) return false
  if (PUBLIC_BY_DESIGN_LOCAL.test(name)) return false
  for (const t of wordTokens(name)) if (SECRETISH_NAME_WORDS.has(t)) return true
  return false
}

export function scanPlaceholderSecrets(text, path) {
  const facts = []
  if (isPlaceholderExemptPath(path)) return facts   // FP TRAP #1 — placeholders belong here
  const src = String(text)
  const { mask } = stripJs(src)
  const lineOf = lineIndexer(src)
  const seen = new Set()
  const add = (idx, token) => {
    const line = lineOf(idx)
    const dk = line + ' ' + token
    if (seen.has(dk)) return
    seen.add(dk)
    facts.push({ at: { line }, kind: 'placeholder-secret', token, snippet: snippetAt(src, idx) })
  }

  // Pass A — self-evident fake credentials (no name context needed). Comment regions are skipped: a
  // fake key pasted into a `//` note is not shipped code. Strings are IN play — a real fake key lives
  // in a string literal (`Authorization: 'Bearer sk-xxxx'`).
  for (const re of selfEvidentSecretRes()) {
    let m
    while ((m = re.exec(src))) {
      if (mask[m.index] === COMMENT) continue
      add(m.index, m[0])
    }
  }

  // Pass B — a generic placeholder value assigned to a secret-ish name. NAME [:=] "VALUE", with an
  // OPTIONAL quote around NAME so a JSON key (`"api-key": "changeme"`) matches as well as `KEY=`.
  const assign = /(['"`]?)([A-Za-z_$][\w.$-]*)\1\s*[:=]\s*(['"`])([^'"`\r\n]{1,160})\3/g
  let a
  while ((a = assign.exec(src))) {
    if (mask[a.index] === COMMENT) continue        // the assignment sits in a comment → not shipped
    const name = a[2], value = a[4].trim()
    if (!isSecretishName(name)) continue           // FP TRAP #3/#4 — require secret-ish, non-public name
    if (!GENERIC_PLACEHOLDER_VALUE.test(value)) continue
    add(a.index, value)
  }

  // Pass C — an env / shell style unquoted assignment (`API_KEY=changeme`), the .env-file shape. Same
  // secret-ish-name gate. Anchored to a line start so it never re-reads a JS `const X = …` (that line
  // starts with `const`, so NAME resolves to `const`, which fails, and Pass B owns it instead).
  const env = /(?:^|\n)[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(['"`]?)([^\s'"`#]{1,160})\2/g
  let e
  while ((e = env.exec(src))) {
    const idx = e.index + e[0].indexOf(e[1])
    if (mask[idx] === COMMENT) continue
    const name = e[1], value = e[3].trim()
    if (!isSecretishName(name)) continue
    if (!GENERIC_PLACEHOLDER_VALUE.test(value)) continue
    add(idx, value)
  }

  facts.sort((x, y) => x.at.line - y.at.line)      // stable V8 sort keeps per-line insertion order
  return facts
}

// ===========================================================================
// 2) FAKE CRYPTO — base64 (btoa/atob or Buffer…toString('base64')) used AS "encryption" for a secret.
//    scanFakeCrypto(text) -> [{ at:{line}, kind:'fake-crypto', snippet }]
// ===========================================================================

// The identifiers that make a base64 call SENSITIVE. Substring + case-insensitive, so camelCase
// (`userPassword`, `authToken`, `apiKey`) is covered. FP TRAP: with none of these in the argument OR
// the immediate context, the call is LEFT ALONE — btoa on an image data-URI, a URL param, or
// JSON.stringify(headers) has none of these words and therefore never fires.
const SENSITIVE_ID = /password|passwd|passphrase|\bpwd\b|secret|token|credential|api[_-]?key|apikey|private[_-]?key|access[_-]?key|client[_-]?secret|session[_-]?key|\bbearer\b|\bjwt\b/i

export function scanFakeCrypto(text) {
  const facts = []
  const src = String(text)
  const { mask } = stripJs(src)
  const lineOf = lineIndexer(src)
  const lines = src.split(/\r?\n/)
  const seen = new Set()
  const add = idx => {
    const line = lineOf(idx)
    if (seen.has(line)) return
    seen.add(line)
    facts.push({ at: { line }, kind: 'fake-crypto', snippet: snippetAt(src, idx) })
  }
  // Context = the call's own line plus the line above it, read from RAW text so a `// encrypt the
  // password` note or an `encryptedPassword =` assignment target still supplies the sensitive signal
  // even when the argument itself is a bare `data`.
  const contextHasSensitive = (arg, line) => {
    if (SENSITIVE_ID.test(arg)) return true
    return SENSITIVE_ID.test(lines[line - 1] || '') || SENSITIVE_ID.test(lines[line - 2] || '')
  }

  // btoa(...) / atob(...). Arg captured up to the first ')'; nesting truncation is harmless for a
  // presence test. Run on RAW text — the mask rejects a call that is itself inside a comment or a
  // string, so `"call btoa(password)"` and `// btoa(password)` do not fire.
  const b64 = /\b(?:window\.)?(btoa|atob)\s*\(([^)]*)\)/g
  let m
  while ((m = b64.exec(src))) {
    if (mask[m.index] !== CODE) continue
    if (contextHasSensitive(m[2] || '', lineOf(m.index))) add(m.index)
  }
  // Buffer.from(x).toString('base64'). The 'base64' literal is BLANKED in stripJs's `code`, so this
  // MUST run on RAW text; the mask still gates out a commented-out call.
  const buf = /\bBuffer\.from\s*\(([^)]*)\)\s*\.\s*toString\s*\(\s*(['"`])base64\2\s*\)/g
  while ((m = buf.exec(src))) {
    if (mask[m.index] !== CODE) continue
    if (contextHasSensitive(m[1] || '', lineOf(m.index))) add(m.index)
  }

  facts.sort((x, y) => x.at.line - y.at.line)
  return facts
}

// ===========================================================================
// 3) CLIENT TOKEN STORAGE — a bearer/auth/session credential written to local/sessionStorage.
//    scanClientTokenStorage(text) -> [{ at:{line}, kind:'client-token-storage', api, key, snippet }]
// ===========================================================================

// Word-level sensitive key tokens (checked against wordTokens(key)). "token" alone covers the whole
// `*_token` / `*Token` family (access_token, refreshToken, idToken), and "session"/"jwt"/"auth" cover
// the rest — so `access_token` fires while `lastAccess`, `accessibilityMode` and `author` (which only
// CONTAIN "access"/"auth" as substrings, not as words) do not. FP TRAP: theme/locale/lang/cache/
// sidebar/consent/visited carry NO sensitive word and fall out here with no explicit deny-list needed.
const STORAGE_SENSITIVE_WORDS = new Set([
  'token', 'tokens', 'auth', 'session', 'jwt', 'credential', 'credentials',
  'password', 'passwd', 'secret', 'bearer', 'apikey', 'oauth',
])

export function scanClientTokenStorage(text) {
  const facts = []
  const src = String(text)
  const { mask } = stripJs(src)
  const lineOf = lineIndexer(src)
  const seen = new Set()
  const apiOf = raw => raw.replace(/^window\./, '')
  const emit = (idx, api, key) => {
    const keyToks = wordTokens(key)
    if (!keyToks.some(t => STORAGE_SENSITIVE_WORDS.has(t))) return
    // FP TRAP: a csrf/xsrf token mirrored in web storage is the standard double-submit-cookie CSRF
    // defense, not a leaked bearer credential — skip unless the key literally says "bearer".
    if ((keyToks.includes('csrf') || keyToks.includes('xsrf')) && !keyToks.includes('bearer')) return
    const line = lineOf(idx)
    const dk = line + ' ' + api + ' ' + key
    if (seen.has(dk)) return
    seen.add(dk)
    facts.push({ at: { line }, kind: 'client-token-storage', api, key, snippet: snippetAt(src, idx) })
  }

  // localStorage.setItem('access_token', …) / sessionStorage.setItem("jwt", …). The KEY is a string
  // literal, so this runs on RAW text; the mask gates out a call written in a comment. A dynamic key
  // (`setItem(k, …)`) has no literal to read and is intentionally not matched — conservative, no FP.
  const setItem = /\b((?:window\.)?(?:local|session)Storage)\s*\.\s*setItem\s*\(\s*(['"`])([^'"`]*)\2/g
  let m
  while ((m = setItem.exec(src))) {
    if (mask[m.index] !== CODE) continue
    emit(m.index, apiOf(m[1]), m[3])
  }
  // localStorage.authToken = …  /  localStorage['refresh_token'] = …  (dotted or bracketed write).
  // `=(?!=)` so a comparison (`localStorage.x === y`) is not mistaken for a write.
  const propWrite = /\b((?:window\.)?(?:local|session)Storage)\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*(['"`])([^'"`]*)\3\s*\])\s*=(?!=)/g
  while ((m = propWrite.exec(src))) {
    if (mask[m.index] !== CODE) continue
    emit(m.index, apiOf(m[1]), m[2] != null ? m[2] : (m[4] || ''))
  }

  facts.sort((x, y) => x.at.line - y.at.line)
  return facts
}

// ===========================================================================
// 4) AUTH TODOs — a TODO/FIXME/HACK/XXX marker in a COMMENT within ~5 lines of an auth-ish token.
//    scanAuthTodos(text) -> [{ at:{line}, kind:'auth-todo', marker, snippet }]
// ===========================================================================

// Auth-context words, matched at WORD level via wordTokens over the ±5-line window (camelCase-aware:
// `handleLogin`->login, `authToken`->auth+token, `isAdmin`->admin, `getSession`->session). `role` is
// deliberately NOT in this set — see ROLE_RE — because a bare `role` collides with the ARIA/JSX
// attribute `role="button"`, a notorious false positive; RBAC `role` is recovered separately with an
// attribute-excluding pattern.
const AUTH_CONTEXT_WORDS = new Set([
  'auth', 'authenticate', 'authentication', 'authenticated', 'authorize', 'authorization', 'authorized',
  'login', 'logout', 'signin', 'signup', 'password', 'passwd', 'passphrase', 'session', 'jwt', 'oauth',
  'bearer', 'token', 'permission', 'permissions', 'admin', 'acl', 'credential', 'credentials',
])
// RBAC `role`, but NOT the ARIA/JSX attribute `role="…"` / `role: "…"` / `role={…}` (the FP). The
// negative lookahead rejects a role immediately followed by `=`/`:` + a quote/brace (an attribute or
// object literal) while keeping `if (user.role)` / `const role = getRole()`.
const ROLE_RE = /\brole(?!\s*[:=]\s*["'{])s?\b/i

function hasAuthContext(windowText) {
  for (const t of wordTokens(windowText)) if (AUTH_CONTEXT_WORDS.has(t)) return true
  return ROLE_RE.test(windowText)
}

export function scanAuthTodos(text) {
  const facts = []
  const src = String(text)
  const { mask } = stripJs(src)
  const lines = src.split(/\r?\n/)
  const lineOf = lineIndexer(src)
  const seen = new Set()
  const AUTH_RADIUS = 5
  const markerRe = /\b(TODO|FIXME|HACK|XXX)\b/g   // built here, not module-level, so lastIndex is fresh

  let m
  while ((m = markerRe.exec(src))) {
    // FP TRAP: prefer COMMENT context. A marker inside a string literal is a weaker signal and is
    // intentionally NOT emitted — only markers the stripper classified as COMMENT count.
    if (mask[m.index] !== COMMENT) continue
    const line = lineOf(m.index)
    const from = Math.max(0, line - 1 - AUTH_RADIUS)
    const to = Math.min(lines.length, line + AUTH_RADIUS)   // slice end exclusive → covers +RADIUS
    // FP TRAP: a marker far from any auth token is ordinary backlog noise — require an auth-ish word
    // within ±5 lines before emitting.
    if (!hasAuthContext(lines.slice(from, to).join('\n'))) continue
    const marker = m[1].toUpperCase()
    const dk = line + ' ' + marker
    if (seen.has(dk)) continue
    seen.add(dk)
    facts.push({ at: { line }, kind: 'auth-todo', marker, snippet: snippetAt(src, m.index) })
  }
  return facts
}
