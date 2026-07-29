import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  scanPlaceholderSecrets, scanFakeCrypto, scanClientTokenStorage, scanAuthTodos,
} from '../plugin/scripts/lib/hygiene_scan.mjs'

// ---------------------------------------------------------------------------
// WHY THIS FILE EXISTS
//
// hygiene_scan is the "cheap high-signal" grep engine the cross-model poll converged on. Every check
// here trades away recall for a near-zero false-positive rate — a placeholder BELONGS in an .env
// sample, base64 IS the right tool for an image, and `theme` in localStorage is fine. So each test
// pins the detection AND the exact suppressing condition beside it: a rule that cries wolf on the
// fixtures below is worse than no rule, because it trains this audience to ignore the badge.
// ---------------------------------------------------------------------------

// --- 1) PLACEHOLDER SECRETS -------------------------------------------------

test('placeholder: a changeme value in a real config file is a fact', () => {
  const f = scanPlaceholderSecrets(`const KEY = 'changeme'`, 'config.ts')
  assert.equal(f.length, 1)
  assert.equal(f[0].kind, 'placeholder-secret')
  assert.equal(f[0].token, 'changeme')
  assert.equal(f[0].at.line, 1)
  assert.equal(typeof f[0].snippet, 'string')
})

test('placeholder FP trap: the SAME line is ZERO in files where placeholders belong', () => {
  const code = `const KEY = 'changeme'`
  assert.equal(scanPlaceholderSecrets(code, '.env.example').length, 0, '.env.example')
  assert.equal(scanPlaceholderSecrets(code, 'config.sample.ts').length, 0, '*.sample')
  assert.equal(scanPlaceholderSecrets(code, 'config.template.js').length, 0, '*.template')
  assert.equal(scanPlaceholderSecrets(code, 'README.md').length, 0, 'README / *.md')
  assert.equal(scanPlaceholderSecrets(code, 'src/__tests__/keys.ts').length, 0, '__tests__')
  assert.equal(scanPlaceholderSecrets(code, 'test/fixtures/keys.ts').length, 0, 'fixtures/')
  assert.equal(scanPlaceholderSecrets(code, 'config.test.ts').length, 0, '*.test.*')
})

test('placeholder: self-evident fake credentials fire WITHOUT a secret-ish name', () => {
  assert.equal(scanPlaceholderSecrets(`fetch(u, { headers: { Authorization: 'Bearer sk-xxxxxxxxxxxx' } })`, 'api.ts').length, 1, 'fake OpenAI key')
  assert.ok(scanPlaceholderSecrets(`const t = "ghp_xxxxxxxxxxxxxxxx"`, 'a.ts').length >= 1, 'fake GitHub PAT')
  assert.ok(scanPlaceholderSecrets(`aws = 'AKIAXXXXXXXXXXXXXXXX'`, 'a.ts').length >= 1, 'fake AWS key id')
  assert.ok(scanPlaceholderSecrets(`const x = "your-api-key-here"`, 'a.ts').length >= 1, 'your-api-key-here')
  assert.ok(scanPlaceholderSecrets(`const c = { apiKey: "your_api_key" }`, 'a.ts').length >= 1, 'your_api_key')
})

test('placeholder FP trap: an x-run only fires in secret-ish context', () => {
  // a non-secret variable holding an x-run is NOT a finding...
  assert.equal(scanPlaceholderSecrets(`const gridTemplate = 'xxxxxxxx'`, 'a.ts').length, 0)
  // ...but the same value under a secret-ish name is
  assert.equal(scanPlaceholderSecrets(`const API_KEY = 'xxxxxxxx'`, 'a.ts').length, 1)
})

test('placeholder FP trap: password123 / admin123 need a secret-ish name', () => {
  assert.equal(scanPlaceholderSecrets(`const label = 'admin123'`, 'a.ts').length, 0, 'plain label')
  assert.equal(scanPlaceholderSecrets(`const password = 'admin123'`, 'a.ts').length, 1)
  assert.equal(scanPlaceholderSecrets(`DB_PASSWORD=password123`, 'a.ts').length, 1, 'env-style unquoted')
})

test('placeholder FP trap: a real-looking secret is left for the real-secret check', () => {
  // OBVIOUS placeholders only — a high-entropy value is a DIFFERENT check, not this one.
  assert.equal(scanPlaceholderSecrets(`const API_KEY = 'sk-proj-8fJ2kLm9QeR4tZ1xYbN7vC'`, 'a.ts').length, 0)
})

test('placeholder FP trap: a public-by-design key name is not a leaked secret', () => {
  assert.equal(scanPlaceholderSecrets(`const NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY = 'changeme'`, 'a.ts').length, 0)
})

test('placeholder FP trap: a placeholder in a comment is a note, not shipped code', () => {
  assert.equal(scanPlaceholderSecrets(`// const API_KEY = 'changeme'`, 'a.ts').length, 0)
  assert.equal(scanPlaceholderSecrets(`// paste sk-xxxxxxxxxxxx here`, 'a.ts').length, 0)
})

// --- 2) FAKE CRYPTO ---------------------------------------------------------

test('fake-crypto: base64 on a password/token/secret is a fact', () => {
  const f = scanFakeCrypto(`const enc = btoa(password)`)
  assert.equal(f.length, 1)
  assert.equal(f[0].kind, 'fake-crypto')
  assert.equal(f[0].at.line, 1)
  assert.equal(scanFakeCrypto(`const x = btoa(user.apiKey)`).length, 1, 'btoa(apiKey)')
  assert.equal(scanFakeCrypto(`atob(sessionToken)`).length, 1, 'atob(token)')
  assert.equal(scanFakeCrypto(`Buffer.from(secret).toString('base64')`).length, 1, 'Buffer base64')
})

test('fake-crypto FP trap: base64 on non-sensitive data does NOT fire', () => {
  assert.equal(scanFakeCrypto(`const dataUri = btoa(imageData)`).length, 0, 'image data')
  assert.equal(scanFakeCrypto(`const h = btoa(JSON.stringify(headers))`).length, 0, 'JSON headers')
  assert.equal(scanFakeCrypto(`const s = btoa(svgString)`).length, 0, 'svg')
  assert.equal(scanFakeCrypto(`Buffer.from(fileBuffer).toString('base64')`).length, 0, 'file buffer')
})

test('fake-crypto FP trap: a call inside a comment or a string does NOT fire', () => {
  assert.equal(scanFakeCrypto(`// btoa(password) is not encryption`).length, 0, 'comment')
  assert.equal(scanFakeCrypto(`const doc = "call btoa(password) here"`).length, 0, 'string')
})

test('fake-crypto: an encrypt-named context makes base64 fake-crypto even with a bare arg', () => {
  const f = scanFakeCrypto(`// encrypt the user password\nconst out = btoa(data)`)
  assert.equal(f.length, 1)
  assert.equal(f[0].at.line, 2)
})

test('fake-crypto FP trap: base64 INSIDE a real crypto flow is an encoding hop, not fake crypto', () => {
  // The shape a CORRECT signed token has: HMAC the payload, then base64 the payload half of
  // `payload.signature`. Caught by the wild benchmark on Yuvadi29/PromptOS, where the base64 line
  // also said `const token =` and so matched the sensitivity window. Firing here would be cry-wolf
  // on an implementation doing the right thing — and would spend the user's trust for nothing.
  const signed = [
    'const signature = crypto',
    '  .createHmac("sha256", SECRET)',
    '  .update(payload)',
    '  .digest("hex");',
    'const token = Buffer.from(payload).toString("base64") + "." + signature;',
  ].join('\n')
  assert.equal(scanFakeCrypto(signed).length, 0, 'an HMAC signing chain above the call')
  assert.equal(scanFakeCrypto(`const t = jwt.sign(claims, SECRET)\nconst b = btoa(token)`).length, 0, 'jwt.sign')
  assert.equal(scanFakeCrypto(`const key = await crypto.subtle.importKey(...)\nbtoa(secret)`).length, 0, 'webcrypto')
  assert.equal(scanFakeCrypto(`const h = await bcrypt.hash(password, 12)\nconst e = btoa(password)`).length, 0, 'bcrypt')
})

test('fake-crypto: the crypto suppressor keys on APIs, so crypto-ish PROSE still fires', () => {
  // The suppressor must not be a magic word. A comment that merely says "sign"/"signature" above a
  // btoa(password) is exactly the case this check exists for — no operation is actually happening.
  assert.equal(scanFakeCrypto(`// sign the user in\nconst out = btoa(password)`).length, 1, 'prose "sign"')
  assert.equal(scanFakeCrypto(`// add a signature later\nconst out = btoa(password)`).length, 1, 'prose "signature"')
  assert.equal(scanFakeCrypto(`const signature = btoa(password)`).length, 1, 'a variable NAMED signature')
})

// --- 3) CLIENT TOKEN STORAGE ------------------------------------------------

test('client-token-storage: a bearer/auth/session key in web storage is a fact', () => {
  const f = scanClientTokenStorage(`localStorage.setItem('access_token', t)`)
  assert.equal(f.length, 1)
  assert.equal(f[0].kind, 'client-token-storage')
  assert.equal(f[0].api, 'localStorage')
  assert.equal(f[0].key, 'access_token')
  assert.equal(scanClientTokenStorage(`sessionStorage.setItem("jwt", x)`).length, 1, 'sessionStorage jwt')
  assert.equal(scanClientTokenStorage(`localStorage.authToken = t`).length, 1, 'dotted write')
  assert.equal(scanClientTokenStorage(`localStorage['refresh_token'] = r`).length, 1, 'bracket write')
  assert.equal(scanClientTokenStorage(`window.localStorage.setItem('user_password', p)`)[0].api, 'localStorage', 'window. prefix stripped')
})

test('client-token-storage FP trap: non-sensitive keys never fire', () => {
  for (const k of ['theme', 'locale', 'lang', 'cache', 'sidebar', 'consent', 'visited', 'lastAccess']) {
    assert.equal(scanClientTokenStorage(`localStorage.setItem('${k}', v)`).length, 0, k)
  }
})

test('client-token-storage FP trap: a csrf/xsrf token mirror is skipped (not a bearer credential)', () => {
  assert.equal(scanClientTokenStorage(`localStorage.setItem('csrf_token', c)`).length, 0)
  assert.equal(scanClientTokenStorage(`localStorage.setItem('xsrfToken', c)`).length, 0)
})

test('client-token-storage FP trap: a call in a comment does NOT fire', () => {
  assert.equal(scanClientTokenStorage(`// localStorage.setItem('access_token', t)`).length, 0)
})

// --- 4) AUTH TODOs ----------------------------------------------------------

test('auth-todo: a marker within ~5 lines of auth context is a fact', () => {
  const src = [
    'function handleLogin(req, res) {',
    '  // TODO: check auth here',
    '  return res.ok()',
    '}',
  ].join('\n')
  const f = scanAuthTodos(src)
  assert.equal(f.length, 1)
  assert.equal(f[0].kind, 'auth-todo')
  assert.equal(f[0].marker, 'TODO')
  assert.equal(f[0].at.line, 2)
})

test('auth-todo: FIXME / HACK / XXX near session / permission / token all count', () => {
  assert.equal(scanAuthTodos(`// FIXME: validate the session\ngetSession()`).length, 1, 'FIXME + session')
  assert.equal(scanAuthTodos(`const p = getPassword()\n// HACK: skip the permission check`).length, 1, 'HACK + permission')
  assert.equal(scanAuthTodos(`// XXX rotate the token\nconst token = read()`).length, 1, 'XXX + token')
})

test('auth-todo FP trap: a marker far from any auth context does NOT fire', () => {
  assert.equal(scanAuthTodos(`// TODO: refactor this later\nconst sum = a + b`).length, 0, 'no auth nearby')
  const far = ['// TODO: tidy up', '', '', '', '', '', '', 'function login() {}'].join('\n')
  assert.equal(scanAuthTodos(far).length, 0, 'login is more than 5 lines away')
})

test('auth-todo FP trap: an ARIA role attribute is not auth context', () => {
  assert.equal(scanAuthTodos(`// TODO: fix the spacing\n<div role="button" />`).length, 0)
})

test('auth-todo FP trap: a marker inside a string is weaker and is not emitted', () => {
  assert.equal(scanAuthTodos(`const msg = "TODO: check auth"`).length, 0)
})

test('auth-todo FP trap: PROSE about markers is not a marker', () => {
  // The self-scan case. ClaudeGuardIL's own comments describe this very check, and every one of
  // them sits beside auth words — so without the leading-marker rule the tool fires nine times on
  // its own source. Documentation that MENTIONS a TODO is not a TODO; a real one leads its comment.
  const prose = [
    '// a bearer token parked in localStorage, and a TODO left sitting inside auth code',
    '// 4) AUTH TODOs — a TODO/FIXME/HACK/XXX marker within ~5 lines of an auth-ish token',
    '// without it, `const s = "TODO: add requireAuth"` would satisfy an auth-hint regex',
  ]
  for (const line of prose) {
    assert.equal(scanAuthTodos(`${line}\nfunction login() {}`).length, 0, line.slice(0, 50))
  }
})

test('auth-todo: the leading-marker rule keeps every real comment style', () => {
  // Only styles that are genuinely JS comments — this scanner runs on CODE_EXT files, so a `#` or
  // an HTML comment would not be comment-masked in the first place and is not a case to support.
  const real = [
    '// TODO: check auth here',
    '  // TODO: check auth here',                   // indented
    '/* FIXME: verify the session */',
    '/**\n * HACK: skip the permission check\n */',  // JSDoc continuation line
    '// - TODO: bullet form',
    '//TODO: no space after the slashes',
  ]
  for (const src of real) {
    assert.equal(scanAuthTodos(`${src}\nfunction login() {}`).length, 1, JSON.stringify(src))
  }
})

// --- determinism ------------------------------------------------------------

test('deterministic: repeated calls yield identical facts (no shared regex lastIndex)', () => {
  const src = `const API_KEY='changeme'\nlocalStorage.setItem('jwt', t)\n// TODO: verify session`
  assert.deepEqual(scanPlaceholderSecrets(src, 'a.ts'), scanPlaceholderSecrets(src, 'a.ts'))
  assert.deepEqual(scanClientTokenStorage(src), scanClientTokenStorage(src))
  assert.deepEqual(scanAuthTodos(src), scanAuthTodos(src))
  assert.deepEqual(scanFakeCrypto(`btoa(password)\nbtoa(password)`), scanFakeCrypto(`btoa(password)\nbtoa(password)`))
})
