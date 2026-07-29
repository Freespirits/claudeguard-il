# Guard: vibecoder hygiene

Four mistakes that show up again and again in AI-assisted code, all cheap to fix. None of them is
exotic — they are the places where "make it work" shipped as-is, and the fix in each case is smaller
than the bug.

Each finding that links here is capped at `likely` or `needs-review`, never `confirmed`. That is
deliberate: a regex can see the sink but not whether it matters. **Read the flagged line before you
change anything** — if the fact is real, the fix below applies; if it is not, allowlist the subject
and move on.

<a id="placeholder-secrets"></a>
## Placeholder credential shipped in source (CG-HYG-001 · CWE-1188)

**Why.** A value like `changeme`, `sk-xxxxxxxx`, `your-api-key-here` or `admin123` sitting in real
source means one of two things, and both are worth a minute of your time:

1. **Nobody ever set the real value.** The integration fails in production, usually silently, often
   in a code path nobody tests.
2. **The placeholder *is* the credential.** `admin123` and `password123` are the first two guesses of
   every credential-stuffing script on the internet. In a public repo, this is account takeover with
   no exploit required.

```diff
- const apiKey = 'sk-xxxxxxxxxxxx'
- const ADMIN_PASSWORD = 'admin123'
+ const apiKey = process.env.OPENAI_API_KEY
+ if (!apiKey) throw new Error('OPENAI_API_KEY is not set')
```

Fail **loudly** when the value is missing. A placeholder is the failure mode where a thrown error
should have been:

```js
// lib/env.js — read once, fail at boot rather than at the first request
function required(name) {
  const v = process.env[name]
  if (!v) throw new Error(`Missing required env var: ${name}`)
  return v
}
export const OPENAI_API_KEY = required('OPENAI_API_KEY')
```

**Where placeholders belong.** `.env.example`, `.env.template`, `.env.sample`, docs, tests and
fixtures — that is what those files are FOR, and this check never fires in them. Keep the example
file committed and the real one ignored:

```bash
printf '\n.env\n.env.*\n!.env.example\n' >> .gitignore
```

**If the placeholder turned out to be a real password you shipped**, treat it as leaked: rotate it
first, then remove it — see [secrets-management.md](secrets-management.md#rotate-and-ignore).

<a id="fake-crypto"></a>
## Base64 is not encryption (CG-HYG-002 · CWE-326)

**Why.** `btoa()`, `atob()` and `Buffer.from(x).toString('base64')` are **encodings**. They take no
key, and anyone can reverse one in a single step — `atob(value)` in any browser console. Code that
uses base64 where it means encryption is storing the secret in plaintext while reading as though it
were protected, which is worse than storing it plainly: it stops anyone from asking the question.

```diff
- // "encrypt" the password before saving
- const encrypted = btoa(password)
- localStorage.setItem('pw', encrypted)
```

**For a password, do not encrypt at all — hash it,** server-side, with a slow algorithm. Encryption
is reversible; that is the wrong property for a password.

```js
// server-side only
import bcrypt from 'bcrypt'
const hash = await bcrypt.hash(password, 12)      // store this
const ok   = await bcrypt.compare(password, hash) // verify like this
```

Better still, do not hold passwords yourself — let Supabase Auth, Auth.js, Clerk or Firebase Auth
own them.

**For data you must genuinely encrypt and later decrypt** (an API token for a third party, say), use
authenticated encryption with a key from the environment, on the server:

```js
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto'

const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'base64') // 32 bytes, never in source

export function encrypt(plain) {
  const iv = randomBytes(12)
  const c = createCipheriv('aes-256-gcm', KEY, iv)
  const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()])
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64')
}

export function decrypt(packed) {
  const b = Buffer.from(packed, 'base64')
  const d = createDecipheriv('aes-256-gcm', KEY, b.subarray(0, 12))
  d.setAuthTag(b.subarray(12, 28))
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8')
}
```

**When this check is wrong.** Base64 is correct and expected for transport and encoding — a data
URI, a Basic-Auth header, a binary blob in JSON. The check only fires when the surrounding code
names the value a password, token, secret or key. If yours is an honest encoding hop inside a real
crypto flow, allowlist the subject.

<a id="token-storage"></a>
## Auth token in localStorage / sessionStorage (CG-HYG-003 · CWE-922)

**Why.** `localStorage` is readable by **any** JavaScript running on your origin — your code, your
dependencies, an injected script, a browser extension. One XSS anywhere on the site reads the token
out of storage and replays it, and the token stays valid until it expires. An `httpOnly` cookie is
invisible to that same script.

```diff
- localStorage.setItem('access_token', session.access_token)
```

**Use an httpOnly cookie set by the server:**

```js
// Next.js route handler / server action
import { cookies } from 'next/headers'

cookies().set('session', token, {
  httpOnly: true,                 // JavaScript cannot read it — the whole point
  secure: true,                   // HTTPS only
  sameSite: 'lax',                // blocks the cross-site CSRF shape
  path: '/',
  maxAge: 60 * 60,                // keep it short; refresh server-side
})
```

**With Supabase**, do not hand-roll it — `@supabase/ssr` puts the session in cookies for you:

```js
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

const cookieStore = cookies()
const supabase = createServerClient(url, anonKey, {
  cookies: {
    get: n => cookieStore.get(n)?.value,
    set: (n, v, o) => cookieStore.set(n, v, o),
    remove: (n, o) => cookieStore.set(n, '', o),
  },
})
```

**What is fine to keep in web storage:** a theme, a locale, a sidebar state, a draft, a cached
non-sensitive response — anything an attacker gains nothing by reading. The check keys on the KEY
name and only fires on `token`/`auth`/`session`/`jwt`/`credential`/`password`/`secret`/`bearer`/
`apikey`/`oauth`, so preferences never trip it. A `csrf`/`xsrf` value mirrored into storage is the
standard double-submit-cookie defence and is skipped by design.

<a id="auth-todos"></a>
## TODO / FIXME left inside auth code (CG-HYG-004 · CWE-489)

**Why.** This is the weakest of the four checks and the only one at `needs-review`: a marker near an
auth word is a **pointer to a place worth reading**, not a proven defect. It earns its place because
of what it sometimes turns out to be — the "temporary" bypass that shipped.

```js
// TODO: add real auth before launch
export async function DELETE(req, { params }) {
  await db.project.delete({ where: { id: params.id } })   // ← ships open
}
```

**Resolve it one of three ways, and none of them is "leave it".**

1. **The work is genuinely outstanding** → do not deploy this path. Fail closed until it is done:
   ```js
   export async function DELETE(req, { params }) {
     const user = await getUser(req)
     if (!user) return new Response('Unauthorized', { status: 401 })
     const project = await db.project.findUnique({ where: { id: params.id } })
     if (project?.ownerId !== user.id) return new Response('Forbidden', { status: 403 })
     await db.project.delete({ where: { id: params.id } })
     return new Response(null, { status: 204 })
   }
   ```
   See [auth-middleware.md](auth-middleware.md) for the middleware-level version.
2. **The work is done and the comment is stale** → delete the comment. A stale marker in auth code
   costs every future reader the same minute it just cost you.
3. **The marker is about something unrelated that merely sits nearby** → allowlist the subject.

**Do not "fix" this by deleting the marker without reading the code.** The comment is the only
signal you have that someone knew this was unfinished.
