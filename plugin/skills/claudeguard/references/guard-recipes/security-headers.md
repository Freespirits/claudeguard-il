# Guard: security headers, CORS, cookies, errors

<a id="csp"></a>
## Content-Security-Policy + standard headers (Next.js)

```js
// next.config.js
const csp = [
  "default-src 'self'",
  "script-src 'self'",                 // add 'nonce-...' for inline scripts; avoid 'unsafe-inline'
  "style-src 'self' 'unsafe-inline'",  // tighten once styles are externalized
  "img-src 'self' data: https:",
  "connect-src 'self' https://*.supabase.co",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ')

const securityHeaders = [
  { key: 'Content-Security-Policy', value: csp },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
]

module.exports = {
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }]
  },
}
```

For non-Next apps: set the same headers in the reverse proxy (nginx/Caddy) or framework
middleware. `helmet` covers Express in one line: `app.use(helmet())` (then add a CSP).

The sections below take the headers in that array one at a time — what each one buys you, and
what it does not.

<a id="tls"></a>
## Serve everything over HTTPS

```js
// next.config.js — send HTTP callers to HTTPS, then tell the browser never to try HTTP again
module.exports = {
  async redirects() {
    return [{
      source: '/:path*',
      has: [{ type: 'header', key: 'x-forwarded-proto', value: 'http' }],
      destination: 'https://your-domain.com/:path*',
      permanent: true,
    }]
  },
  async headers() {
    return [{ source: '/:path*', headers: [
      { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
    ]}]
  },
}
```

Where: `next.config.js`. Vercel, Netlify and Cloudflare Pages terminate TLS and redirect for you,
so a plain-HTTP finding on those usually means a custom domain whose certificate has not finished
provisioning — check the domain settings before changing code. Self-hosted: `certbot --nginx`
issues and auto-renews a free certificate.

Protects against: anyone sharing the network (café Wi-Fi, hotel, ISP, a compromised router)
reading or rewriting the traffic, session cookies included.
Does **not** protect against: interception of the very first plain-HTTP request, before the
redirect is served. HSTS below is what closes that.

<a id="hsts"></a>
## Strict-Transport-Security

One line in the `securityHeaders` array above:

```js
{ key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
```

```nginx
# or, at the proxy
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

Where: `headers()` in `next.config.js`, or the reverse proxy. Send it only over HTTPS. Make sure
**every** subdomain can serve TLS before adding `includeSubDomains` — browsers will refuse plain
HTTP for all of them for the full `max-age` (two years here), and there is no quick undo.

Protects against: the downgrade window on every visit after the first — the browser upgrades to
HTTPS itself rather than asking your server and being redirected.
Does **not** protect against: the first ever visit from a device that has not seen the header.
Submitting the domain at hstspreload.org ships it in the browser instead, closing that too.

<a id="nosniff"></a>
## X-Content-Type-Options: nosniff

```js
{ key: 'X-Content-Type-Options', value: 'nosniff' },
```

Where: the `securityHeaders` array above. Pair it with an explicit, trusted `Content-Type` on
anything you serve back from user input:

```ts
// app/api/files/[id]/route.ts
return new Response(fileStream, {
  headers: {
    'Content-Type': 'application/octet-stream',              // never echo the uploaded type
    'Content-Disposition': 'attachment; filename="download"', // never echo the uploaded name
  },
})
```

Protects against: a browser deciding an uploaded `.txt` or `.jpg` is really HTML and running it
as a page on your origin.
Does **not** protect against: a file you yourself serve with a dangerous `Content-Type`. Where you
can, host user uploads on a separate domain (a storage bucket) so nothing they upload is
same-origin with your session cookies.

<a id="frame-ancestors"></a>
## Stop other sites framing your pages (clickjacking)

```js
{ key: 'Content-Security-Policy', value: "frame-ancestors 'none'" },  // modern; supports allowlists
{ key: 'X-Frame-Options', value: 'DENY' },                            // fallback for old browsers
```

To permit exactly one embedder instead of none:

```js
{ key: 'Content-Security-Policy', value: "frame-ancestors 'self' https://partner.example.com" },
```

Where: the `securityHeaders` array above. `frame-ancestors` wins wherever both are understood;
keep `X-Frame-Options` alongside it for older clients. Note `X-Frame-Options` has no allowlist
form worth using — if you need one, `frame-ancestors` is the answer.

Protects against: an attacker loading your page invisibly on top of their own and collecting a
logged-in visitor's clicks — the "click to win" square sitting over your Delete Account button.
Does **not** protect against: an attacker who copies your page rather than framing it. That is
phishing, and no header stops it.

<a id="referrer"></a>
## Referrer-Policy

```js
{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
```

Where: the `securityHeaders` array above. Use `no-referrer` on pages whose URLs carry
password-reset or invitation tokens.

Protects against: the full URL — including any token sitting in the query string — being handed
to every third-party site your pages link to or load a script, font or pixel from.
Does **not** protect against: the token being in the URL at all. It is still in browser history,
proxy logs, server logs and shared screenshots. Put secrets in the request body, or make the URL
parameter single-use and short-lived.

<a id="cors"></a>
## CORS — allowlist, never reflect

```ts
const ALLOWED = new Set(['https://app.example.com'])
function corsHeaders(origin: string | null) {
  if (origin && ALLOWED.has(origin)) {
    return { 'Access-Control-Allow-Origin': origin, 'Vary': 'Origin',
             'Access-Control-Allow-Credentials': 'true' }
  }
  return {}   // deny by omission
}
// ❌ never: 'Access-Control-Allow-Origin': '*' together with credentials
```

<a id="cookies"></a>
## Cookies — secure flags

```ts
cookies().set('session', token, {
  httpOnly: true,     // not readable by JS (XSS can't steal it)
  secure: true,       // HTTPS only
  sameSite: 'lax',    // 'strict' for sensitive apps
  path: '/',
  maxAge: 60 * 60 * 8,
})
```
Prefer HttpOnly cookies over storing tokens in `localStorage` (which XSS can read).

Protects against: `httpOnly` keeps injected JavaScript from reading the session with
`document.cookie`; `secure` keeps it off any plain-HTTP request; `sameSite` blocks the browser
from attaching it to a cross-site form post (CSRF).
Does **not** protect against: an attacker who does not need to *read* the cookie — injected
script can still call your API from the victim's own browser, cookie attached. Rate limits,
re-authentication for dangerous actions and a CSP remain necessary.

<a id="redirects"></a>
## Redirect only to somewhere you control (open redirect)

```ts
// app/api/login/route.ts
// ❌ `next` comes from the query string and can be any URL on the internet
// return Response.redirect(searchParams.get('next')!)

// ✅ accept a PATH, never a URL, and re-anchor it to your own origin
function safeNext(raw: string | null, origin: string) {
  // '//evil.com' and 'https://evil.com' are both absolute; only a single leading slash is a path
  if (!raw || !raw.startsWith('/') || raw.startsWith('//')) return '/'
  return new URL(raw, origin).toString()
}

const origin = new URL(req.url).origin
return Response.redirect(safeNext(searchParams.get('next'), origin), 303)
```

If cross-origin redirects are genuinely required, allowlist the host — never pattern-match it
(`endsWith('example.com')` matches `notexample.com`):

```ts
const ALLOWED_HOSTS = new Set(['app.example.com', 'docs.example.com'])
const target = new URL(raw)
if (!ALLOWED_HOSTS.has(target.host)) return new Response('Bad redirect', { status: 400 })
```

Where: every handler that reads a `next`, `return_to`, `callback` or `redirect_uri` parameter.
Auth callbacks are where this almost always lives.

Protects against: a phishing link that begins on your trusted domain and lands on the attacker's,
and against an OAuth code being delivered to a callback URL you never approved.
Does **not** protect against: an allowlisted host that has an open redirect of its own — the chain
ends up in the same place. Keep the list short and to domains you operate.

<a id="image-hosts"></a>
## Restrict next/image to hosts you trust

```diff
  // next.config.js
  images: {
-   remotePatterns: [{ protocol: 'https', hostname: '**' }],   // any host on the internet
+   remotePatterns: [
+     { protocol: 'https', hostname: 'your-project.supabase.co', pathname: '/storage/v1/**' },
+     { protocol: 'https', hostname: 'images.unsplash.com' },
+   ],
  },
```

Where: `next.config.js`. List only the hosts you actually load images from; the build fails loudly
on one you missed, which is how you find the rest.

Protects against: strangers using `/_next/image?url=…` as an open proxy — serving their content
from your domain and reputation, and making **your server** fetch URLs of their choosing (the
SSRF shape: private addresses, `169.254.169.254` cloud metadata, internal admin panels).
Does **not** protect against: an allowlisted host serving something hostile, or a bucket where
users can upload arbitrary files. Prefer storage you control, with a `pathname` narrower than
`/**`.

<a id="error-handling"></a>
## Errors — don't leak internals in prod

```ts
try { /* ... */ } catch (err) {
  console.error(err)                                  // full detail server-side
  const dev = process.env.NODE_ENV !== 'production'
  return Response.json(
    { error: dev ? String(err) : 'Internal error' },  // generic to the client in prod
    { status: 500 })
}
```
Also: disable source maps in production builds, and remove debug/verbose logging of secrets.
