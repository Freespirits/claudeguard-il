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
