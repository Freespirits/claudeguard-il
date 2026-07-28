# Web checks

Contents: [Secrets](#secrets) · [Auth & authorization](#auth) · [API routes / IDOR](#api) ·
[Input validation](#input) · [Injection & XSS](#injection) · [Headers/CORS/cookies](#headers) ·
[Rate limiting](#rate) · [Info leakage](#leak) · [Dependencies](#deps) · [Hosting](#hosting)

Applies to Next.js, React, Vue, Svelte, Astro, plain JS, and their API/back-ends. For each item:
what it is, how to detect (static signal + preferred tool), severity, and the guard to apply.

<a id="secrets"></a>
## 1. Secrets in the client / repo
- **`NEXT_PUBLIC_` / `VITE_` / `PUBLIC_` prefix on a real secret.** Any var with these prefixes
  is inlined into the browser bundle. A service key, DB URL with password, Stripe secret, or LLM
  API key behind such a prefix is exposed. Static signal: grep env prefixes for names containing
  `SECRET|SERVICE_ROLE|PRIVATE|API_KEY|TOKEN|PASSWORD`. **P0** if the key is privileged/live.
  Guard: `guard-recipes/secrets-management.md`.
- **Committed `.env` / `.env.local` / `.env.production`.** Check git tracking and git history
  (a removed `.env` still lives in history). Tool: `gitleaks`/`trufflehog`; fallback: read files
  + entropy scan. **P0/P1** by key power. Guard: `secrets-management.md#rotate-and-ignore`.
- **Hardcoded keys in source** (`sk-...`, `AKIA...`, `AIza...`, JWT, Slack/GitHub tokens, private
  keys). Regex + entropy. **P0/P1**. Rotate — do not just delete; assume compromised.
- **Secrets reaching the bundle.** If a build output exists, grep `dist`/`.next`/`build` for key
  shapes. Confirms client exposure vs server-only.

<a id="auth"></a>
## 2. Authentication & authorization
- **Client-side-only auth.** Route guard exists only in React/router, no server check. Anyone
  calls the API directly. Static signal: protected data fetched in an API route/server action
  with no session/user check. **P1**. Guard: `auth-middleware.md`.
- **Missing server-side authorization (broken access control).** Endpoint verifies *logged in*
  but not *allowed*. **P1**, OWASP A01.
- **JWT trusted without verification / weak secret / `alg:none`.** Look for `jwt.decode` used as
  auth (no `verify`), secrets in code, or unsigned tokens accepted. **P0/P1**.
- **Session/cookie handling.** No expiry, no rotation on login, tokens in `localStorage`
  (XSS-readable). **P2**.

<a id="api"></a>
## 3. API routes / IDOR / mass assignment
- **IDOR.** Handler reads `id`/`userId` from params/body and queries without checking ownership
  against the session. Signal: `where({ id: req.query.id })` with no `AND owner = session.user`.
  **P1**, OWASP A01. Guard: `auth-middleware.md#ownership-check`.
- **Mass assignment.** `create/update({ ...req.body })` lets a user set `role`, `isAdmin`,
  `credits`. **P1**. Guard: `zod-validation.md#pick-allowed-fields`.
- **Verb/route exposure.** Debug/admin/internal routes reachable in prod (`/api/debug`,
  `/api/admin/*` unguarded). **P1/P2**.

<a id="input"></a>
## 4. Input validation
- **No schema validation** on request bodies/queries. Signal: handlers use `req.body.x` directly
  with no `zod`/`yup`/`valibot`/`joi`. **P2** (raises severity of injection/mass-assignment).
  Guard: `zod-validation.md`.
- **Unbounded input** (no length/size caps) → DoS / cost. **P2/P3**.

<a id="injection"></a>
## 5. Injection & XSS
- **SQL/NoSQL injection.** String-concatenated queries; unparameterized `$where`, `sql\`...\``
  built from input; Mongo query built from `req.body`. **P0/P1**, CWE-89. Guard:
  `zod-validation.md` + parameterized queries.
- **XSS.** `dangerouslySetInnerHTML`, `v-html`, `innerHTML =`, unsanitized markdown/HTML render.
  **P1/P2**, CWE-79. Guard: `security-headers.md#csp` + sanitize (DOMPurify).
- **SSRF.** Server fetches a URL taken from user input with no allowlist. **P1**, CWE-918.
- **Open redirect.** `redirect(req.query.next)` without allowlist. **P2/P3**.
- **Command/path injection.** `exec`, `child_process`, `fs` paths built from input. **P0/P1**.

<a id="headers"></a>
## 6. Security headers, CORS, cookies
- **Missing CSP** (or `unsafe-inline`/`unsafe-eval`). **P2**. Guard: `security-headers.md#csp`.
- **Missing** `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`/frame-
  ancestors, `Referrer-Policy`, `Permissions-Policy`. **P3**. Guard: `security-headers.md`.
- **Permissive CORS** (`Access-Control-Allow-Origin: *` with credentials, or reflected origin).
  **P2**, CWE-942.
- **Cookie flags** missing `HttpOnly` / `Secure` / `SameSite`. **P2**.

<a id="rate"></a>
## 7. Rate limiting & abuse
- **No rate limit on auth** (login/signup/reset/OTP) → credential stuffing, bombing. **P2**.
  Guard: `rate-limiting.md`.
- **No rate limit on expensive endpoints** (search, export, **LLM calls** → cost DoS). **P2**.
- **No captcha / lockout** on repeated failures. **P3**.

<a id="leak"></a>
## 8. Information leakage
- **Verbose errors / stack traces in prod** (`NODE_ENV` not production, error object returned
  to client). **P2/P3**. Guard: `security-headers.md#error-handling`.
- **Source maps served in prod** (`.map` reachable). **P3**.
- **Exposed `.git`, `.env`, `.DS_Store`, backups** on the host. Confirmed in Tier 1. **P1/P2**.

<a id="deps"></a>
## 9. Dependencies
- **Known-vulnerable packages.** Tool: `npm audit --json` / `pnpm audit` / `pip-audit` /
  `osv-scanner`. Fallback: read lockfile, flag obviously outdated critical packages. Severity =
  the CVE's, capped by reachability. Guard: `dependency-hygiene.md`.
- **Risky `postinstall`** scripts / unpinned deps / `latest` ranges. **P2/P3**.

<a id="hosting"></a>
## 10. Hosting / platform (Vercel, Netlify, etc.)
- **Env vars exposed to the wrong scope** (build-time public vs server). **P1/P2**.
- **Preview deployments unauthenticated** exposing staging data. **P2**.
- **Serverless function leaking secrets in logs.** **P2**.

## Detection priority
Run in this order so the cheapest high-value checks come first: secrets → Supabase/Firebase (see
`supabase-firebase.md`) → auth/IDOR → injection → headers → rate limit → deps → leakage.
