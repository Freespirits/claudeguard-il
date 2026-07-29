# Guard: secrets management

<a id="rotate-and-ignore"></a>
## If a secret leaked: rotate first, then remove

Order matters — deleting the file does **not** un-leak the key.

1. **Rotate/revoke** the key at the provider now (Supabase, OpenAI, Stripe, AWS, …). Assume any
   committed or client-shipped key is already compromised.
2. **Move it server-side.** No `NEXT_PUBLIC_`/`VITE_`/`PUBLIC_` prefix for real secrets.
3. **Ignore and untrack:**
   ```bash
   printf '\n.env\n.env.*\n!.env.example\n*.pem\nserviceAccountKey.json\n' >> .gitignore
   git rm --cached .env .env.local .env.production 2>/dev/null || true
   git commit -m "chore: stop tracking secret files"
   ```
4. **Purge history** if the secret was committed (after rotating):
   ```bash
   # git filter-repo (preferred) — install: pip install git-filter-repo
   git filter-repo --path .env --invert-paths
   # or the BFG: bfg --delete-files .env
   ```
   Then force-push and tell collaborators to re-clone.

<a id="public-prefixes"></a>
## Bundler-inlined public prefixes

Certain prefixes are **textually substituted into the client bundle at build time**. There is no
runtime check to fail and no way to un-ship the value: whatever sits behind the prefix is in the
JavaScript every visitor downloads.

| Framework | Inlined into the browser bundle |
|---|---|
| Next.js | `NEXT_PUBLIC_*` |
| Vite, SvelteKit, Astro | `VITE_*`, `PUBLIC_*` |
| Create React App | `REACT_APP_*` |
| Expo | `EXPO_PUBLIC_*` |
| Nuxt | everything under `runtimeConfig.public` |

Fix: drop the prefix and move the read to the server. Renaming alone is not enough — the old
value is already in every bundle you have deployed.

```diff
  # .env.local
- NEXT_PUBLIC_OPENAI_API_KEY=sk-live-…    # inlined: readable in DevTools by anyone
+ OPENAI_API_KEY=sk-live-…                # server-only: no prefix, no client reader
```

```ts
// ❌ app/components/Chat.tsx   ('use client')  — this compiles the key into the bundle
// const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY

// ✅ app/api/chat/route.ts     (server)        — the browser calls this route instead
const key = process.env.OPENAI_API_KEY!
```

Then **rotate** the old key at the provider — see
[rotate first, then remove](#rotate-and-ignore) — and confirm it is really gone:

```bash
npm run build
grep -r "sk-live" .next/static/ && echo "STILL LEAKING" || echo "clean"
```

Protects against: a visitor opening DevTools and reading the credential straight out of your
JavaScript.
Does **not** protect against: keys that are public **by design** — the Supabase `anon` key, a
Firebase `apiKey`, a Stripe publishable key. Those belong behind the prefix, and the thing that
protects the data is RLS / security rules, not secrecy of the identifier.

<a id="server-only"></a>
## Keep server-only values on the server

A variable with no inlined prefix is **not** leaked to the browser — it is simply `undefined`
there. Reading it from a client component is a correctness bug, and the tempting "fix" (adding
`NEXT_PUBLIC_`) turns it into a real breach. Move the read instead, and make the boundary
enforceable:

```bash
npm i server-only
```

```ts
// lib/stripe.ts
import 'server-only'   // the BUILD fails if a client component ever imports this file
import Stripe from 'stripe'
export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
```

```ts
// app/api/checkout/route.ts — the secret stays here; the browser only sees the result
import { stripe } from '@/lib/stripe'

export async function POST(req: Request) {
  const session = await stripe.checkout.sessions.create({ /* … */ })
  return Response.json({ url: session.url })
}
```

Where: `import 'server-only'` on the first line of every module that touches a secret. Outside
Next.js, keep secrets in a separate server entrypoint (Vite: a file never imported from `src/`
client code; SvelteKit: `$env/static/private`, which the compiler already refuses to expose).
For Supabase `service_role` specifically, use the two-client split in
[rls-policies.md](rls-policies.md#service-role-server-only).

Protects against: a later refactor quietly pulling a secret-bearing module into the client
graph — the build breaks instead of shipping.
Does **not** protect against: a secret that has already been exposed (rotate it), or a server
route that hands the secret's *powers* to anonymous callers — that is an authentication problem,
see [auth-middleware.md](auth-middleware.md).

<a id="next-config"></a>
## `env:` and `publicRuntimeConfig` in next.config bypass the prefix rule

Both blocks inline whatever they list into the browser bundle **regardless of prefix**, so a
variable whose name says "server" still ships. This is the one path where the `NEXT_PUBLIC_`
convention everything else relies on simply does not apply.

```diff
  // next.config.js
  module.exports = {
-   env: {
-     DATABASE_URL: process.env.DATABASE_URL,             // -> into the bundle
-     STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,   // -> into the bundle
-   },
-   publicRuntimeConfig: {
-     apiSecret: process.env.API_SECRET,                  // -> serialised into every page
-   },
  }
```

Read server values straight from `process.env` in server code, and give the browser only what it
genuinely needs, through an explicitly public variable:

```ts
// app/api/report/route.ts   (server) — no next.config entry required
const dbUrl = process.env.DATABASE_URL!

// app/components/Map.tsx    ('use client') — deliberately public, and named that way
const mapToken = process.env.NEXT_PUBLIC_MAPBOX_TOKEN!
```

Where: `next.config.js` / `next.config.mjs` / `next.config.ts` at the repo root. After deleting
the block, rotate everything that was listed inside it.

Protects against: server configuration reaching the browser with none of the usual naming
signals, so nobody reviewing the code notices.
Does **not** protect against: values you meant to be public. Those are fine — but put them in a
`NEXT_PUBLIC_` variable rather than `publicRuntimeConfig`, which also forces every page out of
static rendering.

## Public vs secret — do not over-flag
- **Public by design (not a finding):** Supabase **anon** key, Firebase `apiKey`, any key
  compiled into a mobile/desktop client (extractable). Protect the *data* (RLS/rules), not the
  identifier.
- **Secret (must be server-side):** Supabase `service_role`, DB URLs with passwords, Stripe/PayPal
  secret keys, LLM provider keys, webhook signing secrets, admin/service-account JSON.

## `.env.example` pattern
Commit a redacted example so teammates know what's needed, never the real values:

```bash
# .env.example  (committed)
SUPABASE_URL=
SUPABASE_SERVICE_ROLE_KEY=      # server only
NEXT_PUBLIC_SUPABASE_ANON_KEY=  # safe to expose
OPENAI_API_KEY=                 # server only
```

## Runtime secrets (Docker/CI)
- Docker: pass at runtime (`--env-file`, Docker/K8s secrets), never `ENV SECRET=` in the image.
- CI: use the platform secret store + OIDC for cloud, never long-lived keys in plaintext YAML.
