# Guard: authentication & authorization

Authenticate (who are you) **and** authorize (are you allowed) on the **server**, for every
protected route. Client-side guards are UX only.

## Require a session (Next.js App Router + Supabase)

```ts
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export async function requireUser() {
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: cookies() as any })
  const { data: { user } } = await supabase.auth.getUser()  // verifies the JWT server-side
  if (!user) throw new Response('Unauthorized', { status: 401 })
  return user
}
```

<a id="ownership-check"></a>
## Enforce ownership (stops IDOR)

The bug: trusting an `id` from the request. The fix: constrain the query by the session user.

```ts
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const user = await requireUser()

  // ❌ IDOR: returns anyone's order
  // const order = await db.order.findUnique({ where: { id: params.id } })

  // ✅ ownership enforced in the query itself
  const order = await db.order.findFirst({
    where: { id: params.id, userId: user.id },
  })
  if (!order) return new Response('Not found', { status: 404 })  // don't reveal existence
  return Response.json(order)
}
```

## Role / permission checks (stops privilege escalation)

```ts
export async function requireRole(user: { id: string }, role: 'admin' | 'editor') {
  const row = await db.user.findUnique({ where: { id: user.id }, select: { role: true } })
  if (row?.role !== role) throw new Response('Forbidden', { status: 403 })
}
```
- Derive the role from the **database/session**, never from a client-sent field or JWT claim the
  client can set.
- Deny by default: if a check is missing, the route should fail closed.

## JWT — verify, don't decode
```ts
// ❌ jwt.decode(token)  → does NOT check the signature
// ✅ jwt.verify(token, process.env.JWT_SECRET!, { algorithms: ['HS256'] })
```
Reject `alg: none`; pin the algorithm; keep the secret server-side and strong.

## Protect many routes at once
Use framework middleware (Next.js `middleware.ts`, Express router-level auth) so new routes are
protected by default, then add per-route ownership/role checks.
