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

## Bound the input
Cap array lengths, string sizes, and pagination limits (`z.number().int().min(1).max(100)`) to
prevent resource-exhaustion DoS.

## Notes
- Validate on the **server**. Client validation is UX, not security.
- Return generic errors to the client; log details server-side only.
