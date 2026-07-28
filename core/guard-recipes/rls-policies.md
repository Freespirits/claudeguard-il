# Guard: Supabase RLS policies

Paste-ready fixes for the most common (and most dangerous) vibecoded finding.

<a id="service-role-server-only"></a>
## Move service_role to the server; use anon in the client

**Never** import the `service_role` key in client code or a `NEXT_PUBLIC_*` var. Two clients:

```ts
// lib/supabase/client.ts  — browser, anon key only (safe to ship)
import { createBrowserClient } from '@supabase/ssr'
export const supabase = createBrowserClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!   // anon key is public BY DESIGN — RLS protects data
)
```

```ts
// lib/supabase/admin.ts  — SERVER ONLY. No NEXT_PUBLIC_ prefix. Never imported by a client file.
import { createClient } from '@supabase/supabase-js'
export const supabaseAdmin = createClient(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,       // bypasses RLS — keep on the server, use sparingly
  { auth: { persistSession: false } }
)
```

Then **rotate** the exposed key in the Supabase dashboard (Settings → API → roll key). Assume the
old one is compromised.

<a id="enable-rls"></a>
## Enable RLS on every table

```sql
alter table public.profiles enable row level security;
-- repeat for EVERY table with user/private data. A table with RLS off is world-read/write
-- through the anon key + auto REST API.
```

Sanity check which tables lack RLS:

```sql
select relname
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity = false;
```

<a id="owner-scoped-policy"></a>
## Owner-scoped policies (not `using (true)`)

```sql
-- Read only your own rows
create policy "read own" on public.profiles
  for select using ( auth.uid() = user_id );

-- Insert only as yourself (WITH CHECK guards the written row)
create policy "insert own" on public.profiles
  for insert with check ( auth.uid() = user_id );

-- Update only your own rows, and can't reassign ownership
create policy "update own" on public.profiles
  for update using ( auth.uid() = user_id )
             with check ( auth.uid() = user_id );

-- Delete only your own rows
create policy "delete own" on public.profiles
  for delete using ( auth.uid() = user_id );
```

Rules of thumb:
- Scope to `auth.uid()`, **never** to a client-supplied `user_id` column value alone.
- Set a policy for **each** of select/insert/update/delete — a missing one for a command means
  that command is denied by default (good) *unless* a broad `for all using (true)` exists (bad).
- Avoid `security definer` functions/views callable by `anon` that read across users.

## Verify the fix
Re-run `/cg-scan`, then `/cg-live` (owned target) and confirm `GET /rest/v1/<table>?select=*`
with the anon key returns only permitted rows (or 401), not the whole table.
