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
- Avoid `security definer` functions/views callable by `anon` that read across users — see
  [SECURITY DEFINER functions](#security-definer) below.

<a id="security-definer"></a>
## SECURITY DEFINER functions: authorize in the body, pin `search_path`

A `security definer` function runs with the **owner's** rights, so RLS does not apply inside it —
and anyone can call it over the auto-generated REST API with `supabase.rpc()`. The function has to
do its own authorization.

```sql
create or replace function public.get_my_orders()
returns setof public.orders
language plpgsql
security definer
set search_path = public, pg_temp   -- pin it: unqualified names must not resolve through a
                                    -- schema the caller can create objects in
as $$
begin
  -- Authorize HERE. RLS is bypassed inside this function.
  if auth.uid() is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;

  return query
    select * from public.orders where user_id = auth.uid();   -- scope rows to the caller
end;
$$;

-- Callable by signed-in users only, not by anonymous visitors:
revoke execute on function public.get_my_orders() from public, anon;
grant  execute on function public.get_my_orders() to authenticated;
```

Where: a migration in `supabase/migrations/*.sql`, then `supabase db push`. Find every existing
definer function and which ones are unpinned:

```sql
select n.nspname, p.proname, p.prosecdef as security_definer, p.proconfig as settings
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname not in ('pg_catalog', 'information_schema') and p.prosecdef;
-- settings null  =>  search_path is NOT pinned
```

Protects against: RLS bypass by anyone who calls the function through `rpc()`, and privilege
escalation by shadowing an unqualified object name the body relies on.
Does **not** protect against: a body that calls `auth.uid()` and then ignores the answer, or one
that returns other users' rows on purpose. The check has to *gate* the query, not merely appear
in the file — that is why the scanner marks these `undeterminable` rather than passing them.

<a id="verify-live"></a>
## Ask the live database what its RLS state actually is

Use this when the repo has no migrations: the schema lives only in the Supabase dashboard, so no
amount of reading the code can answer the question. Paste this into the dashboard →
**SQL Editor** (it only reads catalog tables):

```sql
select c.relname                as table_name,
       c.relrowsecurity         as rls_enabled,
       count(p.polname)         as policies
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
left join pg_policy p on p.polrelid = c.oid
where n.nspname = 'public' and c.relkind = 'r'
group by c.relname, c.relrowsecurity
order by c.relrowsecurity asc, c.relname;   -- rls_enabled = false sorts first: start there
```

- `rls_enabled = false` → world-readable and world-writable through the anon key. Fix with
  [Enable RLS on every table](#enable-rls).
- `rls_enabled = true, policies = 0` → deny-all. Safe, but the feature is broken; write an
  [owner-scoped policy](#owner-scoped-policy) rather than `using (true)`.

Then prove it from outside, using the anon key that already ships in your bundle:

```bash
curl -s "https://<project-ref>.supabase.co/rest/v1/<table>?select=*&limit=5" \
  -H "apikey: <your NEXT_PUBLIC_SUPABASE_ANON_KEY>"
# []  or a permission error  -> not readable anonymously
# rows                       -> anyone with your bundle can read this table
```

Protects against: nothing on its own — this is a measurement, not a fix. It exists so an unknown
becomes a yes or a no in about ten seconds.
Does **not** cover: anything reached through the `service_role` key, which bypasses RLS by
design, or Postgres `grant`s, which are a separate layer from RLS.

## Verify the fix
Re-run `/cg-scan`, then `/cg-live` (owned target) and confirm `GET /rest/v1/<table>?select=*`
with the anon key returns only permitted rows (or 401), not the whole table.
