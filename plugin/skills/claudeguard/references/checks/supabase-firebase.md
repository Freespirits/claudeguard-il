# Supabase / Firebase checks

The #1 source of real breaches in this community. Backend-as-a-service means the client talks to
the DB directly, so **the database's own access rules are the security boundary.** If they are
off or permissive, the app is wide open — no server code required to exploit it.

Contents: [Supabase RLS](#rls) · [service_role](#service) · [anon key power](#anon) ·
[Firebase rules](#fb-rules) · [Firebase config](#fb-config) · [Storage](#storage)

<a id="rls"></a>
## Supabase — Row Level Security
- **RLS disabled on a table** that holds user or private data. With RLS off, the public `anon`
  key can read and write the whole table via the auto-generated REST/GraphQL API. Signal: a
  migration/SQL with `create table` but no `enable row level security`; or a table not listed in
  any `create policy`. Confirm in Tier 1 by hitting `.../rest/v1/<table>?select=*` with the anon
  key. **P0**. Guard: `rls-policies.md#enable-rls`.
- **Permissive policy** — `using (true)` / `with check (true)` on read *and* write, or a policy
  that doesn't scope to `auth.uid()`. Effectively "RLS on, but allows everyone." **P0/P1**.
  Guard: `rls-policies.md#owner-scoped-policy`.
- **Policy checks read but not write** (or vice-versa) — insert/update/delete left open. **P1**.
- **`security definer` functions / views** that bypass RLS and are callable by anon. **P1**.
- **RLS relies on a client-supplied `user_id`** instead of `auth.uid()`. Spoofable. **P1**.

<a id="service"></a>
## Supabase — service_role key
- **`service_role` key in client code or a `NEXT_PUBLIC_*` var.** This key **bypasses RLS
  entirely** — total DB control. If it reaches the browser it is game over. Signal: the
  service_role JWT (role claim `service_role`) or a var named `SERVICE_ROLE` used in client
  files / public env. **P0**. Guard: `rls-policies.md#service-role-server-only`.
- **service_role used in an unauthenticated API route** as a shortcut, exposing admin power to
  anyone who calls the route. **P0/P1**.

<a id="anon"></a>
## Supabase — anon key scope
- The anon key is *meant* to be public — that is fine **only if RLS is correct on every table.**
  So an exposed anon key is not itself the finding; the finding is any table it can reach that it
  shouldn't. Enumerate tables and check each has RLS + scoped policies. **P0** per open table.
- **Overly broad grants** to the `anon`/`authenticated` Postgres roles. **P1**.

<a id="fb-rules"></a>
## Firebase — Security Rules
- **Open rules.** `allow read, write: if true;` or `if request.auth != null;` used as the only
  gate (any logged-in user can touch any doc). Signal: `firestore.rules` / `database.rules.json`
  / `storage.rules`. **P0/P1**. Guard: `firebase-rules.md`.
- **Test-mode rules left in prod** (`allow read, write: if request.time < timestamp.date(...)`).
  **P0**.
- **Rules not scoped to `request.auth.uid == resource.data.ownerId`.** **P1**.
- **Missing validation** in rules (any shape/size of data accepted). **P2**.

<a id="fb-config"></a>
## Firebase — client config & auth
- Firebase `apiKey` in client is **expected** (it's an identifier, not a secret) — do **not**
  flag it as a leaked secret. The real questions are: are the **rules** locked down, and is
  **App Check** / auth enforced. Flagging the apiKey as "exposed" is a classic false positive —
  the verifier must suppress it. **P4/info** unless rules are also open (then the rules are the
  P0).
- **Client-side-only auth checks** with open rules → bypassable. **P1**.
- **Admin SDK service-account JSON committed** (`serviceAccountKey.json`, private key). **P0**.

<a id="storage"></a>
## Storage buckets (both)
- **Public bucket with private files** / world-readable Storage rules. **P1/P2**.
- **Unsigned upload URLs** allowing arbitrary writes. **P2**.

## How to verify (kept honest)
Static analysis can only *suspect* RLS is off (e.g. no policy found). Mark such findings
`likely`. To reach `confirmed`, either read the actual policy SQL, or run Tier 1 with the user's
attestation and observe a public read succeeding. Never claim "your DB is open" from static
signals alone — say "no RLS policy found for table X; confirm with /cg-live or in the dashboard."
