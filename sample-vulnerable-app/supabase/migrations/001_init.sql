-- DELIBERATELY INSECURE SAMPLE for testing ClaudeGuardIL.

-- P0: table with private data and NO Row Level Security. With RLS off, the public anon key can
-- read and write every row through the auto-generated REST API.
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  email text not null,
  total_cents integer not null,
  created_at timestamptz default now()
);
-- (missing) alter table public.orders enable row level security;
-- (missing) create policy ... using ( auth.uid() = user_id );

create table public.profiles (
  id uuid primary key,
  full_name text,
  phone text
);
-- P0: profiles also has no RLS and no policies.
