-- Fixed: RLS is enabled and an owner-scoped policy restricts every row to its owner.
create table public.notes (
  id uuid primary key,
  user_id uuid not null,
  body text
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all using (auth.uid() = user_id);
