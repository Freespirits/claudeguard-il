-- Planted benchmark fixture: a table created with NO row level security. Anyone holding the anon
-- key from the browser bundle can read and write the whole table.
create table public.notes (
  id uuid primary key,
  user_id uuid not null,
  body text
);
