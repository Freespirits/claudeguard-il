create table public.orders (id uuid primary key, user_id uuid not null, item text);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for all using (auth.uid() = user_id);

create table public.profiles (id uuid primary key, display_name text);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for all using (auth.uid() = id);
