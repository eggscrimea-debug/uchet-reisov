-- Синхронизация «Учет рейсов»
create table if not exists public.app_state (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default jsonb_build_object('version', 5, 'rids', jsonb_build_array(), 'periodCosts', jsonb_build_array()),
  updated_at timestamptz not null default now()
);

alter table public.app_state enable row level security;

grant select, insert, update, delete on public.app_state to authenticated;

drop policy if exists "Users can read own app state" on public.app_state;
drop policy if exists "Users can insert own app state" on public.app_state;
drop policy if exists "Users can update own app state" on public.app_state;
drop policy if exists "Users can delete own app state" on public.app_state;

create policy "Users can read own app state" on public.app_state for select to authenticated using (auth.uid() = user_id);
create policy "Users can insert own app state" on public.app_state for insert to authenticated with check (auth.uid() = user_id);
create policy "Users can update own app state" on public.app_state for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "Users can delete own app state" on public.app_state for delete to authenticated using (auth.uid() = user_id);

alter publication supabase_realtime add table public.app_state;