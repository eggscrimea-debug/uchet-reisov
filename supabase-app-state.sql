-- Основное хранилище журнала отправок для Supabase.
-- Выполнить один раз в SQL Editor после supabase-edit-lock.sql
-- Данные не удаляются: создаётся таблица, если её ещё нет.

create table if not exists public.app_state (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.app_state enable row level security;

drop policy if exists "app_state_select_own" on public.app_state;
create policy "app_state_select_own" on public.app_state
  for select to authenticated
  using (auth.uid() = user_id);

drop policy if exists "app_state_insert_own" on public.app_state;
create policy "app_state_insert_own" on public.app_state
  for insert to authenticated
  with check (auth.uid() = user_id);

drop policy if exists "app_state_update_own" on public.app_state;
create policy "app_state_update_own" on public.app_state
  for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

grant select, insert, update on public.app_state to authenticated;

-- Проверка: таблица должна появиться в public.
select table_name
from information_schema.tables
where table_schema = 'public'
  and table_name in ('app_state', 'edit_lock')
order by table_name;
