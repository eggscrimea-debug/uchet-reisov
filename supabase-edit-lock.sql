-- Журнал отправок: блокировка общего редактирования для Supabase
-- Выполнить целиком в Supabase Dashboard -> SQL Editor -> New query.
-- Предполагается, что public.app_state уже создана и хранит data jsonb по user_id.

create table if not exists public.edit_lock (
  user_id uuid primary key references auth.users(id) on delete cascade,
  session_id text not null,
  owner_label text not null default 'Пользователь',
  expires_at timestamptz not null,
  updated_at timestamptz not null default now()
);

alter table public.edit_lock enable row level security;

drop policy if exists "edit_lock_select_own" on public.edit_lock;
create policy "edit_lock_select_own" on public.edit_lock
  for select to authenticated using (auth.uid() = user_id);

drop policy if exists "edit_lock_insert_own" on public.edit_lock;
create policy "edit_lock_insert_own" on public.edit_lock
  for insert to authenticated with check (auth.uid() = user_id);

drop policy if exists "edit_lock_update_own" on public.edit_lock;
create policy "edit_lock_update_own" on public.edit_lock
  for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);

grant select, insert, update, delete on public.edit_lock to authenticated;

create or replace function public.acquire_edit_lock(
  p_session_id text,
  p_owner_label text,
  p_lease_seconds integer default 120
)
returns table(acquired boolean, session_id text, owner_label text, expires_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_row public.edit_lock%rowtype;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  if p_session_id is null or length(trim(p_session_id)) < 12 then
    raise exception 'Invalid editing session';
  end if;

  insert into public.edit_lock as l(user_id, session_id, owner_label, expires_at, updated_at)
  values (v_uid, p_session_id, coalesce(nullif(trim(p_owner_label), ''), 'Пользователь'),
          now() + make_interval(secs => greatest(60, least(coalesce(p_lease_seconds,120), 300))), now())
  on conflict (user_id) do update
    set session_id = excluded.session_id,
        owner_label = excluded.owner_label,
        expires_at = excluded.expires_at,
        updated_at = now()
    where l.expires_at <= now() or l.session_id = excluded.session_id
  returning l.* into v_row;

  if found then
    return query select true, v_row.session_id, v_row.owner_label, v_row.expires_at;
  else
    select * into v_row from public.edit_lock where user_id = v_uid;
    return query select false, v_row.session_id, v_row.owner_label, v_row.expires_at;
  end if;
end;
$$;

create or replace function public.renew_edit_lock(
  p_session_id text,
  p_lease_seconds integer default 120
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare v_uid uuid := auth.uid(); v_count integer;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  update public.edit_lock
     set expires_at = now() + make_interval(secs => greatest(60, least(coalesce(p_lease_seconds,120), 300))),
         updated_at = now()
   where user_id = v_uid and session_id = p_session_id and expires_at > now();
  get diagnostics v_count = row_count;
  return v_count = 1;
end;
$$;

create or replace function public.release_edit_lock(p_session_id text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare v_uid uuid := auth.uid(); v_count integer;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  delete from public.edit_lock where user_id = v_uid and session_id = p_session_id;
  get diagnostics v_count = row_count;
  return v_count = 1;
end;
$$;

revoke all on function public.acquire_edit_lock(text,text,integer) from public;
revoke all on function public.renew_edit_lock(text,integer) from public;
revoke all on function public.release_edit_lock(text) from public;
grant execute on function public.acquire_edit_lock(text,text,integer) to authenticated;
grant execute on function public.renew_edit_lock(text,integer) to authenticated;
grant execute on function public.release_edit_lock(text) to authenticated;

-- Важно: для общего журнала все устройства должны входить под одной учетной записью Supabase.
-- Таблица app_state остается с RLS auth.uid() = user_id, как в первоначальной настройке.
