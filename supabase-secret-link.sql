-- Secret-link access for the shared journal.
-- Run once in Supabase SQL Editor. This replaces per-user access with one shared workspace.
create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;

create table if not exists private.workspace_secret (
  singleton boolean primary key default true check (singleton),
  secret_hash bytea not null
);
revoke all on schema private from public, anon, authenticated;
revoke all on private.workspace_secret from public, anon, authenticated;
insert into private.workspace_secret(singleton, secret_hash)
values (true, decode('3f69f13628c8b03f95ad55e75cea189fae5a0c31100946afdeff2a5eae6660c2','hex'))
on conflict (singleton) do update set secret_hash = excluded.secret_hash;

create or replace function public.has_workspace_access()
returns boolean
language sql
stable
security definer
set search_path = public, private, extensions, pg_temp
as $$
  select coalesce(
    extensions.digest(
      coalesce((nullif(current_setting('request.headers', true), '')::jsonb ->> 'x-workspace-key'), ''),
      'sha256'
    ) = (select secret_hash from private.workspace_secret where singleton = true),
    false
  );
$$;
revoke all on function public.has_workspace_access() from public;
grant execute on function public.has_workspace_access() to authenticated;

-- All devices use one fixed workspace row, not their individual anonymous user IDs.
do $$
declare c record;
begin
  for c in
    select conrelid::regclass as tbl, conname
    from pg_constraint
    where contype = 'f'
      and conrelid in ('public.app_state'::regclass, 'public.edit_lock'::regclass)
  loop
    execute format('alter table %s drop constraint %I', c.tbl, c.conname);
  end loop;
end $$;

insert into public.app_state(user_id, data, updated_at)
select '00000000-0000-4000-8000-000000000001'::uuid, data, updated_at
from public.app_state
order by updated_at desc nulls last
limit 1
on conflict (user_id) do update
set data = excluded.data, updated_at = excluded.updated_at
where public.app_state.updated_at is null
   or excluded.updated_at >= public.app_state.updated_at;

alter table public.app_state enable row level security;
drop policy if exists "app_state_select_own" on public.app_state;
drop policy if exists "app_state_insert_own" on public.app_state;
drop policy if exists "app_state_update_own" on public.app_state;
drop policy if exists "app_state_shared_workspace" on public.app_state;
create policy "app_state_shared_workspace" on public.app_state
for all to authenticated
using (
  user_id = '00000000-0000-4000-8000-000000000001'::uuid
  and public.has_workspace_access()
)
with check (
  user_id = '00000000-0000-4000-8000-000000000001'::uuid
  and public.has_workspace_access()
);
grant select, insert, update on public.app_state to authenticated;

alter table public.edit_lock enable row level security;
drop policy if exists "edit_lock_select_own" on public.edit_lock;
drop policy if exists "edit_lock_select_workspace" on public.edit_lock;
create policy "edit_lock_select_workspace" on public.edit_lock
for select to authenticated
using (
  user_id = '00000000-0000-4000-8000-000000000001'::uuid
  and public.has_workspace_access()
);
revoke all on public.edit_lock from public, anon, authenticated;
grant select on public.edit_lock to authenticated;

create or replace function public.acquire_edit_lock(
  p_session_id text,
  p_owner_label text,
  p_lease_seconds integer default 120
)
returns table(acquired boolean, session_id text, owner_label text, expires_at timestamptz)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_workspace constant uuid := '00000000-0000-4000-8000-000000000001';
  v_row public.edit_lock%rowtype;
begin
  if auth.uid() is null or not public.has_workspace_access() then
    raise exception 'Valid invitation link required';
  end if;
  if p_session_id is null or length(trim(p_session_id)) < 12 then
    raise exception 'Invalid editing session';
  end if;
  insert into public.edit_lock as l(user_id, session_id, owner_label, expires_at, updated_at)
  values (v_workspace, p_session_id, coalesce(nullif(trim(p_owner_label), ''), 'Пользователь'),
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
    select * into v_row from public.edit_lock where user_id = v_workspace;
    return query select false, v_row.session_id, v_row.owner_label, v_row.expires_at;
  end if;
end;
$$;

create or replace function public.renew_edit_lock(p_session_id text, p_lease_seconds integer default 120)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare v_workspace constant uuid := '00000000-0000-4000-8000-000000000001'; v_count integer;
begin
  if auth.uid() is null or not public.has_workspace_access() then raise exception 'Valid invitation link required'; end if;
  update public.edit_lock
     set expires_at = now() + make_interval(secs => greatest(60, least(coalesce(p_lease_seconds,120), 300))),
         updated_at = now()
   where user_id = v_workspace and session_id = p_session_id and expires_at > now();
  get diagnostics v_count = row_count;
  return v_count = 1;
end;
$$;

create or replace function public.release_edit_lock(p_session_id text)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare v_workspace constant uuid := '00000000-0000-4000-8000-000000000001'; v_count integer;
begin
  if auth.uid() is null or not public.has_workspace_access() then raise exception 'Valid invitation link required'; end if;
  delete from public.edit_lock where user_id = v_workspace and session_id = p_session_id;
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
