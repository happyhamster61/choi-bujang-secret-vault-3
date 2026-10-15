-- Stage 10 original migration was applied as stage10_private_verified_note_backup.
-- One-time, pre-attack snapshot: NEVER refresh a previously captured baseline.
-- Only the original virtual account B's single note is copied, not other rows.
create table if not exists public.stage10_note_backups (
  note_uuid uuid primary key, owner_id uuid not null, title text not null,
  content text not null,
  content_sha256 text not null check (content_sha256 ~ '^[a-f0-9]{64}$'),
  verified_at timestamptz not null, baseline_commit text not null
);
create table if not exists public.stage10_restore_audit (
  id bigint generated always as identity primary key,
  note_uuid uuid not null, actor_owner_id uuid not null,
  restored_at timestamptz not null default now(),
  action text not null default 'single_note_restore'
);
alter table public.stage10_note_backups enable row level security;
alter table public.stage10_restore_audit enable row level security;
revoke all on table public.stage10_note_backups from public, anon, authenticated;
revoke all on table public.stage10_restore_audit from public, anon, authenticated;
do $$
declare current_note_count integer;
begin
  select count(*) into current_note_count from public.training_notes;
  if current_note_count <> 6 or exists(select 1 from public.stage10_note_backups)
      or (select count(*) from (
        select owner_id from public.training_notes where owner_id is not null
        group by owner_id having count(*) = 4
      ) a) <> 1
      or (select count(*) from (
        select owner_id from public.training_notes where owner_id is not null
        group by owner_id having count(*) = 1
      ) b) <> 1
      or (select count(*) from public.training_notes where owner_id is null) <> 1 then
    raise exception 'Stage10 clean pre-attack baseline not established';
  end if;
  insert into public.stage10_note_backups
    (note_uuid, owner_id, title, content, content_sha256, verified_at, baseline_commit)
    select note_uuid,owner_id,title,content,
      encode(extensions.digest(content,'sha256'),'hex'),transaction_timestamp(),
      'cbdbbed3bb5f2c97bb5efeb82c0d9e7ef750c27c'
    from public.training_notes
    where owner_id in (
      select owner_id from public.training_notes where owner_id is not null
      group by owner_id having count(*)=1
    );
  if (select count(*) from public.stage10_note_backups) <> 1
      or exists (
        select 1 from public.stage10_note_backups b
        left join public.training_notes n on n.note_uuid=b.note_uuid
        where n.note_uuid is null or b.owner_id is distinct from n.owner_id
          or b.title is distinct from n.title
          or b.content_sha256 is distinct from encode(extensions.digest(n.content,'sha256'),'hex')
      ) then raise exception 'Stage10 baseline mismatch'; end if;
end $$;

CREATE OR REPLACE FUNCTION public.stage10_restore_verified_note(p_note_uuid uuid, p_owner_id uuid)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public'
AS $function$
declare
  snapshot public.stage10_note_backups%rowtype;
  existing_owner uuid;
  existing boolean;
  resulting_hash text;
begin
  if p_note_uuid is null or p_owner_id is null then
    raise exception 'restore_identity_required';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_note_uuid::text, 0));
  select * into snapshot
    from public.stage10_note_backups
    where note_uuid = p_note_uuid and owner_id = p_owner_id
    for share;
  if not found
    or snapshot.content_sha256 <> encode(extensions.digest(snapshot.content, 'sha256'), 'hex')
    or snapshot.verified_at is null
    or snapshot.baseline_commit <> 'cbdbbed3bb5f2c97bb5efeb82c0d9e7ef750c27c' then
    raise exception 'verified_backup_not_found';
  end if;

  select exists(select 1 from public.training_notes where note_uuid = p_note_uuid)
    into existing;
  if existing then
    select owner_id into existing_owner
      from public.training_notes where note_uuid = p_note_uuid for update;
    if existing_owner is distinct from p_owner_id then
      raise exception 'restore_owner_mismatch';
    end if;
    update public.training_notes
      set title = snapshot.title, content = snapshot.content
      where note_uuid = p_note_uuid and owner_id = p_owner_id;
  else
    insert into public.training_notes (note_uuid, owner_id, title, content)
      values (snapshot.note_uuid, snapshot.owner_id, snapshot.title, snapshot.content);
  end if;

  select encode(extensions.digest(content, 'sha256'), 'hex') into resulting_hash
    from public.training_notes
    where note_uuid = p_note_uuid and owner_id = p_owner_id;
  if resulting_hash is distinct from snapshot.content_sha256 then
    raise exception 'restore_integrity_failed';
  end if;
  insert into public.stage10_restore_audit (note_uuid, actor_owner_id)
    values (p_note_uuid, p_owner_id);
  return p_note_uuid;
end $function$;
revoke all on function public.stage10_restore_verified_note(uuid,uuid)
  from public, anon, authenticated;
grant execute on function public.stage10_restore_verified_note(uuid,uuid)
  to service_role;
