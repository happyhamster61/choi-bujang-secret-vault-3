-- Add an API-facing UUID without replacing the existing bigint identity or its rows.
alter table public.training_notes
  add column if not exists note_uuid uuid;

update public.training_notes
set note_uuid = gen_random_uuid()
where note_uuid is null;

alter table public.training_notes
  alter column note_uuid set default gen_random_uuid(),
  alter column note_uuid set not null;

create unique index if not exists training_notes_note_uuid_uidx
  on public.training_notes (note_uuid);
