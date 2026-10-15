-- Stage 8: new resource types live separately from existing training_notes.
-- Run in the Supabase SQL Editor using the trusted database administrator.
-- Existing note UUIDs, owners and contents are not modified.
create table if not exists public.training_zone_resources (
  resource_id uuid primary key default gen_random_uuid(),
  zone text not null check (zone in ('class_announcement', 'instructor_material')),
  class_id uuid not null,
  title text not null,
  content text not null,
  created_at timestamptz not null default now()
);
create index if not exists training_zone_resources_scope_idx
  on public.training_zone_resources (class_id, zone, resource_id);

-- These rows are provisioned by an administrator, NOT from an API request.
create table if not exists public.training_class_memberships (
  class_id uuid not null,
  user_id uuid not null,
  role text not null check (role in ('student', 'instructor')),
  primary key (class_id, user_id)
);
create index if not exists training_class_memberships_user_idx
  on public.training_class_memberships(user_id, class_id);

alter table public.training_zone_resources enable row level security;
alter table public.training_class_memberships enable row level security;
revoke all on table public.training_zone_resources from anon, authenticated;
revoke all on table public.training_class_memberships from anon, authenticated;
-- Server-side service key access is required. Do not grant clients direct access.
