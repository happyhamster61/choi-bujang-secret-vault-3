-- Stage 11 applied as migration stage11_device_approval_proof.
-- Device approval is exclusively a trusted database operator action.
create table if not exists public.stage11_devices (
  device_id uuid primary key,
  owner_id uuid not null,
  public_jwk jsonb not null,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'revoked')),
  requested_at timestamptz not null default now(),
  approved_at timestamptz,
  constraint stage11_approved_at check(status <> 'approved' or approved_at is not null)
);
create index if not exists stage11_devices_owner_idx
  on public.stage11_devices(owner_id,status);
create table if not exists public.stage11_device_nonces (
  device_id uuid not null references public.stage11_devices(device_id) on delete cascade,
  nonce text not null,
  used_at timestamptz not null default now(),
  primary key (device_id,nonce)
);
alter table public.stage11_devices enable row level security;
alter table public.stage11_device_nonces enable row level security;
revoke all on public.stage11_devices from public, anon, authenticated;
revoke all on public.stage11_device_nonces from public, anon, authenticated;
-- Never auto-approve a registration or trust role/state in request body.
