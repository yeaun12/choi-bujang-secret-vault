-- Stage 11: additive, server-only WebAuthn device registry. No existing data is updated.
create table if not exists public.stage11_device_credentials (
  credential_id text primary key,
  owner_id uuid not null,
  public_key_jwk jsonb not null,
  sign_count bigint not null default 0 check (sign_count >= 0),
  approved_at timestamptz not null default now(),
  revoked_at timestamptz
);
create index if not exists stage11_credentials_owner on public.stage11_device_credentials(owner_id);
create table if not exists public.stage11_device_challenges (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  kind text not null check (kind in ('register','request')),
  challenge text not null,
  request_method text,
  request_path text,
  body_sha256 text,
  expires_at timestamptz not null,
  consumed_at timestamptz
);
create index if not exists stage11_challenges_owner on public.stage11_device_challenges(owner_id, kind, expires_at);
alter table public.stage11_device_credentials enable row level security;
alter table public.stage11_device_challenges enable row level security;
revoke all on public.stage11_device_credentials from PUBLIC, anon, authenticated;
revoke all on public.stage11_device_challenges from PUBLIC, anon, authenticated;
grant select, insert, update on public.stage11_device_credentials to service_role;
grant select, insert, update on public.stage11_device_challenges to service_role;
-- Never expose private per-user device state or pending one-use challenges to client DB roles.
