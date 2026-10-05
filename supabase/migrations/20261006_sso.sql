-- ============================================================
-- SAML SSO (Supabase Auth SSO providers), domain verification, and the same sign-in rules for direct
-- database reads as for the API.
-- ============================================================

-- ── One SSO connection per org ─────────────────────────────────────────────────
create table if not exists sso_connections (
  org_id         uuid primary key references organizations(id) on delete cascade,
  provider_id    text unique,                 -- Supabase Auth SSO provider id (null until the IdP is registered)
  idp_entity_id  text,
  metadata_url   text,
  jit_enabled    boolean not null default true,
  jit_role       text not null default 'developer' check (jit_role in ('developer', 'security_reviewer')),
  enforce_sso    boolean not null default false,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

-- ── Email domains an org claims, proved by a DNS TXT record ─────────────────────
create table if not exists sso_domains (
  id                  uuid primary key default gen_random_uuid(),
  org_id              uuid not null references organizations(id) on delete cascade,
  domain              text not null,
  verification_token  text not null,
  verified_at         timestamptz,
  created_at          timestamptz not null default now(),
  unique (org_id, domain)
);
-- Any org may start claiming a domain, but only one can ever hold it verified.
create unique index if not exists sso_domains_verified_once on sso_domains (domain) where verified_at is not null;

-- Server-only (service role): RLS on, no policies.
alter table sso_connections enable row level security;
alter table sso_domains     enable row level security;

-- ── Direct reads follow the API's sign-in rules ────────────────────────────────
-- current_org_id() scopes every browser read policy. It now yields the org only for a session the API would
-- also accept:
--   * 2FA on  → only the session that completed the 2FA step (org_members.active_session_id)
--   * a newer sign-in elsewhere revoked this session → nothing (single active session)
--   * the org enforces SSO → only a session from that org's IdP (admins exempt, as break-glass)
-- so a password-only session can no longer read org data around 2FA or SSO through PostgREST.
create or replace function current_org_id() returns uuid as $$
  select m.org_id
  from org_members m
  where m.user_id = auth.uid()
    and (
      (m.active_session_id is not null and m.active_session_id = (auth.jwt() ->> 'session_id'))
      or (m.active_session_id is null
          and not exists (select 1 from user_2fa f where f.user_id = m.user_id and f.enabled))
    )
    and (
      m.role = 'admin'
      or not exists (select 1 from sso_connections c where c.org_id = m.org_id and c.enforce_sso)
      or exists (
        select 1
        from sso_connections c, jsonb_array_elements(coalesce(auth.jwt() -> 'amr', '[]'::jsonb)) a
        where c.org_id = m.org_id and a ->> 'method' = 'sso/saml' and a ->> 'provider' = c.provider_id
      )
    )
  limit 1;
$$ language sql security definer stable set search_path = public;
