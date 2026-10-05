-- ============================================================
-- Per-organisation SCIM tokens (replaces the single SCIM_TOKEN / SCIM_ORG_ID environment pair, which could
-- serve only one org). Only a SHA-256 hash of each token is stored; the token itself is shown once.
-- ============================================================

create table if not exists scim_tokens (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid not null unique references organizations(id) on delete cascade,  -- one active token per org
  token_hash    text not null unique,
  token_prefix  text not null,          -- first characters, to recognise a token in the UI
  created_by    uuid,
  created_at    timestamptz not null default now(),
  last_used_at  timestamptz
);

-- Server-only (service role): RLS on, no policies.
alter table scim_tokens enable row level security;
