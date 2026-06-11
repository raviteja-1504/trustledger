-- ── Two-Factor Authentication ────────────────────────────────────────────────
create table user_2fa (
  user_id      uuid primary key references auth.users(id) on delete cascade,
  enabled      boolean not null default false,
  secret       text,              -- TOTP secret (base32, encrypted in prod)
  backup_codes text[] default '{}',
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

alter table user_2fa enable row level security;
create policy "user_2fa_own" on user_2fa
  for all using (user_id = auth.uid());

-- ── User profiles ─────────────────────────────────────────────────────────────
create table user_profiles (
  user_id        uuid primary key references auth.users(id) on delete cascade,
  display_name   text,
  bio            text,
  avatar_url     text,
  github_login   text,
  timezone       text default 'UTC',
  locale         text default 'en',
  theme          text default 'system' check (theme in ('light','dark','system')),
  notification_digest_day text default 'monday'
    check (notification_digest_day in ('monday','tuesday','wednesday','thursday','friday','saturday','sunday','never')),
  updated_at     timestamptz not null default now()
);

alter table user_profiles enable row level security;
create policy "user_profiles_own" on user_profiles
  for all using (user_id = auth.uid());
create policy "user_profiles_read_org" on user_profiles
  for select using (
    exists (
      select 1 from org_members om1
      join org_members om2 on om1.org_id = om2.org_id
      where om1.user_id = auth.uid() and om2.user_id = user_profiles.user_id
    )
  );

-- ── Integration tokens (encrypted at rest in prod) ────────────────────────────
create table integration_tokens (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references organizations(id) on delete cascade,
  provider   text not null,   -- 'gitlab' | 'bitbucket' | 'jira' | 'linear' | 'pagerduty'
  token      text not null,   -- in production: pgp_sym_encrypt(token, key)
  username   text,
  workspace  text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (org_id, provider)
);

alter table integration_tokens enable row level security;
create policy "integration_tokens_own_org" on integration_tokens
  for all using (org_id = current_org_id());

-- ── Notification delivery log ─────────────────────────────────────────────────
create table notification_log (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references organizations(id) on delete cascade,
  user_id      uuid references auth.users(id),
  type         text not null,   -- 'alert' | 'sla' | 'weekly' | 'invite' | 'scan'
  channel      text not null,   -- 'email' | 'slack' | 'teams' | 'in_app'
  title        text not null,
  delivered    boolean not null default false,
  error_msg    text,
  created_at   timestamptz not null default now()
);

create index on notification_log (org_id, user_id, created_at desc);
create index on notification_log (org_id, type, created_at desc);

alter table notification_log enable row level security;
create policy "notif_log_own_org" on notification_log
  for select using (org_id = current_org_id());
