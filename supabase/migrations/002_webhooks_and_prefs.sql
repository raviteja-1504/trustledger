-- ── Outbound webhook configurations ──────────────────────────────────────────
create table webhook_configs (
  id                    uuid primary key default gen_random_uuid(),
  org_id                uuid not null references organizations(id) on delete cascade,
  url                   text not null,
  secret                text,                         -- HMAC signing secret
  events                text[] not null default '{}',
  enabled               boolean not null default true,
  created_by            uuid references auth.users(id),
  last_delivery_at      timestamptz,
  last_delivery_status  int,                          -- last HTTP response status
  created_at            timestamptz not null default now()
);

create index on webhook_configs (org_id);
alter table webhook_configs enable row level security;
create policy "webhook_configs_own_org" on webhook_configs
  for all using (org_id = current_org_id());

-- ── Notification preferences ──────────────────────────────────────────────────
create table notification_preferences (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references auth.users(id) on delete cascade,
  org_id          uuid not null references organizations(id) on delete cascade,

  -- Channel toggles
  email_enabled   boolean not null default true,
  slack_enabled   boolean not null default true,
  in_app_enabled  boolean not null default true,

  -- Severity filters (receive notifications only for these severities)
  min_severity    text not null default 'P2'   -- P1 | P2 | P3 | P4
    check (min_severity in ('P1','P2','P3','P4')),

  -- Event type subscriptions
  scan_completed  boolean not null default false,  -- too noisy for most users
  violation_opened boolean not null default true,
  alert_fired     boolean not null default true,
  attestation_reminder boolean not null default true,
  weekly_digest   boolean not null default true,

  updated_at      timestamptz not null default now(),
  unique (user_id, org_id)
);

alter table notification_preferences enable row level security;
create policy "notif_prefs_own" on notification_preferences
  for all using (user_id = auth.uid());

-- ── Webhook delivery log (for debugging) ──────────────────────────────────────
create table webhook_delivery_log (
  id          uuid primary key default gen_random_uuid(),
  webhook_id  uuid not null references webhook_configs(id) on delete cascade,
  org_id      uuid not null references organizations(id),
  event_type  text not null,
  status_code int,
  duration_ms int,
  success     boolean not null default false,
  error_msg   text,
  created_at  timestamptz not null default now()
);

create index on webhook_delivery_log (webhook_id, created_at desc);
alter table webhook_delivery_log enable row level security;
create policy "webhook_log_own_org" on webhook_delivery_log
  for select using (org_id = current_org_id());

-- ── Repository scanning schedule ──────────────────────────────────────────────
create table scan_schedules (
  id              uuid primary key default gen_random_uuid(),
  org_id          uuid not null references organizations(id) on delete cascade,
  repo_id         uuid not null references repositories(id) on delete cascade,
  cron_expression text not null default '0 2 * * *',  -- daily at 02:00 UTC
  branch          text not null default 'main',
  enabled         boolean not null default true,
  last_run_at     timestamptz,
  created_at      timestamptz not null default now(),
  unique (org_id, repo_id)
);

alter table scan_schedules enable row level security;
create policy "scan_schedules_own_org" on scan_schedules
  for all using (org_id = current_org_id());
