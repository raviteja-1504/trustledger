-- ============================================================
-- TrustLedger — Initial Schema
-- ============================================================
-- Enable UUID generation
create extension if not exists "pgcrypto";

-- ── Organizations ─────────────────────────────────────────────────────────────
create table organizations (
  id          uuid primary key default gen_random_uuid(),
  slug        text unique not null,
  name        text not null,
  github_org  text unique,           -- GitHub org handle (e.g. "novapay")
  plan        text not null default 'trial' check (plan in ('trial','starter','growth','enterprise')),
  ai_threshold        float  not null default 0.80,  -- flag repos above this AI%
  attest_sla_hours    int    not null default 24,    -- SLA for CRITICAL attestation
  block_on_critical   boolean not null default true,
  block_on_high       boolean not null default false,
  require_two_reviewers boolean not null default false,
  created_at  timestamptz not null default now()
);

-- ── Users & membership ────────────────────────────────────────────────────────
-- (auth.users is managed by Supabase Auth — we store profile / role here)
create table org_members (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references organizations(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  email      text not null,
  name       text,
  role       text not null default 'developer'
               check (role in ('admin','security_reviewer','developer','auditor','viewer')),
  github_login text,
  avatar_url   text,
  created_at   timestamptz not null default now(),
  unique (org_id, user_id)
);

-- ── Repositories ──────────────────────────────────────────────────────────────
create table repositories (
  id               uuid primary key default gen_random_uuid(),
  org_id           uuid not null references organizations(id) on delete cascade,
  repo_full_name   text not null,       -- "org/repo-name"
  default_branch   text not null default 'main',
  github_repo_id   bigint,
  is_active        boolean not null default true,
  created_at       timestamptz not null default now(),
  unique (org_id, repo_full_name)
);

-- ── Scans ─────────────────────────────────────────────────────────────────────
create table scans (
  id                  uuid primary key default gen_random_uuid(),
  org_id              uuid not null references organizations(id) on delete cascade,
  repo_id             uuid references repositories(id),
  repo_full_name      text not null,
  pr_number           int,
  commit_sha          text not null,
  branch              text,
  overall_risk        text not null default 'LOW'
                        check (overall_risk in ('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN')),
  total_ai_percentage float not null default 0,
  file_count          int   not null default 0,
  triggered_by        text not null default 'webhook'
                        check (triggered_by in ('webhook','api','manual','scheduled')),
  duration_ms         int,
  created_at          timestamptz not null default now()
);

-- ── Scan files ────────────────────────────────────────────────────────────────
create table scan_files (
  id               uuid primary key default gen_random_uuid(),
  scan_id          uuid not null references scans(id) on delete cascade,
  org_id           uuid not null,
  file_path        text not null,
  language         text,
  ai_percentage    float not null default 0,
  risk_score       text not null default 'LOW'
                     check (risk_score in ('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN')),
  risk_indicators  text[]   not null default '{}',
  content_hash     text,                -- SHA-256 of file content
  line_count       int,
  created_at       timestamptz not null default now(),
  unique (scan_id, file_path)
);

-- ── Attestations (IMMUTABLE — no UPDATE/DELETE allowed) ──────────────────────
create table attestations (
  id               uuid primary key default gen_random_uuid(),
  org_id           uuid not null references organizations(id),
  scan_id          uuid not null references scans(id),
  file_path        text not null,
  risk_score       text not null,
  reviewer_id      uuid references auth.users(id),
  reviewer_email   text not null,
  reviewer_github  text,
  payload_hash     text not null,       -- SHA-256(scan_id||file_path||reviewer_email||timestamp)
  created_at       timestamptz not null default now()
);
-- Prevent any updates or deletes — attestations are permanent records
create rule attestations_no_update as on update to attestations do instead nothing;
create rule attestations_no_delete as on delete to attestations do instead nothing;

-- ── Violations ────────────────────────────────────────────────────────────────
create table violations (
  id               uuid primary key default gen_random_uuid(),
  org_id           uuid not null references organizations(id),
  scan_id          uuid not null references scans(id),
  file_path        text not null,
  risk_score       text not null,
  status           text not null default 'open'
                     check (status in ('open','in_review','resolved','accepted')),
  assigned_to      uuid references auth.users(id),
  assigned_email   text,
  notes            jsonb not null default '[]',
  escalated        boolean not null default false,
  sla_deadline     timestamptz,
  resolved_at      timestamptz,
  resolved_by      uuid references auth.users(id),
  created_at       timestamptz not null default now(),
  unique (scan_id, file_path)
);

-- ── Secrets ───────────────────────────────────────────────────────────────────
create table secret_findings (
  id             uuid primary key default gen_random_uuid(),
  org_id         uuid not null references organizations(id),
  scan_id        uuid not null references scans(id),
  file_path      text not null,
  secret_type    text not null,
  severity       text not null check (severity in ('CRITICAL','HIGH','MEDIUM')),
  label          text not null,
  masked_value   text not null,
  line_number    int,
  status         text not null default 'open' check (status in ('open','resolved','false_positive')),
  resolved_by    uuid references auth.users(id),
  resolved_email text,
  resolved_at    timestamptz,
  created_at     timestamptz not null default now()
);

-- ── Incidents ─────────────────────────────────────────────────────────────────
create table incidents (
  id              uuid primary key default gen_random_uuid(),
  org_id          uuid not null references organizations(id),
  title           text not null,
  description     text,
  severity        text not null check (severity in ('P1','P2','P3','P4')),
  status          text not null default 'active'
                    check (status in ('active','contained','resolved','post-mortem')),
  incident_type   text not null,
  affected_repo   text,
  affected_file   text,
  impact          text,
  root_cause      text,
  lesson_learned  text,
  timeline        jsonb not null default '[]',
  stakeholders    jsonb not null default '[]',
  playbook        jsonb not null default '[]',
  related_cve     text,
  detected_at     timestamptz not null default now(),
  contained_at    timestamptz,
  resolved_at     timestamptz,
  created_by      uuid references auth.users(id),
  created_at      timestamptz not null default now()
);

-- ── Alerts ────────────────────────────────────────────────────────────────────
create table alerts (
  id               uuid primary key default gen_random_uuid(),
  org_id           uuid not null references organizations(id),
  alert_type       text not null,
  severity         text not null check (severity in ('P1','P2','P3','P4')),
  status           text not null default 'firing'
                     check (status in ('firing','acknowledged','snoozed','resolved')),
  title            text not null,
  body             text,
  repo             text,
  scan_id          uuid references scans(id),
  runbook_url      text,
  escalation_emails text[],
  acknowledged_by  uuid references auth.users(id),
  acknowledged_at  timestamptz,
  snooze_until     timestamptz,
  resolved_at      timestamptz,
  notes            jsonb not null default '[]',
  fired_at         timestamptz not null default now(),
  created_at       timestamptz not null default now()
);

-- ── Risk Register ─────────────────────────────────────────────────────────────
create table risk_register (
  id               uuid primary key default gen_random_uuid(),
  org_id           uuid not null references organizations(id),
  title            text not null,
  description      text,
  category         text not null,
  likelihood       int  not null check (likelihood between 1 and 5),
  impact           int  not null check (impact     between 1 and 5),
  treatment        text not null default 'mitigate'
                     check (treatment in ('mitigate','accept','transfer','avoid')),
  status           text not null default 'open'
                     check (status in ('open','mitigating','accepted','closed')),
  owner_id         uuid references auth.users(id),
  owner_email      text,
  due_date         date,
  mitigation       text,
  related_incident uuid references incidents(id),
  auto_derived     boolean not null default false,
  notes            jsonb not null default '[]',
  created_at       timestamptz not null default now()
);

-- ── Compliance exceptions ─────────────────────────────────────────────────────
create table compliance_exceptions (
  id               uuid primary key default gen_random_uuid(),
  org_id           uuid not null references organizations(id),
  framework_id     text not null,
  control_id       text not null,
  title            text not null,
  description      text,
  risk_accepted    boolean not null default false,
  owner_id         uuid references auth.users(id),
  owner_email      text,
  due_date         date,
  remediation      text,
  status           text not null default 'open'
                     check (status in ('open','in-progress','resolved')),
  created_at       timestamptz not null default now()
);

-- ── Audit log (append-only, tamper-evident hash chain) ───────────────────────
create table audit_log (
  id            bigserial primary key,           -- monotonic integer for ordering
  org_id        uuid not null references organizations(id),
  event_type    text not null,
  actor_id      uuid references auth.users(id),
  actor_email   text,
  resource_type text,
  resource_id   text,
  payload       jsonb not null default '{}',
  prev_hash     text,                            -- hash of previous row
  entry_hash    text not null,                   -- SHA-256(prev_hash||event_type||actor_email||payload||timestamp)
  created_at    timestamptz not null default now()
);
-- Prevent updates and deletes — audit log is immutable
create rule audit_log_no_update as on update to audit_log do instead nothing;
create rule audit_log_no_delete as on delete to audit_log do instead nothing;

-- ── GitHub App installations ──────────────────────────────────────────────────
create table github_installations (
  id                  uuid primary key default gen_random_uuid(),
  org_id              uuid not null references organizations(id),
  installation_id     bigint unique not null,
  github_org          text not null,
  access_token        text,                       -- encrypted via pgp_sym_encrypt
  token_expires_at    timestamptz,
  created_at          timestamptz not null default now()
);

-- ── API keys (for CI/CD integration) ─────────────────────────────────────────
create table api_keys (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references organizations(id) on delete cascade,
  name        text not null,
  key_hash    text not null unique,              -- SHA-256 of the actual key
  key_prefix  text not null,                    -- first 8 chars for display ("tl_live_ab12cd34...")
  created_by  uuid references auth.users(id),
  last_used   timestamptz,
  expires_at  timestamptz,
  revoked     boolean not null default false,
  created_at  timestamptz not null default now()
);

-- ── Webhook delivery log ──────────────────────────────────────────────────────
create table webhook_deliveries (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid references organizations(id),
  source        text not null,                   -- 'github', 'gitlab'
  event_type    text not null,
  payload       jsonb not null,
  signature_ok  boolean not null default false,
  processed     boolean not null default false,
  scan_id       uuid references scans(id),
  error         text,
  created_at    timestamptz not null default now()
);

-- ============================================================
-- INDEXES
-- ============================================================
create index on scans         (org_id, created_at desc);
create index on scans         (repo_full_name, created_at desc);
create index on scan_files    (scan_id);
create index on scan_files    (org_id, risk_score);
create index on attestations  (scan_id, file_path);
create index on attestations  (org_id, created_at desc);
create index on violations    (org_id, status);
create index on violations    (scan_id);
create index on secret_findings (org_id, status);
create index on incidents     (org_id, status);
create index on alerts        (org_id, status, fired_at desc);
create index on audit_log     (org_id, created_at desc);
create index on api_keys      (key_hash);

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================
alter table organizations        enable row level security;
alter table org_members          enable row level security;
alter table repositories         enable row level security;
alter table scans                enable row level security;
alter table scan_files           enable row level security;
alter table attestations         enable row level security;
alter table violations           enable row level security;
alter table secret_findings      enable row level security;
alter table incidents            enable row level security;
alter table alerts               enable row level security;
alter table risk_register        enable row level security;
alter table compliance_exceptions enable row level security;
alter table audit_log            enable row level security;
alter table github_installations enable row level security;
alter table api_keys             enable row level security;

-- Helper: get the org_id for the current user
create or replace function current_org_id() returns uuid as $$
  select org_id from org_members
  where user_id = auth.uid()
  limit 1;
$$ language sql security definer stable;

-- Policies — users see only their org's data
create policy "org_members_own_org" on org_members
  for all using (user_id = auth.uid() or org_id = current_org_id());

create policy "orgs_own" on organizations
  for all using (id = current_org_id());

create policy "repos_own_org" on repositories
  for all using (org_id = current_org_id());

create policy "scans_own_org" on scans
  for all using (org_id = current_org_id());

create policy "scan_files_own_org" on scan_files
  for all using (org_id = current_org_id());

create policy "attestations_own_org" on attestations
  for select using (org_id = current_org_id());
create policy "attestations_insert_own_org" on attestations
  for insert with check (org_id = current_org_id());

create policy "violations_own_org" on violations
  for all using (org_id = current_org_id());

create policy "secrets_own_org" on secret_findings
  for all using (org_id = current_org_id());

create policy "incidents_own_org" on incidents
  for all using (org_id = current_org_id());

create policy "alerts_own_org" on alerts
  for all using (org_id = current_org_id());

create policy "risk_register_own_org" on risk_register
  for all using (org_id = current_org_id());

create policy "compliance_exceptions_own_org" on compliance_exceptions
  for all using (org_id = current_org_id());

create policy "audit_log_own_org" on audit_log
  for select using (org_id = current_org_id());
create policy "audit_log_insert" on audit_log
  for insert with check (org_id = current_org_id());

create policy "gh_installations_own_org" on github_installations
  for all using (org_id = current_org_id());

create policy "api_keys_own_org" on api_keys
  for all using (org_id = current_org_id());

-- ============================================================
-- REALTIME (enable for live dashboard updates)
-- ============================================================
alter publication supabase_realtime add table scans;
alter publication supabase_realtime add table violations;
alter publication supabase_realtime add table attestations;
alter publication supabase_realtime add table alerts;
alter publication supabase_realtime add table incidents;
