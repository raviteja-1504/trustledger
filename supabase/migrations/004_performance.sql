-- ============================================================
-- Performance Indexes + Query Optimisation (Day 10)
-- ============================================================

-- ── Full-text search indexes (pg_trgm for ILIKE queries) ──────────────────────
create extension if not exists pg_trgm;

-- violations.file_path — heavily filtered
create index if not exists idx_violations_file_path_trgm
  on violations using gin (file_path gin_trgm_ops);

-- scans.repo_full_name — most common filter
create index if not exists idx_scans_repo_trgm
  on scans using gin (repo_full_name gin_trgm_ops);

-- secret_findings.label — search by label
create index if not exists idx_secrets_label_trgm
  on secret_findings using gin (label gin_trgm_ops);

-- incidents.title — full-text search
create index if not exists idx_incidents_title_trgm
  on incidents using gin (title gin_trgm_ops);

-- audit_log.event_type — frequent filter
create index if not exists idx_audit_log_event_type
  on audit_log (org_id, event_type, created_at desc);

-- audit_log.actor_email
create index if not exists idx_audit_log_actor_email_trgm
  on audit_log using gin (actor_email gin_trgm_ops);

-- ── Composite indexes for common query patterns ───────────────────────────────

-- Dashboard: scans by org + date (most queried)
create index if not exists idx_scans_org_created
  on scans (org_id, created_at desc)
  include (repo_full_name, overall_risk, total_ai_percentage, file_count);

-- Violations: open violations per org (sidebar badge)
create index if not exists idx_violations_org_status
  on violations (org_id, status, risk_score)
  include (scan_id, file_path, sla_deadline);

-- Attestations: lookup by scan+file (most common query)
create index if not exists idx_attestations_scan_file
  on attestations (scan_id, file_path)
  include (reviewer_email, payload_hash, created_at);

-- Scan files: by org+risk (top risk files panel)
create index if not exists idx_scan_files_org_risk
  on scan_files (org_id, risk_score, ai_percentage desc)
  include (scan_id, file_path, risk_indicators);

-- Alerts: firing alerts per org (very hot path — sidebar badge)
create index if not exists idx_alerts_org_status_fired
  on alerts (org_id, status, severity, fired_at desc)
  include (title, body, repo);

-- Incidents: active incidents per org (sidebar badge)
create index if not exists idx_incidents_org_status
  on incidents (org_id, status, severity, detected_at desc)
  include (title, affected_repo);

-- Secret findings: open secrets per org
create index if not exists idx_secrets_org_status
  on secret_findings (org_id, status, severity)
  include (file_path, label, created_at);

-- Webhook configs: enabled webhooks per org
create index if not exists idx_webhook_configs_org_enabled
  on webhook_configs (org_id, enabled)
  include (url, events, last_delivery_status);

-- API keys: by hash (auth path — must be fast)
-- Already exists from 001, but ensure it's a btree not default
drop index if exists api_keys_key_hash_idx;
create unique index if not exists idx_api_keys_hash
  on api_keys (key_hash)
  include (org_id, revoked, expires_at);

-- ── Partial indexes (only index what's queried) ────────────────────────────────

-- Open violations only (partial — most queries filter status='open')
create index if not exists idx_violations_open_only
  on violations (org_id, risk_score, created_at desc)
  where status in ('open', 'in_review');

-- Active alerts only
create index if not exists idx_alerts_firing_only
  on alerts (org_id, severity, fired_at desc)
  where status = 'firing';

-- Active incidents
create index if not exists idx_incidents_active_only
  on incidents (org_id, severity, detected_at desc)
  where status in ('active', 'contained');

-- Non-revoked API keys
create index if not exists idx_api_keys_active_only
  on api_keys (key_hash)
  where revoked = false;

-- ── Query planner hints ──────────────────────────────────────────────────────
-- Tell the planner that scans.created_at is frequently queried
alter table scans        cluster on idx_scans_org_created;
alter table violations   cluster on idx_violations_org_status;
alter table audit_log    cluster on idx_audit_log_event_type;

-- ── Connection pooling recommendation ────────────────────────────────────────
comment on schema public is
  'TrustLedger — use PgBouncer or Supabase connection pooling (transaction mode) in production.
   Set pool_size=20 for typical workloads, 50 for high-traffic.
   Use prepared statement caching for dashboard queries.';

-- ── Row estimates (help query planner) ───────────────────────────────────────
analyze scans;
analyze violations;
analyze scan_files;
analyze attestations;
analyze audit_log;
analyze alerts;
