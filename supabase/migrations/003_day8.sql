-- ── IP allowlist column for API keys ─────────────────────────────────────────
alter table api_keys add column if not exists ip_allowlist text[] default '{}';

-- ── Microsoft Teams webhook in org settings ───────────────────────────────────
alter table organizations add column if not exists teams_webhook text;

-- ── Retention policy column ────────────────────────────────────────────────────
alter table organizations add column if not exists retention_policy jsonb default '{
  "scans_days": 365,
  "audit_log_days": 2555,
  "violations_days": 365,
  "secret_findings_days": 365,
  "incidents_days": 2555
}';

-- ── Webhook retry tracking ────────────────────────────────────────────────────
alter table webhook_configs add column if not exists retry_count int not null default 0;
alter table webhook_configs add column if not exists next_retry_at timestamptz;
alter table webhook_configs add column if not exists permanently_failed boolean not null default false;

-- ── Platform admin role ────────────────────────────────────────────────────────
alter table org_members drop constraint if exists org_members_role_check;
alter table org_members add constraint org_members_role_check
  check (role in ('platform_admin','admin','security_reviewer','developer','auditor','viewer'));

-- ── Scan schedule cron table (created in 002, adding indexes) ─────────────────
create index if not exists scan_schedules_org_enabled_idx on scan_schedules (org_id, enabled);

-- ── GDPR audit events ─────────────────────────────────────────────────────────
-- Existing audit_log table covers this — no schema change needed.
-- Just ensure relevant event types are well-defined.
comment on column audit_log.event_type is
  'Values: scan_complete | attestation | merge_blocked | merge_allowed |
   policy_violation | policy_change | secret_detected | integration_connected |
   user_added | user_removed | sla_breach | alert_fired | alert_resolved |
   incident_created | incident_resolved | api_key_created | api_key_revoked |
   violation_resolved | violation_escalated | report_generated |
   org_settings_changed | data_deletion | gdpr_export | account_deletion';
