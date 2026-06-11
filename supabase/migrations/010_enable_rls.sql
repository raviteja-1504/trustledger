-- ============================================================
-- Migration 010: Enable Row Level Security on remaining tables
-- These tables are accessed only via service_role (server-side
-- API routes), which bypasses RLS — so enabling RLS with no
-- policies blocks direct anon/authenticated access via the
-- PostgREST API without affecting the app.
-- ============================================================

alter table alerts             enable row level security;
alter table api_keys           enable row level security;
alter table attestations       enable row level security;
alter table audit_log          enable row level security;
alter table incidents          enable row level security;
alter table org_members        enable row level security;
alter table organizations      enable row level security;
alter table repositories       enable row level security;
alter table risk_register      enable row level security;
alter table scan_files         enable row level security;
alter table scans              enable row level security;
alter table secret_findings    enable row level security;
alter table violations         enable row level security;
alter table webhook_deliveries enable row level security;
