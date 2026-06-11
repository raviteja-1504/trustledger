-- ============================================================
-- TrustLedger Development Seed Data
-- Run with: supabase db seed
-- Or via psql: psql $DATABASE_URL < supabase/seed.sql
-- ============================================================

-- ── Dev organisation ─────────────────────────────────────────────────────────
insert into organizations (id, slug, name, github_org, plan)
values (
  '00000000-0000-0000-0000-000000000001',
  'dev-org',
  'Dev Organisation',
  'dev-org',
  'growth'
) on conflict (slug) do nothing;

-- ── Dev user (Supabase Auth uid — replace with real uid after first sign-in) ──
-- The auth.users row is created by Supabase Auth on first login.
-- This seed just creates the org_members record.
-- Replace 'REPLACE_WITH_YOUR_USER_ID' with the UUID from auth.users.
-- You can find it in: Supabase Dashboard → Authentication → Users

-- insert into org_members (org_id, user_id, email, name, role)
-- values (
--   '00000000-0000-0000-0000-000000000001',
--   'REPLACE_WITH_YOUR_USER_ID',
--   'your@email.com',
--   'Your Name',
--   'admin'
-- ) on conflict (org_id, user_id) do nothing;

-- ── Sample repositories ───────────────────────────────────────────────────────
insert into repositories (org_id, repo_full_name, default_branch)
values
  ('00000000-0000-0000-0000-000000000001', 'dev-org/payments-api',    'main'),
  ('00000000-0000-0000-0000-000000000001', 'dev-org/auth-service',    'main'),
  ('00000000-0000-0000-0000-000000000001', 'dev-org/fraud-detection', 'main')
on conflict (org_id, repo_full_name) do nothing;

-- ── Sample scan ───────────────────────────────────────────────────────────────
insert into scans (id, org_id, repo_full_name, pr_number, commit_sha, overall_risk, total_ai_percentage, file_count, triggered_by)
values (
  '00000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000001',
  'dev-org/payments-api',
  42,
  'abc123def456',
  'CRITICAL',
  0.71,
  5,
  'manual'
) on conflict (id) do nothing;

-- ── Sample scan files ─────────────────────────────────────────────────────────
insert into scan_files (scan_id, org_id, file_path, language, ai_percentage, risk_score, risk_indicators, line_count)
values
  ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001',
   'src/processors/card_validator.py', 'python', 0.91, 'CRITICAL',
   array['sql-injection','hardcoded-secret','eval-exec'], 120),
  ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001',
   'src/gateway/stripe_client.py', 'python', 0.76, 'HIGH',
   array['hardcoded-secret'], 85),
  ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001',
   'src/utils/currency_formatter.py', 'python', 0.21, 'LOW',
   array['comment-density'], 45)
on conflict (scan_id, file_path) do nothing;

-- ── Sample violations ─────────────────────────────────────────────────────────
insert into violations (org_id, scan_id, file_path, risk_score, sla_deadline)
values
  ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002',
   'src/processors/card_validator.py', 'CRITICAL',
   now() + interval '24 hours'),
  ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002',
   'src/gateway/stripe_client.py', 'HIGH',
   now() + interval '48 hours')
on conflict (scan_id, file_path) do nothing;

-- ── Sample incident ───────────────────────────────────────────────────────────
insert into incidents (org_id, title, description, severity, status, incident_type, affected_repo, detected_at, timeline, stakeholders, playbook)
values (
  '00000000-0000-0000-0000-000000000001',
  'Production API key committed to source control',
  'A live Stripe API key was found in card_validator.py. Treat as compromised.',
  'P1',
  'active',
  'secret-exposed',
  'dev-org/payments-api',
  now() - interval '2 hours',
  '[{"time": "' || now()::text || '", "action": "Incident created", "actor": "TrustLedger"}]',
  '["security@dev-org.io"]',
  '[]'
) on conflict do nothing;

-- ── Sample org policy ────────────────────────────────────────────────────────
update organizations
set
  ai_threshold       = 0.80,
  attest_sla_hours   = 24,
  block_on_critical  = true,
  block_on_high      = false
where id = '00000000-0000-0000-0000-000000000001';
