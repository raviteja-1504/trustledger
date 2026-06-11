-- ── Feature flags table ──────────────────────────────────────────────────────
create table feature_flags (
  id           uuid primary key default gen_random_uuid(),
  key          text unique not null,
  description  text,
  enabled      boolean not null default false,
  rollout_pct  int check (rollout_pct between 0 and 100),
  plans        text[],          -- null = all plans
  org_ids      text[],          -- null = all orgs
  updated_at   timestamptz not null default now()
);

-- Public read so clients can fetch flags without auth
alter table feature_flags enable row level security;
create policy "flags_public_read" on feature_flags
  for select using (true);
create policy "flags_service_write" on feature_flags
  for all using (auth.role() = 'service_role');

-- Seed default flags
insert into feature_flags (key, description, enabled, rollout_pct, plans) values
  ('beta_pr_comment_bot',  'Rich PR comment with full risk breakdown',        false, 50,  null),
  ('beta_scan_scheduling', 'Scheduled automatic repository scanning',         false, 20,  null),
  ('white_label',          'Custom branding and white-label support',         false, null, array['enterprise']),
  ('advanced_analytics',   'Trend analysis, velocity metrics, predictions',   false, null, array['growth','enterprise']),
  ('ai_attribution',       'Detect which AI model generated code',            true,  null, null),
  ('slack_commands',       'Slack /trustledger slash commands',                true,  null, null),
  ('realtime_presence',    'Show concurrent reviewers on PR page',            true,  null, null)
on conflict (key) do nothing;
