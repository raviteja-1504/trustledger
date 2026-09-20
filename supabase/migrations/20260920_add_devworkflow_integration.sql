-- Developer workflow / PR integration phase:
--   1. organizations.slack_webhook -- per-org Slack incoming webhook URL.
--      teams_webhook already exists (003_day8.sql) but was never wired into
--      the alert-delivery call sites; slack_webhook didn't exist at all.
--      Both were previously only ever saved to browser localStorage by the
--      Settings UI, so every org shared one global SLACK_WEBHOOK_URL env var.
--   2. scans.check_run_sync_error -- set when attestation's automatic
--      GitHub check-run flip-to-success fails (after one retry), so the PR
--      review page can surface a visible "GitHub status update failed —
--      Retry" banner instead of the failure being silently swallowed.
alter table organizations add column if not exists slack_webhook text;
alter table scans add column if not exists check_run_sync_error text;
