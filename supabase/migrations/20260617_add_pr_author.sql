-- Phase 2: developer-scoped views
-- Add pr_author (GitHub login of the PR opener) to scans table so we can
-- filter API responses to only show a developer their own PRs.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS pr_author text;

-- Index for fast per-author queries in /api/dashboard and /api/scans
CREATE INDEX IF NOT EXISTS idx_scans_pr_author ON scans (org_id, pr_author);

-- Backfill is not possible without GitHub API calls, so existing rows stay NULL.
-- New scans from the webhook will populate pr_author going forward.
