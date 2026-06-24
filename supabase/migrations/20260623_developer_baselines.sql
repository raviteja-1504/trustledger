-- Developer baseline table: rolling average of each author's PR patterns
-- Used to detect deviation from historical behavior (Phase 3 of multi-signal scoring)
CREATE TABLE IF NOT EXISTS developer_baselines (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  github_login    text NOT NULL,
  pr_count        integer NOT NULL DEFAULT 0,        -- number of PRs used to build baseline
  avg_loc_per_pr  float   NOT NULL DEFAULT 0,        -- average lines added per PR
  avg_commits_per_pr float NOT NULL DEFAULT 0,       -- average commits per PR
  avg_files_per_pr   float NOT NULL DEFAULT 0,       -- average files changed per PR
  avg_ai_percentage  float NOT NULL DEFAULT 0,       -- historical average AI% per PR
  last_updated    timestamptz NOT NULL DEFAULT NOW(),
  UNIQUE(org_id, github_login)
);

CREATE INDEX IF NOT EXISTS idx_developer_baselines_org_login
  ON developer_baselines(org_id, github_login);
