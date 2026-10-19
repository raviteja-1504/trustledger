-- Migration: daily Trust Score snapshots (src/lib/governanceScore.ts), so the score has a real history.
--
-- One row per org per day, written by /api/trust-score (whenever the page is opened) and by the daily
-- pipeline-health cron (so days nobody looked are still recorded). The latest computation of the day wins.
-- Best-effort: before this migration is applied, the score is still computed live; only the history is empty.
create table if not exists trust_score_history (
  org_id       uuid not null references organizations(id) on delete cascade,
  day          date not null,
  total        int  not null check (total between 0 and 1000),
  -- { "exposure": 0.82, "review": 0.6, ... } -- each dimension's 0-1 value
  dimensions   jsonb not null,
  -- [{ "repo": "acme/app", "score": 740 }, ...]
  repo_scores  jsonb not null default '[]'::jsonb,
  computed_at  timestamptz not null default now(),
  primary key (org_id, day)
);

alter table trust_score_history enable row level security;
create policy "trust_score_history_select_own_org" on trust_score_history for select using (org_id = current_org_id());
-- Writes go through the service role (/api/trust-score, the daily cron).
