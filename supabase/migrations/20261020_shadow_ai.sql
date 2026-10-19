-- Migration: Shadow AI -- an org's approved AI tools, and triage of AI-tool detections.
--
-- Detections themselves are not stored here: they are derived from data every scan already persists
-- (scans.ai_tooling -- explicit evidence such as .cursorrules or "Co-authored-by: Claude"; scan_files.attribution
-- -- per-file style guesses), see src/lib/shadowAi.ts. This only adds what people decide about them.
--
-- Best-effort, like finding_triage: before this migration is applied, /api/shadow-ai still lists detections,
-- with no saved policy (nothing is a violation yet) and no saved triage.

-- { "allowed": ["github-copilot", ...], "updated_at": "...", "updated_by": "email" }. NULL = not configured.
alter table organizations add column if not exists ai_tool_policy jsonb;

create table if not exists shadow_ai_triage (
  org_id           uuid not null references organizations(id) on delete cascade,
  -- Stable per (repo, tool, evidence location): "<repo>|<tool>|<file or commit:sha>". See shadowAi.ts detectionKey().
  detection_key    text not null,
  status           text not null default 'open' check (status in ('open', 'investigating', 'acceptable', 'resolved')),
  -- [{ "at": "...", "by": "email", "text": "..." }]
  notes            jsonb not null default '[]'::jsonb,
  updated_by_email text,
  updated_at       timestamptz not null default now(),
  primary key (org_id, detection_key)
);

alter table shadow_ai_triage enable row level security;
create policy "shadow_ai_triage_select_own_org" on shadow_ai_triage for select using (org_id = current_org_id());
-- Writes go through /api/shadow-ai (service role), which enforces permissions and writes the audit log.
