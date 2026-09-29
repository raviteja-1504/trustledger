-- Migration: finding triage (accepted risk / false positive, with expiry) and scan health/telemetry.
--
-- finding_triage holds DECISIONS about a finding, keyed by the scanner's stable fingerprint
-- (src/lib/findingIdentity.ts), so a decision follows the finding across PRs and pushes. The finding's
-- lifecycle (new / existing / reopened / fixed) is derived from each PR's scan history and not stored here
-- (see src/lib/findingLifecycle.ts). A suppressed finding still appears in every scan; it just no longer
-- raises a merge-blocking violation.
--
-- All application reads/writes of these are best-effort: before this migration is applied, scans run
-- exactly as before and triage simply reads as empty.
create table if not exists finding_triage (
  org_id          uuid not null references organizations(id) on delete cascade,
  repo_full_name  text not null,
  fingerprint     text not null,
  rule_id         text not null,
  file_path       text,
  status          text not null check (status in ('accepted', 'false_positive')),
  reason          text,
  expires_at      timestamptz,
  set_by_email    text,
  set_at          timestamptz not null default now(),
  primary key (org_id, repo_full_name, fingerprint)
);

create index if not exists finding_triage_org_repo_idx on finding_triage (org_id, repo_full_name);

alter table finding_triage enable row level security;
create policy "finding_triage_select_own_org" on finding_triage for select using (org_id = current_org_id());
-- Writes go through /api/findings/* (service role), which enforces roles and writes the audit log.

-- What a scan could not fully analyze, and where its time went (src/lib/scanHealth.ts).
alter table scans add column if not exists health jsonb;
alter table scans add column if not exists telemetry jsonb;
