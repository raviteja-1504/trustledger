-- Server-side store for policy-violation status overrides.
--
-- The Violations page (and the Sidebar badge) derive a live list of
-- "violations" on the fly from dashboard data (deriveViolations() in
-- src/lib/violations.ts) rather than reading rows from the `violations`
-- table directly -- some of those derived items (deploy_blocked,
-- ai_threshold, no_reviewer) are repo-level rollups with no single
-- (scan_id, file_path) row to attach a status to. Whether a given derived
-- violation is open/in_review/resolved was therefore tracked ONLY in
-- localStorage (tl_violation_statuses), so resolving one on one device or
-- browser never showed up anywhere else -- the exact "different values on
-- different sessions" bug reported for the sidebar badges. This table
-- gives that status a real, org-scoped, server-side home, keyed by the
-- same synthetic violation id the client already computes.

create table if not exists violation_overrides (
  org_id         uuid not null references organizations(id) on delete cascade,
  violation_id   text not null,
  status         text not null default 'open' check (status in ('open','in_review','resolved')),
  assigned_email text,
  note           text,
  escalated      boolean not null default false,
  updated_by     uuid references auth.users(id),
  updated_at     timestamptz not null default now(),
  primary key (org_id, violation_id)
);

create index if not exists violation_overrides_org_status on violation_overrides (org_id, status);

alter table violation_overrides enable row level security;

create policy "violation_overrides_own_org" on violation_overrides
  for all using (org_id = current_org_id());
