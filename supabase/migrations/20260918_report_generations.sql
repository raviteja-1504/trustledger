-- Migration: report generation history (compliance overhaul -- Reports phase 3)
--
-- Generating a compliance report previously left no persisted trace at
-- all beyond a generic audit_log entry -- no queryable record of who
-- generated what, for which framework/period, or with what signature.
-- A real compliance report needs that traceability (was this the report
-- an auditor was actually handed, and when). Metadata only -- the PDF
-- itself is not stored here; it's regenerable on demand from the same
-- DB data, and storing every generated PDF forever would reintroduce
-- the unbounded-storage-growth pattern already fixed elsewhere this
-- session (scan_files.content duplication).
create table if not exists report_generations (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid not null references organizations(id),
  framework     text not null,
  period_start  timestamptz not null,
  period_end    timestamptz not null,
  generated_by  uuid references auth.users(id),
  generated_by_email text,
  signature     text not null,
  created_at    timestamptz not null default now()
);

create index if not exists report_generations_org_created_idx
  on report_generations (org_id, created_at desc);

alter table report_generations enable row level security;

create policy "report_generations_select_own_org" on report_generations
  for select using (org_id = current_org_id());

create policy "report_generations_insert_own_org" on report_generations
  for insert with check (org_id = current_org_id());

-- Deliberately no update/delete policy -- a generation record, once
-- written, is a historical fact.
