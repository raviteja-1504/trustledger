-- Migration: real persistence for compliance workflow state
--
-- Three of the four compliance surfaces (Compliance exceptions, Risk
-- Register workflow, Evidence collection) currently store their state in
-- localStorage only -- invisible to any other reviewer, lost on a new
-- device, with no audit trail. This migration gives them a real home.
--
-- risk_register already exists (001_initial.sql) with almost the exact
-- shape the Risk Register page needs -- it was simply never wired up
-- (same pattern as the Evidence GET endpoint: real backend, disconnected
-- frontend). This ALTERs it to add what's missing rather than creating a
-- parallel table.

-- external_id correlates a row to the page's derived-risk id scheme
-- (e.g. "DR-CRIT-UNATT-payments-api") so a fresh derivation on each page
-- load can be upserted onto existing human-set workflow state (status,
-- treatment, owner, notes) without clobbering it. Manual risks also get
-- an external_id (their own generated "MR-..." id) so both kinds of risk
-- go through the same upsert/update path.
alter table risk_register
  add column if not exists external_id         text,
  add column if not exists repo                text,
  add column if not exists related_cve         text,
  add column if not exists related_link        text,
  add column if not exists residual_likelihood smallint check (residual_likelihood between 1 and 5),
  add column if not exists residual_impact     smallint check (residual_impact between 1 and 5),
  add column if not exists updated_at          timestamptz not null default now(),
  add column if not exists updated_by          uuid references auth.users(id);

create unique index if not exists risk_register_org_external_idx
  on risk_register (org_id, external_id) where external_id is not null;

-- Evidence collection log -- append-only by design (no update/delete
-- policy below), matching audit_log's tamper-evident philosophy: a
-- correction is a new entry, never a silent edit of history. This is
-- what POST /api/evidence/collect should have written to all along
-- instead of fabricating rows into compliance_exceptions.
create table if not exists evidence_log (
  id                 uuid primary key default gen_random_uuid(),
  org_id             uuid not null references organizations(id),
  framework_id       text not null,
  control_id         text not null,
  note               text,
  file_url           text,
  collected_by       uuid references auth.users(id),
  collected_by_email text,
  created_at         timestamptz not null default now()
);

create index if not exists evidence_log_org_control_idx
  on evidence_log (org_id, framework_id, control_id, created_at desc);

alter table evidence_log enable row level security;

create policy "evidence_log_select_own_org" on evidence_log
  for select using (org_id = current_org_id());

create policy "evidence_log_insert_own_org" on evidence_log
  for insert with check (org_id = current_org_id());

-- Deliberately no update/delete policy for any role -- append-only.
