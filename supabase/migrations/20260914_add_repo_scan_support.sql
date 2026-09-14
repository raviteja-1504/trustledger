-- Whole-repository scanning (Phase 2): a scan can now take a while to
-- produce results (fetching + analysing every file in a repo, not just a
-- PR's changed files), so callers need a status to poll instead of assuming
-- a scans row is always already-finished the moment it exists.

alter table scans add column if not exists status text not null default 'completed'
  check (status in ('queued','analyzing','completed','failed'));

alter table scans add column if not exists scan_mode text not null default 'pr'
  check (scan_mode in ('pr','repo'));

alter table scans add column if not exists error_message text;
alter table scans add column if not exists files_total   int;
alter table scans add column if not exists files_scanned int;

create index if not exists scans_status_idx on scans (org_id, status) where status <> 'completed';
