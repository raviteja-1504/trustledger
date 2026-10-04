-- Operational events: a short-retention timeline of what the system did, for tracing problems.
--
-- One row per notable step — a GitHub webhook received, a scan queued / started / finished / failed, a check run
-- updated, an API request that failed. Rows that belong together share a trace_id, so the Trace page can show
-- "webhook → queue → worker → check run" for one pull request. Kept 30 days (the daily pipeline-health job deletes
-- older rows). Written only by the server (service role); no client access.

create table if not exists ops_events (
  id           bigint generated always as identity primary key,
  created_at   timestamptz not null default now(),
  org_id       uuid,
  trace_id     text not null,
  kind         text not null,             -- e.g. webhook.received, scan.queued, scan.started, scan.completed, scan.failed
  level        text not null default 'info' check (level in ('info', 'warn', 'error')),
  message      text,
  scan_id      uuid,
  delivery_id  text,
  repo         text,
  pr_number    integer,
  ref_id       text,                      -- the reference shown to users on an error response
  duration_ms  integer,
  data         jsonb not null default '{}'::jsonb
);

create index if not exists ops_events_org_created_idx on ops_events (org_id, created_at desc);
create index if not exists ops_events_trace_idx       on ops_events (trace_id);
create index if not exists ops_events_scan_idx        on ops_events (scan_id) where scan_id is not null;
create index if not exists ops_events_repo_pr_idx     on ops_events (repo, pr_number) where repo is not null;
create index if not exists ops_events_ref_idx         on ops_events (ref_id) where ref_id is not null;
create index if not exists ops_events_kind_created_idx on ops_events (kind, created_at desc);

alter table ops_events enable row level security;
-- No policies: only the service role (server code) can read or write.
