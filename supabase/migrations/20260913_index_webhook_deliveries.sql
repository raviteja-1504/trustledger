-- webhook_deliveries had zero index beyond its primary key despite storing
-- the largest unbounded jsonb payload of any hot-path table (the full raw
-- webhook body per PR event, forever, with no retention). The only lookup
-- against it (api/sync-check-run/route.ts's crash-recovery path) filtered
-- with `ilike(payload::text, ...)` -- a sequential scan plus a jsonb-to-text
-- cast over every row for the org, getting slower every day as the table
-- grows with no bound. Adding repo_full_name as its own column lets that
-- lookup use a real index instead.

alter table webhook_deliveries add column if not exists repo_full_name text;

create index if not exists webhook_deliveries_org_repo_created
  on webhook_deliveries (org_id, repo_full_name, created_at desc);
