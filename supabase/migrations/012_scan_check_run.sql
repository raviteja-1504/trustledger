-- Persist the GitHub Check Run + installation so attestations can update
-- the PR's check status from "action_required" to "success" once all
-- CRITICAL/HIGH files have been attested.
alter table scans add column if not exists check_run_id bigint;
alter table scans add column if not exists installation_id bigint;
