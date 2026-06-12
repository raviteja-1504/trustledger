-- Persist scanned file content so attestation reviewers can see inline
-- source (highlighted risky lines) instead of "Source not available".
alter table scan_files add column if not exists content text;
