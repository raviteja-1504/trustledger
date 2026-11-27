-- One child per parent: the audit chain cannot fork.
--
-- Entries link by prev_hash. Two writers that read the same newest entry at the same moment (two server instances; the
-- in-process lock cannot see across instances) used to both append to it, forking the chain. With this index the second
-- insert fails (unique_violation, 23505) and lib/audit.ts re-reads the new tail and appends after it instead. The first
-- entry of an org has prev_hash NULL, so NULL is mapped to 'GENESIS' to make "two genesis entries" a violation too.
--
-- A chain that ALREADY has a fork cannot be indexed: the statement is skipped with a notice and the fork stays visible
-- (verification reports FORK_DETECTED and no checkpoint is signed over it) until it is investigated.
DO $$
BEGIN
  CREATE UNIQUE INDEX IF NOT EXISTS audit_log_one_child_per_parent
    ON audit_log (org_id, (COALESCE(prev_hash, 'GENESIS')));
EXCEPTION WHEN unique_violation THEN
  RAISE NOTICE 'audit_log_one_child_per_parent not created: an organisation already has two entries with the same parent (a fork). Resolve it, then run this migration again.';
END $$;
