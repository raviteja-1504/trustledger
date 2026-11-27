-- One child per parent, for NEW entries only.
--
-- 20261128_audit_one_child_per_parent.sql builds a unique index over the whole table; Postgres refuses that while ANY organisation
-- still has an old fork, and that migration then skips the index (only a notice), leaving every organisation unprotected.
-- Old entries are immutable and cannot be repaired, so this index is partial: it covers only entries added after this
-- migration (id above the current newest). Historic forks stay visible to verification (FORK_DETECTED) but can no longer
-- block the protection, and no new fork can be created: a second writer is refused (unique_violation, 23505) and lib/audit.ts
-- re-reads the tail and appends after it.
DO $$
DECLARE
  cutoff bigint;
BEGIN
  SELECT COALESCE(MAX(id), 0) INTO cutoff FROM audit_log;
  IF to_regclass('public.audit_log_one_child_new_entries') IS NULL THEN
    EXECUTE format(
      'CREATE UNIQUE INDEX audit_log_one_child_new_entries ON audit_log (org_id, (COALESCE(prev_hash, ''GENESIS''))) WHERE id > %s',
      cutoff);
  END IF;
END $$;
