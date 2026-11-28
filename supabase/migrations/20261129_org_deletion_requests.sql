-- ============================================================
-- Organisation deletion as a tracked, reversible-until-executed job — 2026-11-29
--
-- Deleting an organisation used to happen in one request. It is now: REQUEST (an admin, confirmed with the organisation's name
-- and a fresh sign-in / authenticator code) -> a waiting period during which anyone with the admin role can CANCEL -> EXECUTE
-- (the admin confirms again once the period is over). One row here tracks it, with an explicit status:
--
--   pending    requested, waiting out the period (cancellable)
--   executing  the deletion function is running (one at a time per organisation)
--   completed  the organisation's data is gone (evidence records retained: see delete_org_cascade)
--   failed     the deletion function failed and changed nothing (it is one transaction); can be executed again or cancelled
--   cancelled  stopped before it ran
--
-- Nothing is scheduled: execution is always a person's explicit action once execute_after has passed.
--
-- This table is part of the RECORD of the deletion, so delete_org_cascade does NOT delete it (it is listed as retained in
-- src/__tests__/lib/deleteOrgCascade.test.ts). Service role only.
-- ============================================================

CREATE TABLE IF NOT EXISTS org_deletion_requests (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid        NOT NULL REFERENCES organizations(id),
  requested_by       uuid,
  requested_by_email text,
  requested_at       timestamptz NOT NULL DEFAULT now(),
  execute_after      timestamptz NOT NULL,
  status             text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'executing', 'completed', 'failed', 'cancelled')),
  preview            jsonb       NOT NULL DEFAULT '{}'::jsonb,   -- what was going to be deleted, as shown when it was requested
  cancelled_at       timestamptz,
  cancelled_by_email text,
  started_at         timestamptz,
  completed_at       timestamptz,
  error              text
);

-- At most one open request per organisation.
CREATE UNIQUE INDEX IF NOT EXISTS org_deletion_one_open_per_org
  ON org_deletion_requests (org_id) WHERE status IN ('pending', 'executing', 'failed');

ALTER TABLE org_deletion_requests ENABLE ROW LEVEL SECURITY;
-- No policies: service role only.
