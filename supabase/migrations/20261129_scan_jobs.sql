-- ============================================================
-- Scan job ledger — 2026-11-29
--
-- One row per scan job (a webhook, a rescan, a dashboard request), holding the ORIGINAL job payload and where it is:
--
--   queued     registered and handed to the queue
--   running    a worker claimed it (one at a time: the claim is a conditional update, so two deliveries of the same job cannot
--              both run it -- QStash retries and duplicate webhooks included)
--   succeeded  the worker finished (a scan was stored, or it was a no-op such as "already scanned" / "superseded": see result)
--   failed     the worker failed; the queue will retry it (attempts < max_attempts)
--   dead       out of attempts: not retried again. Visible to the organisation, with the reason, and replayable.
--
-- Duplicates: dedupe_key is repo + PR + commit (unique per forced rescan). A second webhook for a job that is still queued or
-- running does not enqueue another; a job that has finished is re-queued (a re-run check on an old commit must still work).
--
-- The ledger is advisory for scanning itself: if this table is missing, scans run exactly as before, without it.
-- Nothing here is scheduled. Service role only (the API reads it for the organisation).
-- ============================================================

CREATE TABLE IF NOT EXISTS scan_jobs (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid        NOT NULL REFERENCES organizations(id),
  dedupe_key       text        NOT NULL,
  repo_full_name   text        NOT NULL,
  pr_number        integer,
  head_sha         text,
  action           text,
  forced           boolean     NOT NULL DEFAULT false,
  job              jsonb       NOT NULL,                     -- the original job, exactly as enqueued: replay sends this again
  status           text        NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'dead')),
  attempts         integer     NOT NULL DEFAULT 0,
  max_attempts     integer     NOT NULL DEFAULT 4,
  last_error       text,                                     -- customer-safe reason of the last failure
  result           text,                                     -- how a succeeded job ended: scanned / already_scanned / superseded / ...
  scan_id          uuid,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  started_at       timestamptz,
  finished_at      timestamptz,
  UNIQUE (org_id, dedupe_key)
);

CREATE INDEX IF NOT EXISTS scan_jobs_org_status_idx ON scan_jobs (org_id, status, updated_at DESC);

ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
-- No policies: service role only.
