-- ============================================================
-- Failed outbound webhook deliveries — 2026-11-27
--
-- A delivery that fails is stored here WITH its original event payload, so a retry re-sends that same event
-- (same id, same body) instead of a generic ping. Backoff after the first failure: 5 min, 15 min, 1 h, 6 h, 24 h
-- (5 retries); after the 5th failed retry the row is marked permanently_failed and never retried again.
--
-- Nothing here schedules anything: retries run only when GET /api/cron/webhook-retry is called.
-- Service role only (no RLS policies): the payload is the customer's event data.
-- ============================================================

CREATE TABLE IF NOT EXISTS webhook_failed_deliveries (
  id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  webhook_id         uuid        NOT NULL REFERENCES webhook_configs(id) ON DELETE CASCADE,
  org_id             uuid        NOT NULL REFERENCES organizations(id),
  event_id           text        NOT NULL,
  event_type         text        NOT NULL,
  payload            jsonb       NOT NULL,                 -- the original event, exactly as first sent
  retry_count        integer     NOT NULL DEFAULT 0,       -- retries already attempted
  next_retry_at      timestamptz,                          -- null once permanently failed
  permanently_failed boolean     NOT NULL DEFAULT false,
  last_status        integer,
  last_error         text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (webhook_id, event_id)
);

CREATE INDEX IF NOT EXISTS webhook_failed_deliveries_due_idx
  ON webhook_failed_deliveries (next_retry_at) WHERE NOT permanently_failed;

ALTER TABLE webhook_failed_deliveries ENABLE ROW LEVEL SECURITY;
