-- ============================================================
-- Platform notices — what the public status page tells people during an incident — 2026-11-29
--
-- A short list the operator writes (in the Supabase SQL editor; docs/operations/runbook.md has the statements): what is wrong, how bad,
-- when it started, when it was resolved. GET /api/status serves the open ones and the last few resolved ones, and the /status page shows
-- them above the live component checks. No customer data belongs here: it is public.
--
-- Service role only (the public endpoint reads it on the server).
-- ============================================================

CREATE TABLE IF NOT EXISTS platform_notices (
  id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  severity    text        NOT NULL CHECK (severity IN ('info', 'degraded', 'outage')),
  title       text        NOT NULL,
  body        text        NOT NULL DEFAULT '',
  started_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz
);

CREATE INDEX IF NOT EXISTS platform_notices_recent_idx ON platform_notices (started_at DESC);

ALTER TABLE platform_notices ENABLE ROW LEVEL SECURITY;
-- No policies: service role only.
