-- Migration 008: Health monitoring helpers
-- Adds a connection stats function used by /api/health and /healthz

-- Returns current Postgres connection pool stats
CREATE OR REPLACE FUNCTION get_connection_stats()
RETURNS json
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT json_build_object(
    'active',  COUNT(*) FILTER (WHERE state = 'active'),
    'idle',    COUNT(*) FILTER (WHERE state = 'idle'),
    'waiting', COUNT(*) FILTER (WHERE wait_event_type IS NOT NULL AND state != 'idle'),
    'max',     (SELECT setting::int FROM pg_settings WHERE name = 'max_connections'),
    'pid_count', COUNT(*)
  )
  FROM pg_stat_activity
  WHERE datname = current_database();
$$;

-- Only service role can call this
REVOKE ALL ON FUNCTION get_connection_stats() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_connection_stats() TO service_role;

-- Slow query log helper (used by observability dashboards)
CREATE TABLE IF NOT EXISTS slow_query_log (
  id           bigserial PRIMARY KEY,
  query_hash   text        NOT NULL,
  query_sample text,
  calls        bigint      NOT NULL DEFAULT 1,
  mean_ms      float       NOT NULL,
  max_ms       float       NOT NULL,
  captured_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE slow_query_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service role only"
  ON slow_query_log
  FOR ALL
  TO service_role
  USING (true);

-- Index for fast lookups by capture time
CREATE INDEX IF NOT EXISTS slow_query_log_captured_at_idx
  ON slow_query_log (captured_at DESC);
