-- Migration: SLA historical/trend aggregation (compliance overhaul Phase 3)
--
-- The SLA Dashboard only ever showed a current-snapshot view ("what's
-- overdue right now") despite the underlying data (alerts.fired_at for
-- when a breach was flagged, violations.resolved_at for when it was
-- cleared) already supporting a real trend. An auditor covering a 6-12
-- month period needs "how has SLA performance evolved," not just today's
-- state.
--
-- Mirrors get_risk_trend()'s pattern (20260914_risk_trend_rpc.sql):
-- server-side GROUP BY so the client never fetches raw rows (immune to
-- Supabase's max_rows cap, and cheaper -- at most p_weeks rows returned
-- regardless of how many alerts/violations exist underneath).
CREATE OR REPLACE FUNCTION get_sla_trend(p_org_id uuid, p_weeks int DEFAULT 12)
RETURNS TABLE (week_start date, breaches bigint, avg_resolve_hours numeric)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH weeks AS (
    SELECT date_trunc('week', now() - (n || ' weeks')::interval)::date AS week_start
    FROM generate_series(0, greatest(p_weeks, 1) - 1) AS n
  ),
  breach_counts AS (
    -- checkSLABreaches() (src/lib/slaMonitor.ts) fires one alert_type='sla'
    -- row the moment a breach is first detected -- the real "when did this
    -- breach happen" event stream, not inferred from current state.
    SELECT date_trunc('week', fired_at)::date AS week_start, COUNT(*) AS breaches
    FROM alerts
    WHERE org_id = p_org_id AND alert_type = 'sla'
    GROUP BY 1
  ),
  resolve_times AS (
    SELECT date_trunc('week', resolved_at)::date AS week_start,
           AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600) AS avg_resolve_hours
    FROM violations
    WHERE org_id = p_org_id AND status = 'resolved' AND resolved_at IS NOT NULL
    GROUP BY 1
  )
  SELECT
    w.week_start,
    COALESCE(bc.breaches, 0)                    AS breaches,
    ROUND(rt.avg_resolve_hours::numeric, 1)      AS avg_resolve_hours
  FROM weeks w
  LEFT JOIN breach_counts bc ON bc.week_start = w.week_start
  LEFT JOIN resolve_times rt ON rt.week_start = w.week_start
  ORDER BY w.week_start;
$$;

REVOKE ALL ON FUNCTION get_sla_trend(uuid, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_sla_trend(uuid, int) TO service_role;
