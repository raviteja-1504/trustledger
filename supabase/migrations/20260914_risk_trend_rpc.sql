-- Migration: exact, server-side weekly risk trend aggregation
--
-- risk_trend was previously computed by fetching up to 5000 individual
-- scan_files rows (ordered newest-first) and bucketing them into weeks in
-- JS. Supabase/PostgREST's server-side max_rows setting on this project
-- silently caps every query at 1000 rows regardless of the client's
-- .limit() call (see dashboardAggregate.ts's long-standing comment about
-- this same cap biting the Risk Distribution donut). A single day's burst
-- of scanning activity (e.g. a large whole-repo scan) can by itself fill
-- all 1000 rows with the same week's data, collapsing risk_trend down to
-- one bucket -- which is why the chart showed a single "09-14" point and
-- Peak/Current/Weekly-Average all coincidentally read "1000".
--
-- Fixed by moving the GROUP BY into Postgres: this returns at most 10 rows
-- (one per week) no matter how many scan_files rows exist underneath it,
-- so it's immune to the row cap, exact, and cheaper (far less data
-- transferred) than the row-fetching approach it replaces.
CREATE OR REPLACE FUNCTION get_risk_trend(p_scan_ids uuid[])
RETURNS TABLE (week_start date, critical_count bigint, high_count bigint, medium_count bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT
    date_trunc('week', created_at)::date AS week_start,
    COUNT(*) FILTER (WHERE risk_score = 'CRITICAL') AS critical_count,
    COUNT(*) FILTER (WHERE risk_score = 'HIGH')     AS high_count,
    COUNT(*) FILTER (WHERE risk_score = 'MEDIUM')   AS medium_count
  FROM scan_files
  WHERE scan_id = ANY(p_scan_ids)
    AND risk_score IN ('CRITICAL', 'HIGH', 'MEDIUM')
  GROUP BY week_start
  ORDER BY week_start DESC
  LIMIT 10;
$$;

REVOKE ALL ON FUNCTION get_risk_trend(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_risk_trend(uuid[]) TO service_role;
