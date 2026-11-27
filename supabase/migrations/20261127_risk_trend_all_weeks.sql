-- get_risk_trend returned only the 10 NEWEST weeks (LIMIT 10 in 20260914_risk_trend_rpc.sql). The dashboard offers 7 / 30 /
-- 90-day periods and custom date ranges: a 90-day period spans 13-14 weeks, so the oldest weeks silently came back empty
-- (flat zeros at the left of the chart, understated peak / direction). The row count is bounded by the period itself (one row
-- per week in it), so there is nothing to cap.
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
  ORDER BY week_start DESC;
$$;

REVOKE ALL ON FUNCTION get_risk_trend(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_risk_trend(uuid[]) TO service_role;
