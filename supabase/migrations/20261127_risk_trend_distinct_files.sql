-- The Risk trend (and the Risk Distribution totals beside it) counted every scan_files row of every scan in the period. A
-- pull request is scanned again on each push and each rescan, and every scan lists all of the PR's files, so one flagged file
-- was counted once per scan -- three scans of a PR, triple the numbers.
--
-- Now each file is counted ONCE: a file is identified by repository + PR (0 for a direct push) + path, taken as it stood in its
-- LATEST scan of the period (so a file flagged HIGH and fixed in a later scan is not counted), and bucketed into the week of
-- that latest scan. The period's totals are the sum of the weeks.
CREATE OR REPLACE FUNCTION get_risk_trend(p_scan_ids uuid[])
RETURNS TABLE (week_start date, critical_count bigint, high_count bigint, medium_count bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH latest AS (
    SELECT DISTINCT ON (s.repo_full_name, COALESCE(s.pr_number, 0), f.file_path)
           f.risk_score, f.created_at
    FROM scan_files f
    JOIN scans s ON s.id = f.scan_id
    WHERE f.scan_id = ANY(p_scan_ids)
    ORDER BY s.repo_full_name, COALESCE(s.pr_number, 0), f.file_path, s.created_at DESC, f.created_at DESC
  )
  SELECT
    date_trunc('week', created_at)::date AS week_start,
    COUNT(*) FILTER (WHERE risk_score = 'CRITICAL') AS critical_count,
    COUNT(*) FILTER (WHERE risk_score = 'HIGH')     AS high_count,
    COUNT(*) FILTER (WHERE risk_score = 'MEDIUM')   AS medium_count
  FROM latest
  WHERE risk_score IN ('CRITICAL', 'HIGH', 'MEDIUM')
  GROUP BY week_start
  ORDER BY week_start DESC;
$$;

REVOKE ALL ON FUNCTION get_risk_trend(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_risk_trend(uuid[]) TO service_role;
