-- Risk trend v3. Every scan of a PR stores ALL of the PR's files (a delta scan copies the unchanged ones in), so counting
-- rows of every scan multiplied each file by the number of scans (migration 20261127_risk_trend_distinct_files.sql fixed
-- that by taking each file's latest row -- but a file that LEFT a PR, or was fixed so a later scan no longer lists it, kept
-- its old HIGH row and was still counted).
--
-- Correct unit: a scan's file list is the PR's state at that moment. So:
--   * get_risk_trend:  for each week, take the LATEST scan of each PR in that week and count its flagged files, each
--                      repo+path once (newest scan wins) -- the state of the org's PRs at the end of that week.
--   * get_risk_totals: the same for the whole period -- the latest scan of every PR -- i.e. the files flagged NOW, which is
--                      the population the review queue is drawn from (the queue additionally leaves out signed-off ones).
-- A direct push (no PR) is one "PR" per repo.
CREATE OR REPLACE FUNCTION get_risk_trend(p_scan_ids uuid[])
RETURNS TABLE (week_start date, critical_count bigint, high_count bigint, medium_count bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH wk AS (
    SELECT DISTINCT ON (s.repo_full_name, COALESCE(s.pr_number, 0), date_trunc('week', s.created_at))
           s.id, date_trunc('week', s.created_at)::date AS week_start
    FROM scans s
    WHERE s.id = ANY(p_scan_ids)
    ORDER BY s.repo_full_name, COALESCE(s.pr_number, 0), date_trunc('week', s.created_at), s.created_at DESC
  ),
  files AS (
    SELECT DISTINCT ON (wk.week_start, s.repo_full_name, f.file_path) wk.week_start, f.risk_score
    FROM wk
    JOIN scans s      ON s.id = wk.id
    JOIN scan_files f ON f.scan_id = wk.id
    ORDER BY wk.week_start, s.repo_full_name, f.file_path, s.created_at DESC
  )
  SELECT
    week_start,
    COUNT(*) FILTER (WHERE risk_score = 'CRITICAL') AS critical_count,
    COUNT(*) FILTER (WHERE risk_score = 'HIGH')     AS high_count,
    COUNT(*) FILTER (WHERE risk_score = 'MEDIUM')   AS medium_count
  FROM files
  WHERE risk_score IN ('CRITICAL', 'HIGH', 'MEDIUM')
  GROUP BY week_start
  ORDER BY week_start DESC;
$$;

CREATE OR REPLACE FUNCTION get_risk_totals(p_scan_ids uuid[])
RETURNS TABLE (critical_count bigint, high_count bigint, medium_count bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH latest AS (
    SELECT DISTINCT ON (s.repo_full_name, COALESCE(s.pr_number, 0)) s.id
    FROM scans s
    WHERE s.id = ANY(p_scan_ids)
    ORDER BY s.repo_full_name, COALESCE(s.pr_number, 0), s.created_at DESC
  ),
  files AS (
    SELECT DISTINCT ON (s.repo_full_name, f.file_path) f.risk_score
    FROM latest
    JOIN scans s      ON s.id = latest.id
    JOIN scan_files f ON f.scan_id = latest.id
    ORDER BY s.repo_full_name, f.file_path, s.created_at DESC
  )
  SELECT
    COUNT(*) FILTER (WHERE risk_score = 'CRITICAL'),
    COUNT(*) FILTER (WHERE risk_score = 'HIGH'),
    COUNT(*) FILTER (WHERE risk_score = 'MEDIUM')
  FROM files;
$$;

REVOKE ALL ON FUNCTION get_risk_trend(uuid[])  FROM PUBLIC;
REVOKE ALL ON FUNCTION get_risk_totals(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION get_risk_trend(uuid[])  TO service_role;
GRANT EXECUTE ON FUNCTION get_risk_totals(uuid[]) TO service_role;
