-- ============================================================
-- Security audit fixes — 2026-11-24
--
-- F3: current_org_id() — add ORDER BY for a deterministic result when a
--     user somehow holds more than one org_members row (edge case; the new
--     partial unique index below prevents it going forward).
--
-- F3: Partial unique index — enforce one-org-per-non-platform-admin user at
--     the DB layer, so the invariant current_org_id() relies on is guaranteed.
--
-- F2: get_user_permissions() / check_permission() — add a caller-authorization
--     guard so a member of Org A cannot enumerate permissions of users in Org B
--     via direct Supabase RPC.
--
-- F5: scan_files.org_id — add the FK constraint that every other tenant table
--     already carries, so a row with a wrong or orphaned org_id is rejected at
--     insert time rather than silently applying the wrong RLS boundary.
-- ============================================================


-- ── F3: current_org_id() — deterministic ordering ────────────────────────────

CREATE OR REPLACE FUNCTION current_org_id() RETURNS uuid AS $$
  SELECT org_id FROM org_members
  WHERE user_id = auth.uid()
  ORDER BY created_at   -- oldest membership wins; deterministic across pg planner
  LIMIT 1;
$$ LANGUAGE sql SECURITY DEFINER STABLE;


-- ── F3: Partial unique index — one org per user (platform_admin exempt) ──────
-- Remove any duplicate rows first (keep the oldest per user).
DELETE FROM org_members
WHERE id IN (
  SELECT id FROM (
    SELECT id,
           ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at) AS rn
    FROM   org_members
    WHERE  role != 'platform_admin'
  ) sub
  WHERE rn > 1
);

CREATE UNIQUE INDEX IF NOT EXISTS org_members_one_org_per_user
  ON org_members (user_id)
  WHERE role != 'platform_admin';


-- ── F2: get_user_permissions() — add caller-authorization guard ───────────────

CREATE OR REPLACE FUNCTION get_user_permissions(p_user_id uuid, p_org_id uuid)
RETURNS jsonb AS $$
DECLARE
  v_member    record;
  v_role_name text;
  v_custom    record;
  v_perms     jsonb;
BEGIN
  -- Caller must be the user themselves, or a member of the same org.
  -- Silently returns {} for unauthorized calls rather than raising an error
  -- (consistent with the original behaviour for a user not found).
  IF auth.uid() != p_user_id AND NOT EXISTS (
    SELECT 1 FROM org_members
    WHERE  user_id = auth.uid() AND org_id = p_org_id
  ) THEN
    RETURN '{}'::jsonb;
  END IF;

  SELECT * INTO v_member FROM org_members
  WHERE  user_id = p_user_id AND org_id = p_org_id;

  IF NOT FOUND THEN
    RETURN '{}'::jsonb;
  END IF;

  v_role_name := v_member.role;

  v_perms := CASE v_role_name
    WHEN 'platform_admin' THEN '{"all": true}'::jsonb
    WHEN 'admin' THEN jsonb_build_object(
      'can_attest_critical',    true,
      'can_attest_high',        true,
      'can_attest_medium',      true,
      'can_resolve_violations', true,
      'can_manage_incidents',   true,
      'can_view_secrets',       true,
      'can_export_data',        true,
      'can_manage_policies',    true,
      'can_manage_team',        true,
      'can_manage_integrations',true,
      'can_view_audit_log',     true,
      'can_trigger_scans',      true,
      'can_create_reports',     true,
      'can_manage_billing',     true
    )
    WHEN 'security_reviewer' THEN jsonb_build_object(
      'can_attest_critical',    true,
      'can_attest_high',        true,
      'can_attest_medium',      true,
      'can_resolve_violations', true,
      'can_manage_incidents',   true,
      'can_view_secrets',       true,
      'can_export_data',        false,
      'can_manage_policies',    false,
      'can_manage_team',        false,
      'can_view_audit_log',     true,
      'can_trigger_scans',      true,
      'can_create_reports',     true
    )
    WHEN 'developer' THEN jsonb_build_object(
      'can_attest_critical',    false,
      'can_attest_high',        false,
      'can_attest_medium',      true,
      'can_resolve_violations', false,
      'can_view_secrets',       false,
      'can_view_audit_log',     false,
      'can_trigger_scans',      true,
      'can_create_reports',     false
    )
    WHEN 'auditor' THEN jsonb_build_object(
      'can_attest_critical',    false,
      'can_attest_high',        false,
      'can_view_secrets',       true,
      'can_export_data',        true,
      'can_view_audit_log',     true,
      'can_create_reports',     true,
      'can_trigger_scans',      false
    )
    ELSE '{}'::jsonb
  END;

  IF v_member.custom_role_id IS NOT NULL THEN
    SELECT * INTO v_custom FROM custom_roles WHERE id = v_member.custom_role_id;
    IF FOUND THEN
      v_perms := v_perms || jsonb_build_object(
        'can_attest_critical',    v_custom.can_attest_critical,
        'can_attest_high',        v_custom.can_attest_high,
        'can_attest_medium',      v_custom.can_attest_medium,
        'can_resolve_violations', v_custom.can_resolve_violations,
        'can_manage_incidents',   v_custom.can_manage_incidents,
        'can_view_secrets',       v_custom.can_view_secrets,
        'can_export_data',        v_custom.can_export_data,
        'can_manage_policies',    v_custom.can_manage_policies,
        'can_manage_team',        v_custom.can_manage_team,
        'can_manage_integrations',v_custom.can_manage_integrations,
        'can_view_audit_log',     v_custom.can_view_audit_log,
        'can_trigger_scans',      v_custom.can_trigger_scans,
        'can_create_reports',     v_custom.can_create_reports,
        'can_manage_billing',     v_custom.can_manage_billing,
        'repo_scope',             v_custom.repo_scope
      );
    END IF;
  END IF;

  RETURN v_perms;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;


-- ── F2: check_permission() — inherits the guard via get_user_permissions() ───

CREATE OR REPLACE FUNCTION check_permission(p_user_id uuid, p_org_id uuid, p_permission text)
RETURNS boolean AS $$
DECLARE
  v_perms jsonb;
BEGIN
  v_perms := get_user_permissions(p_user_id, p_org_id);
  IF v_perms->>'all' = 'true' THEN RETURN true; END IF;
  RETURN (v_perms->>p_permission)::boolean = true;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;


-- ── F5: scan_files.org_id — add missing FK constraint ────────────────────────
-- Remove orphaned rows first so the constraint does not fail on existing data.
DELETE FROM scan_files
WHERE  org_id NOT IN (SELECT id FROM organizations);

ALTER TABLE scan_files
  ADD CONSTRAINT scan_files_org_fk
  FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
