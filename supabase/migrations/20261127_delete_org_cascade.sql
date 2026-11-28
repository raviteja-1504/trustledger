-- ============================================================
-- delete_org_cascade(target_org_id) — transactional organisation deletion — 2026-11-27
--
-- Why this exists: POST /api/orgs/delete used to call a function that was never created, then fell back to
-- unchecked JS deletes. Those silently did nothing for audit_log / attestations (the immutability rules below turn
-- DELETE into a no-op) and then failed on the organizations row (audit_log, attestations and audit_checkpoints
-- reference it with no ON DELETE action), so an org could be left half deleted with no error reported.
--
-- Retention policy (deliberate):
--   DELETED   everything that is customer data: members, API keys, integrations, repositories, scans (except as
--             noted), findings, triage, webhooks, notification history, SSO/SCIM config, and so on.
--   RETAINED  the immutable evidence records, because deleting them would defeat their purpose and the database
--             forbids it:
--               audit_log           the hash-chained audit trail (includes the org_deleted entry the API writes first)
--               attestations        signed reviewer attestations
--               audit_checkpoints   signed commitments to the audit chain
--               signing_keys        public keys, so retained attestations / checkpoints stay verifiable
--             and the scans rows an attestation points at (attestations.scan_id has a foreign key), detached from
--             their repository.
--   TOMBSTONE the organizations row stays (the retained rows reference it) but is anonymised: name, slug, GitHub
--             handle and webhook URLs are replaced / cleared and deleted_at is set.
--
-- The function runs in one transaction: it either completes or changes nothing. Dependency order between the
-- tables is resolved at run time (a delete blocked by a foreign key is retried after the others), and it fails
-- with an error rather than skipping anything if some table cannot be cleared.
--
-- Keep the table list in step with the org-scoped tables: a test (src/__tests__/lib/deleteOrgCascade.test.ts)
-- compares it with every table that has an org_id column.
-- ============================================================

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS deleted_at timestamptz;

CREATE OR REPLACE FUNCTION delete_org_cascade(target_org_id uuid)
RETURNS void
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
  -- org-scoped tables whose rows are deleted (everything with an org_id except the retained set below)
  tbls      text[] := ARRAY[
    'alerts', 'api_keys', 'compliance_exceptions', 'control_owners', 'custom_roles', 'developer_baselines',
    'evidence_log', 'finding_triage', 'github_installations', 'incidents', 'integration_tokens', 'notification_log',
    'notification_preferences', 'ops_events', 'org_members', 'report_generations', 'repositories', 'risk_register',
    'scan_files', 'scan_schedules', 'scans', 'scim_tokens', 'secret_findings', 'shadow_ai_triage', 'sso_connections',
    'sso_domains', 'trust_score_history', 'violation_overrides', 'violations', 'webhook_configs',
    'webhook_deliveries', 'webhook_delivery_log',
    'webhook_failed_deliveries', 'scan_jobs'
  ];
  remaining text[];
  t         text;
  progressed boolean;
  last_err  text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM organizations WHERE id = target_org_id AND deleted_at IS NULL) THEN
    RAISE EXCEPTION 'org_not_found' USING ERRCODE = 'P0002';
  END IF;

  -- scans an attestation refers to are kept; free them from the repository that is about to go
  UPDATE scans s SET repo_id = NULL
   WHERE s.org_id = target_org_id AND s.repo_id IS NOT NULL
     AND EXISTS (SELECT 1 FROM attestations a WHERE a.scan_id = s.id);

  remaining := tbls;
  WHILE COALESCE(array_length(remaining, 1), 0) > 0 LOOP
    progressed := false;
    FOREACH t IN ARRAY remaining LOOP
      BEGIN
        IF t = 'scans' THEN
          DELETE FROM scans s WHERE s.org_id = target_org_id
            AND NOT EXISTS (SELECT 1 FROM attestations a WHERE a.scan_id = s.id);
        ELSE
          EXECUTE format('DELETE FROM %I WHERE org_id = $1', t) USING target_org_id;
        END IF;
        remaining  := array_remove(remaining, t);
        progressed := true;
      EXCEPTION
        WHEN foreign_key_violation THEN
          GET STACKED DIAGNOSTICS last_err = MESSAGE_TEXT;   -- something still references it: retry after the others
        WHEN undefined_table THEN
          -- a table from a migration this database never ran holds no data of this organisation: nothing to delete
          remaining  := array_remove(remaining, t);
          progressed := true;
      END;
    END LOOP;
    IF NOT progressed THEN
      RAISE EXCEPTION 'org_delete_blocked: % (%)', array_to_string(remaining, ', '), last_err;
    END IF;
  END LOOP;

  -- anonymised tombstone: the retained evidence rows keep a valid organizations reference
  UPDATE organizations SET
    name          = 'Deleted organization',
    slug          = 'deleted-' || replace(id::text, '-', ''),
    github_org    = NULL,
    teams_webhook = NULL,
    slack_webhook = NULL,
    ai_tool_policy = NULL,
    deleted_at    = now()
  WHERE id = target_org_id;
END;
$$;

-- Only the server (service role) may call it: it deletes an entire organisation.
REVOKE ALL ON FUNCTION delete_org_cascade(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION delete_org_cascade(uuid) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION delete_org_cascade(uuid) TO service_role;
