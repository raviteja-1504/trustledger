-- ============================================================
-- Control ownership — 2026-11-26
--
-- Who is responsible for each compliance control (framework + control id). Mutable by design: ownership changes
-- hands. Every change is written to the audit log (resource_type 'control_owner'), so the history is not lost.
--
-- Remediation tracking is NOT here: it already lives in compliance_exceptions (owner, due date, status, accepted
-- risk). The gap report (GET /api/evidence/gaps) joins the two, so a control's gaps, owner and remediation status
-- are read together.
-- ============================================================

CREATE TABLE IF NOT EXISTS control_owners (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            uuid        NOT NULL REFERENCES organizations(id),
  framework_id      text        NOT NULL,
  control_id        text        NOT NULL,
  owner_email       text        NOT NULL,
  assigned_by_email text,
  assigned_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, framework_id, control_id)
);

CREATE INDEX IF NOT EXISTS control_owners_org_framework_idx ON control_owners (org_id, framework_id);

ALTER TABLE control_owners ENABLE ROW LEVEL SECURITY;

CREATE POLICY "control_owners_select_own_org" ON control_owners
  FOR SELECT USING (org_id = current_org_id());
-- Writes go through the API (service role), which checks the caller's permission and that the owner is a member.
