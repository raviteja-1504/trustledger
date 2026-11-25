-- ============================================================
-- Signed audit checkpoints — 2026-11-25
--
-- A checkpoint commits to the audit chain's state at a moment: how many entries it held, the hash of the
-- latest one and of the first, and the previous checkpoint's hash. It is signed with the platform's Ed25519
-- signing key (the same keys as attestations, registered in signing_keys).
--
-- What this adds over the hash chain alone: a chain whose NEWEST entries were deleted still links and
-- recomputes, so truncation is invisible to it. A signed checkpoint recorded earlier says "the chain had N
-- entries ending in hash H", so verification fails when fewer entries remain or entry N changed.
--
-- Trust model (read before claiming anything about this table):
--  * The rules below block UPDATE/DELETE through the normal API, but a Supabase project owner can drop them,
--    and could delete checkpoints along with audit rows. This table is therefore NOT immutable storage.
--  * The guarantee comes from copies kept OUTSIDE this database: set AUDIT_CHECKPOINT_SINK_URL to push each
--    signed checkpoint to a store the database owner cannot rewrite, or export them (GET /api/audit/checkpoints)
--    and hold them elsewhere. Verification against such a copy is what detects a coordinated rewrite.
--  * Entries written after the latest checkpoint are not covered by it.
--  * The private key is never stored here: only its public half, in signing_keys, which keeps retired keys so
--    old checkpoints stay verifiable after rotation. A revoked key's checkpoints are reported as untrusted.
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_checkpoints (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid        NOT NULL REFERENCES organizations(id),
  sequence      integer     NOT NULL CHECK (sequence >= 1),
  entry_count   integer     NOT NULL CHECK (entry_count >= 1),
  last_entry_id bigint      NOT NULL,
  payload       jsonb       NOT NULL,          -- the canonical payload that was hashed and signed
  payload_hash  text        NOT NULL,          -- sha256 hex of the canonical payload
  signature     text        NOT NULL,          -- base64 Ed25519 signature over payload_hash
  key_id        uuid        NOT NULL REFERENCES signing_keys(id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, sequence)
);

CREATE INDEX IF NOT EXISTS audit_checkpoints_org_seq_idx ON audit_checkpoints (org_id, sequence DESC);

ALTER TABLE audit_checkpoints ENABLE ROW LEVEL SECURITY;
-- No browser-access policies: service_role only.

CREATE RULE audit_checkpoints_no_update AS ON UPDATE TO audit_checkpoints DO INSTEAD NOTHING;
CREATE RULE audit_checkpoints_no_delete AS ON DELETE TO audit_checkpoints DO INSTEAD NOTHING;
