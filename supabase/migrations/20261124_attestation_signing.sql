-- ============================================================
-- Ed25519 attestation signing — 2026-11-24
--
-- Adds:
--   signing_keys   — public-key registry for key rotation and revocation.
--   attestations.payload_json   — canonical payload that was signed.
--   attestations.signature      — base64-encoded Ed25519 signature.
--   attestations.signing_key_id — FK to the key used.
--
-- Existing attestations (no signature) are preserved as-is; their
-- payload_hash (SHA-256) remains the only integrity record for the
-- pre-signing period.  New attestations (after ATTESTATION_SIGNING_KEY
-- is set in the deployment environment) carry all three new columns.
--
-- Trust model notes
-- -----------------
-- * Private keys are NEVER stored in this table.  The app loads them
--   from ATTESTATION_SIGNING_KEY (env var).  In production this env var
--   should reference a secret from a secrets manager (Doppler, AWS
--   Secrets Manager, GCP Secret Manager) rather than a literal PEM
--   value embedded in the deployment config.
--
-- * The Postgres RULE-based immutability on attestations blocks UPDATE
--   and DELETE, but a Supabase project owner with direct database access
--   can drop the rules and modify rows.  This is documented as a
--   known trust assumption: immutability is enforced at the application
--   level and by the cryptographic chain, not by hardware.
--
-- * Key rotation: generate a new key pair, set ATTESTATION_SIGNING_KEY
--   to the new private key PEM, then run:
--     UPDATE signing_keys SET status = 'retired', retired_at = now()
--     WHERE id = '<old-key-id>';
--   Historical attestations remain verifiable because their signing_key_id
--   still points to the retired key's public key in this table.
--
-- * Key revocation: same as rotation but set status = 'revoked' with a
--   revoked_reason.  The verify endpoint will return "key_revoked" for
--   any attestation that used that key.
-- ============================================================

CREATE TABLE IF NOT EXISTS signing_keys (
  id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid        REFERENCES organizations(id) ON DELETE CASCADE,  -- NULL = platform-wide key
  algorithm       text        NOT NULL DEFAULT 'ed25519',
  public_key_pem  text        NOT NULL,
  status          text        NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'retired', 'revoked')),
  revoked_at      timestamptz,
  revoked_reason  text,
  retired_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (public_key_pem)     -- prevents double-registration of the same key
);

CREATE INDEX IF NOT EXISTS signing_keys_org_status_idx
  ON signing_keys (org_id, status, created_at DESC);

ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
-- No browser-access policies: service_role only (consistent with 20261005_browser_read_only_rls.sql).

-- ── New columns on attestations ───────────────────────────────────────────────
ALTER TABLE attestations
  ADD COLUMN IF NOT EXISTS payload_json   jsonb,
  ADD COLUMN IF NOT EXISTS signature      text,
  ADD COLUMN IF NOT EXISTS signing_key_id uuid REFERENCES signing_keys(id);

CREATE INDEX IF NOT EXISTS idx_attestations_signing_key
  ON attestations (signing_key_id)
  WHERE signing_key_id IS NOT NULL;
