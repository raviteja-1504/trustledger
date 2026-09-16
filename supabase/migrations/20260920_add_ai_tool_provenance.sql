-- Migration: AI tool/model fingerprinting persistence (roadmap Phase 1, item 2)
--
-- TrustLedger already computes two real AI-tool-attribution signals on
-- every scan -- detectAIToolingArtifacts() (explicit config-file/commit
-- markers, e.g. .cursorrules, "Co-authored-by: Claude") and
-- attributeCode() (per-file stylistic model attribution) -- but neither
-- survives past the scan request today: no DB column exists for either,
-- so they're computed, used transiently to build the AI-likelihood
-- "boosts" summary string, then discarded. This adds the two columns so
-- both become real, queryable, historical provenance evidence, following
-- the same jsonb-column precedent as evidence_breakdown
-- (20260623_add_evidence_breakdown.sql).
ALTER TABLE scans      ADD COLUMN IF NOT EXISTS ai_tooling  jsonb;
ALTER TABLE scan_files ADD COLUMN IF NOT EXISTS attribution jsonb;
