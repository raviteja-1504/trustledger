-- Store the computed repository trust score (score, factor breakdown, label)
-- per scan. Was already computed by runScan() but never persisted, so the
-- PR page had no way to show it.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS repository_trust jsonb;
