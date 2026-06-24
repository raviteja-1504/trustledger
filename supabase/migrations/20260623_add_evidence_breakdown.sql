-- Store multi-signal evidence breakdown per scan
ALTER TABLE scans ADD COLUMN IF NOT EXISTS evidence_breakdown jsonb;
