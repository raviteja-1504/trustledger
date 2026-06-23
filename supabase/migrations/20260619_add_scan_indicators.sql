-- Store detailed security indicators (with line numbers) directly in scan_files
-- so the PR page can show exact line numbers without re-running the scanner.
ALTER TABLE scan_files ADD COLUMN IF NOT EXISTS indicators jsonb DEFAULT '[]'::jsonb;
