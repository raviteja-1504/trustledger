-- Track the single active session per org member, so a new login can
-- invalidate any previously issued session (kick out old sessions).
alter table org_members
  add column if not exists active_session_id text,
  add column if not exists active_session_at timestamptz;
