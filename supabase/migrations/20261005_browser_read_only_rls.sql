-- ============================================================
-- Browser sessions get READ access to their own org's data, and nothing else.
--
-- Every write in TrustLedger goes through an API route (service role, which bypasses RLS) where the
-- caller's role and custom-role permissions are checked. But the early migrations gave signed-in users
-- `for all` / `for insert` policies, so anyone holding a session JWT and the public anon key could skip
-- the API and write through PostgREST directly:
--   * org_members  -- set their own role to admin, or (no WITH CHECK) move their row into another org
--   * attestations / audit_log / evidence_log / report_generations -- forge sign-offs and audit entries
--   * scans, violations, incidents, custom_roles, ... -- edit or delete anything in the org
--   * user_2fa     -- read the TOTP secret, or switch 2FA off from a password-only session
-- and every member could read webhook signing secrets, integration tokens and API key hashes.
--
-- After this migration:
--   * org tables: one SELECT policy each (realtime and any direct reads keep working), no write policies
--   * secret-bearing tables (api_keys, webhook_configs, integration_tokens, user_2fa): no policies at all,
--     i.e. no browser access -- the API routes read them with the service role
--   * own-row tables (user_profiles, notification_preferences): unchanged
-- Idempotent; tables that don't exist on this database are skipped.
-- ============================================================

do $$
declare
  read_tables  text[] := array[
    'org_members', 'organizations', 'repositories', 'scans', 'scan_files', 'attestations', 'violations',
    'secret_findings', 'incidents', 'alerts', 'risk_register', 'compliance_exceptions', 'github_installations',
    'scan_schedules', 'custom_roles', 'webhook_deliveries', 'violation_overrides', 'audit_log', 'evidence_log',
    'report_generations'
  ];
  secret_tables text[] := array['api_keys', 'webhook_configs', 'integration_tokens', 'user_2fa'];
  r record;
  t text;
begin
  -- 1. Drop every write-capable policy on the org tables, and every policy on the secret tables.
  for r in
    select policyname, tablename from pg_policies
    where schemaname = 'public'
      and ((tablename = any(read_tables) and cmd <> 'SELECT') or tablename = any(secret_tables))
  loop
    execute format('drop policy %I on public.%I', r.policyname, r.tablename);
  end loop;

  -- 2. Make sure RLS is on (no policy + RLS on = no browser access).
  foreach t in array read_tables || secret_tables loop
    if to_regclass('public.' || t) is not null then
      execute format('alter table public.%I enable row level security', t);
    end if;
  end loop;

  -- 3. A read policy for each org table that has none left (the `for all` ones were also its read access).
  foreach t in array read_tables loop
    if to_regclass('public.' || t) is not null
       and not exists (select 1 from pg_policies where schemaname = 'public' and tablename = t and cmd = 'SELECT') then
      if t = 'org_members' then
        execute 'create policy "org_members_read_own_org" on public.org_members for select using (user_id = auth.uid() or org_id = current_org_id())';
      elsif t = 'organizations' then
        execute 'create policy "organizations_read_own" on public.organizations for select using (id = current_org_id())';
      else
        execute format('create policy %I on public.%I for select using (org_id = current_org_id())', t || '_read_own_org', t);
      end if;
    end if;
  end loop;
end $$;
