-- ============================================================
-- Close remaining RLS / schema gaps found in enterprise-readiness audit:
--
-- 1. webhook_deliveries.org_id was nullable and had RLS enabled (010) but
--    no policy — every other multi-tenant table has both a NOT NULL org_id
--    and a matching policy. Bring it in line with the rest of the schema.
--
-- Note: all application API routes use the service_role client
-- (src/lib/supabase.ts: createServiceClient), which bypasses RLS by
-- Postgres design regardless of policies present. These policies are
-- defense-in-depth against any direct PostgREST access using the anon/
-- authenticated key (e.g. a future client-side query bypassing the API
-- layer) — they do not, by themselves, protect against an API route that
-- forgets to filter by org_id. That enforcement has to happen in the
-- route code itself.
-- ============================================================

-- Backfill safety: if any existing rows have a null org_id, they cannot be
-- attributed to a tenant and must be removed before the column can be
-- made NOT NULL (there is no correct org to assign them to).
delete from webhook_deliveries where org_id is null;

alter table webhook_deliveries
  alter column org_id set not null;

create policy "webhook_deliveries_own_org" on webhook_deliveries
  for all using (org_id = current_org_id());
