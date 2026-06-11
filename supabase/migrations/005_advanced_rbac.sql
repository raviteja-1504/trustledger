-- ============================================================
-- Advanced RBAC — Custom Permission Sets (Day 10)
-- ============================================================

-- ── Custom role definitions ───────────────────────────────────────────────────
-- Allows enterprise customers to define granular permission sets
-- beyond the built-in admin/security_reviewer/developer roles.

create table custom_roles (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references organizations(id) on delete cascade,
  name         text not null,
  description  text,
  -- Permission flags (granular)
  can_attest_critical boolean not null default false,
  can_attest_high     boolean not null default false,
  can_attest_medium   boolean not null default true,
  can_resolve_violations boolean not null default false,
  can_manage_incidents   boolean not null default false,
  can_view_secrets       boolean not null default false,
  can_export_data        boolean not null default false,
  can_manage_policies    boolean not null default false,
  can_manage_team        boolean not null default false,
  can_manage_integrations boolean not null default false,
  can_view_audit_log     boolean not null default true,
  can_trigger_scans      boolean not null default true,
  can_create_reports     boolean not null default false,
  can_manage_billing     boolean not null default false,
  -- Repo scope (null = all repos, array = specific repos)
  repo_scope             text[],
  created_at   timestamptz not null default now(),
  unique (org_id, name)
);

alter table custom_roles enable row level security;
create policy "custom_roles_own_org" on custom_roles
  for all using (org_id = current_org_id());

-- ── Assign custom roles to members ────────────────────────────────────────────
alter table org_members add column if not exists custom_role_id uuid references custom_roles(id);

-- ── Helper function: get effective permissions for a user ─────────────────────
create or replace function get_user_permissions(p_user_id uuid, p_org_id uuid)
returns jsonb as $$
declare
  v_member    record;
  v_role_name text;
  v_custom    record;
  v_perms     jsonb;
begin
  select * into v_member from org_members
  where user_id = p_user_id and org_id = p_org_id;

  if not found then
    return '{}'::jsonb;
  end if;

  v_role_name := v_member.role;

  -- Default permissions by built-in role
  v_perms := case v_role_name
    when 'platform_admin' then '{"all": true}'::jsonb
    when 'admin' then jsonb_build_object(
      'can_attest_critical', true,
      'can_attest_high', true,
      'can_attest_medium', true,
      'can_resolve_violations', true,
      'can_manage_incidents', true,
      'can_view_secrets', true,
      'can_export_data', true,
      'can_manage_policies', true,
      'can_manage_team', true,
      'can_manage_integrations', true,
      'can_view_audit_log', true,
      'can_trigger_scans', true,
      'can_create_reports', true,
      'can_manage_billing', true
    )
    when 'security_reviewer' then jsonb_build_object(
      'can_attest_critical', true,
      'can_attest_high', true,
      'can_attest_medium', true,
      'can_resolve_violations', true,
      'can_manage_incidents', true,
      'can_view_secrets', true,
      'can_export_data', false,
      'can_manage_policies', false,
      'can_manage_team', false,
      'can_view_audit_log', true,
      'can_trigger_scans', true,
      'can_create_reports', true
    )
    when 'developer' then jsonb_build_object(
      'can_attest_critical', false,
      'can_attest_high', false,
      'can_attest_medium', true,
      'can_resolve_violations', false,
      'can_view_secrets', false,
      'can_view_audit_log', false,
      'can_trigger_scans', true,
      'can_create_reports', false
    )
    when 'auditor' then jsonb_build_object(
      'can_attest_critical', false,
      'can_attest_high', false,
      'can_view_secrets', true,
      'can_export_data', true,
      'can_view_audit_log', true,
      'can_create_reports', true,
      'can_trigger_scans', false
    )
    else '{}'::jsonb
  end;

  -- Override with custom role if assigned
  if v_member.custom_role_id is not null then
    select * into v_custom from custom_roles where id = v_member.custom_role_id;
    if found then
      v_perms := v_perms || jsonb_build_object(
        'can_attest_critical', v_custom.can_attest_critical,
        'can_attest_high', v_custom.can_attest_high,
        'can_attest_medium', v_custom.can_attest_medium,
        'can_resolve_violations', v_custom.can_resolve_violations,
        'can_manage_incidents', v_custom.can_manage_incidents,
        'can_view_secrets', v_custom.can_view_secrets,
        'can_export_data', v_custom.can_export_data,
        'can_manage_policies', v_custom.can_manage_policies,
        'can_manage_team', v_custom.can_manage_team,
        'can_manage_integrations', v_custom.can_manage_integrations,
        'can_view_audit_log', v_custom.can_view_audit_log,
        'can_trigger_scans', v_custom.can_trigger_scans,
        'can_create_reports', v_custom.can_create_reports,
        'can_manage_billing', v_custom.can_manage_billing,
        'repo_scope', v_custom.repo_scope
      );
    end if;
  end if;

  return v_perms;
end;
$$ language plpgsql security definer stable;

-- ── Permission check helper ───────────────────────────────────────────────────
create or replace function check_permission(p_user_id uuid, p_org_id uuid, p_permission text)
returns boolean as $$
declare
  v_perms jsonb;
begin
  v_perms := get_user_permissions(p_user_id, p_org_id);
  if v_perms->>'all' = 'true' then return true; end if;
  return (v_perms->>p_permission)::boolean = true;
end;
$$ language plpgsql security definer stable;

-- ── RLS policies using permission function ────────────────────────────────────
-- Secrets: only visible to users with can_view_secrets
drop policy if exists "secrets_own_org" on secret_findings;
create policy "secrets_with_permission" on secret_findings
  for select using (
    org_id = current_org_id() and
    check_permission(auth.uid(), current_org_id(), 'can_view_secrets')
  );
create policy "secrets_insert_own_org" on secret_findings
  for insert with check (org_id = current_org_id());

-- ── Seed default custom roles ─────────────────────────────────────────────────
-- These are example roles that orgs can modify or add to.
comment on table custom_roles is
  'Custom RBAC roles. Orgs can create granular permission sets beyond the built-in
   admin/security_reviewer/developer/auditor roles. Assign via org_members.custom_role_id.
   The get_user_permissions() function merges built-in + custom permissions.';
