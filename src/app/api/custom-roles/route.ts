/**
 * Custom Roles API -- granular permission sets that replace a member's built-in role permissions
 * (see lib/permissions.ts). Assign one with PATCH /api/team { user_id, custom_role_id }.
 *
 * GET    /api/custom-roles          → roles + which member holds which   (team managers)
 * POST   /api/custom-roles          → create   { name, description?, ...flags }
 * PATCH  /api/custom-roles          → update   { id, name?, description?, ...flags }
 * DELETE /api/custom-roles?id=...   → delete; its members fall back to their built-in role
 *
 * A non-admin team manager can only create or edit roles within their own permissions (checkGrantable).
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../_middleware";
import { checkGrantable } from "@/lib/permissionResolver";
import { PERMISSION_KEYS, permissionsFromRow, type PermissionKey } from "@/lib/permissions";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";

const SETUP_HINT = "Custom roles need database migration 005_advanced_rbac.";

const flagShape = Object.fromEntries(PERMISSION_KEYS.map(k => [k, z.boolean().optional()])) as Record<PermissionKey, z.ZodOptional<z.ZodBoolean>>;
const nameSchema = z.string().trim().min(1, "Name is required").max(60);
const CreateSchema = z.object({ name: nameSchema, description: z.string().trim().max(200).nullish(), ...flagShape }).strict();
const UpdateSchema = z.object({ id: z.string().uuid(), name: nameSchema.optional(), description: z.string().trim().max(200).nullish(), ...flagShape }).strict();

type Row = { id: string; name: string; description: string | null } & Partial<Record<PermissionKey, boolean>>;

function isNotSetUp(err: { code?: string; message?: string } | null | undefined): boolean {
  return !!err && (err.code === "42P01" || err.code === "42703" || /custom_role/.test(err.message ?? ""));
}

async function gate(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return { auth, res: NextResponse.json({ error: auth.error }, { status: 401 }) };
  const permErr = await requirePermission(auth, "can_manage_team");
  if (permErr) return { auth, res: NextResponse.json({ error: permErr }, { status: 403 }) };
  return { auth, res: null };
}

function flagsOf(body: Partial<Record<PermissionKey, boolean | undefined>>) {
  return Object.fromEntries(PERMISSION_KEYS.filter(k => body[k] !== undefined).map(k => [k, body[k]])) as Partial<Record<PermissionKey, boolean>>;
}

export async function GET(req: NextRequest) {
  const { auth, res } = await gate(req);
  if (res) return res;
  const db = createServiceClient();
  const { data: roles, error } = await db.from("custom_roles").select("*").eq("org_id", auth.org_id).order("name");
  if (error) {
    if (isNotSetUp(error)) return NextResponse.json({ roles: [], assignments: {}, set_up: false, message: SETUP_HINT });
    return safeError(error, { code: "custom_roles_fetch_failed", message: "We couldn't load custom roles right now. Please try again." });
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: members } = await (db.from("org_members") as any)
    .select("user_id, custom_role_id").eq("org_id", auth.org_id).not("custom_role_id", "is", null) as
    { data: Array<{ user_id: string | null; custom_role_id: string }> | null };
  const assignments: Record<string, string> = {};
  for (const m of members ?? []) if (m.user_id) assignments[m.user_id] = m.custom_role_id;
  return NextResponse.json({ roles: roles ?? [], assignments, set_up: true });
}

export async function POST(req: NextRequest) {
  const { auth, res } = await gate(req);
  if (res) return res;
  const parsed = CreateSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "invalid_body", issues: parsed.error.issues.map(i => i.message) }, { status: 400 });
  const { name, description, ...rest } = parsed.data;
  const flags = permissionsFromRow(flagsOf(rest));   // every flag explicit: unset means "not allowed"

  const grantErr = await checkGrantable(auth, { permissions: flags });
  if (grantErr) return NextResponse.json({ error: grantErr }, { status: 403 });

  const db = createServiceClient();
  const { data, error } = await db.from("custom_roles")
    .insert({ org_id: auth.org_id, name, description: description ?? null, ...flags })
    .select("*").single();
  if (error) {
    if (error.code === "23505") return NextResponse.json({ error: "duplicate_name" }, { status: 409 });
    if (isNotSetUp(error)) return NextResponse.json({ error: "custom_roles_not_set_up", message: SETUP_HINT }, { status: 422 });
    return safeError(error, { code: "custom_role_create_failed", message: "We couldn't create that role. Please try again." });
  }
  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "policy_change", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "custom_role", resource_id: (data as Row).id, payload: { action: "created", name, permissions: flags },
  });
  return NextResponse.json({ role: data }, { status: 201 });
}

export async function PATCH(req: NextRequest) {
  const { auth, res } = await gate(req);
  if (res) return res;
  const parsed = UpdateSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "invalid_body", issues: parsed.error.issues.map(i => i.message) }, { status: 400 });
  const { id, name, description, ...rest } = parsed.data;

  const db = createServiceClient();
  const { data: current } = await db.from("custom_roles").select("*").eq("id", id).eq("org_id", auth.org_id).maybeSingle();
  if (!current) return NextResponse.json({ error: "custom_role_not_found" }, { status: 404 });

  // Both the role as it stands and as it will be must be within the caller's reach -- otherwise a
  // limited manager could edit a broader role they couldn't have created.
  const next = permissionsFromRow({ ...(current as Row), ...flagsOf(rest) });
  for (const permissions of [permissionsFromRow(current as Row), next]) {
    const grantErr = await checkGrantable(auth, { permissions });
    if (grantErr) return NextResponse.json({ error: grantErr }, { status: 403 });
  }

  const updates: Record<string, unknown> = { ...flagsOf(rest) };
  if (name !== undefined) updates.name = name;
  if (description !== undefined) updates.description = description ?? null;
  const { data, error } = await db.from("custom_roles").update(updates).eq("id", id).eq("org_id", auth.org_id).select("*").single();
  if (error) {
    if (error.code === "23505") return NextResponse.json({ error: "duplicate_name" }, { status: 409 });
    return safeError(error, { code: "custom_role_update_failed", message: "We couldn't save that role. Please try again." });
  }
  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "policy_change", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "custom_role", resource_id: id, payload: { action: "updated", changes: updates },
  });
  return NextResponse.json({ role: data });
}

export async function DELETE(req: NextRequest) {
  const { auth, res } = await gate(req);
  if (res) return res;
  const id = new URL(req.url).searchParams.get("id");
  if (!id) return NextResponse.json({ error: "id_required" }, { status: 400 });

  const db = createServiceClient();
  const { data: current } = await db.from("custom_roles").select("*").eq("id", id).eq("org_id", auth.org_id).maybeSingle();
  if (!current) return NextResponse.json({ error: "custom_role_not_found" }, { status: 404 });
  const grantErr = await checkGrantable(auth, { permissions: permissionsFromRow(current as Row) });
  if (grantErr) return NextResponse.json({ error: grantErr }, { status: 403 });

  // Members holding it go back to their built-in role (the foreign key would otherwise block the delete).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error: unassignErr } = await (db.from("org_members") as any)
    .update({ custom_role_id: null }).eq("org_id", auth.org_id).eq("custom_role_id", id);
  if (unassignErr) return safeError(unassignErr, { code: "custom_role_delete_failed", message: "We couldn't remove that role. Please try again." });
  const { error } = await db.from("custom_roles").delete().eq("id", id).eq("org_id", auth.org_id);
  if (error) return safeError(error, { code: "custom_role_delete_failed", message: "We couldn't remove that role. Please try again." });

  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "policy_change", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "custom_role", resource_id: id, payload: { action: "deleted", name: (current as Row).name },
  });
  return NextResponse.json({ ok: true });
}
