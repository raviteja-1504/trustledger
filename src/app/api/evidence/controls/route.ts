/**
 * Control ownership: who is responsible for each compliance control.
 *
 * GET    /api/evidence/controls?framework=soc2                          → every control with its owner (null = unowned)
 * PUT    /api/evidence/controls  { framework, control_id, owner_email } → assign or change the owner
 * DELETE /api/evidence/controls?framework=soc2&control_id=CC8.1         → remove the owner
 *
 * The owner must be a member of the organisation. Every change is written to the audit log with the previous owner.
 * Writes need can_export_data, like the rest of the evidence routes.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import { getFrameworkMapping } from "@/lib/controlMapping";
import { isValidOwnerEmail } from "@/lib/controlTracking";
import { loadControlOwners } from "@/lib/evidenceTracking";

const FRAMEWORKS = ["soc2", "iso27001", "pcidss", "aigov"];

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });
  const fw = getFrameworkMapping(req.nextUrl.searchParams.get("framework") ?? "soc2");
  if (!fw) return NextResponse.json({ error: "unknown_framework", supported: FRAMEWORKS }, { status: 400 });
  try {
    const owners = new Map((await loadControlOwners(createServiceClient(), org_id, fw.framework_id)).map(o => [o.control_id, o]));
    return NextResponse.json({
      framework_id: fw.framework_id,
      controls: fw.controls.map(c => ({
        control_id: c.control_id, control_name: c.control_name, owner: owners.get(c.control_id)?.owner_email ?? null,
        assigned_at: owners.get(c.control_id)?.assigned_at ?? null, assigned_by: owners.get(c.control_id)?.assigned_by_email ?? null,
      })),
    }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    return safeError(err, { code: "control_owners_failed", message: "We couldn't load control owners right now. Please try again." });
  }
}

export async function PUT(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = await requirePermission(auth, "can_export_data");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  let body: { framework?: string; control_id?: string; owner_email?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "invalid_json" }, { status: 400 }); }
  const fw = getFrameworkMapping(body.framework ?? "");
  if (!fw) return NextResponse.json({ error: "unknown_framework", supported: FRAMEWORKS }, { status: 400 });
  if (!fw.controls.some(c => c.control_id === body.control_id)) {
    return NextResponse.json({ error: "unknown_control_id", framework: fw.framework_id, valid_controls: fw.controls.map(c => c.control_id) }, { status: 400 });
  }
  if (!isValidOwnerEmail(body.owner_email)) return NextResponse.json({ error: "invalid_owner_email" }, { status: 400 });
  const owner = body.owner_email.trim().toLowerCase();

  const db = createServiceClient();
  try {
    const { data: members, error: memberErr } = await db.from("org_members").select("email").eq("org_id", auth.org_id) as { data: Array<{ email: string | null }> | null; error: unknown };
    if (memberErr) throw memberErr;
    if (!(members ?? []).some(m => m.email?.toLowerCase() === owner)) {
      return NextResponse.json({ error: "owner_not_a_member", message: "The owner must be a member of this organisation." }, { status: 400 });
    }
    const previous = (await loadControlOwners(db, auth.org_id, fw.framework_id)).find(o => o.control_id === body.control_id)?.owner_email ?? null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { error: upErr } = await (db.from("control_owners") as any).upsert({
      org_id: auth.org_id, framework_id: fw.framework_id, control_id: body.control_id, owner_email: owner,
      assigned_by_email: auth.actor_email ?? null, assigned_at: new Date().toISOString(),
    }, { onConflict: "org_id,framework_id,control_id" });
    if (upErr) throw upErr;
    await writeAuditLog(db, {
      org_id: auth.org_id, event_type: "org_settings_changed", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "control_owner", resource_id: `${fw.framework_id}:${body.control_id}`,
      payload: { framework: fw.framework_id, control_id: body.control_id, owner, previous_owner: previous },
    });
    return NextResponse.json({ ok: true, framework_id: fw.framework_id, control_id: body.control_id, owner, previous_owner: previous });
  } catch (err) {
    return safeError(err, { code: "control_owner_failed", message: "We couldn't save that owner right now. Please try again." });
  }
}

export async function DELETE(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = await requirePermission(auth, "can_export_data");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const p = req.nextUrl.searchParams;
  const fw = getFrameworkMapping(p.get("framework") ?? "");
  const controlId = p.get("control_id");
  if (!fw || !controlId || !fw.controls.some(c => c.control_id === controlId)) return NextResponse.json({ error: "unknown_control" }, { status: 400 });

  const db = createServiceClient();
  try {
    const previous = (await loadControlOwners(db, auth.org_id, fw.framework_id)).find(o => o.control_id === controlId)?.owner_email ?? null;
    if (!previous) return NextResponse.json({ ok: true, removed: false });
    const { error: delErr } = await db.from("control_owners").delete().eq("org_id", auth.org_id).eq("framework_id", fw.framework_id).eq("control_id", controlId);
    if (delErr) throw delErr;
    await writeAuditLog(db, {
      org_id: auth.org_id, event_type: "org_settings_changed", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "control_owner", resource_id: `${fw.framework_id}:${controlId}`,
      payload: { framework: fw.framework_id, control_id: controlId, owner: null, previous_owner: previous },
    });
    return NextResponse.json({ ok: true, removed: true, previous_owner: previous });
  } catch (err) {
    return safeError(err, { code: "control_owner_failed", message: "We couldn't remove that owner right now. Please try again." });
  }
}
