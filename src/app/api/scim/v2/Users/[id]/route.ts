/**
 * SCIM 2.0 User by ID
 * GET/PUT/PATCH/DELETE /api/scim/v2/Users/{id}
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyScimRequest } from "@/lib/scimAuth";
import { requireAudit } from "@/lib/auditRequired";

const SCIM_CONTENT_TYPE = "application/scim+json";

function verifySCIMToken(req: NextRequest): Promise<{ org_id: string } | null> {
  return verifyScimRequest(req, createServiceClient());
}

function scimUser(member: Record<string, unknown>, host: string) {
  return {
    schemas:  ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id:       member.user_id as string,
    userName: member.email as string,
    name:     { formatted: (member.name as string) ?? member.email },
    emails:   [{ value: member.email as string, primary: true }],
    active:   true,
    meta: { resourceType: "User", location: `${host}/api/scim/v2/Users/${member.user_id as string}` },
  };
}

async function getMember(db: ReturnType<typeof createServiceClient>, orgId: string, userId: string) {
  const { data } = await db
    .from("org_members")
    .select("user_id, email, name, role, org_id")
    .eq("org_id", orgId)
    .eq("user_id", userId)
    .single() as { data: Record<string, unknown> | null };
  return data;
}

/**
 * Remove a member and record it. The removal stays in force even if the record cannot be written (revoking access is the safe
 * direction); the IdP is told it failed and retries, and a retry writes the entry (`already_absent`) even though the row is
 * gone, so the record is not lost. Returns a response only on failure.
 */
async function deprovision(db: ReturnType<typeof createServiceClient>, orgId: string, userId: string): Promise<NextResponse | null> {
  const member = await getMember(db, orgId, userId);
  const { error } = await db.from("org_members").delete().eq("user_id", userId).eq("org_id", orgId);
  if (error) return NextResponse.json({ schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"], status: "500", detail: "Could not remove the user." }, { status: 500, headers: { "Content-Type": SCIM_CONTENT_TYPE } });
  return requireAudit(db, {
    org_id: orgId, event_type: "user_removed", actor_id: null, actor_email: "scim",
    resource_type: "user", resource_id: userId, payload: { via: "scim", email: member?.email ?? null, already_absent: !member },
  });
}

export async function GET(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const params = await ctx.params;
  const auth = await verifySCIMToken(req);
  if (!auth) return new NextResponse("Unauthorized", { status: 401 });

  const db     = createServiceClient();
  const member = await getMember(db, auth.org_id, params.id);
  if (!member) return new NextResponse("", { status: 404 });

  return NextResponse.json(scimUser(member, new URL(req.url).origin), {
    headers: { "Content-Type": SCIM_CONTENT_TYPE },
  });
}

export async function PATCH(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const params = await ctx.params;
  const auth = await verifySCIMToken(req);
  if (!auth) return new NextResponse("Unauthorized", { status: 401 });

  const body = await req.json() as {
    Operations: Array<{ op: string; path?: string; value?: unknown }>;
  };

  const db = createServiceClient();

  // Handle deactivation: PATCH { Operations: [{ op: "replace", path: "active", value: false }] }
  const deactivate = body.Operations?.some(
    op => op.op?.toLowerCase() === "replace" && op.path === "active" && op.value === false
  );

  if (deactivate) {
    // Remove org membership (de-provision)
    const failed = await deprovision(db, auth.org_id, params.id);
    if (failed) return failed;
    return new NextResponse(null, { status: 204 });   // a 204 must have no body (an empty string throws)
  }

  const member = await getMember(db, auth.org_id, params.id);
  if (!member) return new NextResponse("", { status: 404 });

  return NextResponse.json(scimUser(member, new URL(req.url).origin), {
    headers: { "Content-Type": SCIM_CONTENT_TYPE },
  });
}

export async function DELETE(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const params = await ctx.params;
  const auth = await verifySCIMToken(req);
  if (!auth) return new NextResponse("Unauthorized", { status: 401 });

  const db = createServiceClient();
  const failed = await deprovision(db, auth.org_id, params.id);
  if (failed) return failed;

  return new NextResponse(null, { status: 204 });   // a 204 must have no body (an empty string throws)
}
