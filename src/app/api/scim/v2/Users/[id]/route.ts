/**
 * SCIM 2.0 User by ID
 * GET/PUT/PATCH/DELETE /api/scim/v2/Users/{id}
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";

const SCIM_CONTENT_TYPE = "application/scim+json";

function verifySCIMToken(req: NextRequest): { org_id: string } | null {
  const token    = (req.headers.get("Authorization") ?? "").replace("Bearer ", "").trim();
  const expected = process.env.SCIM_TOKEN ?? "";
  if (!expected || token !== expected) return null;
  const orgId = process.env.SCIM_ORG_ID ?? "";
  if (!orgId) return null;
  return { org_id: orgId };
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

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  const auth = verifySCIMToken(req);
  if (!auth) return new NextResponse("Unauthorized", { status: 401 });

  const db     = createServiceClient();
  const member = await getMember(db, auth.org_id, params.id);
  if (!member) return new NextResponse("", { status: 404 });

  return NextResponse.json(scimUser(member, new URL(req.url).origin), {
    headers: { "Content-Type": SCIM_CONTENT_TYPE },
  });
}

export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
  const auth = verifySCIMToken(req);
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
    await db.from("org_members").delete().eq("user_id", params.id).eq("org_id", auth.org_id);
    return new NextResponse("", { status: 204 });
  }

  const member = await getMember(db, auth.org_id, params.id);
  if (!member) return new NextResponse("", { status: 404 });

  return NextResponse.json(scimUser(member, new URL(req.url).origin), {
    headers: { "Content-Type": SCIM_CONTENT_TYPE },
  });
}

export async function DELETE(req: NextRequest, { params }: { params: { id: string } }) {
  const auth = verifySCIMToken(req);
  if (!auth) return new NextResponse("Unauthorized", { status: 401 });

  const db = createServiceClient();
  await db.from("org_members").delete().eq("user_id", params.id).eq("org_id", auth.org_id);

  return new NextResponse("", { status: 204 });
}
