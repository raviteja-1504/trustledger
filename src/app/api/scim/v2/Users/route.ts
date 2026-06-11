/**
 * SCIM 2.0 Users endpoint
 * Enables Okta, Azure AD, and Google Workspace to auto-provision
 * and de-provision TrustLedger users without admin intervention.
 *
 * Spec: https://www.rfc-editor.org/rfc/rfc7644
 * Base URL: /api/scim/v2
 *
 * Supported operations:
 *   GET    /Users           → list users
 *   GET    /Users/{id}      → get user
 *   POST   /Users           → provision new user
 *   PUT    /Users/{id}      → replace user
 *   PATCH  /Users/{id}      → update user (e.g. deactivate)
 *   DELETE /Users/{id}      → deprovision user
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";

const SCIM_CONTENT_TYPE = "application/scim+json";

// ── SCIM Bearer token auth ────────────────────────────────────────────────────
function verifySCIMToken(req: NextRequest): { org_id: string } | null {
  const auth  = req.headers.get("Authorization") ?? "";
  const token = auth.replace("Bearer ", "").trim();
  const expected = process.env.SCIM_TOKEN ?? "";
  if (!expected || token !== expected) return null;

  const orgId = process.env.SCIM_ORG_ID ?? "";
  if (!orgId) return null;
  return { org_id: orgId };
}

function scimUser(member: Record<string, unknown>, host: string) {
  return {
    schemas:    ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id:         member.user_id as string,
    userName:   member.email as string,
    name:       { formatted: member.name as string ?? member.email },
    emails:     [{ value: member.email as string, primary: true }],
    active:     true,
    meta: {
      resourceType: "User",
      location:     `${host}/api/scim/v2/Users/${member.user_id as string}`,
    },
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
      organization: member.org_id as string,
    },
  };
}

// ── GET — list or filter users ────────────────────────────────────────────────
export async function GET(req: NextRequest) {
  const auth = verifySCIMToken(req);
  if (!auth) return new NextResponse("Unauthorized", { status: 401 });

  const url    = new URL(req.url);
  const filter = url.searchParams.get("filter");  // e.g. userName eq "alice@org.io"
  const start  = parseInt(url.searchParams.get("startIndex") ?? "1") - 1;
  const count  = parseInt(url.searchParams.get("count") ?? "100");
  const host   = url.origin;

  const db = createServiceClient();
  let query = db
    .from("org_members")
    .select("user_id, email, name, role, org_id")
    .eq("org_id", auth.org_id)
    .range(start, start + count - 1);

  // Simple userName filter support
  if (filter && filter.includes("userName eq ")) {
    const email = filter.match(/userName eq ["']?([^"']+)["']?/)?.[1] ?? "";
    query = query.eq("email", email) as typeof query;
  }

  const { data: members, count: total } = await query as {
    data: Record<string, unknown>[] | null;
    count: number | null;
  };

  const resources = (members ?? []).map(m => scimUser(m, host));

  return NextResponse.json({
    schemas:      ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    totalResults: total ?? resources.length,
    startIndex:   start + 1,
    itemsPerPage: count,
    Resources:    resources,
  }, { headers: { "Content-Type": SCIM_CONTENT_TYPE } });
}

// ── POST — provision new user ─────────────────────────────────────────────────
export async function POST(req: NextRequest) {
  const auth = verifySCIMToken(req);
  if (!auth) return new NextResponse("Unauthorized", { status: 401 });

  const body = await req.json() as {
    userName:  string;
    name?:     { formatted?: string; givenName?: string; familyName?: string };
    emails?:   Array<{ value: string; primary?: boolean }>;
    active?:   boolean;
  };

  const email   = body.userName ?? body.emails?.find(e => e.primary)?.value ?? "";
  const name    = body.name?.formatted ?? `${body.name?.givenName ?? ""} ${body.name?.familyName ?? ""}`.trim();
  const host    = new URL(req.url).origin;

  if (!email) {
    return NextResponse.json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status:  "400",
      detail:  "userName is required",
    }, { status: 400, headers: { "Content-Type": SCIM_CONTENT_TYPE } });
  }

  const db = createServiceClient();

  // Create user in Supabase Auth
  const { data: authUser, error: authErr } = await db.auth.admin.createUser({
    email,
    email_confirm: true,
    user_metadata:  { name, scim_provisioned: true },
  });

  if (authErr || !authUser.user) {
    return NextResponse.json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status:  "409",
      detail:  authErr?.message ?? "User creation failed",
    }, { status: 409, headers: { "Content-Type": SCIM_CONTENT_TYPE } });
  }

  // Create org membership
  await db.from("org_members").upsert({
    org_id:   auth.org_id,
    user_id:  authUser.user.id,
    email,
    name:     name || null,
    role:     "developer",
  }, { onConflict: "org_id,user_id" });

  const member = { user_id: authUser.user.id, email, name, org_id: auth.org_id };
  return NextResponse.json(scimUser(member, host), {
    status:  201,
    headers: { "Content-Type": SCIM_CONTENT_TYPE },
  });
}
