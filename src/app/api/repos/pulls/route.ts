/**
 * Open pull requests of a connected repository (for the dashboard's New Scan panel).
 *
 * GET /api/repos/pulls?repo=owner/name → { pulls: [{ number, title, author, branch, head_sha, draft, updated_at }] }
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { resolveConnectedRepo } from "@/lib/connectedRepo";
import { getInstallationToken, listOpenPullRequests } from "@/lib/github";
import { safeError } from "@/lib/errors";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const db = createServiceClient();
  const target = await resolveConnectedRepo(db, auth.org_id, req.nextUrl.searchParams.get("repo"));
  if (!target.ok) return NextResponse.json({ error: target.error, message: target.message }, { status: target.status });

  try {
    const { token } = await getInstallationToken(target.installationId);
    const pulls = await listOpenPullRequests(token, target.owner, target.name);
    return NextResponse.json({
      pulls: pulls.map(p => ({ number: p.number, title: p.title, author: p.author, branch: p.branch, head_sha: p.head_sha, draft: p.draft, updated_at: p.updated_at })),
    });
  } catch (err) {
    return safeError(err, { code: "github_error", message: "We couldn't load this repository's pull requests from GitHub. Check that the TrustLedger GitHub App can access it." });
  }
}
