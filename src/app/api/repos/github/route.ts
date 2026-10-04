/**
 * GitHub App connection status for Settings → Repositories.
 *
 * GET /api/repos/github → { installed, accounts: ["acme", ...], install_url }
 *
 * install_url opens GitHub's "Install TrustLedger" page; after installing, GitHub sends the user back to
 * /api/auth/callback, which links the installation to this org. null when the App's details can't be read.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { getAppPublicInfo } from "@/lib/github";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const db = createServiceClient();
  const { data: installs } = await db
    .from("github_installations")
    .select("github_org")
    .eq("org_id", auth.org_id)
    .limit(20) as { data: Array<{ github_org: string | null }> | null };

  const installUrl = await getAppPublicInfo().then(a => a.install_url, () => null);
  const accounts = (installs ?? []).map(i => i.github_org).filter((x): x is string => !!x && x !== "unknown");
  return NextResponse.json({ installed: (installs ?? []).length > 0, accounts, install_url: installUrl });
}
