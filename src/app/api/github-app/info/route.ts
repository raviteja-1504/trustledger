/**
 * GET /api/github-app/info -> { configured: boolean, install_url: string | null }
 *
 * Whether this TrustLedger deployment already has its GitHub App (GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY set), and the
 * link a customer clicks to install it. The setup wizard shows a customer only that link; the app-creation guide is for
 * whoever runs the deployment, and only while no app is configured. Reports no secret.
 */
import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "../../_middleware";
import { getAppPublicInfo } from "@/lib/github";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const configured = !!((process.env.GITHUB_APP_ID ?? "").trim() && (process.env.GITHUB_APP_PRIVATE_KEY ?? "").trim());
  if (!configured) return NextResponse.json({ configured: false, install_url: null }, { headers: { "Cache-Control": "private, no-store" } });

  try {
    const info = await getAppPublicInfo();
    return NextResponse.json({ configured: true, install_url: info.install_url }, { headers: { "Cache-Control": "private, no-store" } });
  } catch {
    // the app is set up but GitHub could not be asked for its link just now: the page offers a retry
    return NextResponse.json({ configured: true, install_url: null }, { headers: { "Cache-Control": "private, no-store" } });
  }
}
