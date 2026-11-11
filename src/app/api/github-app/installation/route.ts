/**
 * GET /api/github-app/installation?id=<installation_id> -> { login }
 *
 * After someone installs the GitHub App, GitHub sends them back with ?installation_id=...: this asks GitHub which account
 * that installation is on, so the setup wizard can fill in the organisation handle instead of asking for it. Returns only
 * the account's public login.
 */
import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "../../_middleware";
import { getInstallationAccount } from "@/lib/github";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const id = req.nextUrl.searchParams.get("id") ?? "";
  if (!/^\d{1,15}$/.test(id)) return NextResponse.json({ error: "invalid_installation_id" }, { status: 400 });

  try {
    const login = await getInstallationAccount(Number(id));
    return NextResponse.json({ login }, { headers: { "Cache-Control": "private, no-store" } });
  } catch {
    return NextResponse.json({ error: "installation_not_found" }, { status: 404 });
  }
}
