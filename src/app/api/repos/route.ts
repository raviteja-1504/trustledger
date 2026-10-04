/**
 * Repository Management API
 * GET   /api/repos              → list the org's repositories (connected or switched off)
 * POST  /api/repos?import=github → add every repo the org's GitHub App installations can read   (admin)
 * POST  /api/repos              → add one repo by owner/name (API / CLI use)                     (admin)
 * PATCH /api/repos              → switch a repo on or off { id, is_active }                       (admin)
 *
 * Import only ADDS repositories that aren't connected yet: one an admin switched off stays off.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../_middleware";
import { getInstallationToken, listInstallationRepos } from "@/lib/github";
import { safeError } from "@/lib/errors";
import { cacheDel, cacheKeys } from "@/lib/cache";

/** Repos switched on/off or added change what the dashboard counts — drop its cached numbers right away. */
async function invalidateDashboard(orgId: string) {
  await Promise.all([7, 30, 90].map(d => cacheDel(cacheKeys.dashboard(orgId, d)))).catch(() => {});
}

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();
  const { data } = await db
    .from("repositories")
    .select("id, repo_full_name, default_branch, is_active, created_at")
    .eq("org_id", org_id)
    .order("repo_full_name") as { data: unknown[] | null };

  return NextResponse.json({ repos: data ?? [] });
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr, message: "Only admins can add repositories." }, { status: 403 });
  const { org_id } = auth;
  const db = createServiceClient();

  if (req.nextUrl.searchParams.get("import") === "github") {
    // ── Import from every GitHub App installation this org has ──────────────
    const { data: installs } = await db
      .from("github_installations")
      .select("installation_id, github_org")
      .eq("org_id", org_id)
      .limit(20) as { data: Array<{ installation_id: number; github_org: string | null }> | null };
    if (!installs || installs.length === 0) {
      return NextResponse.json({ error: "github_app_not_installed", message: "Install the TrustLedger GitHub App first." }, { status: 422 });
    }

    try {
      const found = new Map<string, string>();
      for (const i of installs) {
        const { token } = await getInstallationToken(i.installation_id);
        for (const r of await listInstallationRepos(token)) found.set(r.full_name, r.default_branch);
      }
      if (found.size === 0) {
        return NextResponse.json({ error: "no_repos_found", message: "The GitHub App can't see any repositories. On GitHub, give it access to the repositories you want scanned." }, { status: 422 });
      }

      const { data: existing } = await db.from("repositories").select("repo_full_name").eq("org_id", org_id) as { data: Array<{ repo_full_name: string }> | null };
      const known = new Set((existing ?? []).map(r => r.repo_full_name));
      const fresh = [...found].filter(([name]) => !known.has(name));
      if (fresh.length > 0) {
        const { error: insErr } = await db
          .from("repositories")
          .upsert(fresh.map(([name, branch]) => ({ org_id, repo_full_name: name, default_branch: branch || "main", is_active: true })),
            { onConflict: "org_id,repo_full_name", ignoreDuplicates: true });
        if (insErr) throw insErr;
        await invalidateDashboard(org_id);
      }
      return NextResponse.json({ added: fresh.length, already_connected: found.size - fresh.length, total: found.size });
    } catch (err) {
      return safeError(err, { code: "import_failed", message: "We couldn't import repositories from GitHub. Check that the TrustLedger GitHub App is still installed." });
    }
  }

  // ── Add a single repo ────────────────────────────────────────────────────
  const body = await req.json().catch(() => ({})) as { repo_full_name?: string; default_branch?: string };
  const name = (body.repo_full_name ?? "").trim();
  if (!REPO_RE.test(name)) return NextResponse.json({ error: "invalid_repo", message: "Use the owner/name form, e.g. my-org/payments-api." }, { status: 400 });

  const { data, error: insErr } = await db
    .from("repositories")
    .upsert({ org_id, repo_full_name: name, default_branch: body.default_branch ?? "main" }, { onConflict: "org_id,repo_full_name" })
    .select("id, repo_full_name, default_branch, is_active, created_at")
    .single() as { data: unknown; error: unknown };

  if (insErr) return NextResponse.json({ error: "insert_failed" }, { status: 500 });
  await invalidateDashboard(org_id);
  return NextResponse.json({ repo: data });
}

export async function PATCH(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr, message: "Only admins can switch repositories on or off." }, { status: 403 });

  const body = await req.json().catch(() => ({})) as { id?: string; is_active?: unknown };
  if (!body.id || typeof body.is_active !== "boolean") return NextResponse.json({ error: "missing_fields", message: "Send the repository id and is_active (true/false)." }, { status: 400 });

  const db = createServiceClient();
  const { data } = await db.from("repositories").update({ is_active: body.is_active }).eq("id", body.id).eq("org_id", auth.org_id)
    .select("id, is_active") as { data: unknown[] | null };
  if (!data || data.length === 0) return NextResponse.json({ error: "repo_not_found" }, { status: 404 });
  await invalidateDashboard(auth.org_id);
  return NextResponse.json({ ok: true });
}
