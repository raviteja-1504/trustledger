/**
 * Repository Management API
 * GET  /api/repos              → list monitored repos
 * POST /api/repos              → add single repo
 * POST /api/repos?import=github → bulk import all repos from GitHub org
 * PATCH /api/repos             → toggle repo active/inactive
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { getInstallationToken } from "@/lib/github";

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
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url     = new URL(req.url);
  const isImport = url.searchParams.get("import") === "github";
  const db      = createServiceClient();

  if (isImport) {
    // ── Bulk import from GitHub org ─────────────────────────────────────────
    const { data: installation } = await db
      .from("github_installations")
      .select("installation_id, github_org")
      .eq("org_id", org_id)
      .single() as { data: { installation_id: number; github_org: string } | null };

    if (!installation) {
      return NextResponse.json({ error:"github_app_not_installed", hint:"Install the TrustLedger GitHub App first" }, { status: 422 });
    }

    // Get installation token
    const { token } = await getInstallationToken(installation.installation_id);

    // Fetch all repos for the installation
    const githubRepos: Array<{ full_name: string; default_branch: string; private: boolean }> = [];
    let page = 1;
    while (true) {
      const res = await fetch(
        `https://api.github.com/installation/repositories?per_page=100&page=${page}`,
        { headers: { Authorization: `token ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" } },
      );
      if (!res.ok) break;
      const data = await res.json() as { repositories: typeof githubRepos; total_count: number };
      githubRepos.push(...data.repositories);
      if (githubRepos.length >= data.total_count || data.repositories.length < 100) break;
      page++;
    }

    if (githubRepos.length === 0) {
      return NextResponse.json({ error:"no_repos_found", hint:"Check GitHub App installation permissions" }, { status: 422 });
    }

    // Upsert all repos
    const { data: inserted, error: insErr } = await db
      .from("repositories")
      .upsert(
        githubRepos.map(r => ({
          org_id,
          repo_full_name:  r.full_name,
          default_branch:  r.default_branch,
          is_active:       true,
        })),
        { onConflict: "org_id,repo_full_name" },
      )
      .select("id, repo_full_name") as { data: unknown[] | null; error: unknown };

    if (insErr) return NextResponse.json({ error:"import_failed" }, { status: 500 });
    return NextResponse.json({ imported: (inserted ?? []).length, total: githubRepos.length });
  }

  // ── Add single repo ──────────────────────────────────────────────────────
  const body = await req.json() as { repo_full_name: string; default_branch?: string };
  if (!body.repo_full_name) return NextResponse.json({ error:"missing_repo" }, { status:400 });

  const { data, error: insErr } = await db
    .from("repositories")
    .upsert({ org_id, repo_full_name: body.repo_full_name, default_branch: body.default_branch ?? "main" },
      { onConflict: "org_id,repo_full_name" })
    .select("id, repo_full_name, default_branch, is_active, created_at")
    .single() as { data: unknown; error: unknown };

  if (insErr) return NextResponse.json({ error:"insert_failed" }, { status:500 });
  return NextResponse.json({ repo: data });
}

export async function PATCH(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as { id: string; is_active: boolean };
  if (!body.id) return NextResponse.json({ error:"missing_id" }, { status:400 });

  const db = createServiceClient();
  await db.from("repositories").update({ is_active: body.is_active }).eq("id", body.id).eq("org_id", org_id);
  return NextResponse.json({ ok: true });
}
