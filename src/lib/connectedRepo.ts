/**
 * Resolves a repository the org has connected (an active `repositories` row) to the GitHub App installation
 * that can read it. Used by dashboard-initiated PR scans and the open-PR picker.
 */
import type { SupabaseClient } from "@supabase/supabase-js";

export type ConnectedRepo =
  | { ok: true; repo: string; owner: string; name: string; installationId: number }
  | { ok: false; status: 400 | 404 | 422; error: "invalid_repo" | "repo_not_connected" | "github_app_not_installed"; message: string };

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function resolveConnectedRepo(db: SupabaseClient<any>, orgId: string, repo: string | null | undefined): Promise<ConnectedRepo> {
  const full = (repo ?? "").trim();
  if (!REPO_RE.test(full)) {
    return { ok: false, status: 400, error: "invalid_repo", message: "Choose a repository in owner/name form." };
  }

  const { data: row } = await db
    .from("repositories")
    .select("repo_full_name")
    .eq("org_id", orgId)
    .eq("repo_full_name", full)
    .eq("is_active", true)
    .maybeSingle() as { data: { repo_full_name: string } | null };
  if (!row) {
    return { ok: false, status: 404, error: "repo_not_connected", message: "That repository isn't connected to your organisation. Add it under Settings → Repositories first." };
  }

  const { data: installs } = await db
    .from("github_installations")
    .select("installation_id, github_org")
    .eq("org_id", orgId)
    .limit(20) as { data: Array<{ installation_id: number; github_org: string | null }> | null };
  const [owner, name] = full.split("/");
  // An org can have the App on several GitHub accounts: prefer the one that owns this repo.
  const install = (installs ?? []).find(i => (i.github_org ?? "").toLowerCase() === owner.toLowerCase()) ?? (installs ?? [])[0];
  if (!install) {
    return { ok: false, status: 422, error: "github_app_not_installed", message: "Install the TrustLedger GitHub App to scan pull requests from the dashboard." };
  }
  return { ok: true, repo: full, owner, name, installationId: install.installation_id };
}
