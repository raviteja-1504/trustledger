/**
 * Repository summary (lib/repoSummary.ts)
 *
 * GET /api/repos/summary?repo=owner/name → the repository record, its current files with sign-off status, its pull
 * requests, its full scan history and totals, from real rows only. Developers see their own pull requests' scans
 * only (as on /api/scans). Reads are paged past the 1000-row cap. Never cached at the edge.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { safeError } from "@/lib/errors";
import {
  buildRepoSummary, overrideKey,
  type SummaryAttestationRow, type SummaryFileRow, type SummaryScanRow, type SummaryViolationRow,
} from "@/lib/repoSummary";

const PAGE = 1000;
const MAX_ROWS = 10_000;
const IN_CHUNK = 200;
const MAX_PRS = 100;          // pull requests whose sign-off counts are computed (the newest)
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
type Page<T> = PromiseLike<{ data: T[] | null; error: unknown }>;

async function all<T>(page: (from: number, to: number) => Page<T>): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; from < MAX_ROWS; from += PAGE) {
    const { data, error } = await page(from, from + PAGE - 1);
    if (error) throw error;
    out.push(...(data ?? []));
    if (!data || data.length < PAGE) break;
  }
  return out;
}

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const { org_id, role, user_id } = auth;
  const repo = req.nextUrl.searchParams.get("repo") ?? "";
  if (!REPO_RE.test(repo)) return NextResponse.json({ error: "invalid_repo", message: "Use the owner/name form." }, { status: 400 });
  const db = createServiceClient();

  try {
    let ownLogin: string | null = null;
    if (role === "developer") {
      const { data: me } = user_id
        ? await db.from("org_members").select("github_login").eq("org_id", org_id).eq("user_id", user_id).maybeSingle() as { data: { github_login?: string | null } | null }
        : { data: null };
      ownLogin = me?.github_login ?? null;
    }
    const { data: repoRow } = await db.from("repositories").select("repo_full_name, default_branch, is_active, created_at")
      .eq("org_id", org_id).eq("repo_full_name", repo).maybeSingle() as { data: { repo_full_name: string; default_branch: string | null; is_active: boolean; created_at: string } | null };

    const scans = role === "developer" && !ownLogin ? [] : await all<SummaryScanRow>((f, t) => {
      let q = db.from("scans").select("id, pr_number, commit_sha, branch, overall_risk, total_ai_percentage, file_count, created_at, triggered_by, pr_author")
        .eq("org_id", org_id).eq("repo_full_name", repo);
      if (ownLogin) q = q.eq("pr_author", ownLogin);
      return q.order("created_at", { ascending: false }).order("id", { ascending: true }).range(f, t) as unknown as Page<SummaryScanRow>;
    });
    if (!repoRow && scans.length === 0) return NextResponse.json({ error: "repo_not_found", message: "This repository isn't connected to your organisation." }, { status: 404 });

    const latest = scans[0];
    // Latest scan of each PR (newest PRs first), for the PR list's sign-off counts.
    const latestPerPr = new Map<number, string>();
    for (const s of scans) { const k = s.pr_number ?? 0; if (!latestPerPr.has(k)) latestPerPr.set(k, s.id); }
    const prScanIds = [...latestPerPr.values()].slice(0, MAX_PRS);
    const chunks = (ids: string[]) => Array.from({ length: Math.ceil(ids.length / IN_CHUNK) }, (_, i) => ids.slice(i * IN_CHUNK, (i + 1) * IN_CHUNK));

    const [latestFiles, prFiles, attestations, violations, overrideRows, secrets] = await Promise.all([
      latest ? all<SummaryFileRow>((f, t) => db.from("scan_files").select("scan_id, file_path, language, risk_score, ai_percentage, risk_indicators")
        .eq("org_id", org_id).eq("scan_id", latest.id).order("file_path", { ascending: true }).range(f, t) as unknown as Page<SummaryFileRow>) : Promise.resolve([]),
      Promise.all(chunks(prScanIds).map(ids => all<SummaryFileRow>((f, t) => db.from("scan_files").select("scan_id, file_path, language, risk_score, ai_percentage, risk_indicators")
        .eq("org_id", org_id).in("scan_id", ids).in("risk_score", ["CRITICAL", "HIGH"]).order("file_path", { ascending: true }).range(f, t) as unknown as Page<SummaryFileRow>))).then(x => x.flat()),
      Promise.all(chunks(prScanIds).map(ids => all<SummaryAttestationRow>((f, t) => db.from("attestations").select("scan_id, file_path, reviewer_email, created_at")
        .eq("org_id", org_id).in("scan_id", ids).order("created_at", { ascending: true }).range(f, t) as unknown as Page<SummaryAttestationRow>))).then(x => x.flat()),
      latest ? all<SummaryViolationRow>((f, t) => db.from("violations").select("scan_id, file_path, status, sla_deadline")
        .eq("org_id", org_id).eq("scan_id", latest.id).order("file_path", { ascending: true }).range(f, t) as unknown as Page<SummaryViolationRow>) : Promise.resolve([]),
      prScanIds.length ? all<{ violation_id: string; status: string }>((f, t) => db.from("violation_overrides").select("violation_id, status")
        .eq("org_id", org_id).order("violation_id", { ascending: true }).range(f, t) as unknown as Page<{ violation_id: string; status: string }>).catch(() => []) : Promise.resolve([]),
      latest ? db.from("secret_findings").select("id", { count: "exact", head: true }).eq("org_id", org_id).eq("scan_id", latest.id).eq("status", "open") as unknown as Promise<{ count: number | null }> : Promise.resolve({ count: 0 }),
    ]);

    // Only overrides for files of these scans matter.
    const wanted = new Set<string>();
    for (const f of [...latestFiles, ...prFiles]) wanted.add(overrideKey(f.risk_score, f.scan_id, f.file_path));
    const overrides: Record<string, string> = {};
    for (const o of overrideRows) if (wanted.has(o.violation_id)) overrides[o.violation_id] = o.status;

    const summary = buildRepoSummary({ scans, latestFiles, prFiles, attestations, violations, overrides });
    return NextResponse.json({
      repo: repoRow ? { name: repoRow.repo_full_name, default_branch: repoRow.default_branch, is_active: repoRow.is_active, connected_at: repoRow.created_at } : { name: repo, default_branch: null, is_active: false, connected_at: null },
      scope: ownLogin || role === "developer" ? "own" : "org",
      open_secrets: secrets.count ?? 0,
      ...summary,
    }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    return safeError(err, { code: "repo_summary_failed", message: "We couldn't load this repository right now. Please try again." });
  }
}
