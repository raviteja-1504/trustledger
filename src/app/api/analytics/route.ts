/**
 * Analytics (lib/orgAnalytics.ts)
 *
 * GET /api/analytics?days=7|30|90 → measured weekly activity, review times, backlog age, AI content trend, reviewers,
 * repositories. Developers see only their own pull requests (as on /api/dashboard). Never cached at the edge: it is
 * per-org data, and the page polls it for live numbers.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { safeError } from "@/lib/errors";
import { computeAnalytics, type AnalyticsRows } from "@/lib/orgAnalytics";

const PAGE = 1000;          // the project's PostgREST max_rows
const MAX_ROWS = 10_000;    // per table, per request
const IN_CHUNK = 200;

type Scan = AnalyticsRows["scans"][number];
type Violation = AnalyticsRows["violations"][number];
type Attestation = AnalyticsRows["attestations"][number];
type Page<T> = PromiseLike<{ data: T[] | null; error: unknown }>;

/** Page through a query past the 1000-row cap. */
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
  const days = [7, 30, 90].includes(Number(req.nextUrl.searchParams.get("days"))) ? Number(req.nextUrl.searchParams.get("days")) : 30;
  const now = new Date();
  const start = new Date(now.getTime() - days * 86400_000).toISOString();
  const db = createServiceClient();

  try {
    let ownLogin: string | null = null;
    if (role === "developer") {
      const { data: me } = user_id
        ? await db.from("org_members").select("github_login").eq("org_id", org_id).eq("user_id", user_id).maybeSingle() as { data: { github_login?: string | null } | null }
        : { data: null };
      ownLogin = me?.github_login ?? null;
      if (!ownLogin) return NextResponse.json({ ...computeAnalytics({ now: now.toISOString(), start, end: now.toISOString(), scans: [], violations: [], attestations: [] }), scope: "own" }, { headers: { "Cache-Control": "private, no-store" } });
    }

    const scanCols = "id, repo_full_name, pr_number, pr_author, created_at, total_ai_percentage, file_count";
    const vCols = "id, scan_id, file_path, risk_score, status, created_at, resolved_at, sla_deadline";
    const toScan = (s: { id: string; repo_full_name: string; pr_number: number | null; pr_author: string | null; created_at: string; total_ai_percentage: number | null; file_count: number | null }): Scan =>
      ({ id: s.id, repo: s.repo_full_name, pr_number: s.pr_number, pr_author: s.pr_author, created_at: s.created_at, total_ai_percentage: s.total_ai_percentage ?? 0, file_count: s.file_count ?? 0 });

    const [scanRows, openedV, resolvedV, openV, attestations] = await Promise.all([
      all((f, t) => { let q = db.from("scans").select(scanCols).eq("org_id", org_id).gte("created_at", start); if (ownLogin) q = q.eq("pr_author", ownLogin); return q.order("created_at", { ascending: false }).range(f, t) as unknown as Page<Parameters<typeof toScan>[0]>; }),
      all((f, t) => db.from("violations").select(vCols).eq("org_id", org_id).gte("created_at", start).order("created_at", { ascending: false }).range(f, t) as unknown as Page<Violation>),
      all((f, t) => db.from("violations").select(vCols).eq("org_id", org_id).gte("resolved_at", start).order("resolved_at", { ascending: false }).range(f, t) as unknown as Page<Violation>),
      all((f, t) => db.from("violations").select(vCols).eq("org_id", org_id).in("status", ["open", "in_review"]).order("created_at", { ascending: false }).range(f, t) as unknown as Page<Violation>),
      all((f, t) => db.from("attestations").select("scan_id, file_path, risk_score, reviewer_email, reviewer_github, created_at").eq("org_id", org_id).gte("created_at", start).order("created_at", { ascending: false }).range(f, t) as unknown as Page<Attestation>),
    ]);

    const violations = [...new Map([...openedV, ...resolvedV, ...openV].map(v => [v.id, v])).values()];
    const scans = scanRows.map(toScan);

    // Scans outside the period that findings / sign-offs in it refer to (review time, backlog by repo).
    const known = new Set(scans.map(s => s.id));
    const missing = [...new Set([...violations.map(v => v.scan_id), ...attestations.map(a => a.scan_id)])].filter(id => id && !known.has(id));
    const extraScans: Scan[] = [];
    for (let i = 0; i < missing.length; i += IN_CHUNK) {
      const { data, error } = await db.from("scans").select(scanCols).eq("org_id", org_id).in("id", missing.slice(i, i + IN_CHUNK)) as { data: Parameters<typeof toScan>[0][] | null; error: unknown };
      if (error) throw error;
      extraScans.push(...(data ?? []).map(toScan));
    }

    // Connected (active) repositories only, as on the dashboard and the Trust Score: a disconnected or demo repo's
    // old findings showed up here as work "waiting now".
    const { data: activeRows, error: activeErr } = await db.from("repositories").select("repo_full_name").eq("org_id", org_id).eq("is_active", true) as
      { data: Array<{ repo_full_name: string }> | null; error: unknown };
    if (activeErr) throw activeErr;
    const active = new Set((activeRows ?? []).map(r => r.repo_full_name));

    // Developers: only findings and sign-offs on their own pull requests.
    const scanById = new Map([...scans, ...extraScans].map(s => [s.id, s]));
    const counted = (scanId: string) => {
      const s = scanById.get(scanId);
      return !!s && active.has(s.repo) && (!ownLogin || s.pr_author === ownLogin);
    };

    // Every scan of those repositories' pull requests (id, PR, time only): which scan is each PR's latest, so what
    // is waiting comes from the latest scan -- also when that scan is newer than any row loaded above.
    const repos = [...new Set([...scanById.values()].map(s => s.repo).filter(r => active.has(r)))];
    const prScans: Array<{ id: string; repo: string; pr_number: number | null; created_at: string }> = [];
    for (let i = 0; i < repos.length; i += IN_CHUNK) {
      const rowsOf = await all((f, t) => db.from("scans").select("id, repo_full_name, pr_number, created_at").eq("org_id", org_id)
        .in("repo_full_name", repos.slice(i, i + IN_CHUNK)).order("created_at", { ascending: false }).range(f, t) as unknown as
        Page<{ id: string; repo_full_name: string; pr_number: number | null; created_at: string }>);
      prScans.push(...rowsOf.map(s => ({ id: s.id, repo: s.repo_full_name, pr_number: s.pr_number, created_at: s.created_at })));
    }

    const result = computeAnalytics({
      now: now.toISOString(), start, end: now.toISOString(),
      scans: scans.filter(s => active.has(s.repo)),
      extraScans: extraScans.filter(s => active.has(s.repo) && (!ownLogin || s.pr_author === ownLogin)),
      prScans,
      violations: violations.filter(v => counted(v.scan_id)),
      attestations: attestations.filter(a => counted(a.scan_id)),
    });
    return NextResponse.json({ ...result, scope: ownLogin ? "own" : "org" }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    return safeError(err, { code: "analytics_failed", message: "We couldn't load analytics right now. Please try again." });
  }
}
