/**
 * Rule catalog API
 *
 * GET /api/rules → every rule the scanner can report (lib/ruleCatalog.ts). Static per deploy, so it is built
 * once per server instance.
 *
 * GET /api/rules?usage=1 → also `usage`: for each rule, how many files and repositories it fires on in the latest
 * scan of each active repository, and how many files are new or fixed against each repository's previous scan
 * (lib/ruleUsage.ts). Developers see their own pull requests' scans only, as on the dashboard. Never cached at
 * the edge (per-org data).
 *
 * GET /api/rules?rule=<id>[&repo=<owner/name>] → every file that rule fires on (up to the cap), for "Show all files".
 */
import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "../_middleware";
import { buildRuleCatalog, type CatalogRule } from "@/lib/ruleCatalog";
import { createServiceClient } from "@/lib/supabase";
import { safeError } from "@/lib/errors";
import { countRuleUsage, latestScanPerRepo, locationsForRule, previousScanPerRepo, type IndicatorRow, type RuleUsage } from "@/lib/ruleUsage";
import { CAPS } from "@/lib/limits";

let cachedRules: CatalogRule[] | null = null;

const PAGE = 1000;          // the project's PostgREST max_rows
const MAX_ROWS = CAPS.tableRows.value;
const IN_CHUNK = 200;
type Page<T> = PromiseLike<{ data: T[] | null; error: unknown }>;
type Db = ReturnType<typeof createServiceClient>;

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

async function indicatorRows(db: Db, orgId: string, scanIds: string[]): Promise<IndicatorRow[]> {
  const rows: IndicatorRow[] = [];
  for (let i = 0; i < scanIds.length; i += IN_CHUNK) {
    const chunk = scanIds.slice(i, i + IN_CHUNK);
    rows.push(...await all<IndicatorRow>((f, t) => db.from("scan_files").select("scan_id, file_path, risk_indicators")
      .eq("org_id", orgId).in("scan_id", chunk).order("file_path", { ascending: true }).range(f, t) as unknown as Page<IndicatorRow>));
  }
  return rows;
}

/** The scans a viewer may see (a developer: their own pull requests'), newest first, for active repositories. */
async function visibleScans(db: Db, orgId: string, role: string | undefined, userId: string | null | undefined) {
  let ownLogin: string | null = null;
  if (role === "developer") {
    const { data: me } = userId
      ? await db.from("org_members").select("github_login").eq("org_id", orgId).eq("user_id", userId).maybeSingle() as { data: { github_login?: string | null } | null }
      : { data: null };
    ownLogin = me?.github_login ?? null;
    if (!ownLogin) return { scans: [], scope: "own" as const };
  }
  const { data: active } = await db.from("repositories").select("repo_full_name").eq("org_id", orgId).eq("is_active", true) as { data: { repo_full_name: string }[] | null };
  const activeRepos = new Set((active ?? []).map(r => r.repo_full_name));
  const scans = (await all<{ id: string; repo_full_name: string; created_at: string }>((f, t) => {
    let q = db.from("scans").select("id, repo_full_name, created_at").eq("org_id", orgId);
    if (ownLogin) q = q.eq("pr_author", ownLogin);
    return q.order("created_at", { ascending: false }).order("id", { ascending: true }).range(f, t) as unknown as Page<{ id: string; repo_full_name: string; created_at: string }>;
  })).filter(s => activeRepos.has(s.repo_full_name));
  return { scans, scope: (ownLogin ? "own" : "org") as "own" | "org" };
}

async function usageFor(orgId: string, role: string | undefined, userId: string | null | undefined): Promise<{ usage: Record<string, RuleUsage>; scope: "org" | "own" }> {
  const db = createServiceClient();
  const { scans, scope } = await visibleScans(db, orgId, role, userId);
  const latest = latestScanPerRepo(scans);
  const previous = previousScanPerRepo(scans);
  const [rows, prevRows] = await Promise.all([indicatorRows(db, orgId, [...latest.keys()]), indicatorRows(db, orgId, [...previous.keys()])]);
  return { usage: countRuleUsage(rows, latest, { rows: prevRows, scanRepo: previous }), scope };
}

async function locationsFor(orgId: string, role: string | undefined, userId: string | null | undefined, ruleId: string, repo: string | null) {
  const db = createServiceClient();
  const { scans, scope } = await visibleScans(db, orgId, role, userId);
  const latest = latestScanPerRepo(scans);
  const rows = await indicatorRows(db, orgId, [...latest.keys()]);
  return { ...locationsForRule(rows, latest, ruleId, { repo }), scope };
}

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  cachedRules ??= buildRuleCatalog();
  const params = req.nextUrl.searchParams;
  const ruleId = params.get("rule");
  if (ruleId) {
    if (!cachedRules.some(r => r.id === ruleId)) return NextResponse.json({ error: "unknown_rule" }, { status: 404 });
    try {
      return NextResponse.json(await locationsFor(auth.org_id!, auth.role, auth.user_id, ruleId, params.get("repo")), { headers: { "Cache-Control": "private, no-store" } });
    } catch (err) {
      return safeError(err, { code: "rule_locations_failed", message: "We couldn't list the files for that rule right now. Please try again." });
    }
  }
  if (params.get("usage") !== "1") return NextResponse.json({ rules: cachedRules });
  try {
    const { usage, scope } = await usageFor(auth.org_id!, auth.role, auth.user_id);
    return NextResponse.json({ rules: cachedRules, usage, scope }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    return safeError(err, { code: "rule_usage_failed", message: "We couldn't count where rules fire right now. Please try again." });
  }
}
