/**
 * One organisation's health numbers, read by the Organisations API (and tested on their own): scan activity and its
 * trend, open work, people, repositories and the latest scan. How the page reads them is lib/orgSummary.ts.
 */
import type { createServiceClient } from "@/lib/supabase";

export type Db = ReturnType<typeof createServiceClient>;
export interface OrgRow { id: string; slug: string; name: string; github_org: string | null; plan: string; created_at: string }

const DAY = 86_400_000;
/** Organisations measured at once: each costs about a dozen queries. */
const CONCURRENCY = 8;

/**
 * Ids of the latest scan of each ACTIVE repository: the scans whose violations are the live ones. A violation on an
 * older scan was superseded by the rescan after it, so counting every row ever written inflates the number (and
 * disagrees with the Threats page and the sidebar badge, which count the latest scans only).
 */
async function latestScanIds(db: Db, orgId: string): Promise<string[]> {
  const { data: repos } = await db.from("repositories").select("repo_full_name").eq("org_id", orgId).eq("is_active", true) as { data: { repo_full_name: string }[] | null };
  const ids = await Promise.all((repos ?? []).map(async r => {
    const { data } = await db.from("scans").select("id").eq("org_id", orgId).eq("repo_full_name", r.repo_full_name)
      .order("created_at", { ascending: false }).limit(1).maybeSingle() as { data: { id: string } | null };
    return data?.id ?? null;
  }));
  return ids.filter((x): x is string => !!x);
}

const IN_CHUNK = 200;

/** One organisation's numbers: scan activity and its trend, open work, people, repositories, the latest scan. */
export async function orgMetrics(db: Db, org: OrgRow, now: Date = new Date()) {
  const iso = (ms: number) => new Date(ms).toISOString();
  const open = ["open", "in_review"];
  const monthStart = iso(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const count = (q: PromiseLike<{ count: number | null }>) => q.then(r => r.count ?? 0);
  const live = await latestScanIds(db, org.id);
  // Violation counts over the live scans, a chunk of scan ids at a time.
  const violationCount = async (narrow: (q: ReturnType<ReturnType<Db["from"]>["select"]>) => unknown) => {
    let n = 0;
    for (let i = 0; i < live.length; i += IN_CHUNK) {
      const q = db.from("violations").select("*", { count: "exact", head: true }).eq("org_id", org.id).in("scan_id", live.slice(i, i + IN_CHUNK)).in("status", open);
      n += await count(narrow(q as never) as PromiseLike<{ count: number | null }>);
    }
    return n;
  };
  const [scans30, scansPrev, scansMonth, openViolations, openCritical, overdue, members, repos, latest] = await Promise.all([
    count(db.from("scans").select("*", { count: "exact", head: true }).eq("org_id", org.id).gte("created_at", iso(now.getTime() - 30 * DAY))),
    count(db.from("scans").select("*", { count: "exact", head: true }).eq("org_id", org.id).gte("created_at", iso(now.getTime() - 60 * DAY)).lt("created_at", iso(now.getTime() - 30 * DAY))),
    count(db.from("scans").select("*", { count: "exact", head: true }).eq("org_id", org.id).gte("created_at", monthStart)),
    violationCount(q => q),
    violationCount(q => (q as unknown as { eq: (c: string, v: string) => unknown }).eq("risk_score", "CRITICAL")),
    violationCount(q => (q as unknown as { lt: (c: string, v: string) => unknown }).lt("sla_deadline", now.toISOString())),
    count(db.from("org_members").select("*", { count: "exact", head: true }).eq("org_id", org.id)),
    count(db.from("repositories").select("*", { count: "exact", head: true }).eq("org_id", org.id).eq("is_active", true)),
    db.from("scans").select("overall_risk, total_ai_percentage, created_at").eq("org_id", org.id).order("created_at", { ascending: false }).limit(1).maybeSingle() as unknown as PromiseLike<{ data: { overall_risk: string; total_ai_percentage: number; created_at: string } | null }>,
  ]);
  return {
    ...org,
    scans_30d: scans30,
    scans_prev_30d: scansPrev,
    scans_this_month: scansMonth,
    open_violations: openViolations,
    open_critical: openCritical,
    overdue,
    member_count: members,
    repo_count: repos,
    latest_risk: latest.data?.overall_risk ?? "UNKNOWN",
    latest_ai_pct: latest.data?.total_ai_percentage ?? 0,
    last_scan: latest.data?.created_at ?? null,
  };
}

/** Measure organisations a few at a time, so a long list doesn't open hundreds of connections at once. */
export async function measureAll(db: Db, orgs: OrgRow[], now: Date) {
  const out: Awaited<ReturnType<typeof orgMetrics>>[] = [];
  for (let i = 0; i < orgs.length; i += CONCURRENCY) out.push(...await Promise.all(orgs.slice(i, i + CONCURRENCY).map(o => orgMetrics(db, o, now))));
  return out;
}

