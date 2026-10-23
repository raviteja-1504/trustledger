/**
 * The PR "merge blocked" alert (alert_type "policy"): one per pull request's LATEST scan while it has open files
 * the org's merge gate blocks on (lib/mergeGate.ts). Idempotent, so it runs after every scan and whenever the
 * alerts are read -- a scan whose alert insert failed or never ran (a cut-short worker, a QStash retry that hit
 * the "already scanned" shortcut) gets it on the next read instead of never.
 *
 * Only a scan that never had a policy alert gets one: a reviewer who resolved it by hand isn't overruled, and an
 * older push of the PR is the newer push's business (alertProgress.ts closes it as superseded).
 */
import { blockingRisks, loadGate } from "./mergeGate";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = any;

const WINDOW_DAYS = 30;
const PAGE = 1000;
const IN_CHUNK = 200;

interface ScanRow { id: string; repo_full_name: string; pr_number: number | null; created_at: string }

/** The newest scan of each pull request. */
export function latestScanPerPr(scans: readonly ScanRow[]): ScanRow[] {
  const best = new Map<string, ScanRow>();
  for (const s of scans) {
    if (!s.pr_number) continue;
    const k = `${s.repo_full_name}#${s.pr_number}`;
    const cur = best.get(k);
    if (!cur || s.created_at > cur.created_at) best.set(k, s);
  }
  return [...best.values()];
}

/** Title and body of the alert, from the open blocking files' risk levels. */
export function policyAlertText(repo: string, prNumber: number, risks: readonly string[]): { title: string; body: string; severity: "P1" | "P2" } {
  const crit = risks.filter(r => r === "CRITICAL").length;
  const high = risks.filter(r => r === "HIGH").length;
  const n = crit + high;
  const s = n === 1 ? "" : "s";
  return {
    severity: crit > 0 ? "P1" : "P2",
    title: `${n} unattested file${s} in ${repo.split("/").pop() ?? repo} PR #${prNumber}`,
    body: [crit ? `${crit} CRITICAL` : "", high ? `${high} HIGH` : ""].filter(Boolean).join(" and ") + ` file${s} require attestation before merge.`,
  };
}

async function inChunks<T>(ids: readonly string[], q: (chunk: string[], from: number, to: number) => PromiseLike<{ data: T[] | null }>): Promise<T[]> {
  const out: T[] = [];
  for (let i = 0; i < ids.length; i += IN_CHUNK) {
    const chunk = ids.slice(i, i + IN_CHUNK);
    for (let from = 0; ; from += PAGE) {
      const { data } = await q(chunk, from, from + PAGE - 1);
      out.push(...(data ?? []));
      if (!data || data.length < PAGE) break;
    }
  }
  return out;
}

/**
 * Create the missing policy alerts for the org (or only for `scanIds`, when the latest of their PR). Returns how
 * many were created. Best-effort: a read error creates nothing.
 */
export async function ensurePolicyAlerts(db: Db, orgId: string, opts: { scanIds?: readonly string[] } = {}): Promise<number> {
  try {
    const risks = blockingRisks(await loadGate(db, orgId));
    if (risks.length === 0) return 0;
    const since = new Date(Date.now() - WINDOW_DAYS * 86_400_000).toISOString();
    const { data: scans } = await db.from("scans").select("id, repo_full_name, pr_number, created_at")
      .eq("org_id", orgId).gte("created_at", since).order("created_at", { ascending: false }).limit(PAGE);
    let latest = latestScanPerPr((scans ?? []) as ScanRow[]);
    if (opts.scanIds) latest = latest.filter(s => opts.scanIds!.includes(s.id));
    if (latest.length === 0) return 0;
    const ids = latest.map(s => s.id);

    const [open, alerts] = await Promise.all([
      inChunks<{ scan_id: string; risk_score: string }>(ids, (c, f, t) => db.from("violations").select("scan_id, risk_score")
        .eq("org_id", orgId).in("scan_id", c).neq("status", "resolved").in("risk_score", risks).range(f, t)),
      inChunks<{ scan_id: string }>(ids, (c, f, t) => db.from("alerts").select("scan_id")
        .eq("org_id", orgId).eq("alert_type", "policy").in("scan_id", c).range(f, t)),
    ]);
    const hasAlert = new Set(alerts.map(a => a.scan_id));
    const openRisks = new Map<string, string[]>();
    for (const v of open) openRisks.set(v.scan_id, [...(openRisks.get(v.scan_id) ?? []), v.risk_score]);

    const rows = latest.filter(s => !hasAlert.has(s.id) && (openRisks.get(s.id)?.length ?? 0) > 0).map(s => {
      const text = policyAlertText(s.repo_full_name, s.pr_number!, openRisks.get(s.id)!);
      return {
        org_id: orgId, alert_type: "policy", severity: text.severity, status: "firing",
        title: text.title, body: text.body, repo: s.repo_full_name, scan_id: s.id, fired_at: new Date().toISOString(),
      };
    });
    if (rows.length === 0) return 0;
    const { error } = await db.from("alerts").insert(rows);
    return error ? 0 : rows.length;
  } catch {
    return 0;
  }
}
