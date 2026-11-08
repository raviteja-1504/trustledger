/**
 * Risk register inputs read straight from the database: the latest scan of each ACTIVE repository, the real
 * attestations on it, and the violations closed without one.
 *
 * The page used to derive risks in the browser from a cached 90-day dashboard payload plus one scan fetch per
 * repository, so a file attested a minute ago still showed as an open "awaiting attestation" risk, a repository
 * last scanned months ago dropped out of the register, and the page waited on a chain of requests. This reads the
 * same facts the merge check and the attestation page use, in a few paged queries.
 */
import type { createServiceClient } from "@/lib/supabase";
import { CAPS } from "@/lib/limits";
import { latestScanPerRepo } from "@/lib/ruleUsage";
import type { RiskInput } from "@/lib/riskRegister";

type Db = ReturnType<typeof createServiceClient>;
type Page<T> = PromiseLike<{ data: T[] | null; error: unknown }>;

const PAGE = 1000;                 // the project's PostgREST max_rows
const IN_CHUNK = 200;
const MAX_ROWS = CAPS.tableRows.value;

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

async function inChunks<T>(ids: readonly string[], read: (chunk: string[]) => Promise<T[]>): Promise<T[]> {
  const out: T[] = [];
  for (let i = 0; i < ids.length; i += IN_CHUNK) out.push(...await read(ids.slice(i, i + IN_CHUNK)));
  return out;
}

export interface LiveRiskState {
  input: RiskInput;
  /** What the register was derived from, so the page can show that it matches the attestation data. */
  basis: {
    repos: number;
    /** HIGH / CRITICAL files in the latest scans. */
    highCriticalFiles: number;
    attestedFiles: number;
    /** Closed on the Violations page without a sign-off. */
    closedWithoutAttestation: number;
    /** Still needing a sign-off: what the file-based risks are made of. */
    waitingFiles: number;
    latestScanAt: string | null;
  };
}

export async function loadLiveRiskState(db: Db, orgId: string): Promise<LiveRiskState> {
  const { data: active } = await db.from("repositories").select("repo_full_name").eq("org_id", orgId).eq("is_active", true) as { data: { repo_full_name: string }[] | null };
  const activeRepos = new Set((active ?? []).map(r => r.repo_full_name));

  const scans = (await all<{ id: string; repo_full_name: string; created_at: string }>((f, t) => db.from("scans")
    .select("id, repo_full_name, created_at").eq("org_id", orgId)
    .order("created_at", { ascending: false }).order("id", { ascending: true }).range(f, t) as unknown as Page<{ id: string; repo_full_name: string; created_at: string }>))
    .filter(s => activeRepos.has(s.repo_full_name));
  const latest = latestScanPerRepo(scans);                      // scan id -> repo
  const latestAt = scans.filter(s => latest.has(s.id)).map(s => s.created_at).sort().pop() ?? null;
  const scanIds = [...latest.keys()];

  type FileRow = { scan_id: string; file_path: string; ai_percentage: number | null; risk_score: string; risk_indicators: string[] | null };
  const [files, attests, violations] = await Promise.all([
    inChunks(scanIds, chunk => all<FileRow>((f, t) => db.from("scan_files")
      .select("scan_id, file_path, ai_percentage, risk_score, risk_indicators").eq("org_id", orgId).in("scan_id", chunk)
      .order("file_path", { ascending: true }).range(f, t) as unknown as Page<FileRow>)),
    inChunks(scanIds, async chunk => ((await db.from("attestations").select("scan_id, file_path").eq("org_id", orgId).in("scan_id", chunk).in("risk_score", ["CRITICAL", "HIGH"])) as { data: { scan_id: string; file_path: string }[] | null }).data ?? []),
    inChunks(scanIds, chunk => all<{ scan_id: string; file_path: string; status: string }>((f, t) => db.from("violations")
      .select("scan_id, file_path, status").eq("org_id", orgId).in("scan_id", chunk).in("risk_score", ["CRITICAL", "HIGH"])
      .order("id", { ascending: true }).range(f, t) as unknown as Page<{ scan_id: string; file_path: string; status: string }>)),
  ]);

  const attested = new Set(attests.map(a => `${a.scan_id}::${a.file_path}`));
  const closed = new Set(violations.filter(v => v.status !== "open" && v.status !== "in_review").map(v => `${v.scan_id}::${v.file_path}`));

  const highCritical = files.filter(f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH");
  const key = (f: { scan_id: string; file_path: string }) => `${f.scan_id}::${f.file_path}`;
  const waiting = highCritical.filter(f => !attested.has(key(f)) && !closed.has(key(f)));

  const perRepo = new Map<string, { total: number; attested: number }>();
  for (const repo of latest.values()) perRepo.set(repo, { total: 0, attested: 0 });
  for (const f of highCritical) {
    const s = perRepo.get(latest.get(f.scan_id)!);
    if (!s) continue;
    s.total++;
    if (attested.has(key(f))) s.attested++;
  }

  return {
    input: {
      waiting: waiting.map(f => ({ repo: latest.get(f.scan_id)!, file_path: f.file_path, risk_score: f.risk_score, ai_pct: f.ai_percentage ?? 0 })),
      repos: [...perRepo].map(([repo, s]) => ({ repo, attestation_rate: s.total === 0 ? 1 : Math.min(1, s.attested / s.total), high_crit_count: s.total })),
      patternFiles: files.map(f => ({ repo: latest.get(f.scan_id)!, file_path: f.file_path, risk_indicators: f.risk_indicators })),
    },
    basis: {
      repos: latest.size,
      highCriticalFiles: highCritical.length,
      attestedFiles: highCritical.filter(f => attested.has(key(f))).length,
      closedWithoutAttestation: highCritical.filter(f => !attested.has(key(f)) && closed.has(key(f))).length,
      waitingFiles: waiting.length,
      latestScanAt: latestAt,
    },
  };
}
