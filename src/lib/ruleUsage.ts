/**
 * Which catalog rules fire in the org's code right now: for each rule id, how many files and repositories in the
 * latest scan of each repository report it (scan_files.risk_indicators). Pure, client-safe.
 */

export interface RuleLocation { repo: string; file_path: string; scan_id: string }
export interface RuleUsage {
  files: number;
  repos: number;
  /** Up to MAX_LOCATIONS of the files, sorted by repository then path, to open on the PR page. */
  where?: RuleLocation[];
}

export interface IndicatorRow { scan_id: string; file_path: string; risk_indicators: unknown }

export const MAX_LOCATIONS = 10;

/** `latestScanRepo` maps each repository's latest scan id to the repository; rows of other scans are ignored. */
export function countRuleUsage(rows: readonly IndicatorRow[], latestScanRepo: ReadonlyMap<string, string>): Record<string, RuleUsage> {
  const files = new Map<string, Map<string, RuleLocation>>();
  for (const r of rows) {
    const repo = latestScanRepo.get(r.scan_id);
    if (!repo || !Array.isArray(r.risk_indicators)) continue;
    for (const id of r.risk_indicators) {        // a repeated id is the same file: the map below is keyed by file
      if (typeof id !== "string" || !id) continue;
      if (!files.has(id)) files.set(id, new Map());
      files.get(id)!.set(`${repo}::${r.file_path}`, { repo, file_path: r.file_path, scan_id: r.scan_id });
    }
  }
  const out: Record<string, RuleUsage> = {};
  for (const [id, f] of files) {
    const all = [...f.values()].sort((a, b) => a.repo.localeCompare(b.repo) || a.file_path.localeCompare(b.file_path));
    out[id] = { files: f.size, repos: new Set(all.map(l => l.repo)).size, where: all.slice(0, MAX_LOCATIONS) };
  }
  return out;
}

export interface RuleView {
  q: string;
  detection: string;      // "all" | RuleDetection
  severity: string;       // "all" | critical | high | medium | low | "varies"
  appliesTo: string;      // "all" | one of the rules' appliesTo values
  firingOnly: boolean;
  sort: "relevance" | "findings" | "severity" | "name";
}
export const DEFAULT_VIEW: RuleView = { q: "", detection: "all", severity: "all", appliesTo: "all", firingOnly: false, sort: "relevance" };

interface ViewableRule { id: string; title: string; description: string; cwe: string | null; severity: string | null; detection: string; appliesTo: string[] }

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const DET_RANK: Record<string, number> = { "data-flow": 0, configuration: 1, pattern: 2 };

/** The rules to show for a view, in order. "relevance" = rules firing in your code first (most files first), then
 *  the catalog's own order; "findings" = most files first; "severity" = critical first; "name" = A-Z. */
export function viewRules<R extends ViewableRule>(rules: readonly R[], usage: Readonly<Record<string, RuleUsage>>, v: RuleView): R[] {
  const s = v.q.trim().toLowerCase();
  const files = (r: R) => usage[r.id]?.files ?? 0;
  const shown = rules.filter(r =>
    (v.detection === "all" || r.detection === v.detection) &&
    (v.severity === "all" || (v.severity === "varies" ? r.severity == null : r.severity === v.severity)) &&
    (v.appliesTo === "all" || r.appliesTo.includes(v.appliesTo)) &&
    (!v.firingOnly || files(r) > 0) &&
    (!s || [r.id, r.title, r.cwe ?? "", r.description, ...r.appliesTo].join(" ").toLowerCase().includes(s)));
  const sev = (r: R) => SEV_RANK[r.severity ?? ""] ?? 4;
  const byCatalog = (a: R, b: R) => (DET_RANK[a.detection] ?? 9) - (DET_RANK[b.detection] ?? 9) || a.title.localeCompare(b.title);
  const cmp: Record<RuleView["sort"], (a: R, b: R) => number> = {
    relevance: (a, b) => Number(files(b) > 0) - Number(files(a) > 0) || files(b) - files(a) || byCatalog(a, b),
    findings:  (a, b) => files(b) - files(a) || sev(a) - sev(b) || a.title.localeCompare(b.title),
    severity:  (a, b) => sev(a) - sev(b) || files(b) - files(a) || a.title.localeCompare(b.title),
    name:      (a, b) => a.title.localeCompare(b.title),
  };
  return [...shown].sort(cmp[v.sort]);
}

/** Every "applies to" value across the rules, for the filter menu (sorted). */
export function appliesToOptions(rules: ReadonlyArray<{ appliesTo: string[] }>): string[] {
  return [...new Set(rules.flatMap(r => r.appliesTo))].sort((a, b) => a.localeCompare(b));
}

/** The latest scan of each repository, from scans in any order. */
export function latestScanPerRepo(scans: ReadonlyArray<{ id: string; repo_full_name: string; created_at: string }>): Map<string, string> {
  const best = new Map<string, { id: string; created_at: string }>();
  for (const s of scans) {
    const cur = best.get(s.repo_full_name);
    if (!cur || s.created_at > cur.created_at) best.set(s.repo_full_name, { id: s.id, created_at: s.created_at });
  }
  return new Map([...best].map(([repo, s]) => [s.id, repo]));
}
