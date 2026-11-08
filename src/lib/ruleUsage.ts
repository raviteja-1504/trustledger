import { CAPS } from "@/lib/limits";
/**
 * Which catalog rules fire in the org's code right now: for each rule id, how many files and repositories in the
 * latest scan of each repository report it (scan_files.risk_indicators). Pure, client-safe.
 */

export interface RuleLocation { repo: string; file_path: string; scan_id: string }
export interface RuleUsage {
  files: number;
  repos: number;
  /** Against each repository's previous scan: files where this rule fires now and did not then (a repository with no previous scan contributes none). */
  new?: number;
  /** Files where it fired in the previous scan and no longer fires in the latest. */
  fixed?: number;
  /** Whether any repository had a previous scan to compare with. */
  compared?: boolean;
  /** Up to MAX_LOCATIONS of the files, sorted by repository then path, to open on the PR page. */
  where?: RuleLocation[];
}

export interface IndicatorRow { scan_id: string; file_path: string; risk_indicators: unknown }

export const MAX_LOCATIONS = CAPS.locationsPerRule.value;

/** The files each rule fires on, per scan: rule id -> "repo::file" -> its location. A repeated id in a file counts once. */
function firing(rows: readonly IndicatorRow[], scanRepo: ReadonlyMap<string, string>) {
  const byRule = new Map<string, Map<string, RuleLocation>>();
  const present = new Set<string>();          // every file the scan covers, firing or not
  for (const r of rows) {
    const repo = scanRepo.get(r.scan_id);
    if (!repo) continue;
    present.add(`${repo}::${r.file_path}`);
    if (!Array.isArray(r.risk_indicators)) continue;
    for (const id of r.risk_indicators) {
      if (typeof id !== "string" || !id) continue;
      if (!byRule.has(id)) byRule.set(id, new Map());
      byRule.get(id)!.set(`${repo}::${r.file_path}`, { repo, file_path: r.file_path, scan_id: r.scan_id });
    }
  }
  return { byRule, present };
}

const sortLocations = (locs: Iterable<RuleLocation>) => [...locs].sort((a, b) => a.repo.localeCompare(b.repo) || a.file_path.localeCompare(b.file_path));

/**
 * `latestScanRepo` maps each repository's latest scan id to the repository; rows of other scans are ignored.
 * With `previous` (each repository's scan before its latest), every rule also gets how many files are new since then
 * and how many were fixed: the answer to "what changed?", per rule.
 */
export function countRuleUsage(
  rows: readonly IndicatorRow[], latestScanRepo: ReadonlyMap<string, string>,
  previous?: { rows: readonly IndicatorRow[]; scanRepo: ReadonlyMap<string, string> },
): Record<string, RuleUsage> {
  const now = firing(rows, latestScanRepo);
  const before = previous ? firing(previous.rows, previous.scanRepo) : null;
  const comparedRepos = new Set(previous ? previous.scanRepo.values() : []);
  const out: Record<string, RuleUsage> = {};
  for (const [id, f] of now.byRule) {
    const all = sortLocations(f.values());
    const u: RuleUsage = { files: f.size, repos: new Set(all.map(l => l.repo)).size, where: all.slice(0, MAX_LOCATIONS) };
    if (before) {
      const was = before.byRule.get(id) ?? new Map<string, RuleLocation>();
      u.compared = comparedRepos.size > 0;
      u.new = [...f.values()].filter(l => comparedRepos.has(l.repo) && !was.has(`${l.repo}::${l.file_path}`)).length;
      u.fixed = [...was.keys()].filter(k => !f.has(k) && now.present.has(k)).length;
    }
    out[id] = u;
  }
  if (before) {
    // A rule that fired before and fires nowhere now is all fixed: it still deserves a row saying so.
    for (const [id, was] of before.byRule) {
      if (out[id]) continue;
      const fixed = [...was.keys()].filter(k => now.present.has(k)).length;
      if (fixed > 0) out[id] = { files: 0, repos: 0, new: 0, fixed, compared: true };
    }
  }
  return out;
}

/** Every file one rule fires on in the latest scans, optionally for one repository, up to `limit`. */
export function locationsForRule(
  rows: readonly IndicatorRow[], latestScanRepo: ReadonlyMap<string, string>, ruleId: string,
  opts: { repo?: string | null; limit?: number } = {},
): { locations: RuleLocation[]; total: number; truncated: boolean } {
  const all = sortLocations((firing(rows, latestScanRepo).byRule.get(ruleId) ?? new Map<string, RuleLocation>()).values())
    .filter(l => !opts.repo || l.repo === opts.repo);
  const limit = opts.limit ?? CAPS.ruleLocations.value;
  return { locations: all.slice(0, limit), total: all.length, truncated: all.length > limit };
}

/** Locations grouped by repository, repositories with the most files first. */
export function groupByRepo(locations: readonly RuleLocation[]): Array<{ repo: string; files: RuleLocation[] }> {
  const m = new Map<string, RuleLocation[]>();
  for (const l of locations) m.set(l.repo, [...(m.get(l.repo) ?? []), l]);
  return [...m].map(([repo, files]) => ({ repo, files })).sort((a, b) => b.files.length - a.files.length || a.repo.localeCompare(b.repo));
}

/** The review page opened on a file (the PR page reads ?file= and expands that row). */
export const fileHref = (l: RuleLocation) => `/pr/${l.scan_id}?file=${encodeURIComponent(l.file_path)}`;

export interface RuleView {
  q: string;
  detection: string;      // "all" | RuleDetection
  severity: string;       // "all" | critical | high | medium | low | "varies"
  appliesTo: string;      // "all" | one of the rules' appliesTo values
  firingOnly: boolean;
  sort: "relevance" | "new" | "findings" | "severity" | "name";
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
    new:       (a, b) => (usage[b.id]?.new ?? 0) - (usage[a.id]?.new ?? 0) || files(b) - files(a) || sev(a) - sev(b) || a.title.localeCompare(b.title),
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

/** The scan before each repository's latest (its second newest), from scans in any order: what "new" is measured against. */
export function previousScanPerRepo(scans: ReadonlyArray<{ id: string; repo_full_name: string; created_at: string }>): Map<string, string> {
  const byRepo = new Map<string, Array<{ id: string; created_at: string }>>();
  for (const s of scans) byRepo.set(s.repo_full_name, [...(byRepo.get(s.repo_full_name) ?? []), { id: s.id, created_at: s.created_at }]);
  const out = new Map<string, string>();
  for (const [repo, list] of byRepo) {
    const sorted = [...list].sort((a, b) => (a.created_at < b.created_at ? 1 : a.created_at > b.created_at ? -1 : 0));
    if (sorted.length > 1) out.set(sorted[1].id, repo);
  }
  return out;
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
