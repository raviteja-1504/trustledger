/**
 * Trust Score: how well an organisation GOVERNS its code, 0-1000, from real data only.
 *
 * Using AI never lowers the score. Points are lost for what is ungoverned: open high-risk findings, risky code
 * nobody reviewed (AI-heavy risky code counts double), missed fix deadlines, leaked secrets, unapproved AI tools,
 * and repositories nobody scans. Every dimension reports its formula, the facts behind it, and the concrete actions
 * that would win points back, so the number can be defended to an auditor and acted on by an engineer.
 *
 * Pure: the API (/api/trust-score) and the daily snapshot job load the inputs; this only computes.
 */

export interface ScoreInput {
  now: string;
  /** Active repositories (repositories.is_active). */
  repos: readonly string[];
  /** Scans in the scoring window, any order. */
  scans: ReadonlyArray<{ id: string; repo: string; pr_number: number | null; created_at: string }>;
  /** HIGH/CRITICAL files of those scans. */
  riskyFiles: ReadonlyArray<{ scan_id: string; file_path: string; risk_score: string; ai_percentage: number }>;
  /** Attestations for those scans. */
  attested: ReadonlyArray<{ scan_id: string; file_path: string }>;
  /** Violations for those scans. */
  violations: ReadonlyArray<{ scan_id: string; file_path: string; risk_score: string; status: string; sla_deadline: string | null }>;
  /** OPEN secret findings for those scans. */
  secrets: ReadonlyArray<{ scan_id: string; severity: string }>;
  /** Shadow AI state (lib/shadowAi.ts summarize), or null when it couldn't be loaded. */
  shadow: { policy_configured: boolean; compliance: number | null; open_violations: number } | null;
}

export interface ScoreAction { label: string; href: string; gain: number }
export interface Dimension {
  key: "exposure" | "review" | "sla" | "shadow_ai" | "coverage" | "secrets";
  label: string;
  weight: number;
  /** 0-1. */
  value: number;
  points: number;
  max_points: number;
  /** Points available if this dimension were perfect. */
  gain: number;
  grade: "A" | "B" | "C" | "D" | "F";
  formula: string;
  facts: string[];
  actions: ScoreAction[];
}
export interface RepoScore {
  repo: string;
  score: number;
  open_critical: number;
  open_high: number;
  review_coverage: number | null;
  open_secrets: number;
  last_scan: string | null;
}
export interface GovernanceScore {
  total: number;
  band: "Excellent" | "Good" | "Fair" | "Poor" | "Critical";
  dimensions: Dimension[];
  repos: RepoScore[];
  computed_at: string;
}

export const WEIGHTS = { exposure: 0.25, review: 0.20, sla: 0.15, shadow_ai: 0.15, coverage: 0.15, secrets: 0.10 } as const;
/** An open CRITICAL finding counts 1, a HIGH 0.3; a repo's exposure score is 1 / (1 + that total). */
export const EXPOSURE_WEIGHT = { CRITICAL: 1, HIGH: 0.3 } as const;
export const SECRET_WEIGHT: Record<string, number> = { CRITICAL: 1, HIGH: 0.5, MEDIUM: 0.2 };
/** A risky file at least this AI-written counts double in review coverage: ungoverned AI is the risk. */
export const AI_HEAVY = 0.5;
/** Without an approved-tools policy, Shadow AI compliance can't be judged: partial credit only. */
export const NO_POLICY_VALUE = 0.6;
const DAY = 86400_000;

export function grade(v: number): Dimension["grade"] {
  return v >= 0.9 ? "A" : v >= 0.75 ? "B" : v >= 0.6 ? "C" : v >= 0.45 ? "D" : "F";
}
export function band(total: number): GovernanceScore["band"] {
  return total >= 850 ? "Excellent" : total >= 700 ? "Good" : total >= 550 ? "Fair" : total >= 400 ? "Poor" : "Critical";
}
const short = (repo: string) => repo.split("/").pop() ?? repo;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const mean = (xs: number[]) => xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 1;

/** The single action across all dimensions that wins back the most points (dashboard tile). */
export function topAction(dimensions: ReadonlyArray<{ actions?: readonly ScoreAction[] }>): ScoreAction | null {
  let best: ScoreAction | null = null;
  for (const d of dimensions) for (const a of d.actions ?? []) if (a.gain > 0 && (!best || a.gain > best.gain)) best = a;
  return best;
}

export function computeGovernanceScore(input: ScoreInput): GovernanceScore {
  const now = Date.parse(input.now);
  const active = new Set(input.repos);
  const scanById = new Map(input.scans.map(s => [s.id, s]));

  // Latest scan per (repo, PR): older pushes of the same PR are superseded.
  const latestByPr = new Map<string, { id: string; repo: string; created_at: string }>();
  for (const s of input.scans) {
    const k = `${s.repo}::${s.pr_number ?? 0}`;
    const cur = latestByPr.get(k);
    if (!cur || s.created_at > cur.created_at) latestByPr.set(k, s);
  }
  const latestIds = new Set([...latestByPr.values()].map(s => s.id));
  const lastScan = new Map<string, string>();
  for (const s of input.scans) if (!lastScan.has(s.repo) || s.created_at > lastScan.get(s.repo)!) lastScan.set(s.repo, s.created_at);
  const scannedRepos = [...active].filter(r => lastScan.has(r));

  // Open violations: latest row per (repo, file), like repoViolations.ts -- superseded rows don't count.
  const latestViolation = new Map<string, { repo: string; risk: string; status: string; sla: string | null; created: string }>();
  for (const v of input.violations) {
    const s = scanById.get(v.scan_id);
    if (!s || !active.has(s.repo)) continue;
    const k = `${s.repo}::${v.file_path}`;
    const cur = latestViolation.get(k);
    if (!cur || s.created_at > cur.created) latestViolation.set(k, { repo: s.repo, risk: v.risk_score, status: v.status, sla: v.sla_deadline, created: s.created_at });
  }
  const openViolations = [...latestViolation.values()].filter(v => v.status === "open" || v.status === "in_review");

  // ── 1. Open risk exposure ──
  const perRepo = new Map<string, { crit: number; high: number }>();
  for (const v of openViolations) {
    const r = perRepo.get(v.repo) ?? { crit: 0, high: 0 };
    if (v.risk === "CRITICAL") r.crit++; else if (v.risk === "HIGH") r.high++;
    perRepo.set(v.repo, r);
  }
  const exposureOf = (repo: string) => { const r = perRepo.get(repo); return r ? 1 / (1 + r.crit * EXPOSURE_WEIGHT.CRITICAL + r.high * EXPOSURE_WEIGHT.HIGH) : 1; };
  const exposure = mean(scannedRepos.map(exposureOf));
  const totCrit = openViolations.filter(v => v.risk === "CRITICAL").length, totHigh = openViolations.filter(v => v.risk === "HIGH").length;

  // ── 2. Human review of risky code (latest scans; AI-heavy files count double) ──
  const attestedSet = new Set(input.attested.map(a => `${a.scan_id}::${a.file_path}`));
  const reviewByRepo = new Map<string, { want: number; got: number; unreviewed: number; aiUnreviewed: number }>();
  for (const f of input.riskyFiles) {
    if (!latestIds.has(f.scan_id)) continue;
    const s = scanById.get(f.scan_id);
    if (!s || !active.has(s.repo)) continue;
    const w = f.ai_percentage >= AI_HEAVY ? 2 : 1;
    const r = reviewByRepo.get(s.repo) ?? { want: 0, got: 0, unreviewed: 0, aiUnreviewed: 0 };
    r.want += w;
    if (attestedSet.has(`${f.scan_id}::${f.file_path}`)) r.got += w;
    else { r.unreviewed++; if (w === 2) r.aiUnreviewed++; }
    reviewByRepo.set(s.repo, r);
  }
  const reviewWant = [...reviewByRepo.values()].reduce((a, r) => a + r.want, 0);
  const review = reviewWant ? [...reviewByRepo.values()].reduce((a, r) => a + r.got, 0) / reviewWant : 1;

  // ── 3. SLA adherence ──
  const withDeadline = openViolations.filter(v => v.sla);
  const breached = withDeadline.filter(v => Date.parse(v.sla!) < now);
  const sla = withDeadline.length ? 1 - breached.length / withDeadline.length : 1;

  // ── 4. Secrets ──
  const secretsByRepo = new Map<string, { w: number; n: number }>();
  for (const sec of input.secrets) {
    const s = scanById.get(sec.scan_id);
    if (!s || !active.has(s.repo)) continue;
    const r = secretsByRepo.get(s.repo) ?? { w: 0, n: 0 };
    r.w += SECRET_WEIGHT[sec.severity] ?? 0.2; r.n++;
    secretsByRepo.set(s.repo, r);
  }
  const secretOf = (repo: string) => 1 / (1 + (secretsByRepo.get(repo)?.w ?? 0));
  const secrets = mean(scannedRepos.map(secretOf));

  // ── 5. Shadow AI ──
  const sh = input.shadow;
  const shadow = !sh ? 1 : !sh.policy_configured ? NO_POLICY_VALUE : sh.compliance ?? 1;

  // ── 6. Coverage ──
  const freshness = (repo: string) => {
    const t = lastScan.get(repo); if (!t) return 0;
    const age = (now - Date.parse(t)) / DAY;
    return age <= 7 ? 1 : age <= 30 ? 0.5 : 0;
  };
  const coverage = active.size ? mean([...active].map(freshness)) : 0;
  const stale = [...active].filter(r => freshness(r) < 1);

  // ── Assemble ──
  const pts = (v: number, w: number) => Math.round(v * w * 1000);
  const repoCount = Math.max(1, scannedRepos.length);
  const dims: Dimension[] = [];
  const dim = (key: Dimension["key"], label: string, value: number, formula: string, facts: string[], actions: ScoreAction[]) => {
    const w = WEIGHTS[key], v = Math.max(0, Math.min(1, value));
    dims.push({ key, label, weight: w, value: v, points: pts(v, w), max_points: pts(1, w), gain: pts(1, w) - pts(v, w), grade: grade(v), formula, facts, actions: actions.filter(a => a.gain > 0).sort((a, b) => b.gain - a.gain).slice(0, 5) });
  };

  dim("exposure", "Open risk", exposure,
    `Per repository: 1 / (1 + open critical × ${EXPOSURE_WEIGHT.CRITICAL} + open high × ${EXPOSURE_WEIGHT.HIGH}), averaged over scanned repositories.`,
    [`${plural(totCrit, "open critical file")}, ${plural(totHigh, "open high-risk file")} across ${plural(perRepo.size, "repository", "repositories")}`],
    [...perRepo.entries()].map(([repo, r]) => ({
      label: `Fix or review ${[r.crit ? plural(r.crit, "critical file") : "", r.high ? plural(r.high, "high-risk file") : ""].filter(Boolean).join(" and ")} in ${short(repo)}`,
      href: `/violations?repo=${encodeURIComponent(repo)}`,
      gain: Math.round((1 - exposureOf(repo)) / repoCount * WEIGHTS.exposure * 1000),
    })));

  dim("review", "Human review of risky code", review,
    `Reviewed share of HIGH/CRITICAL files in each pull request's latest scan; files at least ${Math.round(AI_HEAVY * 100)}% AI-written count double.`,
    reviewWant ? [`${plural([...reviewByRepo.values()].reduce((a, r) => a + r.unreviewed, 0), "high-risk file")} unreviewed, ${[...reviewByRepo.values()].reduce((a, r) => a + r.aiUnreviewed, 0)} of them mostly AI-written`] : ["No high-risk files in recent scans"],
    [...reviewByRepo.entries()].filter(([, r]) => r.unreviewed > 0).map(([repo, r]) => ({
      label: `Review ${plural(r.unreviewed, "high-risk file")} in ${short(repo)}${r.aiUnreviewed ? ` (${r.aiUnreviewed} mostly AI-written)` : ""}`,
      href: `/scans?repo=${encodeURIComponent(repo)}`,
      gain: Math.round((r.want - r.got) / reviewWant * WEIGHTS.review * 1000),
    })));

  dim("sla", "Fix deadlines met", sla,
    "Share of open findings with a deadline that are still within it.",
    [withDeadline.length ? `${plural(breached.length, "finding")} past deadline of ${withDeadline.length} open` : "No open findings with a deadline"],
    breached.length ? [{ label: `Resolve ${plural(breached.length, "overdue finding")}`, href: "/sla", gain: pts(1, WEIGHTS.sla) - pts(sla, WEIGHTS.sla) }] : []);

  dim("shadow_ai", "Approved AI tools", shadow,
    `Share of explicit AI-tool evidence that is for approved tools. Without an approved-tools policy: ${Math.round(NO_POLICY_VALUE * 100)}%.`,
    [!sh ? "Shadow AI data unavailable" : !sh.policy_configured ? "No approved-tools policy set" : sh.compliance == null ? "No AI-tool evidence yet" : `${Math.round(sh.compliance * 100)}% of AI-tool evidence is for approved tools; ${plural(sh.open_violations, "open violation")}`],
    !sh ? [] : !sh.policy_configured
      ? [{ label: "Choose your approved AI tools", href: "/shadow-ai", gain: pts(1, WEIGHTS.shadow_ai) - pts(shadow, WEIGHTS.shadow_ai) }]
      : sh.open_violations ? [{ label: `Resolve ${plural(sh.open_violations, "unapproved AI tool detection")}`, href: "/shadow-ai", gain: pts(1, WEIGHTS.shadow_ai) - pts(shadow, WEIGHTS.shadow_ai) }] : []);

  dim("coverage", "Scan coverage", coverage,
    "Per active repository: scanned in the last 7 days = 1, last 30 days = 0.5, otherwise 0; averaged.",
    [active.size ? `${active.size - stale.length} of ${plural(active.size, "active repository", "active repositories")} scanned in the last 7 days` : "No active repositories"],
    active.size ? stale.map(repo => ({
      label: `${lastScan.has(repo) ? "Rescan" : "Run a first scan of"} ${short(repo)}`,
      href: "/scans",
      gain: Math.round((1 - freshness(repo)) / active.size * WEIGHTS.coverage * 1000),
    })) : [{ label: "Connect a repository", href: "/settings", gain: pts(1, WEIGHTS.coverage) }]);

  dim("secrets", "Leaked secrets", secrets,
    "Per repository: 1 / (1 + open critical × 1 + high × 0.5 + medium × 0.2), averaged over scanned repositories.",
    [`${plural([...secretsByRepo.values()].reduce((a, r) => a + r.n, 0), "open secret")} in ${plural(secretsByRepo.size, "repository", "repositories")}`],
    [...secretsByRepo.entries()].map(([repo, r]) => ({
      label: `Rotate and resolve ${plural(r.n, "secret")} in ${short(repo)}`,
      href: `/secrets?repo=${encodeURIComponent(repo)}`,
      gain: Math.round((1 - secretOf(repo)) / repoCount * WEIGHTS.secrets * 1000),
    })));

  const total = dims.reduce((a, d) => a + d.points, 0);

  // Per-repo score: the repo-scoped dimensions, reweighted to 1000.
  const repoW = WEIGHTS.exposure + WEIGHTS.review + WEIGHTS.coverage + WEIGHTS.secrets;
  const repos: RepoScore[] = [...active].map(repo => {
    const r = reviewByRepo.get(repo);
    const rv = r && r.want ? r.got / r.want : 1;
    const pr = perRepo.get(repo);
    const score = Math.round(((lastScan.has(repo) ? exposureOf(repo) : 1) * WEIGHTS.exposure + rv * WEIGHTS.review + freshness(repo) * WEIGHTS.coverage + (lastScan.has(repo) ? secretOf(repo) : 1) * WEIGHTS.secrets) / repoW * 1000);
    return { repo, score, open_critical: pr?.crit ?? 0, open_high: pr?.high ?? 0, review_coverage: r && r.want ? rv : null, open_secrets: secretsByRepo.get(repo)?.n ?? 0, last_scan: lastScan.get(repo) ?? null };
  }).sort((a, b) => a.score - b.score);

  return { total, band: band(total), dimensions: dims, repos, computed_at: input.now };
}
