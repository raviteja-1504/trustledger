/**
 * Risk register: risks derived from the latest scan of each repository, merged with what people recorded about them
 * (status, owner, due date, treatment, notes -- risk_register rows, /api/risk-register/state). Pure, client-safe.
 *
 * Derived risks state only facts from the scan data. Owner, due date, status and residual scores are decisions, so
 * they come from a person or not at all: a derived risk starts open and unassigned, with no due date. (They used to
 * be invented -- owners assigned round-robin from the member list, a due date of "today + N days" recomputed on
 * every load so it could never be overdue, some risks pre-marked "mitigating", and made-up residual scores.)
 */
import type { DashboardData, ScanResult } from "@/types";
import { cweFor } from "./cweMap";

export type RiskStatus    = "open" | "mitigating" | "accepted" | "closed";
export type RiskCategory  = "ai-code" | "supply-chain" | "secrets" | "compliance" | "access" | "infrastructure";
export type TreatmentType = "mitigate" | "accept" | "transfer" | "avoid";
type Score = 1 | 2 | 3 | 4 | 5;

export interface RiskItem {
  id: string;
  title: string;
  description: string;
  category: RiskCategory;
  likelihood: Score;
  impact:     Score;
  residual_likelihood?: Score;
  residual_impact?:     Score;
  status: RiskStatus;
  treatment: TreatmentType;
  owner: string;             // "unassigned" when nobody owns it
  due_date?: string;
  mitigation: string;
  related_cve?: string;      // free-text, manually-entered risks only -- never auto-derived (see related_cwe)
  related_cwe?: string;      // e.g. "CWE-89 — SQL Injection", derived from the real matched indicator
  related_link?: string;
  identified_at: string;     // YYYY-MM-DD: first recorded (the row's created_at), today until it's been recorded
  auto_derived: boolean;     // derived from scan data vs manually entered
  notes: string[];
  repo?: string;
}

export interface PersistedRisk {
  status?:       RiskStatus;
  treatment?:    TreatmentType;
  owner?:        string;
  due_date?:     string;
  mitigation?:   string;
  residual_likelihood?: Score;
  residual_impact?:     Score;
  notes?:        string[];
  identified_at?: string;
}

export interface ManualRisk extends RiskItem { _manual: true }

export interface PersistStore {
  overrides: Record<string, PersistedRisk>;
  manuals:   ManualRisk[];
}

export interface RiskRow {
  external_id:         string | null;
  auto_derived:        boolean;
  title:               string;
  description:         string | null;
  category:            string;
  likelihood:          number;
  impact:              number;
  residual_likelihood: number | null;
  residual_impact:     number | null;
  status:              string;
  treatment:           string;
  owner_email:         string | null;
  due_date:            string | null;
  mitigation:          string | null;
  related_cve:         string | null;
  related_cwe:         string | null;
  related_link:        string | null;
  repo:                string | null;
  notes:               string[];
  created_at:          string;
}

const day = (iso: string) => iso.split("T")[0];
const opt = <T,>(v: T | null | undefined): T | undefined => (v == null ? undefined : v);

export function rowsToStore(rows: readonly RiskRow[]): PersistStore {
  const overrides: Record<string, PersistedRisk> = {};
  const manuals: ManualRisk[] = [];
  for (const r of rows) {
    if (!r.external_id) continue;
    if (r.auto_derived) {
      overrides[r.external_id] = {
        status:               r.status as RiskStatus,
        treatment:            r.treatment as TreatmentType,
        owner:                opt(r.owner_email),
        due_date:             opt(r.due_date),
        mitigation:           opt(r.mitigation),
        residual_likelihood:  opt(r.residual_likelihood) as Score | undefined,
        residual_impact:      opt(r.residual_impact) as Score | undefined,
        notes:                Array.isArray(r.notes) ? r.notes : [],
        identified_at:        r.created_at ? day(r.created_at) : undefined,
      };
    } else {
      manuals.push({
        _manual: true,
        id:            r.external_id,
        auto_derived:  false,
        title:         r.title,
        description:   r.description ?? "",
        category:      r.category as RiskCategory,
        likelihood:    r.likelihood as Score,
        impact:        r.impact as Score,
        residual_likelihood: opt(r.residual_likelihood) as Score | undefined,
        residual_impact:     opt(r.residual_impact) as Score | undefined,
        status:        r.status as RiskStatus,
        treatment:     r.treatment as TreatmentType,
        owner:         r.owner_email || "unassigned",
        due_date:      opt(r.due_date),
        mitigation:    r.mitigation ?? "",
        related_cve:   opt(r.related_cve),
        related_cwe:   opt(r.related_cwe),
        related_link:  opt(r.related_link),
        identified_at: day(r.created_at),
        notes:         Array.isArray(r.notes) ? r.notes : [],
        repo:          opt(r.repo),
      });
    }
  }
  return { overrides, manuals };
}

/** Derived and manual risks with what people recorded applied. A field nobody set keeps the derived value -- an
 *  empty recorded field never blanks it (an unset owner stays "unassigned", not undefined). Highest score first. */
export function mergeRisks(derived: readonly RiskItem[], store: PersistStore): RiskItem[] {
  const score = (r: RiskItem) => r.likelihood * r.impact;
  return [...derived, ...store.manuals].map(r => {
    const ov = store.overrides[r.id];
    if (!ov) return r;
    const out: RiskItem = { ...r };
    for (const [k, v] of Object.entries(ov) as [keyof PersistedRisk, unknown][]) {
      if (v === undefined || v === null || v === "") continue;
      if (k === "notes") { if (Array.isArray(v) && v.length > 0) out.notes = v as string[]; continue; }
      (out as unknown as Record<string, unknown>)[k] = v;
    }
    return out;
  }).sort((a, b) => score(b) - score(a));
}

function groupByRepo<T>(items: readonly T[], repoOf: (t: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const item of items) {
    const repo = repoOf(item);
    const arr = m.get(repo) ?? [];
    arr.push(item);
    m.set(repo, arr);
  }
  return m;
}

// "CWE-89 — SQL Injection" or undefined if this indicator id has no mapping -- never a made-up value.
function cweLabel(indicatorId: string): string | undefined {
  const cwe = cweFor(indicatorId);
  return cwe ? `${cwe.id} — ${cwe.title}` : undefined;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const short = (repo: string) => repo.split("/").pop() ?? repo;
const names = (files: ReadonlyArray<{ file_path: string }>) => {
  const n = files.map(f => f.file_path.split("/").pop());
  return n.length > 5 ? `${n.slice(0, 5).join(", ")} and ${n.length - 5} more` : n.join(", ");
};

/**
 * Risks from the latest scan of each repository. `data` should already have sign-offs applied (violation statuses),
 * `scans` are those latest scans. Every derived risk starts open, unassigned and without a due date.
 */
export function deriveRisks(data: DashboardData, scans: readonly ScanResult[], today = new Date().toISOString()): RiskItem[] {
  const now = day(today);
  const risks: RiskItem[] = [];
  const repoSlug = (r: string) => r.replace(/[^a-zA-Z0-9]/g, "-");
  const base = { auto_derived: true as const, status: "open" as const, treatment: "mitigate" as const, owner: "unassigned", identified_at: now, notes: [] as string[] };
  const waiting = data.top_risk_files.filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH"));

  // Unsigned CRITICAL / HIGH files, one risk per repository per level.
  for (const [level, likelihood, impact] of [["CRITICAL", 5, 5], ["HIGH", 4, 4]] as const) {
    groupByRepo(waiting.filter(f => f.risk_score === level), f => f.repo).forEach((files, repo) => {
      const avgAi = files.reduce((s, f) => s + f.ai_pct, 0) / files.length;
      risks.push({
        ...base, id: `DR-${level === "CRITICAL" ? "CRIT" : "HIGH"}-UNATT-${repoSlug(repo)}`, category: "ai-code", likelihood, impact, repo,
        title: level === "CRITICAL"
          ? `${plural(files.length, "CRITICAL file")} unattested in ${short(repo)} — merge blocked`
          : `${plural(files.length, "HIGH-risk file")} awaiting attestation in ${short(repo)}`,
        description: `${names(files)} flagged ${level} (avg ${(avgAi * 100).toFixed(0)}% AI-written) and not yet signed off.`,
        mitigation: "Review each file on its PR page and attest it, or fix the finding and rescan.",
        related_link: "/dashboard#review-queue",
      });
    });
  }

  // Risk patterns in the latest scan's files.
  const PATTERNS = [
    { indicator: "hardcoded-secret", id: "SECRETS",    category: "secrets" as const, likelihood: 5, impact: 5, link: "/secrets",
      title: (n: number, r: string) => `${plural(n, "hardcoded credential")} detected in ${short(r)}`,
      desc: "contain API keys, passwords or tokens in source. Treat them as compromised.",
      mitigation: "Rotate every exposed credential, move it to a secrets manager, and add a secret-scanning pre-commit hook." },
    { indicator: "eval-exec",        id: "EVAL-EXEC",  category: "ai-code" as const, likelihood: 4, impact: 5, link: "/violations",
      title: (n: number, r: string) => `eval()/exec() RCE pattern in ${plural(n, "file")} in ${short(r)}`,
      desc: "run eval/exec on input that may be user-controlled. Full server compromise if exploited.",
      mitigation: "Replace eval/exec with a safe parser (e.g. ast.literal_eval in Python, a sandboxed expression library in JS)." },
    { indicator: "sql-injection",    id: "SQL-INJECT", category: "ai-code" as const, likelihood: 5, impact: 5, link: "/violations",
      title: (n: number, r: string) => `SQL injection pattern in ${plural(n, "file")} in ${short(r)}`,
      desc: "build SQL with string formatting or concatenation, bypassing parameterisation.",
      mitigation: "Use parameterised queries or the ORM's query builder for every dynamic value." },
    { indicator: "jwt-none-alg",     id: "JWT-BYPASS", category: "ai-code" as const, likelihood: 4, impact: 5, link: "/violations",
      title: (n: number, r: string) => `JWT 'none' algorithm accepted in ${plural(n, "file")} in ${short(r)}`,
      desc: "accept the insecure 'none' JWT algorithm, so tokens can be forged.",
      mitigation: "Pin the accepted algorithms (e.g. only RS256 or HS256) when verifying tokens." },
  ];
  groupByRepo(scans, s => s.repo).forEach((repoScans, repo) => {
    for (const p of PATTERNS) {
      const files = repoScans.flatMap(s => s.files.filter(f => (f.risk_indicators ?? []).includes(p.indicator)));
      if (files.length === 0) continue;
      risks.push({
        ...base, id: `DR-${p.id}-${repoSlug(repo)}`, category: p.category, likelihood: p.likelihood as Score, impact: p.impact as Score, repo,
        title: p.title(files.length, repo), description: `${names(files)} ${p.desc}`, mitigation: p.mitigation,
        related_cwe: cweLabel(p.indicator), related_link: p.link,
      });
    }
  });

  // Org-wide sign-off backlog: the same files as above, counted across repositories.
  if (waiting.length > 0) {
    const repos = new Set(waiting.map(f => f.repo)).size;
    risks.push({
      ...base, id: "DR-DEPLOY-BLOCK", category: "compliance", likelihood: 4, impact: 4,
      title: `${plural(waiting.length, "HIGH/CRITICAL file")} awaiting sign-off across ${plural(repos, "repo")}`,
      description: "Unsigned high-risk changes hold merges at the policy gate and count against SOC 2 CC8.1 change-management evidence.",
      mitigation: "Work through the review queue, oldest and CRITICAL first.",
      related_link: "/dashboard#review-queue",
    });
  }

  // Repositories whose HIGH/CRITICAL files are mostly unsigned.
  data.repos.filter(r => r.attestation_rate < 0.6 && (r.high_crit_count ?? 1) > 0).forEach(r => {
    const pct = Math.round(r.attestation_rate * 100);
    risks.push({
      ...base, id: `DR-LOW-ATT-${repoSlug(r.repo)}`, category: "compliance", likelihood: 3, impact: 4, repo: r.repo,
      title: `Low attestation — ${short(r.repo)} at ${pct}%`,
      description: `${pct}% of ${short(r.repo)}'s HIGH/CRITICAL files are signed off, below the 60% threshold. Audit risk for SOC 2 CC8.1.`,
      mitigation: "Assign a reviewer for this repository and sign off its HIGH/CRITICAL files (only those count towards attestation).",
      related_link: `/repo/${r.repo}`,
    });
  });

  // One risk per id, even if the inputs repeat a repository under two spellings that slug the same.
  const seen = new Set<string>();
  return risks.filter(r => (seen.has(r.id) ? false : (seen.add(r.id), true)));
}
