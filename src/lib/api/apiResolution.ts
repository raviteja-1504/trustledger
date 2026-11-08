/**
 * Resolving API security issues. The inventory is derived from scanned code, so an endpoint reported as missing
 * authentication stayed that way forever -- even when the team knows auth is applied by a gateway or app-wide
 * middleware the scanner can't see. A resolution records that decision (kind, reason, who, until when), keeps the
 * endpoint listed, and takes it out of the "missing auth" counts. Stored in finding_triage (like every other
 * triage decision: role-gated, audited, expiring), keyed by a stable key for the endpoint.
 *
 * Pure and client-safe (no crypto): the key is a small non-cryptographic hash, plenty for telling a team's own
 * endpoints apart.
 */
import type { ApiSecurityReport, ApiRepoSummary, InventoryEndpoint, ApiSecurityFinding } from "./apiSecurityReport";

export type ApiResolutionKind = "auth-elsewhere" | "public-by-design" | "not-an-endpoint" | "accepted-risk" | "false-positive";

export interface ApiResolutionChoice { kind: ApiResolutionKind; ruleId: string; status: "accepted" | "false_positive"; label: string; help: string; /** What it can be said about: an endpoint, or a finding that is not about one endpoint. */ appliesTo: "endpoint" | "finding" }

/** What a reviewer can say about an endpoint. The rule id is what finding_triage stores; the status is its two-valued form. */
export const RESOLUTION_CHOICES: readonly ApiResolutionChoice[] = [
  { kind: "auth-elsewhere", ruleId: "api-auth-elsewhere", status: "accepted", appliesTo: "endpoint", label: "Auth is handled elsewhere", help: "A gateway, app-wide middleware or the framework's security config protects it; the scanner can't see that." },
  { kind: "public-by-design", ruleId: "api-public-by-design", status: "accepted", appliesTo: "endpoint", label: "Public on purpose", help: "It is meant to be open to everyone, for example a login, health check or public catalogue." },
  { kind: "not-an-endpoint", ruleId: "api-not-an-endpoint", status: "false_positive", appliesTo: "endpoint", label: "Not a real endpoint", help: "The scanner misread something: test code, a mock, a comment or an example." },
  { kind: "accepted-risk", ruleId: "api-accepted-risk", status: "accepted", appliesTo: "finding", label: "Accept the risk", help: "You know about it and are choosing to live with it, for now. It stays on record until the decision expires." },
  { kind: "false-positive", ruleId: "api-false-positive", status: "false_positive", appliesTo: "finding", label: "False positive", help: "The finding is wrong: the configuration is fine, or it does not apply here." },
];

/** The choices a reviewer is offered for an endpoint (or for a finding about one) vs for any other finding. */
export const choicesFor = (target: "endpoint" | "finding"): ApiResolutionChoice[] => RESOLUTION_CHOICES.filter(c => c.appliesTo === target);
export const API_RULE_IDS: readonly string[] = RESOLUTION_CHOICES.map(c => c.ruleId);
export const kindOfRule = (ruleId: string | null | undefined): ApiResolutionKind | null => RESOLUTION_CHOICES.find(c => c.ruleId === ruleId)?.kind ?? null;
export const choiceOf = (kind: ApiResolutionKind): ApiResolutionChoice => RESOLUTION_CHOICES.find(c => c.kind === kind)!;

export interface Resolution {
  kind: ApiResolutionKind;
  status: "accepted" | "false_positive";
  reason: string | null;
  expires_at: string | null;
  set_by_email: string | null;
  set_at: string;
}

/** A stored decision for an API issue, as the triage store returns it (with the rule it was recorded under). */
export interface StoredResolution extends Omit<Resolution, "kind"> { rule_id: string; repo: string; fingerprint: string }

/** cyrb53: a fast 53-bit string hash, as 14 hex digits. */
function hash53(s: string): string {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 2654435761); h2 = Math.imul(h2 ^ c, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(14, "0");
}

/** `/users/:id`, `/users/{userId}` and `/users/<int:id>` are the same route: parameter names don't matter, nor a trailing slash. */
export function normalizePath(path: string): string {
  const p = path.trim().replace(/\?.*$/, "").replace(/(:\w+|\{[^}]*\}|<[^>]*>)/g, "{}").replace(/\/{2,}/g, "/");
  return (p.length > 1 ? p.replace(/\/$/, "") : p).toLowerCase();
}

/** The key an endpoint's resolution is stored under: stable across scans, line moves and parameter renames. */
export function endpointKey(repo: string, method: string, path: string): string {
  return `api-${hash53(`${repo}\n${method.toUpperCase()}\n${normalizePath(path)}`)}`;
}

/** A finding that is not about one endpoint (a weak security scheme in a spec, say) is keyed by what it says and where. */
export function findingKey(f: Pick<ApiSecurityFinding, "repo" | "id" | "file" | "detail">): string {
  return `api-${hash53(`${f.repo}\n${f.id}\n${f.file}\n${f.detail.replace(/\d+/g, "#")}`)}`;
}

export type ResolutionMap = ReadonlyMap<string, Resolution>;

const isActive = (r: Pick<Resolution, "expires_at">, now: Date) => !r.expires_at || Date.parse(r.expires_at) > now.getTime();

/** Group stored decisions by repository and key, dropping any that expired and any under an unknown rule. */
export function resolutionsByRepo(stored: readonly StoredResolution[], now: Date = new Date()): Map<string, Map<string, Resolution>> {
  const out = new Map<string, Map<string, Resolution>>();
  for (const s of stored) {
    const kind = kindOfRule(s.rule_id);
    if (!kind || !isActive(s, now)) continue;
    const m = out.get(s.repo) ?? new Map<string, Resolution>();
    m.set(s.fingerprint, { kind, status: s.status, reason: s.reason, expires_at: s.expires_at, set_by_email: s.set_by_email, set_at: s.set_at });
    out.set(s.repo, m);
  }
  return out;
}

/**
 * The report with each endpoint and finding's resolution attached, and the counts that depend on it corrected:
 * `flagged` and `findings` count only what is still unresolved. The input is not modified (it may be cached).
 */
export function applyResolutions(report: ApiSecurityReport, byRepo: ReadonlyMap<string, ResolutionMap>): ApiSecurityReport {
  const lookup = (repo: string, key: string) => byRepo.get(repo)?.get(key);
  const endpoints: InventoryEndpoint[] = report.endpoints.map(e => {
    const resolution = lookup(e.repo, e.key);
    return resolution ? { ...e, resolution } : e;
  });
  // A missing-auth finding IS its endpoint: resolving either settles both.
  const endpointAt = new Map(endpoints.map(e => [`${e.repo}\n${e.file}\n${e.line}`, e]));
  const findings: ApiSecurityFinding[] = report.findings.map(f => {
    const resolution = f.resolution ?? lookup(f.repo, f.key) ?? endpointAt.get(`${f.repo}\n${f.file}\n${f.line}`)?.resolution;
    return resolution ? { ...f, resolution } : f;
  });

  const resolvedFlagged = endpoints.filter(e => e.flagged && e.resolution);
  // Resolved ones sink below the open ones, so the list still starts with what needs a decision.
  const rank = (e: InventoryEndpoint) => (e.flagged && !e.resolution ? 0 : e.auth === "none" && !e.resolution ? 1 : e.resolution ? 4 : e.auth === "public" ? 2 : 3);
  endpoints.sort((a, b) => rank(a) - rank(b) || a.repo.localeCompare(b.repo) || a.path.localeCompare(b.path) || a.method.localeCompare(b.method));

  const repos = report.repos.map(r => ({
    ...r,
    flagged: r.flagged - resolvedFlagged.filter(e => e.repo === r.repo).length,
    findings: r.findings - findings.filter(f => f.repo === r.repo && f.resolution).length,
    resolved: endpoints.filter(e => e.repo === r.repo && e.resolution).length,
  }));
  return {
    ...report,
    endpoints,
    findings,
    repos,
    counts: {
      ...report.counts,
      flagged: report.counts.flagged - resolvedFlagged.length,
      findings: report.counts.findings - findings.filter(f => f.resolution).length,
      resolvedEndpoints: endpoints.filter(e => e.resolution).length,
      resolvedFindings: findings.filter(f => f.resolution).length,
    },
  };
}

// ── Insights ────────────────────────────────────────────────────────────────

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export interface ApiInsights {
  /** Endpoints that change data and show no auth: the highest-impact gap. */
  unprotectedWrites: InventoryEndpoint[];
  /** The repository with the lowest auth coverage among those with at least `minEndpoints`. */
  weakestRepo: { repo: string; coverage: number; endpoints: number } | null;
  /** Share of endpoints declared in OpenAPI specs: how much of the API is documented. */
  specCoverage: number | null;
  /** Unresolved missing-auth endpoints. */
  needDecision: number;
}

export function apiInsights(report: Pick<ApiSecurityReport, "endpoints" | "repos" | "counts">, minEndpoints = 3): ApiInsights {
  const open = (e: InventoryEndpoint) => !e.resolution;
  const unprotectedWrites = report.endpoints.filter(e => e.auth === "none" && WRITE_METHODS.has(e.method) && open(e));
  const coverage = (r: ApiRepoSummary) => (r.endpoints ? (r.authRequired + r.explicitlyPublic) / r.endpoints : 1);
  const candidates = report.repos.filter(r => r.endpoints >= minEndpoints);
  const weakest = [...candidates].sort((a, b) => coverage(a) - coverage(b) || b.endpoints - a.endpoints || a.repo.localeCompare(b.repo))[0];
  const fromSpecs = report.endpoints.filter(e => e.source === "spec").length;
  return {
    unprotectedWrites,
    weakestRepo: weakest && coverage(weakest) < 1 ? { repo: weakest.repo, coverage: Math.round(coverage(weakest) * 100), endpoints: weakest.endpoints } : null,
    specCoverage: report.counts.endpoints > 0 ? Math.round((fromSpecs / report.counts.endpoints) * 100) : null,
    needDecision: report.counts.flagged,
  };
}
