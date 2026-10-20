/**
 * The API security report for an org: every endpoint the latest scan of each repo declares (code and OpenAPI
 * specs), what authentication is visible for it, and the API findings -- operations without auth, weak spec
 * security schemes, and endpoints missing the auth their siblings have.
 *
 * Pure: takes scanned file contents, returns the report. api/api-security/route.ts does the fetching.
 */
import type { ScanIndicator } from "../scanner";
import { APPSEC_RULES } from "../appsecRules";
import { extractEndpoints, findEndpointMissingAuth, type ApiEndpoint } from "./apiInventory";
import { scanOpenApiSpec, isOpenApiDoc, specOperations } from "./openapiSpec";
import { parseConfigDocuments } from "../iac/configTree";

export interface ReportScan { repo: string; scan_id: string; scanned_at?: string; files: Array<{ file_path: string; content?: string | null }> }

export interface InventoryEndpoint extends ApiEndpoint { repo: string; scan_id: string; source: "code" | "spec"; flagged: boolean }

export interface ApiSecurityFinding {
  id: string; title: string; severity: ScanIndicator["severity"]; cwe: string;
  repo: string; scan_id: string; file: string; line: number; detail: string; fix: string;
}

/** One repository's part of the report: which scan it comes from, and its counts (over ALL its endpoints). */
export interface ApiRepoSummary {
  repo: string; scan_id: string; scanned_at: string | null;
  endpoints: number; authRequired: number; explicitlyPublic: number; noAuthVisible: number; flagged: number; specs: number; findings: number;
}

export interface ApiSecurityReport {
  endpoints: InventoryEndpoint[];
  findings: ApiSecurityFinding[];
  counts: { endpoints: number; authRequired: number; explicitlyPublic: number; noAuthVisible: number; flagged: number; specs: number; findings: number };
  /** Per repository, so a repository filter can show exact counts even when the endpoint list is capped. */
  repos: ApiRepoSummary[];
  /** True when more endpoints were found than the list carries (MAX_ENDPOINTS); counts are always complete. */
  truncated: boolean;
}

const MAX_ENDPOINTS = 2000;
const SOURCE_RE = /\.(?:[cm]?[jt]sx?|py|java|kt|cs|go|php)$/i;
const SPEC_RE = /\.(?:ya?ml|json)$/i;
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function toFinding(i: ScanIndicator, repo: string, scan_id: string, file: string): ApiSecurityFinding {
  const rule = APPSEC_RULES[i.id];
  return {
    id: i.id, title: rule?.title ?? i.label, severity: i.severity, cwe: rule?.cwe ?? i.cwe ?? "",
    repo, scan_id, file, line: i.line ?? 1, detail: i.detail ?? "", fix: rule?.fix.description ?? "",
  };
}

export function buildApiSecurityReport(scans: readonly ReportScan[]): ApiSecurityReport {
  const endpoints: InventoryEndpoint[] = [];
  const findings: ApiSecurityFinding[] = [];
  let specs = 0;
  const specsByRepo = new Map<string, number>();
  for (const scan of scans) {
    for (const f of scan.files) {
      const content = f.content;
      if (!content) continue;
      if (SOURCE_RE.test(f.file_path)) {
        const flagged = findEndpointMissingAuth(f.file_path, content);
        const flaggedLines = new Set(flagged.map(x => x.line));
        for (const e of extractEndpoints(f.file_path, content)) {
          endpoints.push({ ...e, repo: scan.repo, scan_id: scan.scan_id, source: "code", flagged: flaggedLines.has(e.line) });
        }
        for (const i of flagged) findings.push(toFinding(i, scan.repo, scan.scan_id, f.file_path));
      } else if (SPEC_RE.test(f.file_path) && /\b(?:openapi|swagger)\b/.test(content.slice(0, 4000))) {
        const docs = parseConfigDocuments(content).filter(isOpenApiDoc);
        if (!docs.length) continue;
        specs++;
        specsByRepo.set(scan.repo, (specsByRepo.get(scan.repo) ?? 0) + 1);
        const specFindings = scanOpenApiSpec(content);
        const flaggedLines = new Set(specFindings.filter(x => x.id === "api-spec-unauthenticated-operation").map(x => x.line));
        for (const doc of docs) {
          for (const op of specOperations(doc)) {
            endpoints.push({
              method: op.method, path: op.path, file: f.file_path, line: op.line, framework: "openapi", repo: scan.repo, scan_id: scan.scan_id, source: "spec",
              auth: op.secured ? "required" : op.explicitPublic ? "public" : "none",
              authEvidence: op.secured ? "security requirement" : op.explicitPublic ? "security: []" : undefined,
              flagged: flaggedLines.has(op.line),
            });
          }
        }
        for (const i of specFindings) findings.push(toFinding(i, scan.repo, scan.scan_id, f.file_path));
      }
    }
  }
  findings.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || a.repo.localeCompare(b.repo) || a.file.localeCompare(b.file) || a.line - b.line);
  // Flagged first, then no visible auth, then the rest -- the order a reviewer works in.
  const rank = (e: InventoryEndpoint) => (e.flagged ? 0 : e.auth === "none" ? 1 : e.auth === "public" ? 2 : 3);
  endpoints.sort((a, b) => rank(a) - rank(b) || a.repo.localeCompare(b.repo) || a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
  const kept = endpoints.slice(0, MAX_ENDPOINTS);
  const repos: ApiRepoSummary[] = scans.map(s => {
    const es = endpoints.filter(e => e.repo === s.repo);
    return {
      repo: s.repo, scan_id: s.scan_id, scanned_at: s.scanned_at ?? null,
      endpoints: es.length, authRequired: es.filter(e => e.auth === "required").length, explicitlyPublic: es.filter(e => e.auth === "public").length,
      noAuthVisible: es.filter(e => e.auth === "none").length, flagged: es.filter(e => e.flagged).length,
      specs: specsByRepo.get(s.repo) ?? 0, findings: findings.filter(f => f.repo === s.repo).length,
    };
  }).sort((a, b) => b.flagged - a.flagged || b.findings - a.findings || b.endpoints - a.endpoints || a.repo.localeCompare(b.repo));
  return {
    endpoints: kept,
    findings,
    repos,
    truncated: endpoints.length > kept.length,
    counts: {
      endpoints: endpoints.length,
      authRequired: endpoints.filter(e => e.auth === "required").length,
      explicitlyPublic: endpoints.filter(e => e.auth === "public").length,
      noAuthVisible: endpoints.filter(e => e.auth === "none").length,
      flagged: endpoints.filter(e => e.flagged).length,
      specs,
      findings: findings.length,
    },
  };
}
