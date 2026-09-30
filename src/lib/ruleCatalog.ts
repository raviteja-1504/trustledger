/**
 * The rule catalog behind /rules: every rule the scanner can report, with its id, title, CWE, typical
 * severity, how it is detected, where it applies, and the remediation it recommends. Assembled from the same
 * sources the scanner itself uses (finding catalog, fix map, each engine's own severity function, the AppSec
 * rules), so it describes what the scanner does rather than a hand-maintained copy.
 * Server-only (imports the scanner and engines).
 */
import { getFixSuggestions } from "./scanner";
import { FINDING_CATALOG, findingMeta } from "./findingCatalog";
import { APPSEC_RULES, type AppsecDomain } from "./appsecRules";
import { DATA_FLOW_LANGUAGES, dataFlowLanguages } from "./ruleLanguages";
import { astTaintSeverity, type AstTaintId } from "./astTaint";
import { astTaintPySeverity, type AstTaintPyId } from "./astTaintPython";
import { astTaintJavaSeverity, type AstTaintJavaId } from "./astTaintJava";
import { astTaintGoSeverity, type AstTaintGoId } from "./astTaintGo";
import { astTaintCSharpSeverity, type AstTaintCSharpId } from "./astTaintCSharp";
import { astTaintPHPSeverity, type AstTaintPHPId } from "./astTaintPHP";

export type RuleDetection = "data-flow" | "configuration" | "pattern";

export interface CatalogRule {
  id: string;
  title: string;
  description: string;
  cwe: string | null;
  /** The highest severity any engine assigns this rule, when one does. */
  severity: "critical" | "high" | "medium" | "low" | null;
  detection: RuleDetection;
  /** Languages (data-flow rules) or file formats (configuration rules) it covers. */
  appliesTo: string[];
  fix: { title: string; description: string; code_before?: string; code_after?: string } | null;
}

const DOMAIN_FORMATS: Record<AppsecDomain, string[]> = {
  kubernetes: ["Kubernetes manifests", "Helm charts"],
  cloud: ["Terraform", "CloudFormation / SAM", "ARM", "Bicep", "Serverless"],
  container: ["Dockerfile", "Docker Compose"],
  api: ["OpenAPI / Swagger", "JavaScript/TypeScript", "Python", "Java", "C#", "Go", "PHP"],
};
const LEGACY_FORMATS: Array<[RegExp, string[]]> = [
  [/^iac-(?:s3|open-ingress|unencrypted|iam|public-db)/, ["Terraform"]],
  [/^iac-/, ["Kubernetes manifests", "Helm charts"]],
  [/^container-compose-/, ["Docker Compose"]],
  [/^container-/, ["Dockerfile"]],
];

const SEV_RANK = { critical: 3, high: 2, medium: 1, low: 0 } as const;
const severityFns: Array<(id: string) => "critical" | "high" | "medium" | null> = [
  id => (DATA_FLOW_LANGUAGES[0].ids.includes(id) ? astTaintSeverity(id as AstTaintId) : null),
  id => (DATA_FLOW_LANGUAGES[1].ids.includes(id) ? astTaintPySeverity(id as AstTaintPyId) : null),
  id => (DATA_FLOW_LANGUAGES[2].ids.includes(id) ? astTaintJavaSeverity(id as AstTaintJavaId) : null),
  id => (DATA_FLOW_LANGUAGES[3].ids.includes(id) ? astTaintGoSeverity(id as AstTaintGoId) : null),
  id => (DATA_FLOW_LANGUAGES[4].ids.includes(id) ? astTaintCSharpSeverity(id as AstTaintCSharpId) : null),
  id => (DATA_FLOW_LANGUAGES[5].ids.includes(id) ? astTaintPHPSeverity(id as AstTaintPHPId) : null),
];

export function buildRuleCatalog(): CatalogRule[] {
  const ids = new Set<string>([...Object.keys(FINDING_CATALOG), ...DATA_FLOW_LANGUAGES.flatMap(l => l.ids)]);
  const rules: CatalogRule[] = [];
  for (const id of ids) {
    const meta = findingMeta(id);
    const appsec = APPSEC_RULES[id];
    const langs = dataFlowLanguages(id);
    const engineSev = severityFns.map(f => f(id)).filter((s): s is "critical" | "high" | "medium" => !!s);
    const severity = appsec?.severity === "info" ? "low"
      : appsec ? (appsec.severity as CatalogRule["severity"])
      : engineSev.length ? engineSev.reduce((a, b) => (SEV_RANK[b] > SEV_RANK[a] ? b : a))
      : null;
    const legacy = LEGACY_FORMATS.find(([re]) => re.test(id))?.[1];
    const detection: RuleDetection = langs.length ? "data-flow" : appsec || legacy ? "configuration" : "pattern";
    const fixRaw = getFixSuggestions([{ id }])[0];
    rules.push({
      id, title: meta.title, description: meta.description, cwe: meta.cwe ?? null, severity, detection,
      appliesTo: langs.length ? langs : appsec ? DOMAIN_FORMATS[appsec.domain] : legacy ?? [],
      fix: fixRaw ? { title: fixRaw.title, description: fixRaw.description, code_before: fixRaw.code_before, code_after: fixRaw.code_after } : null,
    });
  }
  const DET_ORDER: Record<RuleDetection, number> = { "data-flow": 0, configuration: 1, pattern: 2 };
  return rules.sort((a, b) => DET_ORDER[a.detection] - DET_ORDER[b.detection] || a.title.localeCompare(b.title));
}
