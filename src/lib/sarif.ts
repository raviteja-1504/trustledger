/**
 * SARIF 2.1.0 export.
 *
 * Converts persisted scan findings into a SARIF log so results can be
 * uploaded to GitHub Code Scanning (github/codeql-action/upload-sarif) or
 * GitLab's Security Dashboard, both of which expect this format rather than
 * a proprietary JSON shape.
 *
 * Schema reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
 */

export interface SarifIndicator {
  id:       string;
  label:    string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  line?:    number;
  detail?:  string;
}

export interface SarifSourceFile {
  file_path:  string;
  indicators: SarifIndicator[];
}

// Reuses the same CWE mapping already maintained for in-app fix suggestions
// (src/lib/scanner.ts FIX_MAP) so the two never drift apart.
export const SARIF_RULE_META: Record<string, { title: string; description: string; cwe?: string }> = {
  "sql-injection":            { title: "SQL Injection",                 description: "String-interpolated SQL query vulnerable to injection.", cwe: "CWE-89" },
  "xss":                      { title: "Cross-Site Scripting",           description: "Unsanitised content inserted into the DOM.", cwe: "CWE-79" },
  "hardcoded-secret":         { title: "Hardcoded Secret",               description: "Credential or API key committed directly in source.", cwe: "CWE-798" },
  "high-entropy-secret":      { title: "High-Entropy Secret",            description: "High-entropy string in a credential-like context, likely a secret.", cwe: "CWE-798" },
  "command-injection":        { title: "OS Command Injection",           description: "Shell command built from unsanitised input.", cwe: "CWE-78" },
  "path-traversal":           { title: "Path Traversal",                 description: "File path built from unsanitised input without canonicalisation.", cwe: "CWE-22" },
  "eval-exec":                { title: "Dynamic Code Execution",         description: "eval()/Function() constructor executing dynamic code.", cwe: "CWE-95" },
  "weak-crypto":              { title: "Weak Cryptographic Hash",        description: "MD5/SHA-1 used where a collision-resistant hash is required.", cwe: "CWE-327" },
  "ssrf":                     { title: "Server-Side Request Forgery",    description: "Outbound request built from unvalidated user input.", cwe: "CWE-918" },
  "insecure-deserialization": { title: "Insecure Deserialization",       description: "Untrusted data deserialised without validation.", cwe: "CWE-502" },
  "prototype-pollution":      { title: "Prototype Pollution",            description: "Object merge without guarding __proto__/constructor/prototype keys.", cwe: "CWE-1321" },
  "open-redirect":            { title: "Open Redirect",                  description: "Redirect target built from unvalidated input.", cwe: "CWE-601" },
  "weak-cors":                { title: "Permissive CORS Policy",         description: "Access-Control-Allow-Origin set to a wildcard.", cwe: "CWE-942" },
  "jwt-none-alg":             { title: "JWT Algorithm Confusion",        description: "JWT verification accepts the 'none' algorithm.", cwe: "CWE-347" },
  "timing-attack":            { title: "Timing Side-Channel",            description: "Non-constant-time comparison of a secret value." },
  "toctou":                   { title: "Time-of-Check to Time-of-Use",   description: "Race condition between a check and its corresponding use." },
  "cookie-no-httponly":       { title: "Cookie Missing HttpOnly",        description: "Session cookie set without the HttpOnly flag.", cwe: "CWE-1004" },
  "cookie-no-secure":         { title: "Cookie Missing Secure Flag",     description: "Cookie set without the Secure flag.", cwe: "CWE-614" },
  "backdoor-detection":       { title: "Suspicious Backdoor Pattern",    description: "Logic bomb or covert data exfiltration pattern.", cwe: "CWE-506" },
  "watermark-detection":      { title: "AI Watermark Detected",         description: "Invisible Unicode watermark characters embedded in source." },
  "ai-model-attribution":     { title: "AI Model Attribution",          description: "Code attributed to a specific AI coding assistant." },
};

function severityToLevel(sev: SarifIndicator["severity"]): "error" | "warning" | "note" {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

function severityScore(sev: SarifIndicator["severity"]): string {
  return { critical: "9.0", high: "7.0", medium: "5.0", low: "3.0", info: "1.0" }[sev];
}

/** Build a SARIF 2.1.0 log for one scan (one GitHub code-scanning "run"). */
export function buildSarifReport(
  files:    SarifSourceFile[],
  toolInfo: { name?: string; version?: string; informationUri?: string } = {},
): object {
  const ruleIds = new Set<string>();
  for (const f of files) for (const ind of f.indicators) ruleIds.add(ind.id);

  const rules = Array.from(ruleIds).map(id => {
    const meta = SARIF_RULE_META[id];
    return {
      id,
      name: meta?.title ?? id,
      shortDescription: { text: meta?.title ?? id },
      fullDescription:  { text: meta?.description ?? "TrustLedger finding." },
      helpUri: "https://github.com/trustledger",
      properties: meta?.cwe ? { tags: [meta.cwe], cwe: meta.cwe } : {},
    };
  });

  const results = files.flatMap(f =>
    f.indicators.map(ind => ({
      ruleId:  ind.id,
      level:   severityToLevel(ind.severity),
      message: { text: ind.detail ?? ind.label },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: f.file_path },
          region: { startLine: Math.max(1, ind.line ?? 1) },
        },
      }],
      properties: { "security-severity": severityScore(ind.severity) },
    })),
  );

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name:            toolInfo.name ?? "TrustLedger",
          version:         toolInfo.version ?? "1.0.0",
          informationUri:  toolInfo.informationUri ?? "https://github.com/trustledger",
          rules,
        },
      },
      results,
    }],
  };
}
