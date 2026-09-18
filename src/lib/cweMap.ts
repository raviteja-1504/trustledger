/**
 * Indicator id → CWE (Common Weakness Enumeration) mapping.
 *
 * Shared, dependency-free (safe to import from either server code or a
 * client component) so both scanner.ts (server-side, stamps this onto
 * every ScanIndicator at scan time) and the Risk Register page (client-
 * side, needs a real per-finding classification instead of a fabricated
 * one) read from the same single source of truth.
 *
 * CWE is the right taxonomy for what this scanner actually produces:
 * pattern-based static analysis findings are weakness CLASSES ("this code
 * concatenates user input into a query"), not specific exploited software
 * instances -- which is what CVE identifies. A generic pattern match can
 * never honestly resolve to a specific CVE (that requires a known
 * package + version + disclosed exploit), but it can honestly resolve to
 * a CWE, because that's a direct description of the weakness pattern
 * itself.
 */

export interface CweEntry {
  id:    string; // e.g. "CWE-89"
  title: string; // official MITRE CWE title
}

export const INDICATOR_CWE_MAP: Record<string, CweEntry> = {
  "sql-injection":              { id: "CWE-89",   title: "SQL Injection" },
  "xss":                        { id: "CWE-79",   title: "Cross-Site Scripting" },
  "hardcoded-secret":           { id: "CWE-798",  title: "Use of Hard-coded Credentials" },
  "high-entropy-secret":        { id: "CWE-798",  title: "Use of Hard-coded Credentials" },
  "command-injection":          { id: "CWE-78",   title: "OS Command Injection" },
  "path-traversal":             { id: "CWE-22",   title: "Path Traversal" },
  "file-inclusion":             { id: "CWE-98",   title: "PHP Local/Remote File Inclusion" },
  "weak-signing-secret":        { id: "CWE-321",  title: "Use of Hard-coded Cryptographic Key" },
  "graphql-introspection-enabled": { id: "CWE-200", title: "Exposure of Sensitive Information to an Unauthorized Actor" },
  "bola-identity-mismatch":     { id: "CWE-639",  title: "Authorization Bypass Through User-Controlled Key" },
  "plaintext-password-storage": { id: "CWE-256",  title: "Plaintext Storage of a Password" },
  "debug-mode-enabled":          { id: "CWE-489",  title: "Active Debug Code" },
  "eval-exec":                  { id: "CWE-95",   title: "Eval Injection" },
  "weak-crypto":                { id: "CWE-327",  title: "Broken or Risky Cryptographic Algorithm" },
  "ssrf":                       { id: "CWE-918",  title: "Server-Side Request Forgery" },
  "insecure-deserialization":   { id: "CWE-502",  title: "Deserialization of Untrusted Data" },
  "prototype-pollution":        { id: "CWE-1321", title: "Prototype Pollution" },
  "open-redirect":              { id: "CWE-601",  title: "URL Redirection to Untrusted Site" },
  "weak-cors":                  { id: "CWE-942",  title: "Permissive Cross-domain Policy" },
  "backdoor-detection":         { id: "CWE-506",  title: "Embedded Malicious Code" },
  "xxe":                        { id: "CWE-611",  title: "XML External Entity Reference" },
  "ldap-injection":             { id: "CWE-90",   title: "LDAP Injection" },
  "idor":                       { id: "CWE-639",  title: "Authorization Bypass Through User-Controlled Key" },
  "php-missing-session-guard":  { id: "CWE-306",  title: "Missing Authentication for Critical Function" },
  "bola-missing-ownership-check": { id: "CWE-639", title: "Authorization Bypass Through User-Controlled Key" },
  "nosql-injection":            { id: "CWE-943",  title: "Data Query Logic Injection" },
  "graphql-injection":          { id: "CWE-943",  title: "Data Query Logic Injection" },
  "ssti":                       { id: "CWE-1336", title: "Template Engine Injection" },
  "xpath-injection":            { id: "CWE-643",  title: "XPath Injection" },
  "csrf-protection-disabled":   { id: "CWE-352",  title: "Cross-Site Request Forgery" },
  "pii-in-logs":                { id: "CWE-532",  title: "Insertion of Sensitive Information into Log File" },
  "mass-assignment":            { id: "CWE-915",  title: "Improperly Controlled Modification of Object Attributes" },
  "jwt-none-alg":                { id: "CWE-347",  title: "Improper Verification of Cryptographic Signature" },
  "insecure-randomness":        { id: "CWE-330",  title: "Use of Insufficiently Random Values" },
  "redos":                       { id: "CWE-1333", title: "Inefficient Regular Expression Complexity" },
  "timing-attack":               { id: "CWE-208",  title: "Observable Timing Discrepancy" },
  "header-injection":            { id: "CWE-113",  title: "CRLF Injection in HTTP Headers" },
  "sensitive-url-data":          { id: "CWE-598",  title: "Use of GET Request With Sensitive Query Strings" },
  "verbose-error":                { id: "CWE-209",  title: "Generation of Error Message Containing Sensitive Information" },
  "insecure-file-upload":        { id: "CWE-434",  title: "Unrestricted Upload of File With Dangerous Type" },
  "toctou":                       { id: "CWE-367",  title: "Time-of-Check Time-of-Use Race Condition" },
  "cookie-no-httponly":          { id: "CWE-1004", title: "Sensitive Cookie Without 'HttpOnly' Flag" },
  "cookie-no-secure":            { id: "CWE-614",  title: "Sensitive Cookie Without 'Secure' Attribute" },
};

export function cweFor(indicatorId: string): CweEntry | undefined {
  return INDICATOR_CWE_MAP[indicatorId];
}
