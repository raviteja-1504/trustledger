/**
 * The one catalog of finding ids -> reviewer-facing title, one-line description and CWE. Every surface that
 * presents a finding (PR page, SARIF export, GitHub check-run annotations, PR comment, check summary) reads
 * its names from here, so a finding is called the same thing everywhere. Client-safe.
 *
 * Ids with no entry still resolve: findingMeta() falls back to the CWE map's title, then to the label the
 * detector emitted.
 */
import { cweFor } from "./cweMap";

export interface CatalogEntry { title: string; description: string; cwe?: string }

export const FINDING_CATALOG: Record<string, CatalogEntry> = {
  "sql-injection":            { title: "SQL Injection",                 description: "String-interpolated SQL query vulnerable to injection.", cwe: "CWE-89" },
  "xss":                      { title: "Cross-Site Scripting",           description: "Unsanitised content inserted into the DOM.", cwe: "CWE-79" },
  "hardcoded-secret":         { title: "Hardcoded Secret",               description: "Credential or API key committed directly in source.", cwe: "CWE-798" },
  "high-entropy-secret":      { title: "High-Entropy Secret",            description: "High-entropy string in a credential-like context, likely a secret.", cwe: "CWE-798" },
  "command-injection":        { title: "OS Command Injection",           description: "Shell command built from unsanitised input.", cwe: "CWE-78" },
  "argument-injection":       { title: "Argument Injection",             description: "Attacker-controlled value passed as a bare argv element, with no `--` end-of-options marker, letting it be read as a flag by the target program instead of data.", cwe: "CWE-88" },
  "path-traversal":           { title: "Path Traversal",                 description: "File path built from unsanitised input without canonicalisation.", cwe: "CWE-22" },
  "xxe":                      { title: "XML External Entity (XXE)",      description: "XML parser configured to resolve external entities/DTDs from untrusted input.", cwe: "CWE-611" },
  "insecure-file-upload":     { title: "Insecure File Upload",           description: "File upload accepted with no MIME-type/extension validation or size limit.", cwe: "CWE-434" },
  "eval-exec":                { title: "Dynamic Code Execution",         description: "eval()/Function() constructor executing dynamic code.", cwe: "CWE-95" },
  "weak-crypto":              { title: "Weak Cryptographic Hash",        description: "MD5/SHA-1 used where a collision-resistant hash is required.", cwe: "CWE-327" },
  "ssrf":                     { title: "Server-Side Request Forgery",    description: "Outbound request built from unvalidated user input.", cwe: "CWE-918" },
  "insecure-deserialization": { title: "Insecure Deserialization",       description: "Untrusted data deserialised without validation.", cwe: "CWE-502" },
  "prototype-pollution":      { title: "Prototype Pollution",            description: "Object merge without guarding __proto__/constructor/prototype keys.", cwe: "CWE-1321" },
  "open-redirect":            { title: "Open Redirect",                  description: "Redirect target built from unvalidated input.", cwe: "CWE-601" },
  "weak-cors":                { title: "Permissive CORS Policy",         description: "Access-Control-Allow-Origin set to a wildcard.", cwe: "CWE-942" },
  "missing-security-headers": { title: "Security Header Explicitly Removed", description: "A known security response header (X-Frame-Options, CSP, etc.) is explicitly removed.", cwe: "CWE-693" },
  "jwt-none-alg":             { title: "JWT Algorithm Confusion",        description: "JWT verification accepts the 'none' algorithm.", cwe: "CWE-347" },
  "timing-attack":            { title: "Timing Side-Channel",            description: "Non-constant-time comparison of a secret value." },
  "toctou":                   { title: "Time-of-Check to Time-of-Use",   description: "Race condition between a check and its corresponding use." },
  "cookie-no-httponly":       { title: "Cookie Missing HttpOnly",        description: "Session cookie set without the HttpOnly flag.", cwe: "CWE-1004" },
  "cookie-no-secure":         { title: "Cookie Missing Secure Flag",     description: "Cookie set without the Secure flag.", cwe: "CWE-614" },
  "backdoor-detection":       { title: "Suspicious Backdoor Pattern",    description: "Logic bomb or covert data exfiltration pattern.", cwe: "CWE-506" },
  "watermark-detection":      { title: "AI Watermark Detected",         description: "Invisible Unicode watermark characters embedded in source." },
  "ai-model-attribution":     { title: "AI Model Attribution",          description: "Code attributed to a specific AI coding assistant." },
  "hallucinated-method-call": { title: "Hallucinated Method Call",      description: "Call to a method/property that does not exist on this built-in type — likely an AI-invented API that will throw TypeError at runtime." },
  "license-header-contamination": { title: "License Header Contamination", description: "An SPDX identifier, license header, or third-party copyright notice was found in this file — may indicate code copied from a licensed source." },
  "ai-blast-radius": { title: "AI Blast Radius", description: "An AI-generated file that's imported by other files in this PR and/or sits in a sensitive area (payment, auth, webhooks) — risk compounds with reach." },
  "file-inclusion":           { title: "PHP File Inclusion",            description: "Request-derived value passed to include/require, allowing local (and, if allow_url_include is on, remote) file inclusion.", cwe: "CWE-98" },
  "weak-signing-secret":      { title: "Hardcoded Signing Secret",      description: "JWT/session signing key is a literal committed to source control.", cwe: "CWE-321" },
  "graphql-introspection-enabled": { title: "GraphQL Introspection Enabled", description: "GraphiQL/Playground/introspection is explicitly enabled, exposing the complete schema for attacker reconnaissance.", cwe: "CWE-200" },
  "bola-identity-mismatch":  { title: "Broken Object Level Authorization",  description: "Caller identity was established via a token/session check, then a write used a different identifier with no ownership comparison.", cwe: "CWE-639" },
  "bola-missing-ownership-check": { title: "Broken Object Level Authorization (AST-verified)", description: "A Spring @PathVariable/@RequestParam-sourced identifier reaches a repository or map-backed lookup with no authorization annotation and no identity comparison in the method body.", cwe: "CWE-639" },
  "plaintext-password-storage": { title: "Plaintext Password Storage",     description: "Password assigned directly from request input with no hashing function anywhere on the line.", cwe: "CWE-256" },
  "debug-mode-enabled":       { title: "Debug Mode Enabled",              description: "Framework debug mode is explicitly enabled, exposing stack traces, source code, and (Werkzeug) an interactive RCE console.", cwe: "CWE-489" },
  "iac-s3-public-acl":        { title: "Public S3 Bucket ACL",            description: "Terraform S3 bucket ACL grants public read access.", cwe: "CWE-284" },
  "iac-open-ingress":         { title: "Open Ingress Rule",               description: "Security group ingress rule allows traffic from 0.0.0.0/0 (or ::/0).", cwe: "CWE-284" },
  "iac-unencrypted-storage":  { title: "Unencrypted Storage",             description: "S3 bucket or RDS instance has no server-side encryption configured.", cwe: "CWE-311" },
  "iac-iam-wildcard":         { title: "Overly Permissive IAM Policy",    description: "IAM statement grants a wildcard Action or Resource.", cwe: "CWE-732" },
  "iac-public-db":            { title: "Publicly Accessible Database",   description: "RDS instance is publicly accessible from the internet.", cwe: "CWE-284" },
  "iac-privileged-container": { title: "Privileged Container",           description: "Kubernetes container runs in privileged mode, granting near-full host access.", cwe: "CWE-250" },
  "iac-container-run-as-root": { title: "Container Runs As Root",        description: "Kubernetes container security context explicitly allows running as root (UID 0).", cwe: "CWE-250" },
  "iac-host-namespace-access": { title: "Host Namespace Access",         description: "Pod shares the host's network, PID, or IPC namespace.", cwe: "CWE-668" },
  "iac-dangerous-capability": { title: "Dangerous Linux Capability",      description: "Container adds a capability (ALL/SYS_ADMIN/NET_ADMIN/SYS_PTRACE/SYS_MODULE) beyond the default set.", cwe: "CWE-250" },
  "iac-unpinned-image-tag":   { title: "Unpinned Container Image Tag",   description: "Container image has no tag/digest or is pinned to the mutable ':latest' tag.", cwe: "CWE-1104" },
  "container-runs-as-root":                 { title: "Container Runs As Root",              description: "Dockerfile has no USER instruction (or explicitly sets USER root) in its final build stage.", cwe: "CWE-250" },
  "container-unpinned-base-image":          { title: "Unpinned Base Image",                 description: "Dockerfile FROM has no tag/digest or is pinned to the mutable ':latest' tag.", cwe: "CWE-1104" },
  "container-add-remote-url":               { title: "ADD From Remote URL",                 description: "Dockerfile ADD fetches directly from a URL with no integrity check.", cwe: "CWE-494" },
  "container-piped-shell-exec":             { title: "Unverified Remote Script Execution",  description: "Dockerfile RUN pipes a remote script directly into a shell with no integrity verification.", cwe: "CWE-494" },
  "container-hardcoded-secret":             { title: "Hardcoded Secret in Dockerfile",      description: "Dockerfile ENV/ARG bakes a credential-shaped value into the image/build history.", cwe: "CWE-798" },
  "container-sensitive-file-copy":          { title: "Sensitive File Copied Into Image",    description: "Dockerfile COPY/ADD bakes a credential/key file into an image layer.", cwe: "CWE-538" },
  "container-exposed-sensitive-port":       { title: "Sensitive Port Exposed",              description: "Dockerfile EXPOSE advertises a management port (SSH/Telnet/RDP) from the container.", cwe: "CWE-668" },
  "container-compose-privileged":           { title: "Privileged Container",                description: "docker-compose service runs in privileged mode, granting near-full host access.", cwe: "CWE-250" },
  "container-compose-docker-socket-mount":  { title: "Docker Socket Mounted Into Container", description: "docker-compose service mounts /var/run/docker.sock, granting root-equivalent host control.", cwe: "CWE-269" },
  "container-compose-host-namespace":       { title: "Host Namespace Access",               description: "docker-compose service shares the host's network, PID, or IPC namespace.", cwe: "CWE-668" },
  "container-compose-dangerous-capability": { title: "Dangerous Linux Capability",          description: "docker-compose service adds a capability (ALL/SYS_ADMIN/NET_ADMIN/SYS_PTRACE/SYS_MODULE) beyond the default set.", cwe: "CWE-250" },
  "container-compose-hardcoded-secret":     { title: "Hardcoded Secret in Compose File",    description: "docker-compose environment: sets a credential-shaped value directly in the file.", cwe: "CWE-798" },
  "container-compose-unpinned-image":       { title: "Unpinned Container Image",            description: "docker-compose image has no tag/digest or is pinned to the mutable ':latest' tag.", cwe: "CWE-1104" },

  "nosql-injection":          { title: "NoSQL Injection",                description: "Request-controlled value used as a NoSQL query value or operator.", cwe: "CWE-943" },
  "graphql-injection":        { title: "GraphQL Injection",              description: "GraphQL query text built from unvalidated input.", cwe: "CWE-943" },
  "ssti":                     { title: "Server-Side Template Injection", description: "Request-controlled value compiled as template source.", cwe: "CWE-1336" },
  "ldap-injection":           { title: "LDAP Injection",                 description: "LDAP filter built from unescaped input.", cwe: "CWE-90" },
  "xpath-injection":          { title: "XPath Injection",                description: "XPath expression built from unvalidated input.", cwe: "CWE-643" },
  "header-injection":         { title: "HTTP Header Injection",          description: "Request-controlled value written into a response header without CR/LF stripping.", cwe: "CWE-113" },
  "redos":                    { title: "Regular Expression DoS",         description: "Request-controlled input matched by a regex prone to catastrophic backtracking.", cwe: "CWE-1333" },
  "mass-assignment":          { title: "Mass Assignment",                description: "Request body bound wholesale onto a data model with no field allowlist.", cwe: "CWE-915" },
  "idor":                     { title: "Insecure Direct Object Reference", description: "Request-controlled identifier selects a record with no ownership check.", cwe: "CWE-639" },
  "pii-in-logs":              { title: "Sensitive Data in Logs",         description: "Personal or credential data written to a log.", cwe: "CWE-532" },
  "insecure-randomness":      { title: "Insecure Randomness",            description: "Non-cryptographic random number generator used for a security-sensitive value.", cwe: "CWE-330" },
  "verbose-error":            { title: "Verbose Error Exposure",         description: "Stack trace or internal error details returned to the client.", cwe: "CWE-209" },
  "csrf-protection-disabled": { title: "CSRF Protection Disabled",       description: "Cross-site request forgery protection explicitly turned off.", cwe: "CWE-352" },
  "sensitive-url-data":       { title: "Sensitive Data in URL",          description: "Credential or sensitive value sent in a URL query string.", cwe: "CWE-598" },
  "php-missing-session-guard": { title: "Missing Authentication Check",  description: "Sensitive PHP endpoint reachable without a session/authentication guard.", cwe: "CWE-306" },
  "cross-file-taint-exposure": { title: "Cross-file Taint",              description: "Tainted data from an imported module may reach a sensitive sink in this file." },
  "ai-comment-pattern":       { title: "AI Comment Pattern",             description: "Comment verbosity and style strongly match AI generation signatures." },
};

/** Title, description and CWE for a finding id, whichever source knows it. */
export function findingMeta(id: string, fallbackLabel?: string): CatalogEntry {
  const entry = FINDING_CATALOG[id];
  if (entry) return entry;
  const cwe = cweFor(id);
  return { title: cwe?.title ?? fallbackLabel ?? id, description: fallbackLabel ?? cwe?.title ?? id, cwe: cwe?.id };
}
