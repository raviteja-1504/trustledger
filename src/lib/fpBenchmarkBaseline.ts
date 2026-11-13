/**
 * False-positive benchmark baseline -- every currently-accepted (file, id,
 * line) security finding produced by scanning this project's own src/ tree
 * (the corpus fpBenchmarkCorpus.benchmark.test.ts scans), each with a real,
 * individually-verified reason it's not a genuine vulnerability. See
 * src/lib/fpBenchmark.ts for the diff mechanism this feeds, and
 * fpBenchmarkCorpus.benchmark.test.ts for how it's consumed.
 *
 * Seeded from a full hand-triage of the 149 findings this corpus
 * produced after fixing the AI_SIGNAL_IDS gap (scanner.ts) -- every entry
 * below was read in source, not bulk-accepted. Six root-cause classes
 * (catalog/label UI text self-matching detector keywords, a detector's own
 * pattern-definition regex self-matching its own vocabulary, demo/seed
 * fixture content never executed, an array-index type-inference gap in
 * hallucinated-method-call, a Supabase realtime filter colliding with the
 * word "filter", and Next.js route handlers parsing their own inbound
 * request URL) explain the overwhelming majority; a handful of individually
 * bespoke cases (weak-cors, verbose-error, three dangerouslySetInnerHTML
 * sites) were each read and reasoned about on their own.
 *
 * A NEW finding not in this list fails fpBenchmarkCorpus.benchmark.test.ts
 * -- either fix the underlying code/detector, or add an entry here with a
 * real reason. A STALE entry (no longer produced live) also fails the test
 * -- remove it once confirmed fixed, or re-verify and update its lineHash if
 * the surrounding line changed.
 */

import type { FpBaselineEntry } from "./fpBenchmark";

export const FP_BASELINE: FpBaselineEntry[] = [
  { file: "src/app/api/scans/pr/route.ts", id: "log-injection", lineHash: "2551c8526f84", line: 97, severity: "medium",
    reason: "recordEvent({ kind: \"scan.queued\", org_id: auth.org_id, ... }): the logged message is the literal kind. The engine taints the whole object literal because one field (auth.org_id, a UUID from the session) is tainted; the context fields themselves are logged as structured JSON." },
  { file: "src/app/api/scans/[id]/rescan/route.ts", id: "log-injection", lineHash: "abbe7b15e136", line: 86, severity: "medium",
    reason: "Same shape as scans/pr/route.ts: recordEvent's message is the literal event kind; only the object as a whole is tainted (auth.org_id), and the logger serializes its context as JSON." },
  { file: "src/lib/seedFileSamples.ts", id: "command-injection", lineHash: "e5aa10162c73", line: 450, severity: "critical",
    reason: "This line is inside seedFileSamples.ts's demo/seed fixture content -- deliberately vulnerable-looking sample code used to seed demo scans, never executed as part of the application itself." },
  { file: "src/lib/scanner.ts", id: "hallucinated-method-call", lineHash: "22a5d5b840fa", line: 1646, severity: "medium",
    reason: "False positive: the detector cannot infer an array-index expression's (e.g. arr[i], match[1]) element type and defaults to flagging real built-in String/Array/Object methods (.trim(), .split(), .toLowerCase(), .sort(), .charCodeAt(), etc.) as hallucinated. Confirmed a genuine built-in at this call site." },
  { file: "src/lib/seedFileSamples.ts", id: "hallucinated-method-call", lineHash: "c214a36398b3", line: 499, severity: "medium",
    reason: "This line is inside seedFileSamples.ts's demo/seed fixture content -- deliberately vulnerable-looking sample code used to seed demo scans, never executed as part of the application itself." },
  { file: "src/components/NewScanPanel.tsx", id: "hardcoded-secret", lineHash: "03a1a70cc450", line: 55, severity: "high",
    reason: "This line is inside an intentionally-vulnerable code SAMPLE embedded as product demo content in NewScanPanel.tsx (shown to users to illustrate what the scanner detects) -- never executed." },
  { file: "src/lib/seedFileSamples.ts", id: "insecure-deserialization", lineHash: "ea197b071a38", line: 422, severity: "critical",
    reason: "This line is inside seedFileSamples.ts's demo/seed fixture content -- deliberately vulnerable-looking sample code used to seed demo scans, never executed as part of the application itself." },
  { file: "src/app/pr/[id]/page.tsx", id: "insecure-randomness", lineHash: "a7c5a5fc3b90", line: 52, severity: "high",
    reason: "UI/catalog/label content describing this vulnerability class to users (a string literal shown in the product's own vulnerability-description, SARIF-rule, or threat-catalog UI) -- not executable code containing the vulnerability itself." },
  { file: "src/lib/vulnCatalog.ts", id: "insecure-randomness", lineHash: "19b975d6ce0f", line: 115, severity: "high",
    reason: "UI/catalog/label content describing this vulnerability class to users (a string literal shown in the product's own vulnerability-description, SARIF-rule, or threat-catalog UI) -- not executable code containing the vulnerability itself." },
  { file: "src/lib/vulnCatalog.ts", id: "jwt-none-alg", lineHash: "2c086b6c0303", line: 45, severity: "critical",
    reason: "UI/catalog/label content describing this vulnerability class to users (a string literal shown in the product's own vulnerability-description, SARIF-rule, or threat-catalog UI) -- not executable code containing the vulnerability itself." },
  { file: "src/lib/licenseContamination.ts", id: "license-header-contamination", lineHash: "54f37ad57cd7", line: 106, severity: "medium",
    reason: "This is the license-detector's OWN pattern-definition string (a literal snippet of real MIT/BSD license text used to detect copied license headers elsewhere) -- self-matches its own regex." },
  { file: "src/lib/licenseContamination.ts", id: "license-header-contamination", lineHash: "27ae6dba759c", line: 110, severity: "medium",
    reason: "This is the license-detector's OWN pattern-definition string (a literal snippet of real MIT/BSD license text used to detect copied license headers elsewhere) -- self-matches its own regex." },
  { file: "src/components/NewScanPanel.tsx", id: "sql-injection", lineHash: "3123f0f4c285", line: 37, severity: "critical",
    reason: "This line is inside an intentionally-vulnerable code SAMPLE embedded as product demo content in NewScanPanel.tsx (shown to users to illustrate what the scanner detects) -- never executed." },
  { file: "src/components/NewScanPanel.tsx", id: "sql-injection", lineHash: "c381c60f5f1c", line: 44, severity: "critical",
    reason: "This line is inside an intentionally-vulnerable code SAMPLE embedded as product demo content in NewScanPanel.tsx (shown to users to illustrate what the scanner detects) -- never executed." },
  { file: "src/lib/seedFileSamples.ts", id: "sql-injection", lineHash: "d93a626aea03", line: 69, severity: "critical",
    reason: "This line is inside seedFileSamples.ts's demo/seed fixture content -- deliberately vulnerable-looking sample code used to seed demo scans, never executed as part of the application itself." },
  { file: "src/lib/errors.ts", id: "verbose-error", lineHash: "2dffa306ce8c", line: 48, severity: "medium",
    reason: "This is safeError(), the app's own centralized safe-error-handling utility. err.stack is passed only to logger.error(...) (server-side structured logging) -- the client response (line 52-53) only ever receives { error: opts.code, message: opts.message, ref_id: refId }, a sanitized message with a correlation id. The detector flags proximity to \"stack\" without seeing that it never reaches the HTTP response." },
  { file: "src/app/api/docs/route.ts", id: "weak-cors", lineHash: "5ad176110a75", line: 6, severity: "medium",
    reason: "Public OpenAPI spec endpoint (GET-only, no auth/cookies/session data) -- wildcard CORS is intentional so external API tooling and documentation generators can fetch the spec cross-origin. No sensitive data is served here." },
  { file: "src/lib/seedFileSamples.ts", id: "weak-crypto", lineHash: "a6417ea270ec", line: 444, severity: "high",
    reason: "This line is inside seedFileSamples.ts's demo/seed fixture content -- deliberately vulnerable-looking sample code used to seed demo scans, never executed as part of the application itself." },
  { file: "src/lib/vulnCatalog.ts", id: "weak-crypto", lineHash: "ea4abd0ebbe6", line: 115, severity: "high",
    reason: "UI/catalog/label content describing this vulnerability class to users (a string literal shown in the product's own vulnerability-description, SARIF-rule, or threat-catalog UI) -- not executable code containing the vulnerability itself." },
  { file: "src/app/docs/api/page.tsx", id: "xss", lineHash: "824f2ab04e15", line: 22, severity: "critical",
    reason: "Static CSS string passed to dangerouslySetInnerHTML with zero interpolated variables (a plain template literal, no ${...} expressions) -- no dynamic content of any kind ever reaches this call." },
  { file: "src/lib/demoSamples.ts", id: "sql-injection", lineHash: "2ee5781b864c", line: 70, severity: "critical",
    reason: "Inside the public live demo's vulnerable SQL-injection sample (a template-literal string shown on /demo and scanned by the sandbox) -- sample text, never executed. The sample exists to be detected." },
  { file: "src/lib/demoSamples.ts", id: "command-injection", lineHash: "a18ad4078b44", line: 142, severity: "critical",
    reason: "Inside the live demo's vulnerable Go command-injection sample (string content shown on /demo) -- sample text, never executed. The sample exists to be detected." },
  { file: "src/lib/demoSamples.ts", id: "command-injection", lineHash: "1049f38dc776", line: 166, severity: "critical",
    reason: "Inside the live demo's FIXED Go sample (string content, never executed). Read as TypeScript only the line-level detector sees it; scanned as Go by the demo sandbox, the anchored-regex check clears it (demoScan.test.ts asserts the fixed sample is clean)." },
  { file: "src/lib/demoSamples.ts", id: "insecure-deserialization", lineHash: "9bdd1f82bf4c", line: 199, severity: "critical",
    reason: "Inside the live demo's vulnerable Java deserialization sample (string content shown on /demo) -- sample text, never executed. The sample exists to be detected." },
  { file: "src/app/blog/posts.tsx", id: "sql-injection", lineHash: "12d5b751170d", line: 19, severity: "critical",
    reason: "A Juliet C# code excerpt quoted inside a <Pre> block of a blog article about false positives -- rendered as text, never executed." },
  { file: "src/lib/ast.ts", id: "xss", lineHash: "a5a8570f0472", line: 484, severity: "critical",
    reason: "This line is inside a detector's own pattern-DEFINITION list (e.g. HIGH_RISKS) -- a regex literal used to detect this vulnerability class elsewhere in scanned code, not an actual occurrence of it in this file." },
  // (The PHP OWASP hardening phase's php-missing-session-guard entries on TS files are gone: that rule now runs on
  // PHP files only.)
  // Added while fixing a Go detector-gap report: PLACEHOLDER_VALUE_RE's
  // bare "password" marker (no word boundary) was silently suppressing any
  // secret value that merely CONTAINED "password" as a substring --
  // tightening it to \bpassword\b surfaced this real, previously-hidden
  // demo-content finding.
  { file: "src/components/NewScanPanel.tsx", id: "hardcoded-secret", lineHash: "713d0879d184", line: 32, severity: "critical",
    reason: "This line is inside an intentionally-vulnerable code SAMPLE embedded as product demo content in NewScanPanel.tsx (shown to users to illustrate what the scanner detects) -- never executed." },
  // Added with the JWT decode-without-verify rule: the demo's Go sample reads claims with ParseUnverified on purpose.
  { file: "src/components/NewScanPanel.tsx", id: "jwt-none-alg", lineHash: "734d4d6a3b1b", line: 67, severity: "critical",
    reason: "This line is inside an intentionally-vulnerable code SAMPLE embedded as product demo content in NewScanPanel.tsx (shown to users to illustrate what the scanner detects) -- never executed." },
  // Added with the JS/TS recall phase: the structural JWT check flags hand-rolled payload decoding.
  { file: "src/lib/jwt.ts", id: "jwt-none-alg", lineHash: "ba3a2f2a74f7", line: 14, severity: "critical",
    reason: "Reviewed: decodeJwtPayload is a documented decode-only helper (its header comment says it does NOT verify the signature and must only be used on tokens already verified via supabase.auth.getUser(), to read extra claims such as session_id). It is never used as an authorization decision on its own." },
  // Added with the Java BOLA PrincipalState work: same known array-index type-inference gap as the entries above.
  // Added with the GitHub install-return flow (the wizard reads GitHub's ?installation_id=... when the person comes back).
  { file: "src/app/onboarding/page.tsx", id: "ssrf", lineHash: "febcf18cc92f", line: 115, severity: "critical",
    reason: "False positive: the request URL is the same-origin relative path /api/github-app/installation?id=<n> (authedFetch sends only to this app's own API, never to another host). The id comes from the address bar (GitHub's installation_id) but is used only after the lines above check it is digits-only (/^\\d+$/), so it cannot change the host or the path. The engine does not treat a regex test as a sanitizer." },
  { file: "src/components/AuthGuard.tsx", id: "open-redirect", lineHash: "f400a09f622b", line: 35, severity: "medium",
    reason: "False positive: the destination is the fixed same-site path /onboarding; only the current page's own query string (GitHub's installation_id and setup_action) is appended after the `?`, so the host and path cannot be changed by the input. A query string cannot turn a path into an external redirect." },
  { file: "src/app/api/alerts/route.ts", id: "ssrf", lineHash: "9319f55dafca", line: 272, severity: "critical",
    reason: "The URL is a user-configured webhook / alert destination, and delivery goes through isPublicHttpUrl() (lib/outboundUrl.ts, tested in outboundUrl.test.ts) which refuses non-http(s), localhost, private, link-local (cloud metadata) and reserved addresses before every fetch in deliverWebhook / sendSlackAlert / sendTeamsAlert. The engine does not recognise that guard. Known residual: it is a host-name check with no DNS resolution, so a public name that resolves to a private address would pass." },
  { file: "src/app/api/incidents/route.ts", id: "ssrf", lineHash: "48206e8a989b", line: 150, severity: "critical",
    reason: "The URL is a user-configured webhook / alert destination, and delivery goes through isPublicHttpUrl() (lib/outboundUrl.ts, tested in outboundUrl.test.ts) which refuses non-http(s), localhost, private, link-local (cloud metadata) and reserved addresses before every fetch in deliverWebhook / sendSlackAlert / sendTeamsAlert. The engine does not recognise that guard. Known residual: it is a host-name check with no DNS resolution, so a public name that resolves to a private address would pass." },
  { file: "src/app/api/scan-worker/route.ts", id: "log-injection", lineHash: "60827333f547", line: 159, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/scan-worker/route.ts", id: "log-injection", lineHash: "2de9dc7692d0", line: 196, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/scan-worker/route.ts", id: "log-injection", lineHash: "975b314bdbaf", line: 217, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/scan-worker/route.ts", id: "log-injection", lineHash: "b7250736564f", line: 819, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/scan-worker/route.ts", id: "log-injection", lineHash: "f1ba5e8adc19", line: 869, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/scan-worker/route.ts", id: "log-injection", lineHash: "ef220cddfe92", line: 937, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/search/route.ts", id: "redos", lineHash: "3e4a3a8a2075", line: 36, severity: "high",
    reason: "The search text is escaped with the standard regex-escape replace (q.replace(/[.*+?^${}()|[\\]\\]/g, \"\\$&\")) before it is placed in the RegExp, so it matches literally and cannot form a pattern. The engine does not recognise that idiom as a sanitizer." },
  { file: "src/app/api/webhook/github/route.ts", id: "log-injection", lineHash: "eabc038cc0b4", line: 86, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/webhook/github/route.ts", id: "log-injection", lineHash: "f3e9382a4046", line: 92, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/webhook/github/route.ts", id: "log-injection", lineHash: "91d2889f79c4", line: 99, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/webhook/github/route.ts", id: "log-injection", lineHash: "ea25721da544", line: 181, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/webhook/github/route.ts", id: "log-injection", lineHash: "c00a02c6db04", line: 224, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/webhook/github/route.ts", id: "log-injection", lineHash: "b71219b1a8de", line: 266, severity: "medium",
    reason: "recordEvent({ kind, message, data }): the logged message is a fixed string (or a short one with a GitHub-signed payload field such as the pull_request action), and the engine taints the whole object literal because one field (an id from the job / webhook) is tainted. lib/logger.ts JSON-encodes the entry in production and strips CR/LF from the message in development, so a line break cannot forge a second log line." },
  { file: "src/app/api/webhooks/route.ts", id: "ssrf", lineHash: "04dea76989b2", line: 60, severity: "critical",
    reason: "The URL is a user-configured webhook / alert destination, and delivery goes through isPublicHttpUrl() (lib/outboundUrl.ts, tested in outboundUrl.test.ts) which refuses non-http(s), localhost, private, link-local (cloud metadata) and reserved addresses before every fetch in deliverWebhook / sendSlackAlert / sendTeamsAlert. The engine does not recognise that guard. Known residual: it is a host-name check with no DNS resolution, so a public name that resolves to a private address would pass." },
];
