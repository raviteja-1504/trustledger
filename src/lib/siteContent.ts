/**
 * Prose the marketing site and the docs share. It lives here, apart from the landing page's client component, so
 * the documentation can render it without the page's icons and styling -- and so the homepage can stay short and
 * link to the full account instead of repeating it.
 */

/** What a pull-request scan does, in order. */
export const PIPELINE_STAGES: { label: string; detail: string }[] = [
  { label: "GitHub webhook", detail: "PR opened or updated" },
  { label: "File fetch", detail: "Every changed file, async via queue" },
  { label: "AI signal scan", detail: "AST · git provenance · behavioral" },
  { label: "Taint engine", detail: "Per-language AST + cross-file data-flow" },
  { label: "Secrets, deps, IaC", detail: "Credentials · CVEs by reachability · cloud, container & API config" },
  { label: "Policy engine", detail: "Risk score against merge gates" },
  { label: "Attestation gate", detail: "Blocks until reviewer sign-off" },
  { label: "Check run", detail: "Posted to the PR" },
];

export const AI_FACTS = [
  { label: "AST structural analysis", desc: "Parses source into an abstract syntax tree and scores structural patterns that correlate with LLM output — long function bodies, uniform naming, missing edge-case handling." },
  { label: "Git provenance scoring", desc: "Scores commit velocity, message entropy, signing rate, and LOC/commit ratio against norms. A 1,300 LOC/commit average from a single author is a signal, not a fact — weighted accordingly." },
  { label: "Developer baseline deviation", desc: "Tracks each contributor's historical AI%, file count, and commit cadence. A sudden 3× spike in AI content on a PR flags as anomalous even if the absolute score is moderate." },
  { label: "AI tool attribution", desc: "Detects .cursor/, .claude/, .copilot-instructions, Windsurf config, and inline marker comments to attribute code to specific assistants — not just \"AI wrote this\" but \"Cursor wrote this\"." },
  { label: "Shadow AI detection", desc: "Flags AI-tool usage signatures that aren't on your org's approved-tools policy list, confidence-scored, with the affected developers surfaced directly." },
  { label: "Cross-file semantic graph", desc: "Builds a call graph across the entire PR to catch AI-generated glue code that wires together real modules in unsafe ways — invisible to a per-file tool." },
];
export const ENGINE_FACTS = [
  { label: "Sink-class bitmask model", desc: "A taint value is a bitmask of 15 sink classes, not a boolean. A sanitizer clears only the classes it neutralizes — and the trace shows it: htmlspecialchars() before a SQL query is called out, not trusted." },
  { label: "Path-sensitive propagation", desc: "Branches are walked on cloned state and merged with a may-taint join; a value sanitized on one branch and raw on another is tracked correctly on both." },
  { label: "Narrow validation guards", desc: "Only unambiguous proofs clear a variable — literal-collection membership, strict numeric checks, equality with a literal, a fully anchored digits-only or character-class pattern. A loose regex match is deliberately NOT trusted." },
  { label: "BOLA ownership dominance", desc: "An authorization check only suppresses a finding when it actually dominates the sink in control-flow order — not merely present somewhere in the function." },
  { label: "Fixed-point call resolution", desc: "Call summaries iterate until nothing changes — same-file and across files — so an eight-deep helper chain or a five-file flow converges, with a safety cap instead of an arbitrary round limit." },
  { label: "Cross-file flows, one finding", desc: "Imports, injected services, Go packages and PHP includes are followed in all ten languages, including Rails autoloading, Kotlin↔Java calls, Rust modules and C/C++ functions across translation units. A flow is reported once, at the caller, listing every file on its path — the callee's duplicate is folded in." },
];

export const IAC_FORMATS = ["Terraform", "CloudFormation / SAM", "ARM templates", "Bicep", "Serverless", "Kubernetes & Helm", "Docker & Compose"];

const LEGACY_K8S = ["iac-privileged-container", "iac-container-run-as-root", "iac-host-namespace-access", "iac-dangerous-capability", "iac-unpinned-image-tag"];
// Older Terraform-only rules; iac-s3-public-acl and iac-public-db are the same checks as cloud-storage-public
// and cloud-db-public (for more formats), so they aren't listed twice.
const LEGACY_CLOUD = ["iac-open-ingress", "iac-unencrypted-storage", "iac-iam-wildcard"];

/** The infrastructure and API check groups; each group's checks are read from the live finding catalog. */
export const CLOUD_API_GROUPS: { name: string; blurb: string; match: (id: string) => boolean }[] = [
  { name: "Kubernetes & Helm", blurb: "Checked per container, with pod-level settings inherited and Helm values respected.", match: id => id.startsWith("iac-k8s-") || LEGACY_K8S.includes(id) },
  { name: "Cloud posture", blurb: "AWS, GCP and Azure resources as your templates define them, before they are created.", match: id => id.startsWith("cloud-") || LEGACY_CLOUD.includes(id) },
  { name: "Containers", blurb: "Dockerfiles and Compose files: what the image is built from and how it runs.", match: id => id.startsWith("container-") },
  { name: "API security", blurb: "Your code's routes and your OpenAPI specs, with the authentication visible for each.", match: id => id.startsWith("api-") },
];

/** The scanner capabilities the homepage used to list as a feature grid; shown in the docs (Taint analysis). */
export const SCANNER_FEATURES: { title: string; desc: string }[] = [
  { title: "Source → Sink Traces", desc: "Every finding ships with the actual data-flow path, hop by hop, with real file and line numbers — including across a file boundary." },
  { title: "Cross-File Data Flow", desc: "In all ten languages: imports and re-exports, injected services (Spring, ASP.NET, NestJS, Axum state), Go packages, PHP includes, Rails autoloading, Rust modules — with a 72-case cross-file suite across six of the languages run on every change." },
  { title: "One Issue, One Finding", desc: "When the pattern layer, the taint engine and cross-file analysis see the same bug, it becomes one finding listing every location and every detector that agreed." },
  { title: "Broken Object-Level Authorization", desc: "Structural ownership-dominance analysis: a resource lookup only clears when a real comparison against the principal dominates every path to the sink." },
  { title: "Reachable Dependencies", desc: "Live CVEs across 8 ecosystems, ranked by whether the vulnerable function is called, the package is reachable from an entry point, used only in tests, or never imported." },
  { title: "Cloud & IaC Posture", desc: "Terraform (AWS, GCP, Azure), CloudFormation, ARM, Bicep and Serverless: public storage, open admin ports, public databases, wildcard IAM, hard-coded credentials — no cloud credentials needed." },
  { title: "Kubernetes & Containers", desc: "Per-container hardening in manifests and Helm charts, RBAC wildcards, committed Secrets; end-of-life base images and disabled sandboxing in Dockerfiles and Compose." },
  { title: "API Endpoint Inventory", desc: "Every route across Express, Next.js, Flask, FastAPI, Spring, ASP.NET, Go and Laravel plus OpenAPI specs — and the endpoint missing the auth its siblings have." },
  { title: "Stable Finding Fingerprints", desc: "A hash of the flow itself, not the line number — the same finding survives unrelated edits elsewhere in the file across scans." },
  { title: "Reviewer Attestation", desc: "Named sign-off recorded per file with signature, timestamp, and risk context at review time — an audit trail that answers itself." },
  { title: "Context-Aware Sanitizers", desc: "An HTML-escaped value dropped into a <script> block or an unquoted attribute is still flagged — encoding for one context doesn't cover another." },
  { title: "Exact Sink Arguments", desc: "Only the exploitable argument counts: the SQL text, not bound parameters; the LDAP filter, not the base DN; the program, not its arguments." },
];
