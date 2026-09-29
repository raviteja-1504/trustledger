/**
 * Expanded AppSec rules -- Kubernetes hardening, cloud posture from the repo (Terraform, CloudFormation,
 * ARM/Bicep, Serverless), container hardening, and API security (OpenAPI specs, endpoint auth).
 * One entry per finding id: what it is, how bad, its CWE, and the fix. findingCatalog.ts, cweMap.ts
 * and scanner.ts's FIX_MAP spread these in, so a rule is defined once.
 *
 * Client-safe: no imports beyond types.
 */
import type { ScanIndicator } from "./scanner";

export type AppsecDomain = "kubernetes" | "cloud" | "container" | "api";
type Sev = ScanIndicator["severity"];

export interface AppsecRule {
  title: string;
  description: string;
  severity: Sev;
  cwe: string;
  cweTitle: string;
  domain: AppsecDomain;
  fix: { title: string; description: string; code_before?: string; code_after?: string; effort: "low" | "medium" | "high" };
}

const CWE_TITLES: Record<string, string> = {
  "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
  "CWE-209": "Generation of Error Message Containing Sensitive Information",
  "CWE-250": "Execution with Unnecessary Privileges",
  "CWE-269": "Improper Privilege Management",
  "CWE-284": "Improper Access Control",
  "CWE-287": "Improper Authentication",
  "CWE-295": "Improper Certificate Validation",
  "CWE-306": "Missing Authentication for Critical Function",
  "CWE-311": "Missing Encryption of Sensitive Data",
  "CWE-319": "Cleartext Transmission of Sensitive Information",
  "CWE-320": "Key Management Errors",
  "CWE-326": "Inadequate Encryption Strength",
  "CWE-522": "Insufficiently Protected Credentials",
  "CWE-527": "Exposure of Version-Control Repository to an Unauthorized Control Sphere",
  "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
  "CWE-548": "Exposure of Information Through Directory Listing",
  "CWE-598": "Use of GET Request Method With Sensitive Query Strings",
  "CWE-601": "URL Redirection to Untrusted Site ('Open Redirect')",
  "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
  "CWE-668": "Exposure of Resource to Wrong Sphere",
  "CWE-693": "Protection Mechanism Failure",
  "CWE-732": "Incorrect Permission Assignment for Critical Resource",
  "CWE-770": "Allocation of Resources Without Limits or Throttling",
  "CWE-778": "Insufficient Logging",
  "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "CWE-798": "Use of Hard-coded Credentials",
  "CWE-862": "Missing Authorization",
  "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
  "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
  "CWE-1104": "Use of Unmaintained Third Party Components",
  "CWE-16": "Configuration",
};

type RuleInput = Omit<AppsecRule, "cweTitle">;
const r = (x: RuleInput): AppsecRule => ({ ...x, cweTitle: CWE_TITLES[x.cwe] ?? x.cwe });

export const APPSEC_RULES: Record<string, AppsecRule> = {
  // ── Kubernetes (per-container, per-resource) ──────────────────────────────
  "iac-k8s-privilege-escalation": r({ domain: "kubernetes", severity: "medium", cwe: "CWE-250",
    title: "Container Can Escalate Privileges", description: "A container does not set allowPrivilegeEscalation: false, so a process inside it can gain more privileges than its parent (setuid binaries, file capabilities).",
    fix: { title: "Disallow privilege escalation", description: "Set allowPrivilegeEscalation: false in the container's securityContext.", code_before: "securityContext: {}", code_after: "securityContext:\n  allowPrivilegeEscalation: false", effort: "low" } }),
  "iac-k8s-missing-run-as-non-root": r({ domain: "kubernetes", severity: "low", cwe: "CWE-250",
    title: "Container May Run As Root", description: "Neither the pod nor the container requires a non-root user (runAsNonRoot / a non-zero runAsUser), so the image's default user -- often root -- is used.",
    fix: { title: "Require a non-root user", description: "Set runAsNonRoot: true (and a non-zero runAsUser) in the pod or container securityContext.", code_after: "securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001", effort: "low" } }),
  "iac-k8s-writable-root-fs": r({ domain: "kubernetes", severity: "low", cwe: "CWE-732",
    title: "Writable Root Filesystem", description: "The container's root filesystem is writable, so an attacker who gets code execution can modify binaries and drop tools.",
    fix: { title: "Mount the root filesystem read-only", description: "Set readOnlyRootFilesystem: true and mount an emptyDir for paths the app must write to.", code_after: "securityContext:\n  readOnlyRootFilesystem: true", effort: "medium" } }),
  "iac-k8s-missing-resource-limits": r({ domain: "kubernetes", severity: "low", cwe: "CWE-770",
    title: "No Resource Limits", description: "The container has no CPU/memory limits: one compromised or runaway pod can starve every other workload on the node.",
    fix: { title: "Set CPU and memory limits", description: "Add resources.limits (and requests) sized for the workload.", code_after: "resources:\n  requests: { cpu: 100m, memory: 128Mi }\n  limits: { cpu: 500m, memory: 512Mi }", effort: "low" } }),
  "iac-k8s-secret-in-env": r({ domain: "kubernetes", severity: "high", cwe: "CWE-798",
    title: "Secret Hard-coded in Pod Env", description: "A credential-named environment variable has a literal value in the manifest, so the secret lives in git and in every copy of the manifest.",
    fix: { title: "Reference a Secret", description: "Store the value in a Kubernetes Secret (or an external secret manager) and use valueFrom.secretKeyRef.", code_before: "- name: DB_PASSWORD\n  value: hunter2", code_after: "- name: DB_PASSWORD\n  valueFrom:\n    secretKeyRef: { name: db, key: password }", effort: "low" } }),
  "iac-k8s-host-path-volume": r({ domain: "kubernetes", severity: "medium", cwe: "CWE-668",
    title: "Host Path Volume", description: "The pod mounts a directory from the node. A container escape starts here: the Docker socket, /etc, /var/lib/kubelet or / give root on the node.",
    fix: { title: "Use a non-host volume", description: "Replace hostPath with emptyDir, a PersistentVolumeClaim, or a projected volume; if a node path is truly required, mount it readOnly and as narrowly as possible.", effort: "medium" } }),
  "iac-k8s-rbac-wildcard": r({ domain: "kubernetes", severity: "high", cwe: "CWE-269",
    title: "Wildcard RBAC Rule", description: "A Role/ClusterRole grants '*' verbs or resources -- including secrets, and in a ClusterRole, across every namespace.",
    fix: { title: "List the exact verbs and resources", description: "Grant only the verbs and resources the service account uses.", code_before: "rules:\n- apiGroups: [\"*\"]\n  resources: [\"*\"]\n  verbs: [\"*\"]", code_after: "rules:\n- apiGroups: [\"\"]\n  resources: [\"configmaps\"]\n  verbs: [\"get\", \"list\"]", effort: "medium" } }),
  "iac-k8s-cluster-admin-binding": r({ domain: "kubernetes", severity: "high", cwe: "CWE-269",
    title: "cluster-admin Granted", description: "A binding gives a user, group or service account the cluster-admin role: full control of the cluster.",
    fix: { title: "Bind a least-privilege role", description: "Create a Role/ClusterRole with only the permissions needed and bind that instead.", effort: "medium" } }),
  "iac-k8s-committed-secret": r({ domain: "kubernetes", severity: "high", cwe: "CWE-798",
    title: "Secret Manifest Committed", description: "A Kubernetes Secret with literal data is committed to the repository; base64 is an encoding, not encryption.",
    fix: { title: "Keep secret values out of git", description: "Use Sealed Secrets, SOPS, External Secrets, or create the Secret at deploy time; rotate the committed values.", effort: "medium" } }),
  "iac-k8s-ingress-no-tls": r({ domain: "kubernetes", severity: "low", cwe: "CWE-319",
    title: "Ingress Without TLS", description: "The Ingress has no tls section, so traffic to it is served over plain HTTP unless something else terminates TLS.",
    fix: { title: "Add a tls section", description: "Configure tls with a certificate (e.g. cert-manager) for each host.", code_after: "tls:\n- hosts: [app.example.com]\n  secretName: app-tls", effort: "low" } }),

  // ── Cloud posture from the repo ──────────────────────────────────────────
  "cloud-storage-public": r({ domain: "cloud", severity: "critical", cwe: "CWE-284",
    title: "Public Storage Bucket", description: "Object storage is readable (or writable) by anyone on the internet: an S3 public ACL, a GCS allUsers binding, or Azure blob public access.",
    fix: { title: "Remove public access", description: "Serve public assets through a CDN with origin access control, and keep the bucket private.", effort: "low" } }),
  "cloud-storage-public-access-block-disabled": r({ domain: "cloud", severity: "high", cwe: "CWE-284",
    title: "S3 Public Access Block Disabled", description: "An S3 Block Public Access setting is turned off, so a later ACL or policy change can make the bucket public.",
    fix: { title: "Enable all four Block Public Access settings", description: "Set block_public_acls, block_public_policy, ignore_public_acls and restrict_public_buckets to true.", code_after: "block_public_acls       = true\nblock_public_policy     = true\nignore_public_acls      = true\nrestrict_public_buckets = true", effort: "low" } }),
  "cloud-resource-policy-public": r({ domain: "cloud", severity: "critical", cwe: "CWE-284",
    title: "Resource Policy Open to Everyone", description: "A bucket/queue/topic/key policy allows Principal '*' with no condition: any AWS account -- or anonymous caller -- can use the resource.",
    fix: { title: "Name the principals", description: "Replace Principal '*' with the specific accounts/roles, or add a Condition (aws:SourceArn, aws:PrincipalOrgID).", effort: "low" } }),
  "cloud-open-admin-port": r({ domain: "cloud", severity: "high", cwe: "CWE-284",
    title: "Admin/Database Port Open to the Internet", description: "A firewall rule allows 0.0.0.0/0 (or '*') to SSH, RDP or a database port.",
    fix: { title: "Restrict the source range", description: "Allow only a bastion, VPN range or specific IPs; use SSM Session Manager / IAP instead of open SSH.", code_before: "cidr_blocks = [\"0.0.0.0/0\"]", code_after: "cidr_blocks = [var.office_cidr]", effort: "low" } }),
  "cloud-db-public": r({ domain: "cloud", severity: "critical", cwe: "CWE-284",
    title: "Database Reachable From the Internet", description: "A managed database is publicly accessible or authorizes 0.0.0.0/0.",
    fix: { title: "Make the database private", description: "Disable public access and connect through private networking.", effort: "medium" } }),
  "cloud-db-unencrypted": r({ domain: "cloud", severity: "medium", cwe: "CWE-311",
    title: "Database Storage Not Encrypted", description: "A managed database does not enable storage encryption at rest.",
    fix: { title: "Enable storage encryption", description: "Set StorageEncrypted: true / storage_encrypted = true (requires a new instance for RDS).", effort: "medium" } }),
  "cloud-db-no-tls": r({ domain: "cloud", severity: "medium", cwe: "CWE-319",
    title: "Database Allows Unencrypted Connections", description: "The database accepts connections without TLS.",
    fix: { title: "Require TLS", description: "Set ssl_mode = \"ENCRYPTED_ONLY\" (Cloud SQL) or the engine's require-SSL parameter.", effort: "low" } }),
  "cloud-disk-unencrypted": r({ domain: "cloud", severity: "medium", cwe: "CWE-311",
    title: "Unencrypted Disk", description: "A block storage volume is explicitly created without encryption.",
    fix: { title: "Encrypt the volume", description: "Set encrypted = true (and a KMS key if required); enable EBS encryption by default for the account.", effort: "low" } }),
  "cloud-iam-admin-wildcard": r({ domain: "cloud", severity: "high", cwe: "CWE-269",
    title: "IAM Statement Grants Everything", description: "An Allow statement grants Action '*' on Resource '*' -- administrator access.",
    fix: { title: "Grant specific actions on specific resources", description: "List the actions and resource ARNs the role needs; use IAM Access Analyzer to generate a least-privilege policy.", effort: "medium" } }),
  "cloud-hardcoded-secret": r({ domain: "cloud", severity: "high", cwe: "CWE-798",
    title: "Credential Hard-coded in Infrastructure Code", description: "A password, access key or secret is written as a literal in the template instead of coming from a secret store or parameter.",
    fix: { title: "Use a secret reference", description: "Use AWS Secrets Manager / SSM SecureString ({{resolve:secretsmanager:...}}), a NoEcho parameter, a Terraform sensitive variable, or Key Vault; rotate the committed value.", effort: "low" } }),
  "cloud-function-url-no-auth": r({ domain: "cloud", severity: "medium", cwe: "CWE-306",
    title: "Function URL Without Authentication", description: "A Lambda function URL uses AuthType NONE: anyone who finds the URL can invoke the function.",
    fix: { title: "Require IAM auth or put it behind an API", description: "Use AuthType AWS_IAM, or front the function with API Gateway and an authorizer.", effort: "low" } }),
  "cloud-api-no-auth": r({ domain: "cloud", severity: "medium", cwe: "CWE-306",
    title: "API Gateway Route Without Authorization", description: "An API Gateway method/route is configured with authorization NONE.",
    fix: { title: "Attach an authorizer", description: "Use a Cognito/JWT/Lambda authorizer or IAM auth; keep NONE only for routes that are public by design.", effort: "medium" } }),
  "cloud-logging-disabled": r({ domain: "cloud", severity: "high", cwe: "CWE-778",
    title: "Audit Logging Disabled", description: "A CloudTrail trail is defined with logging turned off, so API activity in the account is not recorded.",
    fix: { title: "Turn logging on", description: "Set IsLogging: true / enable_logging = true, multi-region, with log file validation.", effort: "low" } }),
  "cloud-kms-no-rotation": r({ domain: "cloud", severity: "low", cwe: "CWE-320",
    title: "KMS Key Rotation Disabled", description: "A symmetric customer-managed KMS key does not enable automatic rotation.",
    fix: { title: "Enable key rotation", description: "Set enable_key_rotation = true / EnableKeyRotation: true.", effort: "low" } }),
  "cloud-lb-plain-http": r({ domain: "cloud", severity: "medium", cwe: "CWE-319",
    title: "Load Balancer Serves Plain HTTP", description: "A load balancer listener accepts HTTP and forwards it instead of redirecting to HTTPS.",
    fix: { title: "Redirect HTTP to HTTPS", description: "Make the HTTP listener's default action a redirect to port 443 with HTTP_301, and serve the app on an HTTPS listener.", effort: "low" } }),
  "cloud-storage-plain-http": r({ domain: "cloud", severity: "medium", cwe: "CWE-319",
    title: "Storage Account Allows HTTP", description: "An Azure storage account accepts unencrypted HTTP requests.",
    fix: { title: "Require HTTPS", description: "Set supportsHttpsTrafficOnly / https_traffic_only_enabled to true.", effort: "low" } }),
  "cloud-weak-tls": r({ domain: "cloud", severity: "medium", cwe: "CWE-326",
    title: "Outdated Minimum TLS Version", description: "The service accepts TLS 1.0/1.1, which are deprecated and have known weaknesses.",
    fix: { title: "Require TLS 1.2 or later", description: "Set the minimum TLS version to TLS1_2.", effort: "low" } }),

  // ── Container ────────────────────────────────────────────────────────────
  "container-eol-base-image": r({ domain: "container", severity: "medium", cwe: "CWE-1104",
    title: "End-of-Life Base Image", description: "The image is built FROM a runtime or OS release that no longer receives security fixes.",
    fix: { title: "Move to a supported release", description: "Update the FROM line to a maintained version (and pin it by digest).", effort: "medium" } }),
  "container-insecure-download": r({ domain: "container", severity: "medium", cwe: "CWE-295",
    title: "TLS Verification Disabled in Build", description: "A build step downloads with certificate checks turned off (curl -k, wget --no-check-certificate, pip --trusted-host, npm strict-ssl false), so the download can be swapped in transit.",
    fix: { title: "Keep certificate verification on", description: "Remove the flag; install the needed CA certificate instead.", effort: "low" } }),
  "container-world-writable": r({ domain: "container", severity: "low", cwe: "CWE-732",
    title: "World-Writable Permissions", description: "A build step makes files world-writable (chmod 777), letting any process in the container modify them.",
    fix: { title: "Grant only what is needed", description: "chown the files to the runtime user and use 755/644 (or narrower).", effort: "low" } }),
  "container-compose-security-opt-disabled": r({ domain: "container", severity: "high", cwe: "CWE-693",
    title: "Container Sandboxing Disabled", description: "A Compose service disables seccomp or AppArmor (security_opt: *:unconfined), removing kernel-level protections against container escape.",
    fix: { title: "Keep the default profiles", description: "Remove the unconfined security_opt; if a syscall is needed, use a custom seccomp profile that allows only it.", effort: "medium" } }),
  "container-compose-exposed-datastore": r({ domain: "container", severity: "medium", cwe: "CWE-668",
    title: "Database Port Published on All Interfaces", description: "A Compose service publishes a database/cache port (Postgres, MySQL, Redis, MongoDB, Elasticsearch, ...) on every host interface.",
    fix: { title: "Bind to localhost or don't publish", description: "Use \"127.0.0.1:5432:5432\", or drop the ports mapping and reach the service over the Compose network.", code_before: "ports:\n  - \"5432:5432\"", code_after: "ports:\n  - \"127.0.0.1:5432:5432\"", effort: "low" } }),

  // ── API security ─────────────────────────────────────────────────────────
  "api-spec-unauthenticated-operation": r({ domain: "api", severity: "medium", cwe: "CWE-306",
    title: "API Operation Without Authentication", description: "The OpenAPI spec declares no security requirement for this operation (none on the operation and none globally).",
    fix: { title: "Declare a security requirement", description: "Add a global `security:` requirement (or one on the operation); mark intentionally public operations with `security: []`.", code_after: "security:\n  - bearerAuth: []", effort: "low" } }),
  "api-spec-insecure-server": r({ domain: "api", severity: "medium", cwe: "CWE-319",
    title: "API Served Over HTTP", description: "The spec lists a non-local http:// server (or the http scheme), so credentials and data can travel unencrypted.",
    fix: { title: "Serve over HTTPS only", description: "Change server URLs/schemes to https.", effort: "low" } }),
  "api-spec-basic-auth": r({ domain: "api", severity: "medium", cwe: "CWE-522",
    title: "HTTP Basic Authentication", description: "The API accepts HTTP Basic credentials: the password is sent with every request and is not bound to a session or scope.",
    fix: { title: "Use tokens", description: "Use OAuth2/OIDC bearer tokens or scoped API keys in a header.", effort: "high" } }),
  "api-spec-key-in-query": r({ domain: "api", severity: "medium", cwe: "CWE-598",
    title: "API Key in Query String", description: "An API key scheme is sent in the query string, where it ends up in server logs, proxies and browser history.",
    fix: { title: "Send the key in a header", description: "Change the security scheme to `in: header`.", code_before: "in: query", code_after: "in: header", effort: "low" } }),
  "api-spec-oauth-implicit": r({ domain: "api", severity: "medium", cwe: "CWE-287",
    title: "OAuth Implicit Flow", description: "The OAuth2 implicit flow returns tokens in the URL fragment and is deprecated by the OAuth 2.0 Security BCP.",
    fix: { title: "Use authorization code + PKCE", description: "Replace the implicit flow with authorizationCode and PKCE.", effort: "medium" } }),
  "api-spec-sensitive-query-param": r({ domain: "api", severity: "medium", cwe: "CWE-598",
    title: "Sensitive Value in Query Parameter", description: "A password/token/secret is passed as a query parameter, which gets logged by servers and proxies.",
    fix: { title: "Move it to the body or a header", description: "Send credentials in the request body (POST) or an Authorization header.", effort: "low" } }),
  "api-endpoint-missing-auth": r({ domain: "api", severity: "high", cwe: "CWE-862",
    title: "Endpoint Missing the Auth Its Siblings Have", description: "Other endpoints in this file require authentication, but this one does not -- the classic forgotten-middleware bug.",
    fix: { title: "Apply the same auth", description: "Add the same auth middleware/decorator/attribute the neighbouring endpoints use, or mark the endpoint as public explicitly (e.g. [AllowAnonymous]) if that is intended.", effort: "low" } }),
};

export function appsecRule(id: string): AppsecRule | undefined {
  return APPSEC_RULES[id];
}

/** A finding for rule `id` at `line` (1-based); label and severity from the rule unless overridden. */
export function appsecHit(id: string, line: number, detail: string, opts: { confidence?: number; severity?: Sev } = {}): ScanIndicator {
  const rule = APPSEC_RULES[id];
  return {
    id, label: rule?.title ?? id, severity: opts.severity ?? rule?.severity ?? "medium",
    line: Math.max(1, line), confidence: opts.confidence ?? 85, detail, cwe: rule?.cwe,
  };
}

/** Catalog projections spread into findingCatalog.ts / cweMap.ts / scanner.ts's FIX_MAP. */
export const APPSEC_CATALOG = Object.fromEntries(Object.entries(APPSEC_RULES).map(([id, x]) => [id, { title: x.title, description: x.description, cwe: x.cwe }]));
export const APPSEC_CWE = Object.fromEntries(Object.entries(APPSEC_RULES).map(([id, x]) => [id, { id: x.cwe, title: x.cweTitle }]));
export const APPSEC_FIXES = Object.fromEntries(Object.entries(APPSEC_RULES).map(([id, x]) => [id, {
  title: x.fix.title, description: x.fix.description,
  ...(x.fix.code_before ? { code_before: x.fix.code_before } : {}), ...(x.fix.code_after ? { code_after: x.fix.code_after } : {}),
  cwe: x.cwe, effort: x.fix.effort,
}]));
