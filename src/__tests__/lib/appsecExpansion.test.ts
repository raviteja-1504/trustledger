import { runScan } from "@/lib/scanner";
import { isScannablePath } from "@/lib/scannableFiles";
import { eolOf } from "@/lib/containerHardening";
import { extractEndpoints, inconsistentAuth } from "@/lib/api/apiInventory";
import { findingMeta } from "@/lib/findingCatalog";
import { cweFor } from "@/lib/cweMap";
import { APPSEC_RULES } from "@/lib/appsecRules";
import { buildApiSecurityReport } from "@/lib/api/apiSecurityReport";

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
/** `id@line` for every finding in `path` whose id starts with one of the prefixes. */
const hits = (f: F, prefixes = ["iac-k8s", "cloud-", "container-eol", "container-insecure", "container-world", "container-compose-security", "container-compose-exposed", "api-"]) =>
  (scan([f]).files[0]?.indicators ?? []).filter(i => prefixes.some(p => i.id.startsWith(p))).map(i => `${i.id}@${i.line}`).sort();
const ids = (f: F, prefixes?: string[]) => [...new Set(hits(f, prefixes).map(h => h.split("@")[0]))].sort();

describe("Kubernetes: per-container scoping", () => {
  const deploy = (containerSc: string, podSc = "", extra = "") => ({ path: "k8s/deploy.yaml", content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
${podSc}      containers:
      - name: app
        image: nginx:1.25.3
${containerSc}${extra}` });
  const HARDENED = `        securityContext:\n          allowPrivilegeEscalation: false\n          runAsNonRoot: true\n          readOnlyRootFilesystem: true\n        resources:\n          limits:\n            cpu: 500m\n            memory: 256Mi\n`;

  it("a hardened container is clean", () => {
    expect(ids(deploy(HARDENED))).toEqual([]);
  });
  it("each missing control is reported on that container", () => {
    expect(ids(deploy(""))).toEqual(["iac-k8s-missing-resource-limits", "iac-k8s-missing-run-as-non-root", "iac-k8s-privilege-escalation", "iac-k8s-writable-root-fs"]);
  });
  it("a pod-level runAsNonRoot covers every container; another container's setting does not", () => {
    const podSc = `      securityContext:\n        runAsNonRoot: true\n`;
    expect(ids(deploy(HARDENED.replace("          runAsNonRoot: true\n", ""), podSc))).toEqual([]);
    const second = `      - name: sidecar\n        image: busybox:1.36\n`;
    const r = hits(deploy(HARDENED, "", second));
    expect(r.every(h => Number(h.split("@")[1]) >= 18)).toBe(true);      // only the sidecar (line 18+) is reported
    expect(r.length).toBeGreaterThan(0);
  });
  it("a literal secret in env; valueFrom is fine", () => {
    const env = `        env:\n        - name: DB_PASSWORD\n          value: s3cr3t-value\n        - name: API_TOKEN\n          valueFrom:\n            secretKeyRef: { name: t, key: v }\n`;
    expect(hits(deploy(HARDENED + env), ["iac-k8s-secret-in-env"])).toEqual(["iac-k8s-secret-in-env@21"]);
  });
  it("host path volumes; the Docker socket is high severity", () => {
    const vols = `      volumes:\n      - name: sock\n        hostPath:\n          path: /var/run/docker.sock\n`;
    const r = scan([deploy(HARDENED + vols)]).files[0].indicators.filter(i => i.id === "iac-k8s-host-path-volume");
    expect(r.map(i => [i.line, i.severity])).toEqual([[21, "high"]]);
  });
  it("RBAC wildcards and cluster-admin bindings (system subjects excepted)", () => {
    const rbac = { path: "k8s/rbac.yaml", content: `apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: god\nrules:\n- apiGroups: ["*"]\n  resources: ["*"]\n  verbs: ["*"]\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: ci\nroleRef:\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n- kind: ServiceAccount\n  name: ci-bot\n` };
    expect(hits(rbac)).toEqual(["iac-k8s-cluster-admin-binding@16", "iac-k8s-rbac-wildcard@6"]);
    const sys = { path: "k8s/rbac.yaml", content: rbac.content.replace("name: ci-bot", "name: system:masters") };
    expect(ids(sys)).toEqual(["iac-k8s-rbac-wildcard"]);
  });
  it("committed Secret data, ingress without TLS; Helm-templated values are not judged", () => {
    const secret = { path: "k8s/secret.yaml", content: `apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  password: aHVudGVyMg==\n` };
    expect(hits(secret)).toEqual(["iac-k8s-committed-secret@6"]);
    const helm = { path: "charts/app/templates/secret.yaml", content: `apiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n  password: {{ .Values.password | b64enc }}\n` };
    expect(ids(helm)).toEqual([]);
    const ing = { path: "k8s/ingress.yaml", content: `apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: web\nspec:\n  rules:\n  - host: a.example.com\n` };
    expect(ids(ing)).toEqual(["iac-k8s-ingress-no-tls"]);
    expect(ids({ ...ing, content: ing.content + "  tls:\n  - hosts: [a.example.com]\n    secretName: t\n" })).toEqual([]);
  });
});

describe("Kubernetes: Helm templates", () => {
  const chart = (containerExtra: string) => ({ path: "deploy/helm/templates/api/deployment.yaml", content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "app.fullname" . }}
spec:
  template:
    spec:
      containers:
        - name: {{ .Values.api.name }}
          image: {{ .Values.api.image }}:{{ .Chart.AppVersion }}
${containerExtra}` });
  it("values rendered in (toYaml/include) are not 'missing'; what the template never sets still is", () => {
    const resources = `          {{- if .Values.api.resources }}\n          resources:\n            {{- toYaml .Values.api.resources | nindent 12 }}\n          {{- end }}\n`;
    const r = hits(chart(resources));
    expect(r.map(h => h.split("@")[0])).not.toContain("iac-k8s-missing-resource-limits");
    expect(r.map(h => h.split("@")[0])).toContain("iac-k8s-privilege-escalation");     // nothing renders a securityContext
    const sc = `          securityContext:\n            {{- toYaml .Values.api.securityContext | nindent 12 }}\n`;
    expect(ids(chart(resources + sc))).toEqual([]);
    const include = `          {{- include "app.containerDefaults" . | nindent 10 }}\n`;
    expect(ids(chart(include))).toEqual([]);
  });
  it("templated names read as '(templated)' in the message", () => {
    const d = scan([chart("")]).files[0].indicators.find(i => i.id === "iac-k8s-privilege-escalation")!;
    expect(d.detail).toContain("Deployment '(templated)', container '(templated)'");
  });
});

describe("cloud posture: Terraform (AWS, GCP, Azure)", () => {
  const tf = (body: string) => ({ path: "infra/main.tf", content: body });
  it("AWS", () => {
    expect(hits(tf(`resource "aws_s3_bucket_public_access_block" "b" {\n  bucket = aws_s3_bucket.b.id\n  block_public_acls = false\n  block_public_policy = true\n}\n`))).toEqual(["cloud-storage-public-access-block-disabled@3"]);
    expect(ids(tf(`resource "aws_ebs_volume" "v" {\n  size = 10\n  encrypted = false\n}\nresource "aws_cloudtrail" "t" {\n  name = "t"\n  enable_logging = false\n}\n`))).toEqual(["cloud-disk-unencrypted", "cloud-logging-disabled"]);
    expect(ids(tf(`resource "aws_kms_key" "k" {\n  description = "k"\n}\nresource "aws_kms_key" "a" {\n  customer_master_key_spec = "RSA_2048"\n}\n`))).toEqual(["cloud-kms-no-rotation"]);
    expect(ids(tf(`resource "aws_kms_key" "k" {\n  enable_key_rotation = true\n}\n`))).toEqual([]);
    expect(ids(tf(`resource "aws_lambda_function_url" "u" {\n  function_name = "f"\n  authorization_type = "NONE"\n}\n`))).toEqual(["cloud-function-url-no-auth"]);
    expect(ids(tf(`resource "aws_api_gateway_method" "m" {\n  http_method = "OPTIONS"\n  authorization = "NONE"\n}\n`))).toEqual([]);
    expect(ids(tf(`resource "aws_lb_listener" "l" {\n  port = 80\n  protocol = "HTTP"\n  default_action {\n    type = "redirect"\n  }\n}\n`))).toEqual([]);
    expect(ids(tf(`resource "aws_lb_listener" "l" {\n  port = 80\n  protocol = "HTTP"\n  default_action {\n    type = "forward"\n  }\n}\n`))).toEqual(["cloud-lb-plain-http"]);
    expect(ids(tf(`resource "aws_s3_bucket_policy" "p" {\n  policy = jsonencode({ Statement = [{ "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject" }] })\n}\n`))).toEqual(["cloud-resource-policy-public"]);
  });
  it("literal credentials, but not variables or references", () => {
    // The generic secret detector reports the same line and CWE, so the two fold into one finding.
    const lit = scan([tf(`resource "aws_db_instance" "d" {\n  password = "Sup3rS3cretPw"\n  storage_encrypted = true\n}\n`)]).files[0].indicators.filter(i => i.line === 2 && i.cwe === "CWE-798");
    expect(lit).toHaveLength(1);
    expect([lit[0].id, ...(lit[0].supportingDetectors ?? [])]).toContain(APPSEC_RULES["cloud-hardcoded-secret"].title);
    expect(ids(tf(`resource "aws_db_instance" "d" {\n  password = var.db_password\n  storage_encrypted = true\n}\n`), ["cloud-hardcoded-secret"])).toEqual([]);
  });
  it("GCP", () => {
    expect(ids(tf(`resource "google_storage_bucket_iam_member" "m" {\n  bucket = "b"\n  role = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n`))).toEqual(["cloud-storage-public"]);
    expect(hits(tf(`resource "google_compute_firewall" "f" {\n  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = ["22", "443"]\n  }\n}\n`))).toEqual(["cloud-open-admin-port@2"]);
    expect(ids(tf(`resource "google_compute_firewall" "f" {\n  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = ["443"]\n  }\n}\n`))).toEqual([]);
    expect(ids(tf(`resource "google_sql_database_instance" "s" {\n  settings {\n    ip_configuration {\n      ssl_mode = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"\n      authorized_networks {\n        value = "0.0.0.0/0"\n      }\n    }\n  }\n}\n`))).toEqual(["cloud-db-no-tls", "cloud-db-public"]);
  });
  it("Azure", () => {
    expect(ids(tf(`resource "azurerm_storage_account" "s" {\n  allow_nested_items_to_be_public = true\n  https_traffic_only_enabled = false\n  min_tls_version = "TLS1_0"\n}\n`))).toEqual(["cloud-storage-plain-http", "cloud-storage-public", "cloud-weak-tls"]);
    expect(ids(tf(`resource "azurerm_network_security_group" "n" {\n  security_rule {\n    direction = "Inbound"\n    access = "Allow"\n    source_address_prefix = "*"\n    destination_port_range = "3389"\n  }\n}\n`))).toEqual(["cloud-open-admin-port"]);
    expect(ids(tf(`resource "azurerm_network_security_group" "n" {\n  security_rule {\n    direction = "Inbound"\n    access = "Allow"\n    source_address_prefix = "10.0.0.0/8"\n    destination_port_range = "3389"\n  }\n}\n`))).toEqual([]);
    expect(ids(tf(`resource "azurerm_mssql_firewall_rule" "r" {\n  start_ip_address = "0.0.0.0"\n  end_ip_address = "255.255.255.255"\n}\n`))).toEqual(["cloud-db-public"]);
    expect(ids(tf(`resource "azurerm_mssql_firewall_rule" "r" {\n  start_ip_address = "0.0.0.0"\n  end_ip_address = "0.0.0.0"\n}\n`))).toEqual([]);
  });
});

describe("cloud posture: CloudFormation, ARM, Bicep, Serverless", () => {
  const CFN = `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      PubliclyAccessible: true
      MasterUserPassword: hunter2hunter2
  Db2:
    Type: AWS::RDS::DBInstance
    Properties:
      StorageEncrypted: true
      MasterUserPassword: !Ref DbPassword
  Admin:
    Type: AWS::IAM::Role
    Properties:
      Policies:
        - PolicyName: all
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: "*"
                Resource: "*"
  Url:
    Type: AWS::Lambda::Url
    Properties:
      AuthType: NONE
`;
  it("YAML template: every rule on its exact line, intrinsics are not literals", () => {
    expect(hits({ path: "infra/template.yaml", content: CFN })).toEqual([
      "cloud-db-public@24", "cloud-db-unencrypted@21", "cloud-function-url-no-auth@44", "cloud-hardcoded-secret@25",
      "cloud-iam-admin-wildcard@39", "cloud-open-admin-port@16", "cloud-storage-public-access-block-disabled@8", "cloud-storage-public@6",
    ]);
  });
  it("JSON template", () => {
    const json = JSON.stringify({ AWSTemplateFormatVersion: "2010-09-09", Resources: { T: { Type: "AWS::CloudTrail::Trail", Properties: { IsLogging: false } } } }, null, 2);
    expect(ids({ path: "cfn/stack.json", content: json })).toEqual(["cloud-logging-disabled"]);
  });
  it("ARM template and Bicep", () => {
    const arm = JSON.stringify({ $schema: "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", resources: [
      { type: "Microsoft.Storage/storageAccounts", name: "st", properties: { allowBlobPublicAccess: true, supportsHttpsTrafficOnly: false, minimumTlsVersion: "TLS1_0" } },
      { type: "Microsoft.Network/networkSecurityGroups", name: "nsg", properties: { securityRules: [{ name: "ssh", properties: { direction: "Inbound", access: "Allow", sourceAddressPrefix: "*", destinationPortRange: "22" } }] } },
    ] }, null, 2);
    expect(ids({ path: "arm/azuredeploy.json", content: arm })).toEqual(["cloud-open-admin-port", "cloud-storage-plain-http", "cloud-storage-public", "cloud-weak-tls"]);
    const bicep = `resource st 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  properties: {\n    allowBlobPublicAccess: true\n    minimumTlsVersion: 'TLS1_1'\n  }\n}\n`;
    expect(hits({ path: "infra/main.bicep", content: bicep })).toEqual(["cloud-storage-public@3", "cloud-weak-tls@4"]);
  });
  it("Serverless: admin IAM and literal secrets; ${ssm:} references are fine", () => {
    const sls = `service: api\nprovider:\n  name: aws\n  environment:\n    STRIPE_SECRET_KEY: sk_not_a_real_value_123\n    DB_PASSWORD: \${ssm:/db/pw}\n  iam:\n    role:\n      statements:\n        - Effect: Allow\n          Action: "*"\n          Resource: "*"\nfunctions:\n  hello:\n    handler: h.hello\n`;
    expect(hits({ path: "serverless.yml", content: sls })).toEqual(["cloud-hardcoded-secret@5", "cloud-iam-admin-wildcard@11"]);
  });
});

describe("container hardening", () => {
  it("end-of-life base images, judged by date", () => {
    const now = new Date("2026-09-29");
    expect(eolOf("node:16-alpine", now)).toMatchObject({ product: "node", version: "16" });
    expect(eolOf("python:3.10-slim", now)).toBeNull();              // supported until 2026-10-31
    expect(eolOf("python:3.10-slim", new Date("2026-11-15"))).toMatchObject({ version: "3.10" });
    expect(eolOf("node:22-buster", now)).toMatchObject({ product: "debian", version: "buster" });
    expect(eolOf("ubuntu:18.04", now)).toMatchObject({ product: "ubuntu" });
    expect(eolOf("node:22-alpine", now)).toBeNull();
    expect(eolOf("mycorp/node:16", now)).toMatchObject({ product: "node" });
    expect(eolOf("golang:1.22", now)).toBeNull();
  });
  it("Dockerfile: EOL base, insecure download (across line continuations), chmod 777", () => {
    const df = `FROM python:2.7\nRUN apt-get update && \\\n    curl -k https://x.example/i.sh -o /i.sh\nRUN chmod -R 777 /app\nUSER app\n`;
    expect(hits({ path: "Dockerfile", content: df })).toEqual(["container-eol-base-image@1", "container-insecure-download@2", "container-world-writable@4"]);
    expect(ids({ path: "Dockerfile", content: `FROM node:22-alpine\nRUN curl -fsSL https://x.example/a -o a\nUSER node\n` })).toEqual([]);
  });
  it("Compose: seccomp/apparmor unconfined, datastore ports on all interfaces (loopback is fine)", () => {
    const compose = `services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n  cache:\n    image: redis:7\n    ports:\n      - "127.0.0.1:6379:6379"\n  app:\n    image: app:1\n    security_opt:\n      - seccomp:unconfined\n    ports:\n      - "8080:8080"\n`;
    expect(hits({ path: "docker-compose.yml", content: compose })).toEqual(["container-compose-exposed-datastore@5", "container-compose-security-opt-disabled@13"]);
  });
});

describe("API security", () => {
  const spec = (body: string) => ({ path: "api/openapi.yaml", content: `openapi: 3.0.3\ninfo: { title: t, version: "1" }\n${body}` });
  it("operations without auth when the spec defines auth; security: [] and [{}] are intentional opt-outs", () => {
    const s = spec(`components:\n  securitySchemes:\n    bearer: { type: http, scheme: bearer }\npaths:\n  /users:\n    get:\n      security:\n        - bearer: []\n  /health:\n    get:\n      security: []\n  /maybe:\n    get:\n      security:\n        - {}\n  /admin:\n    delete:\n      responses: {}\n`);
    // /users is secured, /health explicitly public, /maybe makes auth optional; /admin declares nothing.
    expect(hits(s)).toEqual(["api-spec-unauthenticated-operation@19"]);
    const withGlobal = spec(`components:\n  securitySchemes:\n    bearer: { type: http, scheme: bearer }\nsecurity:\n  - bearer: []\npaths:\n  /admin:\n    delete:\n      responses: {}\n`);
    expect(hits(withGlobal)).toEqual([]);
  });
  it("a spec with no authentication anywhere is reported once", () => {
    const r = scan([spec(`paths:\n  /a:\n    get: {}\n    post: {}\n  /b:\n    delete: {}\n`)]).files[0].indicators.filter(i => i.id === "api-spec-unauthenticated-operation");
    expect(r).toHaveLength(1);
    expect(r[0].severity).toBe("high");
  });
  it("http servers, Basic, API key in query, implicit flow, credentials in query params", () => {
    const s = spec(`servers:\n  - url: http://api.example.com\n  - url: http://localhost:8080\ncomponents:\n  securitySchemes:\n    basic: { type: http, scheme: basic }\n    key:\n      type: apiKey\n      in: query\n      name: api_key\n    oauth:\n      type: oauth2\n      flows:\n        implicit:\n          authorizationUrl: https://x\n          scopes: {}\nsecurity:\n  - basic: []\npaths:\n  /login:\n    get:\n      parameters:\n        - name: password\n          in: query\n`);
    expect(ids(s)).toEqual(["api-spec-basic-auth", "api-spec-insecure-server", "api-spec-key-in-query", "api-spec-oauth-implicit", "api-spec-sensitive-query-param"]);
  });
});

describe("API endpoint inventory and auth consistency", () => {
  it("Express: per-route and app.use() auth; a write missing the auth its siblings have", () => {
    const src = `const router = express.Router();\nrouter.get("/users", requireUser, list);\nrouter.get("/users/:id", requireUser, show);\nrouter.post("/users", create);\nrouter.post("/login", login);\n`;
    const eps = extractEndpoints("src/routes/users.ts", src);
    expect(eps.map(e => `${e.method} ${e.path} ${e.auth}`)).toEqual(["GET /users required", "GET /users/:id required", "POST /users none", "POST /login none"]);
    expect(inconsistentAuth(eps).map(e => e.path)).toEqual(["/users"]);            // /login is a public path
    expect(hits({ path: "src/routes/users.ts", content: src })).toEqual(["api-endpoint-missing-auth@4"]);
    const global = `const router = express.Router();\nrouter.use(authenticate);\nrouter.get("/a", a);\nrouter.post("/b", b);\n`;
    expect(extractEndpoints("r.ts", global).every(e => e.auth === "required")).toBe(true);
  });
  it("statements without semicolons; path-scoped app.use; names that merely contain 'auth' are not auth", () => {
    const src = `app.use(security.updateAuthenticatedUsers())\napp.use('/rest/basket', security.isAuthorized())\napp.get('/rest/basket/:id', basket())\napp.post('/rest/basket/:id/checkout', order())\napp.get('/rest/products/search', search())\napp.post('/rest/feedback', utils.asyncHandler(createFeedback()))\n`;
    expect(extractEndpoints("server.ts", src).map(e => `${e.method} ${e.path} ${e.auth}`)).toEqual([
      "GET /rest/basket/:id required", "POST /rest/basket/:id/checkout required", "GET /rest/products/search none", "POST /rest/feedback none",
    ]);
    // Mostly public (2 protected vs 2 open): an open write here is the file's normal, not a forgotten check.
    expect(inconsistentAuth(extractEndpoints("server.ts", src))).toEqual([]);
    // An inline handler is judged by what it calls, not by auth-looking names inside it.
    const reads = `router.post("/notes", (req, res) => { const auth = req.headers.authorization; db.save(auth) })\n`;
    expect(extractEndpoints("notes.ts", reads)[0].auth).toBe("none");
    const checks = `router.post("/notes", (req, res) => { if (!req.isAuthenticated()) return res.sendStatus(401); db.save(req.body) })\n`;
    expect(extractEndpoints("notes.ts", checks)[0].auth).toBe("required");
  });
  it("Go: a wrapped handler (crAPI's middlewares.SetMiddlewareAuthentication); a public landing path is never flagged", () => {
    const src = `r.HandleFunc("/community/home", controllers.Home).Methods("GET")\nr.HandleFunc("/community/api/v2/community/posts/{postID}", middlewares.SetMiddlewareAuthentication(s.GetPost)).Methods("GET")\nr.HandleFunc("/community/api/v2/community/posts/recent", middlewares.SetMiddlewareAuthentication(s.Recent)).Methods("GET")\n`;
    const eps = extractEndpoints("routes.go", src);
    expect(eps.map(e => e.auth)).toEqual(["none", "required", "required"]);
    expect(inconsistentAuth(eps)).toEqual([]);
  });
  it("route-shaped text inside a string (sample code, docs) is not an endpoint", () => {
    const src = "const SAMPLE = `const router = express.Router();\\nrouter.get(\"/a\", requireUser, a);\\nrouter.delete(\"/a/:id\", del);\\n`;\n";
    expect(extractEndpoints("page.tsx", src)).toEqual([]);
  });
  it("public reads next to protected writes are not flagged", () => {
    const src = `app.get("/posts", list);\napp.get("/posts/:id", show);\napp.post("/posts", auth, create);\napp.delete("/posts/:id", auth, remove);\n`;
    expect(ids({ path: "src/posts.js", content: src })).toEqual([]);
  });
  it("Flask/FastAPI, Spring, ASP.NET, Go, Laravel", () => {
    const flask = `@app.route("/a", methods=["POST"])\n@login_required\ndef a():\n    pass\n\n@app.route("/b", methods=["POST"])\ndef b():\n    pass\n`;
    expect(extractEndpoints("app.py", flask).map(e => e.auth)).toEqual(["required", "none"]);
    const fastapi = `@router.get("/me")\nasync def me(user = Depends(get_current_user)):\n    return user\n`;
    expect(extractEndpoints("api.py", fastapi)[0]).toMatchObject({ method: "GET", auth: "required" });
    const spring = `@RestController\n@RequestMapping("/api")\npublic class C {\n  @PreAuthorize("hasRole('ADMIN')")\n  @DeleteMapping("/users/{id}")\n  public void del() {}\n  @PostMapping("/users")\n  public void add() {}\n}\n`;
    expect(extractEndpoints("C.java", spring).map(e => `${e.method} ${e.path} ${e.auth}`)).toEqual(["DELETE /api/users/{id} required", "POST /api/users none"]);
    const cs = `[ApiController]\n[Route("api/[controller]")]\n[Authorize]\npublic class UsersController : ControllerBase {\n  [HttpGet]\n  public IActionResult List() => Ok();\n  [AllowAnonymous]\n  [HttpPost("register")]\n  public IActionResult Reg() => Ok();\n}\n`;
    expect(extractEndpoints("UsersController.cs", cs).map(e => `${e.method} ${e.path} ${e.auth}`)).toEqual(["GET /api/users required", "POST /api/users/register public"]);
    const go = `admin := r.Group("/admin", AuthRequired())\nadmin.POST("/users", create)\nr.GET("/ping", ping)\n`;
    expect(extractEndpoints("main.go", go).map(e => `${e.method} ${e.path} ${e.auth}`)).toEqual(["POST /users required", "GET /ping none"]);
    const php = `<?php\nRoute::middleware(['auth:sanctum'])->group(function () {\n  Route::post('/orders', [O::class, 'store']);\n});\nRoute::get('/products', [P::class, 'index']);\n`;
    expect(extractEndpoints("routes/api.php", php).map(e => `${e.method} ${e.path} ${e.auth}`)).toEqual(["POST /orders required", "GET /products none"]);
  });
  it("Next.js App Router route handlers", () => {
    const src = `export async function GET() { return Response.json([]); }\nexport async function POST(req: Request) {\n  const session = await getServerSession();\n  return Response.json({});\n}\n`;
    expect(extractEndpoints("src/app/api/items/[id]/route.ts", src).map(e => `${e.method} ${e.path} ${e.auth}`)).toEqual(["GET /api/items/:id none", "POST /api/items/:id required"]);
  });
});

describe("API security report", () => {
  it("inventories code and spec endpoints, flags inconsistent auth, collects findings, orders flagged first", () => {
    const r = buildApiSecurityReport([{ repo: "acme/api", scan_id: "s", files: [
      { file_path: "src/routes/orders.ts", content: `const router = express.Router();\nrouter.get("/orders", requireUser, list);\nrouter.post("/orders", requireUser, create);\nrouter.delete("/orders/:id", remove);\n` },
      { file_path: "api/openapi.yaml", content: `openapi: 3.0.3\ninfo: { title: t, version: "1" }\ncomponents:\n  securitySchemes:\n    key: { type: apiKey, in: query, name: k }\npaths:\n  /a:\n    get:\n      security:\n        - key: []\n  /b:\n    post: {}\n` },
      { file_path: "README.md", content: "router.post(\"/x\", y)" },
    ] }]);
    expect(r.counts).toMatchObject({ endpoints: 5, authRequired: 3, noAuthVisible: 2, flagged: 2, specs: 1 });
    expect(r.endpoints.slice(0, 2).every(e => e.flagged)).toBe(true);
    expect(r.endpoints.find(e => e.path === "/orders/:id")).toMatchObject({ source: "code", flagged: true });
    expect(r.endpoints.find(e => e.path === "/b")).toMatchObject({ source: "spec", framework: "openapi", flagged: true });
    expect(r.findings.map(f => f.id).sort()).toEqual(["api-endpoint-missing-auth", "api-spec-key-in-query", "api-spec-unauthenticated-operation"]);
    expect(r.findings[0].severity).toBe("high");
    expect(r.findings.every(f => f.fix.length > 0)).toBe(true);
  });
  it("empty and missing content", () => {
    expect(buildApiSecurityReport([]).counts.endpoints).toBe(0);
    expect(buildApiSecurityReport([{ repo: "r", scan_id: "s", files: [{ file_path: "a.ts", content: null }] }]).endpoints).toEqual([]);
  });
});

describe("intake and catalog", () => {
  it("cloud templates and API specs are fetched; arbitrary YAML/JSON is not", () => {
    for (const p of ["infra/main.bicep", "template.yaml", "stacks/network.yml", "cfn/db.json", "serverless.yml", "api/openapi.yaml", "docs/swagger.json", "arm/azuredeploy.json", "x.template"]) expect(isScannablePath(p)).toBe(true);
    for (const p of [".github/workflows/ci.yml", "package-lock.json", "tsconfig.json", "config/app.yaml"]) expect(isScannablePath(p)).toBe(false);
  });
  it("every rule has a catalog title, a CWE, and a fix", () => {
    for (const [id, rule] of Object.entries(APPSEC_RULES)) {
      expect(findingMeta(id).title).toBe(rule.title);
      expect(cweFor(id)?.id).toBe(rule.cwe);
      expect(rule.fix.description.length).toBeGreaterThan(10);
    }
  });
});
