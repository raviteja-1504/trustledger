/**
 * Cloud security posture from the repository: the cloud resources a repo DEFINES, checked before they
 * exist. No cloud credentials are involved -- this reads infrastructure code only.
 *
 *  - Terraform (AWS, GCP, Azure) -- adds what iacTerraform.ts doesn't cover (it keeps its own rules: public
 *    S3 ACL, open AWS security groups, S3/RDS encryption, IAM wildcards, public RDS).
 *  - AWS CloudFormation / SAM (YAML or JSON), per resource `Type`.
 *  - Azure Resource Manager templates (JSON) and Bicep.
 *  - Serverless Framework (serverless.yml).
 *
 * Every finding names the resource and points at the offending line.
 */
import type { ScanIndicator } from "../scanner";
import { appsecHit } from "../appsecRules";
import { extractHclResourceBlocks } from "../iacTerraform";
import { parseConfigDocuments, get, getCI, path, str, bool, items, strings, entries, entryLine, walkMaps, type CNode } from "./configTree";

/** SSH, RDP, Docker API and common databases/caches/search engines. */
const ADMIN_PORTS = [22, 3389, 2375, 2376, 3306, 5432, 1433, 1521, 6379, 27017, 9200, 9300, 5984, 11211, 5601];
const PORT_NAMES: Record<number, string> = { 22: "SSH", 3389: "RDP", 2375: "Docker API", 2376: "Docker API", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 9300: "Elasticsearch", 5984: "CouchDB", 11211: "Memcached", 5601: "Kibana" };
const OPEN_SOURCES = new Set(["0.0.0.0/0", "::/0", "*", "internet", "any"]);

/** Admin ports inside a port range; `all` for an unbounded range. */
function adminPortsIn(from: number, to: number): number[] {
  if (Number.isNaN(from) || Number.isNaN(to)) return [];
  return ADMIN_PORTS.filter(p => p >= from && p <= to);
}
function portsFromSpec(spec: string): number[] {
  const s = spec.trim();
  if (s === "*" || s === "-1" || s === "") return ADMIN_PORTS;
  const m = /^(\d+)(?:\s*-\s*(\d+))?$/.exec(s);
  return m ? adminPortsIn(Number(m[1]), Number(m[2] ?? m[1])) : [];
}
const describePorts = (ports: number[]) =>
  ports.length === ADMIN_PORTS.length ? "all ports" : ports.map(p => `${p} (${PORT_NAMES[p]})`).join(", ");

const SECRET_ATTR_RE = /^(?:master_?password|admin_?password|password|db_?password|secret_?key|access_?key|client_?secret|secret|api_?key|auth_?token|token)$/i;

// ── Terraform ────────────────────────────────────────────────────────────────

interface Attr { value: string; line: number }

/** `name = value` attributes directly inside lines[start..end] (nested blocks included -- callers scope). */
function attrs(lines: string[], start: number, end: number, name: string): Attr[] {
  const re = new RegExp(`^\\s*${name}\\s*=\\s*(.+?)\\s*$`);
  const out: Attr[] = [];
  for (let j = start; j <= end; j++) {
    const m = re.exec(lines[j]);
    if (m) out.push({ value: m[1].replace(/\s+#.*$|\s+\/\/.*$/, ""), line: j + 1 });
  }
  return out;
}
const unq = (v: string) => v.replace(/^"(.*)"$/, "$1");
const isLiteralString = (v: string) => /^"[^"$]*"$/.test(v) && v.length > 2;

/** `header {` sub-blocks (by brace depth) inside a range. */
function subBlocks(lines: string[], start: number, end: number, header: RegExp): Array<{ start: number; end: number }> {
  const out: Array<{ start: number; end: number }> = [];
  for (let i = start; i <= end; i++) {
    if (!header.test(lines[i])) continue;
    let depth = 0;
    for (let j = i; j <= end; j++) {
      for (const ch of lines[j]) { if (ch === "{") depth++; else if (ch === "}") depth--; }
      if (depth === 0) { out.push({ start: i, end: j }); i = j; break; }
    }
  }
  return out;
}

function listValues(v: string): string[] {
  return (v.match(/"([^"]*)"/g) ?? []).map(unq);
}

export function scanTerraformCloud(content: string): ScanIndicator[] {
  const lines = content.split("\n");
  const out: ScanIndicator[] = [];
  const blocks = (type: string) => extractHclResourceBlocks(lines, type);
  const first = (b: { start: number; end: number }, name: string) => attrs(lines, b.start, b.end, name)[0];

  for (const b of blocks("aws_s3_bucket_public_access_block")) {
    for (const k of ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]) {
      const a = first(b, k);
      if (a && a.value === "false") out.push(appsecHit("cloud-storage-public-access-block-disabled", a.line, `Public access block '${b.name}' sets ${k} = false.`, { confidence: 90 }));
    }
  }

  const PRINCIPAL_STAR_RE = /"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*"\*"\s*\})|\bidentifiers\s*=\s*\[\s*"\*"\s*\]/;
  for (const type of ["aws_s3_bucket_policy", "aws_sqs_queue_policy", "aws_sns_topic_policy", "aws_kms_key", "aws_ecr_repository_policy"]) {
    for (const b of blocks(type)) {
      const body = lines.slice(b.start, b.end + 1);
      if (body.some(l => /"Condition"|\bcondition\s*\{/.test(l)) || body.some(l => /"Effect"\s*:\s*"Deny"|effect\s*=\s*"Deny"/.test(l))) continue;
      const idx = body.findIndex(l => PRINCIPAL_STAR_RE.test(l));
      if (idx >= 0) out.push(appsecHit("cloud-resource-policy-public", b.start + idx + 1, `${type} '${b.name}' allows Principal '*' with no condition.`, { confidence: 80 }));
    }
  }

  for (const b of blocks("aws_ebs_volume")) {
    const a = first(b, "encrypted");
    if (a?.value === "false") out.push(appsecHit("cloud-disk-unencrypted", a.line, `EBS volume '${b.name}' sets encrypted = false.`, { confidence: 90 }));
  }
  for (const b of blocks("aws_instance")) {
    for (const sb of subBlocks(lines, b.start, b.end, /^\s*(?:root_block_device|ebs_block_device)\s*\{/)) {
      const a = attrs(lines, sb.start, sb.end, "encrypted")[0];
      if (a?.value === "false") out.push(appsecHit("cloud-disk-unencrypted", a.line, `Instance '${b.name}' has a block device with encrypted = false.`, { confidence: 90 }));
    }
  }
  for (const b of blocks("aws_cloudtrail")) {
    const a = first(b, "enable_logging");
    if (a?.value === "false") out.push(appsecHit("cloud-logging-disabled", a.line, `CloudTrail '${b.name}' sets enable_logging = false.`, { confidence: 90 }));
  }
  for (const b of blocks("aws_kms_key")) {
    const spec = first(b, "customer_master_key_spec") ?? first(b, "key_spec");
    if (spec && unq(spec.value) !== "SYMMETRIC_DEFAULT") continue;          // rotation only applies to symmetric keys
    const a = first(b, "enable_key_rotation");
    if (!a || a.value === "false") out.push(appsecHit("cloud-kms-no-rotation", a?.line ?? b.start + 1, `KMS key '${b.name}' does not enable automatic rotation.`, { confidence: 80 }));
  }
  for (const b of blocks("aws_lambda_function_url")) {
    const a = first(b, "authorization_type");
    if (a && unq(a.value) === "NONE") out.push(appsecHit("cloud-function-url-no-auth", a.line, `Lambda function URL '${b.name}' has authorization_type = "NONE".`, { confidence: 90 }));
  }
  for (const b of blocks("aws_api_gateway_method")) {
    const a = first(b, "authorization");
    const method = first(b, "http_method");
    if (a && unq(a.value) === "NONE" && unq(method?.value ?? "") !== "OPTIONS") {
      out.push(appsecHit("cloud-api-no-auth", a.line, `API Gateway method '${b.name}' has authorization = "NONE".`, { confidence: 75 }));
    }
  }
  for (const b of blocks("aws_apigatewayv2_route")) {
    const a = first(b, "authorization_type");
    if (a && unq(a.value) === "NONE") out.push(appsecHit("cloud-api-no-auth", a.line, `API Gateway route '${b.name}' has authorization_type = "NONE".`, { confidence: 75 }));
  }
  for (const type of ["aws_lb_listener", "aws_alb_listener"]) {
    for (const b of blocks(type)) {
      const p = first(b, "protocol");
      if (!p || unq(p.value) !== "HTTP") continue;
      if (lines.slice(b.start, b.end + 1).some(l => /type\s*=\s*"redirect"/.test(l))) continue;
      out.push(appsecHit("cloud-lb-plain-http", p.line, `Listener '${b.name}' serves HTTP without redirecting to HTTPS.`, { confidence: 80 }));
    }
  }

  // Literal credentials in resources and providers.
  const HEADER_RE = /^\s*(?:resource|provider|module)\s+"/;
  for (let i = 0; i < lines.length; i++) {
    if (!HEADER_RE.test(lines[i])) continue;
    const m = /^\s*(\w+)\s+"([\w-]+)"(?:\s+"([\w-]+)")?/.exec(lines[i]);
    let depth = 0;
    let end = i;
    for (let j = i; j < lines.length; j++) {
      for (const ch of lines[j]) { if (ch === "{") depth++; else if (ch === "}") depth--; }
      end = j;
      if (depth === 0) break;
    }
    for (let j = i; j <= end; j++) {
      const a = /^\s*([\w]+)\s*=\s*("[^"]*")\s*$/.exec(lines[j]);
      if (!a || !SECRET_ATTR_RE.test(a[1]) || !isLiteralString(a[2])) continue;
      const v = unq(a[2]);
      if (/^(?:changeme|placeholder|example|xxx+|\*+|todo)$/i.test(v) || v.length < 6) continue;
      out.push(appsecHit("cloud-hardcoded-secret", j + 1, `${m?.[1] ?? "block"} '${m?.[3] ?? m?.[2] ?? "?"}' sets ${a[1]} to a literal value.`, { confidence: 85 }));
    }
    i = end;
  }

  // GCP
  for (const type of ["google_storage_bucket_iam_member", "google_storage_bucket_iam_binding", "google_storage_bucket_access_control", "google_storage_default_object_access_control"]) {
    for (const b of blocks(type)) {
      for (const a of [...attrs(lines, b.start, b.end, "member"), ...attrs(lines, b.start, b.end, "members"), ...attrs(lines, b.start, b.end, "entity")]) {
        if (/allUsers|allAuthenticatedUsers/.test(a.value)) out.push(appsecHit("cloud-storage-public", a.line, `${type} '${b.name}' grants access to ${/allUsers/.test(a.value) ? "allUsers (anyone)" : "allAuthenticatedUsers (any Google account)"}.`, { confidence: 90 }));
      }
    }
  }
  for (const b of blocks("google_compute_firewall")) {
    const dir = first(b, "direction");
    if (dir && unq(dir.value) === "EGRESS") continue;
    const src = first(b, "source_ranges");
    if (!src || !listValues(src.value).some(v => OPEN_SOURCES.has(v.toLowerCase()))) continue;
    const ports = subBlocks(lines, b.start, b.end, /^\s*allow\s*\{/).flatMap(sb => {
      const ps = attrs(lines, sb.start, sb.end, "ports")[0];
      return ps ? listValues(ps.value).flatMap(portsFromSpec) : ADMIN_PORTS;
    });
    const uniq = [...new Set(ports)];
    if (uniq.length) out.push(appsecHit("cloud-open-admin-port", src.line, `Firewall '${b.name}' allows 0.0.0.0/0 to ${describePorts(uniq)}.`, { confidence: 85 }));
  }
  for (const b of blocks("google_sql_database_instance")) {
    for (const sb of subBlocks(lines, b.start, b.end, /^\s*authorized_networks\s*\{/)) {
      const v = attrs(lines, sb.start, sb.end, "value")[0];
      if (v && OPEN_SOURCES.has(unq(v.value))) out.push(appsecHit("cloud-db-public", v.line, `Cloud SQL instance '${b.name}' authorizes ${unq(v.value)}.`, { confidence: 90 }));
    }
    const ssl = first(b, "ssl_mode");
    const req = first(b, "require_ssl");
    if (ssl && unq(ssl.value) === "ALLOW_UNENCRYPTED_AND_ENCRYPTED") out.push(appsecHit("cloud-db-no-tls", ssl.line, `Cloud SQL instance '${b.name}' allows unencrypted connections.`, { confidence: 85 }));
    else if (req?.value === "false") out.push(appsecHit("cloud-db-no-tls", req.line, `Cloud SQL instance '${b.name}' sets require_ssl = false.`, { confidence: 85 }));
  }

  // Azure
  for (const b of blocks("azurerm_storage_account")) {
    for (const k of ["allow_nested_items_to_be_public", "allow_blob_public_access"]) {
      const a = first(b, k);
      if (a?.value === "true") out.push(appsecHit("cloud-storage-public", a.line, `Storage account '${b.name}' sets ${k} = true, allowing anonymous access to blob containers.`, { confidence: 85, severity: "high" }));
    }
    for (const k of ["https_traffic_only_enabled", "enable_https_traffic_only"]) {
      const a = first(b, k);
      if (a?.value === "false") out.push(appsecHit("cloud-storage-plain-http", a.line, `Storage account '${b.name}' sets ${k} = false.`, { confidence: 90 }));
    }
  }
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*(min_tls_version|minimum_tls_version|ssl_minimal_tls_version_enforced)\s*=\s*"(TLS1_0|TLS1_1|1\.0|1\.1|TLS1_0_OR_HIGHER)"/.exec(lines[i]);
    if (m) out.push(appsecHit("cloud-weak-tls", i + 1, `${m[1]} = "${m[2]}" accepts deprecated TLS versions.`, { confidence: 90 }));
  }
  const nsgRules = [
    ...blocks("azurerm_network_security_rule").map(b => ({ ...b, label: b.name })),
    ...blocks("azurerm_network_security_group").flatMap(b => subBlocks(lines, b.start, b.end, /^\s*security_rule\s*\{/).map(sb => ({ ...sb, name: b.name, label: b.name }))),
  ];
  for (const rule of nsgRules) {
    const get1 = (n: string) => attrs(lines, rule.start, rule.end, n)[0];
    if (unq(get1("direction")?.value ?? "") !== "Inbound" || unq(get1("access")?.value ?? "") !== "Allow") continue;
    const src = get1("source_address_prefix");
    const srcs = [...(src ? [unq(src.value)] : []), ...listValues(get1("source_address_prefixes")?.value ?? "")];
    if (!srcs.some(s => OPEN_SOURCES.has(s.toLowerCase()))) continue;
    const portSpecs = [...(get1("destination_port_range") ? [unq(get1("destination_port_range")!.value)] : []), ...listValues(get1("destination_port_ranges")?.value ?? "")];
    const ports = [...new Set(portSpecs.flatMap(portsFromSpec))];
    if (ports.length) out.push(appsecHit("cloud-open-admin-port", (src ?? get1("access"))!.line, `NSG rule in '${rule.label}' allows ${srcs.join(", ")} to ${describePorts(ports)}.`, { confidence: 85 }));
  }
  for (const type of ["azurerm_mssql_firewall_rule", "azurerm_sql_firewall_rule", "azurerm_postgresql_firewall_rule", "azurerm_postgresql_flexible_server_firewall_rule", "azurerm_mysql_firewall_rule", "azurerm_mysql_flexible_server_firewall_rule"]) {
    for (const b of blocks(type)) {
      const s = first(b, "start_ip_address");
      const e = first(b, "end_ip_address");
      if (s && e && unq(s.value) === "0.0.0.0" && unq(e.value) === "255.255.255.255") {
        out.push(appsecHit("cloud-db-public", s.line, `Firewall rule '${b.name}' allows every IPv4 address to the database.`, { confidence: 90 }));
      }
    }
  }
  return out;
}

// ── CloudFormation / SAM ─────────────────────────────────────────────────────

export function isCloudFormation(content: string): boolean {
  return /AWSTemplateFormatVersion|Transform["']?\s*:\s*["']?AWS::Serverless/.test(content) ||
    (/(?:^|\n)\s*"?Resources"?\s*:/.test(content) && /"?Type"?\s*:\s*["']?AWS::[A-Za-z0-9]+::/.test(content));
}

/** An intrinsic (Ref, Fn::*, !Tag, dynamic reference) rather than a literal. */
function isIntrinsic(n: CNode | undefined): boolean {
  if (!n) return false;
  if (n.kind === "map") return n.entries.some(e => e.key === "Ref" || e.key.startsWith("Fn::"));
  if (n.kind === "scalar") return n.value.startsWith("!") || n.value.includes("{{resolve:") || n.value.includes("${");
  return false;
}

function policyStatements(doc: CNode | undefined): CNode[] {
  return items(getCI(doc, "Statement"));
}

function cfnPublicPrincipal(st: CNode): boolean {
  const p = get(st, "Principal");
  return str(p) === "*" || strings(get(p, "AWS")).includes("*");
}

export function scanCloudFormation(content: string): ScanIndicator[] {
  if (!isCloudFormation(content)) return [];
  const out: ScanIndicator[] = [];
  for (const doc of parseConfigDocuments(content)) {
    for (const res of entries(get(doc, "Resources"))) {
      const type = str(get(res.node, "Type")) ?? "";
      const props = get(res.node, "Properties");
      const name = res.key;
      const line = (key: string) => entryLine(props, key) ?? res.line;
      const b = (key: string) => bool(get(props, key));

      if (type === "AWS::S3::Bucket") {
        const acl = str(get(props, "AccessControl"));
        if (acl === "PublicRead" || acl === "PublicReadWrite") out.push(appsecHit("cloud-storage-public", line("AccessControl"), `Bucket ${name} uses AccessControl: ${acl}.`, { confidence: 90 }));
        const pab = get(props, "PublicAccessBlockConfiguration");
        for (const e of entries(pab)) {
          if (bool(e.node) === false) out.push(appsecHit("cloud-storage-public-access-block-disabled", e.line, `Bucket ${name} sets ${e.key}: false.`, { confidence: 90 }));
        }
      }
      if (["AWS::S3::BucketPolicy", "AWS::SQS::QueuePolicy", "AWS::SNS::TopicPolicy", "AWS::KMS::Key", "AWS::ECR::Repository"].includes(type)) {
        const policy = get(props, "PolicyDocument") ?? get(props, "KeyPolicy") ?? get(props, "RepositoryPolicyText");
        for (const st of policyStatements(policy)) {
          if (str(get(st, "Effect")) !== "Allow" || get(st, "Condition") || !cfnPublicPrincipal(st)) continue;
          out.push(appsecHit("cloud-resource-policy-public", entryLine(st, "Principal") ?? st.line, `${type.split("::").pop()} ${name} allows Principal '*' with no condition.`, { confidence: 85 }));
        }
      }
      if (type === "AWS::EC2::SecurityGroup" || type === "AWS::EC2::SecurityGroupIngress") {
        const rules = type === "AWS::EC2::SecurityGroup" ? items(get(props, "SecurityGroupIngress")) : props ? [props] : [];
        for (const rule of rules) {
          const cidr = str(get(rule, "CidrIp")) ?? str(get(rule, "CidrIpv6"));
          if (!cidr || !OPEN_SOURCES.has(cidr)) continue;
          const proto = str(get(rule, "IpProtocol")) ?? "";
          const from = Number(str(get(rule, "FromPort")) ?? "0");
          const to = Number(str(get(rule, "ToPort")) ?? String(from));
          const ports = proto === "-1" || proto === "all" ? ADMIN_PORTS : adminPortsIn(from, to);
          if (ports.length) out.push(appsecHit("cloud-open-admin-port", entryLine(rule, "CidrIp") ?? entryLine(rule, "CidrIpv6") ?? rule.line, `Security group ${name} allows ${cidr} to ${describePorts(ports)}.`, { confidence: 90 }));
        }
      }
      if (type === "AWS::RDS::DBInstance" || type === "AWS::RDS::DBCluster") {
        if (b("PubliclyAccessible") === true) out.push(appsecHit("cloud-db-public", line("PubliclyAccessible"), `${name} sets PubliclyAccessible: true.`, { confidence: 90 }));
        const enc = get(props, "StorageEncrypted");
        if (bool(enc) !== true && !isIntrinsic(enc) && !(type === "AWS::RDS::DBInstance" && get(props, "DBClusterIdentifier"))) {
          out.push(appsecHit("cloud-db-unencrypted", enc ? line("StorageEncrypted") : res.line, `${name} does not set StorageEncrypted: true.`, { confidence: 80 }));
        }
      }
      if (type === "AWS::EC2::Volume" && b("Encrypted") === false) out.push(appsecHit("cloud-disk-unencrypted", line("Encrypted"), `Volume ${name} sets Encrypted: false.`, { confidence: 90 }));
      if (type === "AWS::CloudTrail::Trail" && b("IsLogging") === false) out.push(appsecHit("cloud-logging-disabled", line("IsLogging"), `Trail ${name} sets IsLogging: false.`, { confidence: 90 }));
      if (type === "AWS::KMS::Key") {
        const spec = str(get(props, "KeySpec"));
        if ((!spec || spec === "SYMMETRIC_DEFAULT") && b("EnableKeyRotation") !== true && !isIntrinsic(get(props, "EnableKeyRotation"))) {
          out.push(appsecHit("cloud-kms-no-rotation", get(props, "EnableKeyRotation") ? line("EnableKeyRotation") : res.line, `KMS key ${name} does not enable rotation.`, { confidence: 80 }));
        }
      }
      if (type === "AWS::Lambda::Url" && str(get(props, "AuthType")) === "NONE") out.push(appsecHit("cloud-function-url-no-auth", line("AuthType"), `Function URL ${name} has AuthType: NONE.`, { confidence: 90 }));
      if (type === "AWS::Serverless::Function" && str(path(props, "FunctionUrlConfig", "AuthType")) === "NONE") {
        out.push(appsecHit("cloud-function-url-no-auth", entryLine(get(props, "FunctionUrlConfig"), "AuthType") ?? res.line, `Function ${name}'s URL has AuthType: NONE.`, { confidence: 90 }));
      }
      if (type === "AWS::ApiGateway::Method" && str(get(props, "AuthorizationType")) === "NONE" && str(get(props, "HttpMethod")) !== "OPTIONS") {
        out.push(appsecHit("cloud-api-no-auth", line("AuthorizationType"), `API method ${name} has AuthorizationType: NONE.`, { confidence: 75 }));
      }
      if (type === "AWS::ApiGatewayV2::Route" && str(get(props, "AuthorizationType")) === "NONE") {
        out.push(appsecHit("cloud-api-no-auth", line("AuthorizationType"), `API route ${name} has AuthorizationType: NONE.`, { confidence: 75 }));
      }
      if (type === "AWS::ElasticLoadBalancingV2::Listener" && str(get(props, "Protocol")) === "HTTP") {
        const redirects = items(get(props, "DefaultActions")).some(a => str(get(a, "Type")) === "redirect");
        if (!redirects) out.push(appsecHit("cloud-lb-plain-http", line("Protocol"), `Listener ${name} serves HTTP without redirecting to HTTPS.`, { confidence: 80 }));
      }
      if (type === "AWS::IAM::Policy" || type === "AWS::IAM::ManagedPolicy" || type === "AWS::IAM::Role" || type === "AWS::IAM::User" || type === "AWS::IAM::Group") {
        const docs = [get(props, "PolicyDocument"), ...items(get(props, "Policies")).map(p => get(p, "PolicyDocument"))];
        for (const st of docs.flatMap(policyStatements)) {
          if (str(get(st, "Effect")) !== "Allow") continue;
          const actions = strings(get(st, "Action"));
          const resources = strings(get(st, "Resource"));
          if ((actions.includes("*") || actions.includes("*:*")) && resources.includes("*")) {
            out.push(appsecHit("cloud-iam-admin-wildcard", entryLine(st, "Action") ?? st.line, `${name} allows Action '*' on Resource '*'.`, { confidence: 90 }));
          }
        }
      }
      // Literal credentials on any resource.
      for (const e of entries(props)) {
        if (!/^(?:MasterUserPassword|Password|DBPassword|AdminPassword|SecretString|AuthToken|ClientSecret|AccessKey|SecretKey)$/i.test(e.key)) continue;
        if (e.node.kind !== "scalar" || isIntrinsic(e.node) || e.node.value.length < 6) continue;
        out.push(appsecHit("cloud-hardcoded-secret", e.line, `${name} sets ${e.key} to a literal value.`, { confidence: 85 }));
      }
    }
  }
  return out;
}

// ── Azure Resource Manager (JSON) ────────────────────────────────────────────

export function isArmTemplate(content: string): boolean {
  return /"\$schema"\s*:\s*"https?:\/\/schema\.management\.azure\.com\/schemas\/[^"]*deploymentTemplate/i.test(content);
}

export function scanArmTemplate(content: string): ScanIndicator[] {
  if (!isArmTemplate(content)) return [];
  const out: ScanIndicator[] = [];
  for (const doc of parseConfigDocuments(content)) {
    walkMaps(doc, map => {
      const type = (str(getCI(map, "type")) ?? "").toLowerCase();
      const props = getCI(map, "properties");
      if (!type.startsWith("microsoft.") || props?.kind !== "map") return;
      const name = str(getCI(map, "name")) ?? type;
      const line = (k: string) => props.entries.find(e => e.key.toLowerCase() === k.toLowerCase())?.line ?? map.line;
      if (type === "microsoft.storage/storageaccounts") {
        if (bool(getCI(props, "allowBlobPublicAccess")) === true) out.push(appsecHit("cloud-storage-public", line("allowBlobPublicAccess"), `Storage account ${name} allows anonymous blob access.`, { confidence: 85, severity: "high" }));
        if (bool(getCI(props, "supportsHttpsTrafficOnly")) === false) out.push(appsecHit("cloud-storage-plain-http", line("supportsHttpsTrafficOnly"), `Storage account ${name} accepts HTTP.`, { confidence: 90 }));
      }
      const tls = str(getCI(props, "minimumTlsVersion")) ?? str(getCI(props, "minimalTlsVersion"));
      if (tls && /^(?:TLS1_0|TLS1_1|1\.0|1\.1)$/.test(tls)) out.push(appsecHit("cloud-weak-tls", line(getCI(props, "minimumTlsVersion") ? "minimumTlsVersion" : "minimalTlsVersion"), `${name} allows ${tls}.`, { confidence: 90 }));
      const rules = type === "microsoft.network/networksecuritygroups" ? items(getCI(props, "securityRules")).map(r => getCI(r, "properties"))
        : type === "microsoft.network/networksecuritygroups/securityrules" ? [props] : [];
      for (const rp of rules) {
        if (str(getCI(rp, "direction")) !== "Inbound" || str(getCI(rp, "access")) !== "Allow") continue;
        const srcs = [str(getCI(rp, "sourceAddressPrefix")) ?? "", ...strings(getCI(rp, "sourceAddressPrefixes"))];
        if (!srcs.some(s => OPEN_SOURCES.has(s.toLowerCase()))) continue;
        const ports = [...new Set([str(getCI(rp, "destinationPortRange")) ?? "", ...strings(getCI(rp, "destinationPortRanges"))].filter(Boolean).flatMap(portsFromSpec))];
        if (ports.length) out.push(appsecHit("cloud-open-admin-port", rp?.line ?? map.line, `NSG ${name} allows ${srcs.filter(Boolean).join(", ")} to ${describePorts(ports)}.`, { confidence: 85 }));
      }
      if (type.endsWith("/firewallrules") && str(getCI(props, "startIpAddress")) === "0.0.0.0" && str(getCI(props, "endIpAddress")) === "255.255.255.255") {
        out.push(appsecHit("cloud-db-public", line("startIpAddress"), `Firewall rule ${name} allows every IPv4 address.`, { confidence: 90 }));
      }
    });
  }
  return out;
}

// ── Bicep (line-level: its syntax is not YAML or JSON) ───────────────────────

export function scanBicep(content: string): ScanIndicator[] {
  const lines = content.split("\n");
  const out: ScanIndicator[] = [];
  lines.forEach((l, i) => {
    if (/^\s*allowBlobPublicAccess\s*:\s*true\b/.test(l)) out.push(appsecHit("cloud-storage-public", i + 1, "Storage account allows anonymous blob access (allowBlobPublicAccess: true).", { confidence: 85, severity: "high" }));
    if (/^\s*supportsHttpsTrafficOnly\s*:\s*false\b/.test(l)) out.push(appsecHit("cloud-storage-plain-http", i + 1, "Storage account accepts HTTP (supportsHttpsTrafficOnly: false).", { confidence: 90 }));
    const tls = /^\s*(minimumTlsVersion|minimalTlsVersion)\s*:\s*'(TLS1_0|TLS1_1|1\.0|1\.1)'/.exec(l);
    if (tls) out.push(appsecHit("cloud-weak-tls", i + 1, `${tls[1]}: '${tls[2]}' accepts deprecated TLS versions.`, { confidence: 90 }));
  });
  // NSG rules: an object that allows inbound from anywhere to an admin port.
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*sourceAddressPrefix\s*:\s*'(\*|Internet|0\.0\.0\.0\/0|Any)'/.test(lines[i])) continue;
    const win = lines.slice(Math.max(0, i - 12), Math.min(lines.length, i + 12)).join("\n");
    if (!/direction\s*:\s*'Inbound'/.test(win) || !/access\s*:\s*'Allow'/.test(win)) continue;
    const port = /destinationPortRange\s*:\s*'([^']*)'/.exec(win);
    const ports = port ? portsFromSpec(port[1]) : [];
    if (ports.length) out.push(appsecHit("cloud-open-admin-port", i + 1, `NSG rule allows inbound from anywhere to ${describePorts(ports)}.`, { confidence: 80 }));
  }
  lines.forEach((l, i) => {
    const m = /^\s*(administratorLoginPassword|adminPassword|password|clientSecret)\s*:\s*'([^']{6,})'/.exec(l);
    if (m && !m[2].includes("${")) out.push(appsecHit("cloud-hardcoded-secret", i + 1, `${m[1]} is a literal value.`, { confidence: 85 }));
  });
  return out;
}

// ── Serverless Framework ─────────────────────────────────────────────────────

export function isServerlessConfig(filePath: string, content: string): boolean {
  return /(?:^|\/)serverless\.ya?ml$/i.test(filePath) || (/^service\s*:/m.test(content) && /^provider\s*:/m.test(content) && /^functions\s*:/m.test(content));
}

export function scanServerless(content: string): ScanIndicator[] {
  const out: ScanIndicator[] = [];
  for (const doc of parseConfigDocuments(content)) {
    const provider = get(doc, "provider");
    const statements = [...items(get(provider, "iamRoleStatements")), ...items(path(provider, "iam", "role", "statements"))];
    for (const st of statements) {
      if (str(get(st, "Effect")) !== "Allow") continue;
      const actions = strings(get(st, "Action"));
      const resources = strings(get(st, "Resource"));
      if ((actions.includes("*") || actions.includes("*:*")) && resources.includes("*")) {
        out.push(appsecHit("cloud-iam-admin-wildcard", entryLine(st, "Action") ?? st.line, "The functions' IAM role allows Action '*' on Resource '*'.", { confidence: 90 }));
      }
    }
    const envBlocks = [get(provider, "environment"), ...entries(get(doc, "functions")).map(f => get(f.node, "environment"))];
    for (const env of envBlocks) {
      for (const e of entries(env)) {
        const v = str(e.node);
        if (!v || !/(?:PASS(?:WORD)?|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)/i.test(e.key)) continue;
        if (v.includes("${") || v.length < 6 || /^(?:true|false|\d+)$/i.test(v)) continue;
        out.push(appsecHit("cloud-hardcoded-secret", e.line, `Environment variable ${e.key} is a literal value in serverless.yml.`, { confidence: 85 }));
      }
    }
  }
  return out;
}
