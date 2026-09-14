/**
 * Dependency vulnerability/health scanning — shared between the client
 * (src/app/dependencies/page.tsx) and the server (api/dependencies/route.ts).
 *
 * There's no dependencies DB table; findings are derived by parsing scanned
 * file content (imports/manifests) against a known-package database. This
 * used to run ONLY in the browser, refetching every repo's latest scan and
 * re-parsing on every page load — expensive, and why the Sidebar badge could
 * only ever show a stale, session-cached number instead of a real one. This
 * module lets the server run the exact same derivation once and cache it.
 */

import { parsePackageJson, parseRequirementsTxt, parseGoMod } from "@/lib/depAnalysis";

// ── Types ──────────────────────────────────────────────────────────────────────

export type DepRisk       = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
export type DepType       = "vulnerable" | "unmaintained" | "hallucinated" | "typosquatting" | "outdated" | "transitive" | "safe";
export type LangEcosystem = "python" | "javascript" | "typescript" | "go" | "java" | "rust" | "ruby" | "csharp" | "php" | "unknown";
export type LicenseRisk   = "safe" | "review" | "block" | "unknown";

export interface DepFinding {
  id: string;
  package_name: string;
  version_used: string;
  latest_version?: string;
  ecosystem: LangEcosystem;
  manager: string;
  risk: DepRisk;
  type: DepType;
  repo: string;
  file_path: string;
  pr_number: number;
  scan_id: string;
  description: string;
  fix?: string;
  cve?: string;
  cvss?: number;
  cvss_vector?: string;
  exploit_public: boolean;
  exploit_detail?: string;
  ai_introduced: boolean;
  is_transitive: boolean;
  pulled_by?: string;
  license_spdx?: string;
  license_risk: LicenseRisk;
  license_note?: string;
  last_publish?: string;
  weekly_downloads?: string;
  is_archived: boolean;
  is_deprecated: boolean;
  health_score: number;
}

/** Minimal shape deriveFindings needs — deliberately narrower than the app's
 *  full ScanResult so the server doesn't need to fabricate unused fields. */
export interface ScanForDeps {
  repo: string;
  pr_number: number;
  scan_id: string;
  files: { file_path: string; content?: string | null; ai_percentage: number }[];
}

interface VulnEntry {
  risk: DepRisk;
  type: DepType;
  cve?: string;
  cvss?: number;
  cvss_vector?: string;
  exploit_public?: boolean;
  exploit_detail?: string;
  safeVersion?: string;
  description: string;
  fix?: string;
  license_spdx?: string;
  license_risk?: LicenseRisk;
  license_note?: string;
  last_publish?: string;
  weekly_downloads?: string;
  is_archived?: boolean;
  is_deprecated?: boolean;
  health_score?: number;
}

// ── Vulnerability + metadata database ─────────────────────────────────────────

export const VULN_DB: Record<string, VulnEntry> = {
  // ── Python ────────────────────────────────────────────────────────────────
  "requests":     { risk:"CRITICAL", type:"vulnerable",   cve:"CVE-2023-32681", cvss:6.1, safeVersion:"2.31.0", description:"Open redirect in requests < 2.31.0 allows attackers to redirect to arbitrary URLs via crafted Host headers.", fix:"pip install 'requests>=2.31.0'", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"85M", last_publish:"2024-05-20", health_score:95, exploit_public:false },
  "PyJWT":        { risk:"CRITICAL", type:"vulnerable",   cve:"CVE-2022-29217", cvss:7.5, safeVersion:"2.8.0",  description:"RSA signature verification bypass via HMAC key substitution. AI routinely generates jwt.decode() with 'none' algorithm accepted.", fix:"pip install 'PyJWT>=2.8.0'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"12M", last_publish:"2024-04-10", health_score:88, exploit_public:true, exploit_detail:"PoC published — token forgery trivial" },
  "pyjwt":        { risk:"CRITICAL", type:"vulnerable",   cve:"CVE-2022-29217", cvss:7.5, safeVersion:"2.8.0",  description:"Same as PyJWT (case-insensitive alias). JWT signature bypass.", fix:"pip install 'PyJWT>=2.8.0'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"12M", last_publish:"2024-04-10", health_score:88, exploit_public:true, exploit_detail:"PoC published — token forgery trivial" },
  "cryptography": { risk:"MEDIUM",   type:"vulnerable",   cve:"CVE-2023-49083", cvss:4.0, safeVersion:"41.0.6", description:"Memory corruption in certain OpenSSL calls in cryptography < 41.0.6. Upgrade recommended.", fix:"pip install 'cryptography>=41.0.6'", license_spdx:"Apache-2.0 OR BSD-3-Clause", license_risk:"safe", weekly_downloads:"8M", last_publish:"2024-06-10", health_score:90, exploit_public:false },
  "django":       { risk:"HIGH",     type:"vulnerable",   cve:"CVE-2023-36053", cvss:7.5, safeVersion:"4.2.4",  description:"ReDoS vulnerability in EmailValidator in Django < 4.2.4. AI frequently generates Django apps with pinned old versions.", fix:"pip install 'django>=4.2.4'", license_spdx:"BSD-3-Clause", license_risk:"safe", weekly_downloads:"7M", last_publish:"2024-04-03", health_score:92, exploit_public:false },
  "flask":        { risk:"MEDIUM",   type:"vulnerable",   cve:"CVE-2023-30861", cvss:7.5, safeVersion:"2.3.2",  description:"Cookie SameSite attribute not respected in Flask < 2.3.2, enabling CSRF attacks.", fix:"pip install 'flask>=2.3.2'", license_spdx:"BSD-3-Clause", license_risk:"safe", weekly_downloads:"5M", last_publish:"2024-03-28", health_score:88, exploit_public:false },
  "paramiko":     { risk:"HIGH",     type:"vulnerable",   cve:"CVE-2023-48795", cvss:5.9, safeVersion:"3.4.0",  description:"Terrapin attack — SSH handshake prefix truncation. AI SSH code commonly imports paramiko without pinning.", fix:"pip install 'paramiko>=3.4.0'", license_spdx:"LGPL-2.1", license_risk:"review", license_note:"LGPL — static linking requires open-sourcing. Dynamic linking is fine.", weekly_downloads:"2M", last_publish:"2024-02-14", health_score:82, exploit_public:true, exploit_detail:"Terrapin PoC widely available (2023)" },
  "psycopg2":     { risk:"LOW",      type:"outdated",     safeVersion:"2.9.9",  description:"Older psycopg2 misses performance and security backports.", fix:"pip install 'psycopg2>=2.9.9'", license_spdx:"LGPL-3.0", license_risk:"review", license_note:"LGPL — dynamic linking is fine for most deployments.", weekly_downloads:"4M", last_publish:"2024-01-20", health_score:78, exploit_public:false },
  "numpy":        { risk:"LOW",      type:"outdated",     safeVersion:"1.26.4", description:"Older numpy release misses security backports and performance improvements.", fix:"pip install 'numpy>=1.26.4'", license_spdx:"BSD-3-Clause", license_risk:"safe", weekly_downloads:"40M", last_publish:"2024-02-25", health_score:96, exploit_public:false },
  "pydantic":     { risk:"SAFE",     type:"safe",         description:"Up to date, actively maintained, no known vulnerabilities.", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"20M", last_publish:"2024-06-01", health_score:97, exploit_public:false },
  "sqlalchemy":   { risk:"LOW",      type:"safe",         description:"SQLAlchemy is safe — ensure parameterised queries via ORM, not raw SQL.", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"10M", last_publish:"2024-05-12", health_score:93, exploit_public:false },
  "ml-utils-fast":{ risk:"CRITICAL", type:"hallucinated", description:"Does NOT exist on PyPI. AI hallucinated this name — any published version executes arbitrary code on install.", fix:"Remove import. Use scikit-learn or numpy instead.", license_spdx:undefined, license_risk:"block", license_note:"Non-existent package — legal status unknown", is_archived:false, health_score:0, exploit_public:true, exploit_detail:"Zero-day supply chain risk — name squatting trivial" },
  "stripe-client":{ risk:"CRITICAL", type:"typosquatting", description:"Typosquatting the official 'stripe' library. Known malicious package containing a credential harvester.", fix:"Use official 'stripe' package: pip install stripe>=7.0.0", license_spdx:undefined, license_risk:"block", license_note:"Malicious — do not use", health_score:0, exploit_public:true, exploit_detail:"Active credential harvester confirmed in PyPI reports" },

  // ── JavaScript / TypeScript ───────────────────────────────────────────────
  "lodash":       { risk:"HIGH",    type:"vulnerable",   cve:"CVE-2021-23337", cvss:7.2, safeVersion:"4.17.21", description:"Command injection via template() in lodash < 4.17.21. AI consistently recommends this version.", fix:"npm install 'lodash@>=4.17.21'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"45M", last_publish:"2021-02-20", is_archived:false, is_deprecated:false, health_score:65, exploit_public:false, cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" },
  "axios":        { risk:"HIGH",    type:"vulnerable",   cve:"CVE-2021-3749",  cvss:7.5, safeVersion:"1.6.2",   description:"ReDoS in axios normaliseHeaders(). AI commonly suggests axios 0.x, which is outdated and vulnerable.", fix:"npm install 'axios@>=1.6.2'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"35M", last_publish:"2024-03-21", health_score:88, exploit_public:false },
  "jsonwebtoken": { risk:"CRITICAL", type:"vulnerable",  cve:"CVE-2022-23529", cvss:7.6, safeVersion:"9.0.0",   description:"Remote code execution via secretOrPublicKey misconfiguration. AI JWT code regularly misuses this library.", fix:"npm install 'jsonwebtoken@>=9.0.0'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"12M", last_publish:"2023-09-14", health_score:79, exploit_public:true, exploit_detail:"PoC exists for crafted header attack" },
  "express":      { risk:"MEDIUM",  type:"vulnerable",   cve:"CVE-2024-43796", cvss:5.0, safeVersion:"4.19.2",  description:"XSS via response.redirect() in express < 4.19.2.", fix:"npm install 'express@>=4.19.2'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"30M", last_publish:"2024-03-25", health_score:90, exploit_public:false },
  "moment":       { risk:"MEDIUM",  type:"unmaintained", description:"Moment.js is legacy and unmaintained since Sep 2022. AI still recommends it. Use date-fns or dayjs.", fix:"Replace with: npm install date-fns  OR  npm install dayjs", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"15M", last_publish:"2022-04-04", is_deprecated:true, health_score:30, exploit_public:false },
  "node-fetch":   { risk:"HIGH",    type:"vulnerable",   cve:"CVE-2022-0235",  cvss:6.1, safeVersion:"3.3.2",   description:"Open redirect in node-fetch < 2.6.7. Use native fetch (Node 18+) instead.", fix:"npm install 'node-fetch@>=3.3.2'  OR  use globalThis.fetch", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"20M", last_publish:"2023-12-21", health_score:72, exploit_public:false },
  "minimist":     { risk:"HIGH",    type:"vulnerable",   cve:"CVE-2021-44906", cvss:9.8, safeVersion:"1.2.6",   description:"Prototype pollution in minimist < 1.2.6. Common AI-introduced transitive dep.", fix:"npm install 'minimist@>=1.2.6'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"40M", last_publish:"2022-03-16", health_score:55, exploit_public:true, exploit_detail:"Widely exploited prototype pollution chain" },
  "colors":       { risk:"HIGH",    type:"unmaintained", description:"Maintainer intentionally published malicious versions (infinite loop). Blacklisted by many registries.", fix:"Replace with: npm install chalk  OR  npm install picocolors", license_spdx:"MIT", license_risk:"review", license_note:"Intentional sabotage history — avoid in production", is_deprecated:true, health_score:10, exploit_public:true, exploit_detail:"v1.4.44-liberty-2 is intentionally malicious" },
  "follow-redirects": { risk:"HIGH", type:"transitive",  cve:"CVE-2022-0536",  cvss:6.1, safeVersion:"1.15.4",  description:"Sensitive data exposure via HTTP redirect in follow-redirects (common axios transitive dep).", fix:"npm install 'follow-redirects@>=1.15.4'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"35M", last_publish:"2023-11-09", health_score:75, exploit_public:false },

  // ── Go ────────────────────────────────────────────────────────────────────
  "github.com/dgrijalva/jwt-go": { risk:"CRITICAL", type:"vulnerable", cve:"CVE-2020-26160", cvss:7.7, safeVersion:"github.com/golang-jwt/jwt/v5", description:"JWT audience claim not validated. This module is archived — AI still imports it.", fix:"Replace with: go get github.com/golang-jwt/jwt/v5", license_spdx:"MIT", license_risk:"safe", is_archived:true, health_score:0, exploit_public:true, exploit_detail:"Widely exploited for privilege escalation" },
  "github.com/gogo/protobuf":    { risk:"HIGH",     type:"vulnerable", cve:"CVE-2021-3121",  cvss:8.6, safeVersion:"1.3.2",  description:"Panic/RCE via malformed protobuf message in gogo/protobuf.", fix:"Update to v1.3.2+", license_spdx:"BSD-3-Clause", license_risk:"safe", weekly_downloads:"500K", last_publish:"2021-09-02", health_score:70, exploit_public:false },
  "gopkg.in/yaml.v2":            { risk:"MEDIUM",   type:"vulnerable", cve:"CVE-2022-28948", cvss:7.5, safeVersion:"v3",     description:"Denial of service via crafted YAML. Upgrade to gopkg.in/yaml.v3.", fix:"go get gopkg.in/yaml.v3", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"2M", last_publish:"2022-05-14", health_score:60, exploit_public:false },

  // ── Java ──────────────────────────────────────────────────────────────────
  // Keyed by full Maven coordinate ("groupId:artifactId"), not bare
  // artifactId -- see parsePomXml/parseBuildGradle below. Java import
  // statements (org.springframework.*) never reliably map to an exact
  // artifact id, so manifest-based coordinates are the only correct source
  // of truth for these entries; keying by artifactId alone silently
  // matched nothing, since nothing ever produced a bare "spring-webmvc"
  // string to look up.
  "org.apache.logging.log4j:log4j-core": { risk:"CRITICAL", type:"vulnerable", cve:"CVE-2021-44228", cvss:10.0, exploit_public:true, exploit_detail:"Log4Shell — remotely exploitable worldwide. Patch within hours.", safeVersion:"2.17.1", description:"Log4Shell: RCE via JNDI lookup in log4j-core < 2.16.0. CVSS 10.0. Actively exploited globally.", fix:"Update to log4j-core >= 2.17.1 in pom.xml or build.gradle", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"5M", last_publish:"2022-02-01", health_score:85, cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
  "org.apache.commons:commons-text":      { risk:"CRITICAL", type:"vulnerable", cve:"CVE-2022-42889", cvss:9.8, exploit_public:true, exploit_detail:"Text4Shell PoC widely available", safeVersion:"1.10.0", description:"Text4Shell: RCE via StringLookup interpolation in commons-text < 1.10.0.", fix:"Update commons-text to >= 1.10.0", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"3M", last_publish:"2023-08-14", health_score:82 },
  "org.springframework:spring-webmvc":    { risk:"CRITICAL", type:"vulnerable", cve:"CVE-2022-22965", cvss:9.8, exploit_public:true, exploit_detail:"Spring4Shell — mass exploitation observed", safeVersion:"5.3.18",  description:"Spring4Shell: RCE via DataBinder in Spring Framework < 5.3.18.", fix:"Update Spring Framework to >= 5.3.18", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"4M", last_publish:"2024-04-12", health_score:88 },
  "org.springframework:spring-core":      { risk:"CRITICAL", type:"vulnerable", cve:"CVE-2022-22965", cvss:9.8, exploit_public:true, exploit_detail:"Spring4Shell — mass exploitation observed", safeVersion:"5.3.18",  description:"Spring4Shell: RCE via DataBinder in Spring Framework < 5.3.18.", fix:"Update Spring Framework to >= 5.3.18", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"4M", last_publish:"2024-04-12", health_score:88 },
  "org.springframework.boot:spring-boot-starter-web": { risk:"HIGH", type:"vulnerable", cve:"CVE-2022-22965", cvss:9.8, exploit_public:true, exploit_detail:"Bundles vulnerable spring-webmvc transitively", safeVersion:"2.6.6", description:"Bundles a vulnerable Spring Framework version affected by Spring4Shell unless overridden.", fix:"Update spring-boot-starter-web to >= 2.6.6, or override spring-core/spring-webmvc directly", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"4M", last_publish:"2024-04-12", health_score:88 },

  // ── Rust ──────────────────────────────────────────────────────────────────
  "openssl":     { risk:"HIGH",   type:"vulnerable", cve:"CVE-2023-0286", cvss:7.4, safeVersion:"0.10.55", description:"Type confusion in X.400 address processing in openssl crate.", fix:"openssl = \"0.10.55\" in Cargo.toml", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"1M", last_publish:"2024-03-20", health_score:85, exploit_public:false },
  "serde_json":  { risk:"SAFE",  type:"safe",        description:"Well-maintained, no known vulnerabilities.", license_spdx:"MIT OR Apache-2.0", license_risk:"safe", weekly_downloads:"5M", last_publish:"2024-06-01", health_score:98, exploit_public:false },

  // ── Ruby ──────────────────────────────────────────────────────────────────
  "rails":       { risk:"HIGH",   type:"vulnerable", cve:"CVE-2024-26143", cvss:7.5, safeVersion:"7.1.3.2", description:"XSS via response headers in Rails < 7.1.3.2.", fix:"gem 'rails', '>= 7.1.3.2'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"500K", last_publish:"2024-05-01", health_score:88, exploit_public:false },
  "nokogiri":    { risk:"HIGH",   type:"vulnerable", cve:"CVE-2022-29181", cvss:7.5, safeVersion:"1.14.3",  description:"Inefficient regex in Nokogiri < 1.14.3 enables ReDoS.", fix:"gem 'nokogiri', '>= 1.14.3'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"300K", last_publish:"2024-03-15", health_score:82, exploit_public:false },

  // ── C# ────────────────────────────────────────────────────────────────────
  "Newtonsoft.Json": { risk:"MEDIUM", type:"outdated", safeVersion:"13.0.3", description:"Older Newtonsoft.Json misses deserialization security hardening.", fix:"<PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"300M", last_publish:"2023-10-19", health_score:78, exploit_public:false },

  // ── PHP ───────────────────────────────────────────────────────────────────
  "guzzlehttp/guzzle": { risk:"HIGH",   type:"vulnerable", cve:"CVE-2023-29197", cvss:7.5, safeVersion:"7.8.1", description:"Header injection vulnerability in Guzzle < 7.8.1.", fix:"composer require 'guzzlehttp/guzzle:>=7.8.1'", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"700K", last_publish:"2024-02-08", health_score:85, exploit_public:false },
  "laravel/framework": { risk:"MEDIUM", type:"vulnerable", cve:"CVE-2024-29291", cvss:5.4, safeVersion:"10.48.14", description:"Auth bypass in certain middleware configurations in Laravel.", fix:"composer update laravel/framework", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"500K", last_publish:"2024-04-10", health_score:90, exploit_public:false },
};

// ── Transitive dependency map ──────────────────────────────────────────────────

export const TRANSITIVE_MAP: Record<string, string[]> = {
  "axios":         ["follow-redirects"],
  "node-fetch":    ["whatwg-url"],
  "webpack":       ["minimist"],
  "jest":          ["minimist"],
  "mocha":         ["minimist"],
  "babel-cli":     ["minimist"],
  "lodash":        [],
  "express":       ["qs", "path-to-regexp"],
  "log4j-core":    [],
};

// ── License classification ─────────────────────────────────────────────────────

export function classifyLicense(spdx?: string): { risk: LicenseRisk; label: string; note: string } {
  if (!spdx) return { risk:"unknown", label:"Unknown", note:"License not identified — review before shipping" };
  const s = spdx.toUpperCase();
  if (s.includes("MIT") || s.includes("APACHE") || s.includes("BSD") || s.includes("ISC") || s.includes("UNLICENSE"))
    return { risk:"safe",   label:spdx, note:"Permissive — commercial use allowed" };
  if (s.includes("LGPL"))
    return { risk:"review", label:spdx, note:"Weak copyleft — dynamic linking fine, static linking requires open-source" };
  if (s.includes("AGPL"))
    return { risk:"block",  label:spdx, note:"AGPL — network use triggers copyleft. Likely incompatible with proprietary products" };
  if (s.includes("GPL"))
    return { risk:"block",  label:spdx, note:"GPL — copyleft contaminates your product. Consult legal before shipping" };
  if (s.includes("MPL") || s.includes("EUPL") || s.includes("EPL"))
    return { risk:"review", label:spdx, note:"File-level copyleft — usually OK if you don't modify the library" };
  return { risk:"unknown", label:spdx, note:"Review license terms before shipping" };
}

// ── Language detection & import parsing ────────────────────────────────────────

export function detectEcosystem(filePath: string): LangEcosystem {
  const ext  = filePath.split(".").pop()?.toLowerCase() ?? "";
  const name = filePath.toLowerCase();
  if (ext === "py" || name.includes("requirements") || name.includes("pyproject")) return "python";
  if (ext === "ts" || ext === "tsx")  return "typescript";
  if (ext === "js" || ext === "jsx" || name.includes("package.json")) return "javascript";
  if (ext === "go"  || name.includes("go.mod"))   return "go";
  if (ext === "java"|| name.includes("pom.xml") || name.includes("build.gradle")) return "java";
  if (ext === "rs"  || name.includes("cargo.toml")) return "rust";
  if (ext === "rb"  || name.includes("gemfile"))  return "ruby";
  if (ext === "cs"  || ext === "csproj")           return "csharp";
  if (ext === "php" || name.includes("composer"))  return "php";
  return "unknown";
}

export const ECO_MANAGER: Record<LangEcosystem, string> = {
  python:"pip", javascript:"npm", typescript:"npm", go:"go mod",
  java:"maven", rust:"cargo", ruby:"bundler", csharp:"NuGet", php:"composer", unknown:"unknown",
};

export function parseImports(content: string, eco: LangEcosystem): string[] {
  const pkgs = new Set<string>();
  for (const line of content.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#") || t.startsWith("//")) continue;
    if (eco === "python") {
      const m1 = t.match(/^import\s+([\w.-]+)/); if (m1) pkgs.add(m1[1].split(".")[0]);
      const m2 = t.match(/^from\s+([\w.-]+)\s+import/); if (m2) pkgs.add(m2[1].split(".")[0]);
    } else if (eco === "typescript" || eco === "javascript") {
      const m1 = t.match(/from\s+['"]([^'"./][^'"]*)['"]/);
      const m2 = t.match(/require\s*\(\s*['"]([^'"./][^'"]*)['"]/);
      if (m1) { const p = m1[1]; pkgs.add(p.startsWith("@") ? p.split("/").slice(0,2).join("/") : p.split("/")[0]); }
      if (m2) pkgs.add(m2[1].split("/")[0]);
    } else if (eco === "go") {
      const m = t.match(/["'](github\.com\/[^"'/]+\/[^"'/]+)/); if (m) pkgs.add(m[1]);
    } else if (eco === "java") {
      // Package prefix only (e.g. "org.springframework") -- an import
      // statement alone can't reliably identify the exact Maven artifactId,
      // so this never matches VULN_DB's groupId:artifactId-keyed Java
      // entries. Kept as a best-effort signal for callers that just want
      // "what packages does this file reference"; parsePomXml/
      // parseBuildGradle above are the real source of truth for CVE matching.
      const m = t.match(/^import\s+([\w.]+)/);
      if (m) { const parts = m[1].split("."); if (parts.length >= 2) pkgs.add(parts.slice(0,2).join(".")); }
    } else if (eco === "rust") {
      const m1 = t.match(/^use\s+([\w]+)/); if (m1) pkgs.add(m1[1]);
      const m2 = t.match(/^extern crate\s+([\w]+)/); if (m2) pkgs.add(m2[1]);
    } else if (eco === "ruby") {
      const m = t.match(/^require\s+['"]([^'"]+)['"]/); if (m) pkgs.add(m[1]);
    } else if (eco === "php") {
      const m = t.match(/use\s+([\w\\]+)/); if (m) pkgs.add(m[1].split("\\")[0].toLowerCase());
    }
  }
  return Array.from(pkgs).filter(Boolean);
}

export function buildFinding(pkg: string, eco: LangEcosystem, repo: string, filePath: string, prNumber: number, scanId: string, aiPct: number, isTransitive = false, pulledBy?: string): DepFinding | null {
  const entry = VULN_DB[pkg];
  if (!entry) return null;
  if (entry.type === "safe") return null;

  const licClass = classifyLicense(entry.license_spdx);
  return {
    id:              `${scanId}::${filePath}::${pkg}${isTransitive?"-t":""}`,
    package_name:    pkg,
    version_used:    entry.safeVersion ? `< ${entry.safeVersion}` : "unknown",
    latest_version:  entry.safeVersion,
    ecosystem:       eco,
    manager:         ECO_MANAGER[eco],
    risk:            entry.risk,
    type:            isTransitive ? "transitive" : entry.type,
    repo, file_path: filePath, pr_number: prNumber, scan_id: scanId,
    description:     entry.description,
    fix:             entry.fix,
    cve:             entry.cve,
    cvss:            entry.cvss,
    cvss_vector:     entry.cvss_vector,
    exploit_public:  entry.exploit_public ?? false,
    exploit_detail:  entry.exploit_detail,
    ai_introduced:   aiPct > 0.4,
    is_transitive:   isTransitive,
    pulled_by:       pulledBy,
    license_spdx:    entry.license_spdx ?? licClass.label,
    license_risk:    entry.license_risk ?? licClass.risk,
    license_note:    entry.license_note ?? licClass.note,
    last_publish:    entry.last_publish,
    weekly_downloads:entry.weekly_downloads,
    is_archived:     entry.is_archived ?? false,
    is_deprecated:   entry.is_deprecated ?? false,
    health_score:    entry.health_score ?? 70,
  };
}

// Maven's <dependency> blocks — matches both direct dependencies and
// <dependencyManagement>/BOM entries (not distinguished; a first pass).
// Regex-based rather than a full XML parser since pom.xml's dependency shape
// is simple and consistent enough not to need one.
export function parsePomXml(content: string): string[] {
  const coords: string[] = [];
  const depBlockRe = /<dependency>([\s\S]*?)<\/dependency>/g;
  let m: RegExpExecArray | null;
  while ((m = depBlockRe.exec(content)) !== null) {
    const block = m[1];
    const g = /<groupId>\s*([^<]+?)\s*<\/groupId>/.exec(block);
    const a = /<artifactId>\s*([^<]+?)\s*<\/artifactId>/.exec(block);
    if (!g || !a) continue;
    coords.push(`${g[1].trim()}:${a[1].trim()}`);
  }
  return coords;
}

// Gradle (Groovy or Kotlin DSL) dependency declarations — the two common
// shapes: 'group:artifact:version' string notation, and the
// group:/name:/version: map notation.
export function parseBuildGradle(content: string): string[] {
  const coords: string[] = [];
  const stringForm = /(?:implementation|api|compile|testImplementation|runtimeOnly|compileOnly|annotationProcessor)\s*[( ]?\s*['"]([^:'"]+):([^:'"]+):[^'"]*['"]/g;
  let m: RegExpExecArray | null;
  while ((m = stringForm.exec(content)) !== null) coords.push(`${m[1].trim()}:${m[2].trim()}`);

  const mapForm = /group\s*:\s*['"]([^'"]+)['"]\s*,\s*name\s*:\s*['"]([^'"]+)['"]/g;
  while ((m = mapForm.exec(content)) !== null) coords.push(`${m[1].trim()}:${m[2].trim()}`);

  return coords;
}

// Manifest files declare dependencies directly — parse the declared package
// identifiers instead of scanning for import statements (which a
// JSON/XML/Gradle manifest won't contain in the same shape as source code).
function manifestPackages(filePath: string, content: string): string[] | null {
  const name = filePath.toLowerCase();
  if (name.endsWith("package.json"))     return parsePackageJson(content).map(p => p.name);
  if (name.endsWith("requirements.txt")) return parseRequirementsTxt(content).map(p => p.name);
  if (name.endsWith("go.mod"))           return parseGoMod(content).map(p => p.name);
  if (name.endsWith("pom.xml"))          return parsePomXml(content);
  if (name.endsWith("build.gradle") || name.endsWith("build.gradle.kts")) return parseBuildGradle(content);
  return null;
}

export function deriveFindings(scans: ScanForDeps[]): DepFinding[] {
  const findings: DepFinding[] = [];
  const seen = new Set<string>();
  for (const scan of scans) {
    for (const file of scan.files) {
      if (!file.content) continue;
      const eco = detectEcosystem(file.file_path);
      if (eco === "unknown") continue;
      const declared = manifestPackages(file.file_path, file.content);
      const imports = declared ?? parseImports(file.content, eco);
      for (const pkg of imports) {
        const f = buildFinding(pkg, eco, scan.repo, file.file_path, scan.pr_number, scan.scan_id, file.ai_percentage);
        if (f && !seen.has(f.id)) { seen.add(f.id); findings.push(f); }
        // Transitive deps
        for (const transitive of TRANSITIVE_MAP[pkg] ?? []) {
          const tf = buildFinding(transitive, eco, scan.repo, file.file_path, scan.pr_number, scan.scan_id, file.ai_percentage, true, pkg);
          if (tf && !seen.has(tf.id)) { seen.add(tf.id); findings.push(tf); }
        }
      }
    }
  }
  return findings;
}
