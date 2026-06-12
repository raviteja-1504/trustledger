"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import InfoTooltip from "@/components/InfoTooltip";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { api } from "@/lib/api";
import { isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import type { DashboardData, ScanResult } from "@/types";

// ── Types ──────────────────────────────────────────────────────────────────────

type DepRisk       = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
type DepType       = "vulnerable" | "unmaintained" | "hallucinated" | "typosquatting" | "outdated" | "transitive" | "safe";
type LangEcosystem = "python" | "javascript" | "typescript" | "go" | "java" | "rust" | "ruby" | "csharp" | "php" | "unknown";
type LicenseRisk   = "safe" | "review" | "block" | "unknown";

interface DepFinding {
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
  pulled_by?: string;       // direct dep that pulls this transitive dep
  // License
  license_spdx?: string;
  license_risk: LicenseRisk;
  license_note?: string;
  // Health
  last_publish?: string;
  weekly_downloads?: string;
  is_archived: boolean;
  is_deprecated: boolean;
  health_score: number;     // 0–100
}

// ── Vulnerability + metadata database ─────────────────────────────────────────

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

const VULN_DB: Record<string, VulnEntry> = {
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
  "log4j-core":    { risk:"CRITICAL", type:"vulnerable", cve:"CVE-2021-44228", cvss:10.0, exploit_public:true, exploit_detail:"Log4Shell — remotely exploitable worldwide. Patch within hours.", safeVersion:"2.17.1", description:"Log4Shell: RCE via JNDI lookup in log4j-core < 2.16.0. CVSS 10.0. Actively exploited globally.", fix:"Update to log4j-core >= 2.17.1 in pom.xml or build.gradle", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"5M", last_publish:"2022-02-01", health_score:85, cvss_vector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
  "commons-text":  { risk:"CRITICAL", type:"vulnerable", cve:"CVE-2022-42889", cvss:9.8, exploit_public:true, exploit_detail:"Text4Shell PoC widely available", safeVersion:"1.10.0", description:"Text4Shell: RCE via StringLookup interpolation in commons-text < 1.10.0.", fix:"Update commons-text to >= 1.10.0", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"3M", last_publish:"2023-08-14", health_score:82 },
  "spring-webmvc": { risk:"CRITICAL", type:"vulnerable", cve:"CVE-2022-22965", cvss:9.8, exploit_public:true, exploit_detail:"Spring4Shell — mass exploitation observed", safeVersion:"5.3.18",  description:"Spring4Shell: RCE via DataBinder in Spring Framework < 5.3.18.", fix:"Update Spring Framework to >= 5.3.18", license_spdx:"Apache-2.0", license_risk:"safe", weekly_downloads:"4M", last_publish:"2024-04-12", health_score:88 },

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
// key: direct package → value: transitive packages it pulls in with known vulns

const TRANSITIVE_MAP: Record<string, string[]> = {
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

function classifyLicense(spdx?: string): { risk: LicenseRisk; label: string; note: string } {
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

const LICENSE_STYLE: Record<LicenseRisk, { bg:string; text:string; border:string }> = {
  safe:    { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0" },
  review:  { bg:"#fffbeb", text:"#b45309", border:"#fde68a" },
  block:   { bg:"#fef2f2", text:"#be123c", border:"#fecdd3" },
  unknown: { bg:"#f8fafc", text:"#475569", border:"#e2e8f0" },
};

// ── Language detection & import parsing ────────────────────────────────────────

function detectEcosystem(filePath: string): LangEcosystem {
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

const ECO_MANAGER: Record<LangEcosystem, string> = {
  python:"pip", javascript:"npm", typescript:"npm", go:"go mod",
  java:"maven", rust:"cargo", ruby:"bundler", csharp:"NuGet", php:"composer", unknown:"unknown",
};

const ECO_COLOR: Record<LangEcosystem, { bg:string; text:string }> = {
  python:     { bg:"#dbeafe", text:"#1d4ed8" },
  typescript: { bg:"#e0e7ff", text:"#4338ca" },
  javascript: { bg:"#fef3c7", text:"#92400e" },
  go:         { bg:"#cffafe", text:"#0e7490" },
  java:       { bg:"#ffedd5", text:"#9a3412" },
  rust:       { bg:"#fce7f3", text:"#9d174d" },
  ruby:       { bg:"#fee2e2", text:"#991b1b" },
  csharp:     { bg:"#ede9fe", text:"#5b21b6" },
  php:        { bg:"#f0fdf4", text:"#15803d" },
  unknown:    { bg:"#f8fafc", text:"#475569" },
};

function parseImports(content: string, eco: LangEcosystem): string[] {
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

function buildFinding(pkg: string, eco: LangEcosystem, repo: string, filePath: string, prNumber: number, scanId: string, aiPct: number, isTransitive = false, pulledBy?: string): DepFinding | null {
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

function deriveFindings(scans: ScanResult[]): DepFinding[] {
  const findings: DepFinding[] = [];
  const seen = new Set<string>();
  for (const scan of scans) {
    for (const file of scan.files) {
      if (!file.content) continue;
      const eco = detectEcosystem(file.file_path);
      if (eco === "unknown") continue;
      const imports = parseImports(file.content, eco);
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

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Offline fallback ───────────────────────────────────────────────────────────

function makeOffline(): DepFinding[] {
  const o = ORG;
  const spec = [
    { pkg:"requests",     eco:"python"     as LangEcosystem, repo:`${o}/payments-api`,    fp:"src/processors/card_validator.py",  pr:482, sid:"sc_mock_001", ai:0.91 },
    { pkg:"PyJWT",        eco:"python"     as LangEcosystem, repo:`${o}/auth-service`,    fp:"src/auth/token_service.py",         pr:341, sid:"sc_mock_002", ai:0.68 },
    { pkg:"ml-utils-fast",eco:"python"     as LangEcosystem, repo:`${o}/fraud-detection`, fp:"models/risk_scorer.ts",             pr:219, sid:"sc_mock_003", ai:0.83 },
    { pkg:"stripe-client",eco:"python"     as LangEcosystem, repo:`${o}/payments-api`,    fp:"src/gateway/stripe_client.py",      pr:479, sid:"sc_mock_001", ai:0.76 },
    { pkg:"lodash",       eco:"typescript" as LangEcosystem, repo:`${o}/data-platform`,   fp:"src/pipelines/etl_runner.py",       pr:103, sid:"sc_mock_005", ai:0.65 },
    { pkg:"axios",        eco:"typescript" as LangEcosystem, repo:`${o}/auth-service`,    fp:"src/notifications/email_client.ts", pr:338, sid:"sc_mock_002", ai:0.49 },
    { pkg:"follow-redirects", eco:"typescript" as LangEcosystem, repo:`${o}/auth-service`, fp:"src/notifications/email_client.ts", pr:338, sid:"sc_mock_002", ai:0.49 },
    { pkg:"cryptography", eco:"python"     as LangEcosystem, repo:`${o}/payments-api`,    fp:"src/crypto/signing.py",             pr:477, sid:"sc_mock_001", ai:0.55 },
    { pkg:"moment",       eco:"javascript" as LangEcosystem, repo:`${o}/data-platform`,   fp:"src/utils/date_helper.js",          pr:102, sid:"sc_mock_005", ai:0.60 },
    { pkg:"paramiko",     eco:"python"     as LangEcosystem, repo:`${o}/risk-engine`,     fp:"src/ssh/connection.py",             pr:90,  sid:"sc_mock_004", ai:0.45 },
    { pkg:"numpy",        eco:"python"     as LangEcosystem, repo:`${o}/fraud-detection`, fp:"src/utils/feature_extractor.py",    pr:218, sid:"sc_mock_003", ai:0.38 },
    { pkg:"django",       eco:"python"     as LangEcosystem, repo:`${o}/payments-api`,    fp:"src/api/views.py",                  pr:476, sid:"sc_mock_001", ai:0.52 },
  ];
  const seen = new Set<string>();
  return spec.flatMap(s => {
    const isT = s.pkg === "follow-redirects";
    const f = buildFinding(s.pkg, s.eco, s.repo, s.fp, s.pr, s.sid, s.ai, isT, isT ? "axios" : undefined);
    if (!f || seen.has(f.id)) return [];
    seen.add(f.id);
    return [f];
  });
}

// ── SBOM generators ────────────────────────────────────────────────────────────

function generateSPDX(findings: DepFinding[], org: string): string {
  const doc = {
    SPDXID: "SPDXRef-DOCUMENT",
    spdxVersion: "SPDX-2.3",
    creationInfo: { created: new Date().toISOString(), creators: [`Tool: TrustLedger v1.0`, `Organization: ${org}`] },
    name: `TrustLedger-SBOM-${org}`,
    dataLicense: "CC0-1.0",
    documentNamespace: `https://trustledger.dev/sbom/${org}/${Date.now()}`,
    packages: findings.map((f, i) => ({
      SPDXID:           `SPDXRef-Package-${i + 1}`,
      name:             f.package_name,
      versionInfo:      f.version_used,
      downloadLocation: "NOASSERTION",
      filesAnalyzed:    false,
      licenseConcluded: f.license_spdx ?? "NOASSERTION",
      licenseDeclared:  f.license_spdx ?? "NOASSERTION",
      copyrightText:    "NOASSERTION",
      comment:          f.description,
      externalRefs: f.cve ? [{ referenceCategory:"SECURITY", referenceType:"cve", referenceLocator: f.cve }] : [],
      annotations: [{
        annotationType: "REVIEW",
        annotator:      "Tool: TrustLedger",
        annotationDate: new Date().toISOString(),
        comment:        `Risk: ${f.risk} | Type: ${f.type} | AI-introduced: ${f.ai_introduced}`,
      }],
    })),
  };
  return JSON.stringify(doc, null, 2);
}

function generateCycloneDX(findings: DepFinding[], org: string): string {
  const doc = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:tl-${Date.now()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "TrustLedger", name: "Dependency Scanner", version: "1.0" }],
      component: { type: "application", name: org },
    },
    components: findings.map(f => ({
      type:    "library",
      name:    f.package_name,
      version: f.version_used,
      purl:    `pkg:${f.ecosystem}/${f.package_name}@${f.version_used}`,
      licenses: f.license_spdx ? [{ license: { id: f.license_spdx } }] : [],
      properties: [
        { name:"trustledger:risk",          value:f.risk         },
        { name:"trustledger:type",          value:f.type         },
        { name:"trustledger:ai_introduced", value:String(f.ai_introduced) },
        { name:"trustledger:repo",          value:f.repo         },
        { name:"trustledger:health_score",  value:String(f.health_score) },
      ],
      vulnerabilities: f.cve ? [{ id:f.cve, ratings:[{ score:f.cvss, severity:f.risk.toLowerCase() }] }] : [],
    })),
  };
  return JSON.stringify(doc, null, 2);
}

// ── Styles ─────────────────────────────────────────────────────────────────────

const RISK_STYLE: Record<DepRisk, { bg:string; text:string; border:string }> = {
  CRITICAL: { bg:"#ede9fe", text:"#5b21b6", border:"#c4b5fd" },
  HIGH:     { bg:"#ffedd5", text:"#7c2d12", border:"#fed7aa" },
  MEDIUM:   { bg:"#fef3c7", text:"#78350f", border:"#fde68a" },
  LOW:      { bg:"#eff6ff", text:"#1d4ed8", border:"#bfdbfe" },
  SAFE:     { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0" },
};

const TYPE_LABELS: Record<DepType, string> = {
  vulnerable:"Vulnerable", unmaintained:"Unmaintained", hallucinated:"Hallucinated",
  typosquatting:"Typosquatting", outdated:"Outdated", transitive:"Transitive", safe:"Safe",
};

function cvssColor(s: number) { return s>=9?"#7c3aed":s>=7?"#f97316":s>=4?"#f59e0b":"#22c55e"; }

function healthBar(score: number) {
  const color = score>=80?"#10b981":score>=50?"#f59e0b":"#ef4444";
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-12 h-1.5 rounded-full overflow-hidden bg-gray-100">
        <div className="h-full rounded-full" style={{ width:`${score}%`, background:color }} />
      </div>
      <span className="text-[9px] font-bold tabular-nums" style={{ color }}>{score}</span>
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function DependenciesPage() {
  const { profile } = useAuth();
  const [findings,    setFindings]    = useState<DepFinding[]>([]);
  const [loading,     setLoading]     = useState(true);
  const [refreshing,  setRefreshing]  = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [expanded,    setExpanded]    = useState<string | null>(null);
  const [filterRisk,  setFilterRisk]  = useState<DepRisk | "all">("all");
  const [filterType,  setFilterType]  = useState<DepType | "all">("all");
  const [filterEco,   setFilterEco]   = useState<LangEcosystem | "all">("all");
  const [filterRepo,  setFilterRepo]  = useState("all");
  const [filterLicense, setFilterLicense] = useState<LicenseRisk | "all">("all");
  const [search,      setSearch]      = useState("");
  const [showFixAll,  setShowFixAll]  = useState(false);
  const [showSbom,    setShowSbom]    = useState(false);
  const [sbomFormat,  setSbomFormat]  = useState<"spdx"|"cyclonedx">("spdx");
  const [copied,      setCopied]      = useState<string | null>(null);

  const fetchFindings = useCallback(async (spinner = false) => {
    if (spinner) setRefreshing(true);
    try {
      const dash: DashboardData = await api.dashboard(ORG, 90);
      const scanPromises = dash.repos.filter(r => r.latest_scan_id).map(r => api.getScan(r.latest_scan_id).catch(() => null));
      const scans = (await Promise.all(scanPromises)).filter((s): s is ScanResult => s !== null);
      const derived = deriveFindings(scans);
      // A successful fetch means real data, even if it's an empty list — only
      // fall back to the offline mock list on an actual fetch failure (catch below).
      setFindings(derived);
      setLastRefreshed(new Date());
    } catch { setLastRefreshed(new Date()); if (isSeedMode() && !profile?.org_id) setFindings(makeOffline()); }
    finally { setLoading(false); if (spinner) setRefreshing(false); }
  }, [profile?.org_id]);

  useEffect(() => {
    fetchFindings();
    const id = setInterval(() => fetchFindings(), 30_000);
    return () => clearInterval(id);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const repos      = useMemo(() => Array.from(new Set(findings.map(f => f.repo))), [findings]);
  const ecosystems = useMemo(() => Array.from(new Set(findings.map(f => f.ecosystem))).filter(e => e !== "unknown") as LangEcosystem[], [findings]);

  const filtered = useMemo(() => findings.filter(f => {
    if (filterRisk    !== "all" && f.risk          !== filterRisk)    return false;
    if (filterType    !== "all" && f.type          !== filterType)    return false;
    if (filterEco     !== "all" && f.ecosystem     !== filterEco)     return false;
    if (filterRepo    !== "all" && f.repo          !== filterRepo)    return false;
    if (filterLicense !== "all" && f.license_risk  !== filterLicense) return false;
    if (search) { const q = search.toLowerCase(); const h = [f.package_name, f.description, f.cve??"", f.repo].join(" ").toLowerCase(); if (!h.includes(q)) return false; }
    return true;
  }), [findings, filterRisk, filterType, filterEco, filterRepo, filterLicense, search]);

  // Fix-all commands grouped by package manager
  const fixAll = useMemo(() => {
    const groups: Record<string, string[]> = {};
    filtered.filter(f => f.fix && f.risk !== "SAFE" && f.type !== "safe").forEach(f => {
      if (!groups[f.manager]) groups[f.manager] = [];
      groups[f.manager].push(f.fix!);
    });
    return groups;
  }, [filtered]);

  // License issues
  const licenseIssues = useMemo(() => findings.filter(f => f.license_risk === "block" || f.license_risk === "review"), [findings]);

  // SBOM content
  const sbomContent = useMemo(() =>
    sbomFormat === "spdx" ? generateSPDX(findings, ORG) : generateCycloneDX(findings, ORG),
  [findings, sbomFormat]);

  function copy(text: string, key: string) {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  }

  function downloadSbom() {
    const ext = sbomFormat === "spdx" ? "spdx.json" : "cdx.json";
    const a = Object.assign(document.createElement("a"), {
      href: URL.createObjectURL(new Blob([sbomContent], { type:"application/json" })),
      download: `trustledger-sbom-${ORG}.${ext}`,
    });
    a.click();
  }

  const vuln    = findings.filter(f => f.type === "vulnerable").length;
  const halluc  = findings.filter(f => f.type === "hallucinated").length;
  const typosq  = findings.filter(f => f.type === "typosquatting").length;
  const crit    = findings.filter(f => f.risk === "CRITICAL").length;
  const exploits= findings.filter(f => f.exploit_public).length;

  // Publish vuln count so posture page can read it
  useEffect(() => {
    try { localStorage.setItem("tl_dep_vuln_count", String(crit + Math.round(vuln * 0.5))); } catch {}
  }, [crit, vuln]);
  const refreshAgo = lastRefreshed ? (() => { const s = Math.floor((Date.now()-lastRefreshed.getTime())/1000); return s<10?"just now":s<60?`${s}s ago`:`${Math.floor(s/60)}m ago`; })() : "";

  return (
    <AuthGuard>
      <PageSkeleton rows={6} cards={4}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center" style={{ background:"rgba(124,58,237,0.1)", border:"1px solid rgba(124,58,237,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
                  <polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Dependency Scanner</h1>
              {crit > 0 && <span className="text-xs font-black text-white bg-violet-600 px-2 py-0.5 rounded-full">{crit} critical</span>}
              {exploits > 0 && <span className="text-[10px] font-black text-white bg-rose-600 px-2 py-0.5 rounded-full animate-pulse">⚡ {exploits} exploits public</span>}
            </div>
            <p className="text-sm text-gray-400">
              Parses real imports across {ecosystems.length} ecosystems · {Object.keys(VULN_DB).length}-entry vuln DB · license + health checks · transitive deps
            </p>
          </div>
          <div className="flex flex-col items-end gap-0.5">
            <div className="flex items-center gap-2">
              {/* Fix All */}
              <button onClick={() => setShowFixAll(v => !v)}
                className={`flex items-center gap-1.5 px-3 py-2 text-xs font-bold rounded-xl border transition-all shadow-sm ${showFixAll?"text-emerald-800 bg-emerald-100 border-emerald-300":"text-emerald-700 bg-emerald-50 border-emerald-200 hover:bg-emerald-100"}`}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                Fix All
              </button>
              {/* SBOM */}
              <button onClick={() => setShowSbom(v => !v)}
                className={`flex items-center gap-1.5 px-3 py-2 text-xs font-bold rounded-xl border transition-all shadow-sm ${showSbom?"text-indigo-800 bg-indigo-100 border-indigo-300":"text-indigo-700 bg-indigo-50 border-indigo-200 hover:bg-indigo-100"}`}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                SBOM
              </button>
              {/* Refresh */}
              <button onClick={() => fetchFindings(true)} disabled={refreshing}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-50 transition-all shadow-sm">
                <svg className={refreshing?"animate-spin":""} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                </svg>
                {refreshing?"Refreshing…":"Refresh"}
              </button>
            </div>
            {refreshAgo && <span className="text-[9px] text-gray-400">Updated {refreshAgo}</span>}
          </div>
        </div>

        {/* Fix All panel */}
        {showFixAll && (
          <div className="animate-fade-up section-card overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-100" style={{ background:"rgba(240,253,244,0.6)" }}>
              <div>
                <p className="text-sm font-bold text-emerald-800">Fix All Commands</p>
                <p className="text-xs text-emerald-600 mt-0.5">Upgrade all vulnerable packages matching current filters — grouped by package manager</p>
              </div>
              <button onClick={() => setShowFixAll(false)} className="text-gray-400 hover:text-gray-600">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>
            {Object.keys(fixAll).length === 0 ? (
              <p className="px-5 py-4 text-xs text-gray-400">No fixable packages in current filter.</p>
            ) : (
              <div className="divide-y divide-gray-50">
                {Object.entries(fixAll).map(([mgr, cmds]) => {
                  const combined = mgr === "pip"
                    ? `pip install ${cmds.map(c => `'${c.replace("pip install ","")}'`).join(" ")}`
                    : mgr === "npm"
                    ? `npm install ${cmds.map(c => c.replace("npm install ","")).join(" ")}`
                    : cmds.join("\n");
                  return (
                    <div key={mgr} className="px-5 py-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[10px] font-black uppercase tracking-wider text-gray-400">{mgr}</span>
                        <button onClick={() => copy(combined, mgr)}
                          className="text-[10px] font-bold text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-100 hover:bg-indigo-100 transition-colors">
                          {copied === mgr ? "Copied ✓" : "Copy"}
                        </button>
                      </div>
                      <pre className="bg-gray-900 rounded-xl px-4 py-3 text-xs text-emerald-400 font-mono overflow-x-auto whitespace-pre-wrap">{combined}</pre>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* SBOM panel */}
        {showSbom && (
          <div className="animate-fade-up section-card overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-100" style={{ background:"rgba(238,242,255,0.6)" }}>
              <div>
                <p className="text-sm font-bold text-indigo-800">SBOM Export</p>
                <p className="text-xs text-indigo-600 mt-0.5">Machine-readable Software Bill of Materials — compatible with SLSA, Sigstore, GitHub Dependency Graph</p>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex gap-0.5 bg-gray-100 p-0.5 rounded-lg">
                  {(["spdx","cyclonedx"] as const).map(f => (
                    <button key={f} onClick={() => setSbomFormat(f)}
                      className={`px-2.5 py-1 text-[10px] font-bold rounded-md transition-all ${sbomFormat===f?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                      {f === "spdx" ? "SPDX 2.3" : "CycloneDX 1.5"}
                    </button>
                  ))}
                </div>
                <button onClick={() => copy(sbomContent, "sbom")}
                  className="text-[10px] font-bold text-indigo-600 bg-indigo-50 border border-indigo-100 px-2.5 py-1.5 rounded-lg hover:bg-indigo-100 transition-colors">
                  {copied === "sbom" ? "Copied ✓" : "Copy JSON"}
                </button>
                <button onClick={downloadSbom}
                  className="text-[10px] font-bold text-white px-2.5 py-1.5 rounded-lg transition-colors"
                  style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
                  Download ↓
                </button>
                <button onClick={() => setShowSbom(false)} className="text-gray-400 hover:text-gray-600">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
              </div>
            </div>
            <pre className="px-5 py-4 text-[10px] font-mono text-gray-600 overflow-auto max-h-64 leading-relaxed">
              {sbomContent.slice(0, 1200)}…
            </pre>
          </div>
        )}

        {/* Summary cards */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label:"Vulnerable",      value:vuln,                color:"#ef4444", bg:"#fef2f2", info:{ title:"Vulnerable Packages",  description:"Packages with a known CVE and a confirmed CVSS score. These have public vulnerability reports — upgrade to the safe version listed in the remediation command." } },
            { label:"Exploits Public", value:exploits,            color:"#7c3aed", bg:"#ede9fe", info:{ title:"Exploits Public",       description:"Packages where working exploit code is publicly available. These are the most urgent — attackers can immediately use the exploit without building their own." } },
            { label:"License Issues",  value:licenseIssues.length,color:"#b45309", bg:"#fffbeb", info:{ title:"License Issues",        description:"Packages with GPL, AGPL, or unknown licenses that may be legally incompatible with a proprietary product. Review = LGPL (linking concern). Block = GPL/AGPL (copyleft)." } },
            { label:"Hallucinated",    value:halluc + typosq,     color:"#9f1239", bg:"#fff1f2", info:{ title:"Hallucinated / Typosq.", description:"Hallucinated = AI invented a package name that doesn't exist (any future publisher is a supply-chain attacker). Typosquatting = the published package is malicious." } },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-4 border" style={{ background:s.bg, borderColor:s.color+"30" }}>
              <p className="text-2xl font-black tabular-nums" style={{ color:s.color }}>{s.value}</p>
              <div className="flex items-center gap-1.5 mt-1">
                <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                <InfoTooltip title={s.info.title} description={s.info.description} position="top" />
              </div>
            </div>
          ))}
        </div>

        {/* Ecosystem chips */}
        {ecosystems.length > 0 && (
          <div className="animate-fade-up flex items-center gap-2 flex-wrap">
            <span className="text-[9px] font-black uppercase tracking-widest text-gray-400 shrink-0">Ecosystems:</span>
            {ecosystems.map(eco => {
              const { bg, text } = ECO_COLOR[eco];
              const count = findings.filter(f => f.ecosystem === eco).length;
              return (
                <button key={eco} onClick={() => setFilterEco(filterEco === eco ? "all" : eco)}
                  className="flex items-center gap-1 text-[10px] font-bold px-2.5 py-1 rounded-lg border transition-all"
                  style={{ background: filterEco===eco ? text+"20" : bg, color:text, borderColor:text+"40" }}>
                  {eco} <span className="opacity-60">·</span> {count}
                </button>
              );
            })}
          </div>
        )}

        {/* Filters */}
        <div className="animate-fade-up flex flex-wrap items-center gap-2">
          <div className="flex items-center rounded-xl border border-gray-200 bg-white overflow-hidden">
            <svg className="ml-3 text-gray-400 shrink-0" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search packages, CVEs…"
              onKeyDown={e => e.key === "Escape" && setSearch("")}
              className="px-3 py-2 text-xs text-gray-700 bg-transparent outline-none w-44" />
            {search && <button onClick={() => setSearch("")} className="pr-2 text-gray-400 hover:text-gray-600 text-xs">✕</button>}
          </div>
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","CRITICAL","HIGH","MEDIUM","LOW","SAFE"] as const).map(r => (
              <button key={r} onClick={() => setFilterRisk(r)}
                className={`px-2.5 py-1.5 text-xs font-semibold rounded-lg transition-all ${filterRisk===r?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                {r==="all"?"All":r}
              </button>
            ))}
          </div>
          <select value={filterType} onChange={e => setFilterType(e.target.value as DepType | "all")}
            className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
            <option value="all">All Types</option>
            {(Object.keys(TYPE_LABELS) as DepType[]).map(t => <option key={t} value={t}>{TYPE_LABELS[t]}</option>)}
          </select>
          <select value={filterLicense} onChange={e => setFilterLicense(e.target.value as LicenseRisk | "all")}
            className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
            <option value="all">All Licenses</option>
            <option value="block">⛔ Block (GPL/AGPL)</option>
            <option value="review">⚠ Review (LGPL)</option>
            <option value="safe">✓ Safe (MIT/Apache)</option>
            <option value="unknown">? Unknown</option>
          </select>
          {repos.length > 1 && (
            <select value={filterRepo} onChange={e => setFilterRepo(e.target.value)}
              className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
              <option value="all">All Repos</option>
              {repos.map(r => <option key={r} value={r}>{r.split("/").pop()}</option>)}
            </select>
          )}
          {(search || filterRisk!=="all" || filterType!=="all" || filterEco!=="all" || filterRepo!=="all" || filterLicense!=="all") && (
            <button onClick={() => { setSearch(""); setFilterRisk("all"); setFilterType("all"); setFilterEco("all"); setFilterRepo("all"); setFilterLicense("all"); }}
              className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50 transition-colors">
              Clear filters
            </button>
          )}
          <span className="text-xs text-gray-400 ml-auto">{filtered.length} packages</span>
        </div>

        {/* Findings table */}
        <div className="animate-fade-up section-card overflow-hidden">
          <div className="grid px-5 py-2.5 border-b border-gray-100 text-[10px] font-black uppercase tracking-widest text-gray-400"
            style={{ gridTemplateColumns:"140px 90px 80px 80px 1fr 120px" }}>
            <span>Package</span><span>Ecosystem</span><span>Risk</span><span>Health</span><span>Issue</span><span>License</span>
          </div>

          {filtered.length === 0 ? (
            <div className="py-14 text-center">
              <p className="text-sm font-bold text-gray-600">No packages match this filter</p>
              <button onClick={() => { setSearch(""); setFilterRisk("all"); setFilterType("all"); setFilterEco("all"); setFilterRepo("all"); setFilterLicense("all"); }}
                className="mt-2 text-xs font-bold text-indigo-600">Clear filters →</button>
            </div>
          ) : filtered.map(dep => {
            const risk    = RISK_STYLE[dep.risk];
            const eco     = ECO_COLOR[dep.ecosystem];
            const licStyle= LICENSE_STYLE[dep.license_risk];
            const isOpen  = expanded === dep.id;
            return (
              <div key={dep.id}>
                <div className="grid items-center px-5 py-3.5 cursor-pointer hover:bg-gray-50/70 transition-colors border-b border-gray-50 last:border-0"
                  style={{ gridTemplateColumns:"140px 90px 80px 80px 1fr 120px" }}
                  onClick={() => setExpanded(isOpen ? null : dep.id)}>

                  {/* Package */}
                  <div className="min-w-0 pr-2">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <p className="text-xs font-bold font-mono text-gray-900 truncate">{dep.package_name}</p>
                      {dep.exploit_public && (
                        <span className="text-[8px] font-black text-rose-700 bg-rose-50 border border-rose-200 px-1 py-0.5 rounded" title={dep.exploit_detail}>⚡ Exploit</span>
                      )}
                      {dep.is_transitive && (
                        <span className="text-[8px] font-bold text-gray-400 bg-gray-100 px-1 py-0.5 rounded">transitive</span>
                      )}
                      {dep.is_archived && (
                        <span className="text-[8px] font-bold text-gray-400 bg-gray-100 px-1 py-0.5 rounded">archived</span>
                      )}
                    </div>
                    <span className="text-[9px] text-gray-400">{dep.manager}</span>
                  </div>

                  {/* Ecosystem */}
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-md w-fit" style={{ background:eco.bg, color:eco.text }}>{dep.ecosystem}</span>

                  {/* Risk */}
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border w-fit" style={{ background:risk.bg, color:risk.text, borderColor:risk.border }}>{dep.risk}</span>

                  {/* Health */}
                  {healthBar(dep.health_score)}

                  {/* Issue */}
                  <div className="min-w-0 px-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] font-bold text-gray-700">{TYPE_LABELS[dep.type]}</span>
                      {dep.cve && <span className="text-[10px] font-mono text-gray-400">{dep.cve}</span>}
                      {dep.cvss && <span className="text-[10px] font-black tabular-nums" style={{ color:cvssColor(dep.cvss) }}>CVSS {dep.cvss}</span>}
                    </div>
                    <p className="text-[10px] text-gray-500 mt-0.5 truncate">{dep.description.slice(0,70)}…</p>
                  </div>

                  {/* License */}
                  <div className="flex items-center justify-between gap-1 pl-1">
                    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded border truncate max-w-[80px]"
                      style={{ background:licStyle.bg, color:licStyle.text, borderColor:licStyle.border }}
                      title={dep.license_note}>
                      {dep.license_spdx ?? "Unknown"}
                    </span>
                    <svg className="text-gray-300 shrink-0" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
                      style={{ transform:isOpen?"rotate(180deg)":"none", transition:"transform 0.2s" }}>
                      <polyline points="6 9 12 15 18 9"/>
                    </svg>
                  </div>
                </div>

                {/* Expanded */}
                {isOpen && (
                  <div className="px-5 pb-5 pt-4 space-y-4 border-b border-gray-100" style={{ background:"rgba(248,250,252,0.8)" }}>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                      {/* Description */}
                      <div className="sm:col-span-2 space-y-3">
                        <div>
                          <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1.5">Description</p>
                          <p className="text-xs text-gray-600 leading-relaxed">{dep.description}</p>
                        </div>
                        {dep.exploit_public && (
                          <div className="flex items-start gap-2 bg-rose-50 border border-rose-200 rounded-xl px-3 py-2">
                            <span className="text-rose-600 text-sm shrink-0">⚡</span>
                            <div>
                              <p className="text-xs font-bold text-rose-800">Public exploit available</p>
                              <p className="text-[10px] text-rose-600 mt-0.5">{dep.exploit_detail}</p>
                            </div>
                          </div>
                        )}
                        {dep.cvss_vector && (
                          <div>
                            <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">CVSS Vector</p>
                            <code className="text-[10px] font-mono text-gray-600 bg-gray-100 px-2 py-1 rounded break-all">{dep.cvss_vector}</code>
                          </div>
                        )}
                      </div>

                      {/* Right panel: package health + license */}
                      <div className="space-y-3">
                        {/* Package health */}
                        <div>
                          <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Package Health</p>
                          <div className="space-y-1.5">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] text-gray-500">Health score</span>
                              {healthBar(dep.health_score)}
                            </div>
                            {dep.weekly_downloads && (
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] text-gray-500">Weekly downloads</span>
                                <span className="text-[10px] font-bold text-gray-700">{dep.weekly_downloads}</span>
                              </div>
                            )}
                            {dep.last_publish && (
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] text-gray-500">Last published</span>
                                <span className="text-[10px] font-mono text-gray-700">{dep.last_publish}</span>
                              </div>
                            )}
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] text-gray-500">Archived</span>
                              <span className={`text-[10px] font-bold ${dep.is_archived?"text-rose-600":"text-emerald-600"}`}>{dep.is_archived?"Yes — abandoned":"No"}</span>
                            </div>
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] text-gray-500">Deprecated</span>
                              <span className={`text-[10px] font-bold ${dep.is_deprecated?"text-amber-600":"text-emerald-600"}`}>{dep.is_deprecated?"Yes":"No"}</span>
                            </div>
                          </div>
                        </div>

                        {/* License */}
                        <div>
                          <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">License</p>
                          <span className="text-[10px] font-bold px-2 py-1 rounded-lg border"
                            style={{ background:LICENSE_STYLE[dep.license_risk].bg, color:LICENSE_STYLE[dep.license_risk].text, borderColor:LICENSE_STYLE[dep.license_risk].border }}>
                            {dep.license_spdx ?? "Unknown"}
                          </span>
                          {dep.license_note && <p className="text-[10px] text-gray-500 mt-1.5 leading-relaxed">{dep.license_note}</p>}
                        </div>
                      </div>
                    </div>

                    {/* Metadata row */}
                    <div className="flex items-center gap-4 flex-wrap pt-1 border-t border-gray-100">
                      <span className="text-[10px] text-gray-500">Found in: <span className="font-mono font-semibold">{dep.file_path.split("/").pop()}</span></span>
                      <span className="text-[10px] text-gray-500">Repo: {dep.repo.split("/").pop()} · PR #{dep.pr_number}</span>
                      {dep.is_transitive && <span className="text-[10px] text-gray-500">Pulled by: <span className="font-mono font-semibold">{dep.pulled_by}</span></span>}
                      <span className="text-[10px] text-gray-500">AI-introduced: {dep.ai_introduced?"Yes":"Unclear"}</span>
                      {dep.version_used && <span className="text-[10px] font-mono text-rose-600 bg-rose-50 px-1.5 py-0.5 rounded">{dep.version_used}</span>}
                      {dep.latest_version && <span className="text-[10px] font-mono text-emerald-600 bg-emerald-50 px-1.5 py-0.5 rounded">→ {dep.latest_version}</span>}
                    </div>

                    {/* Fix */}
                    {dep.fix && (
                      <div>
                        <div className="flex items-center justify-between mb-1.5">
                          <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">Remediation</p>
                          <button onClick={() => copy(dep.fix!, `fix-${dep.id}`)}
                            className="text-[9px] font-bold text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-100 hover:bg-indigo-100">
                            {copied === `fix-${dep.id}` ? "Copied ✓" : "Copy"}
                          </button>
                        </div>
                        <div className="bg-gray-900 rounded-xl px-4 py-3">
                          <code className="text-xs text-emerald-400 font-mono">{dep.fix}</code>
                        </div>
                      </div>
                    )}

                    {/* External links */}
                    <div className="flex items-center gap-2 flex-wrap">
                      {dep.cve && (
                        <a href={`https://nvd.nist.gov/vuln/detail/${dep.cve}`} target="_blank" rel="noopener noreferrer"
                          className="text-[10px] font-bold text-indigo-600 bg-indigo-50 border border-indigo-100 px-2.5 py-1 rounded-lg hover:bg-indigo-100 transition-colors">
                          {dep.cve} on NVD ↗
                        </a>
                      )}
                      {dep.cve && (
                        <a href={`https://github.com/advisories?query=${dep.cve}`} target="_blank" rel="noopener noreferrer"
                          className="text-[10px] font-bold text-gray-600 bg-gray-50 border border-gray-200 px-2.5 py-1 rounded-lg hover:bg-gray-100 transition-colors">
                          GitHub Advisory ↗
                        </a>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Footer note */}
        <div className="animate-fade-up flex items-start gap-3 bg-violet-50 border border-violet-100 rounded-xl px-4 py-3">
          <svg className="shrink-0 mt-0.5 text-violet-500" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <p className="text-xs text-violet-800 leading-relaxed">
            <span className="font-bold">How it works:</span> Imports are parsed from real scanned file content across Python, TypeScript, JS, Go, Java, Rust, Ruby, C# and PHP.
            Each import is cross-referenced against a {Object.keys(VULN_DB).length}-entry vulnerability database with CVE scores, license compliance, package health metrics, exploit availability, and transitive dependency tracking.
            SBOM exports are generated in SPDX 2.3 and CycloneDX 1.5 format.
          </p>
        </div>
      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
