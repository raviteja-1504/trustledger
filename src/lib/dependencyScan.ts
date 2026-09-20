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
import { lookupVulnerabilities, OSV_ECOSYSTEM, type OsvLookup, type OsvVulnerability } from "@/lib/osvClient";
import { lookupNpmLicense } from "@/lib/npmLicense";
import { mapWithConcurrency } from "@/lib/github";

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

// ── Non-CVE risk database ──────────────────────────────────────────────────────
// Everything CVE-shaped used to be hand-typed and stale here too -- that's
// now replaced by a live OSV.dev lookup in deriveFindings() below. What's
// left is risk OSV structurally cannot know about: a package that doesn't
// exist (hallucinated), a real package's malicious impostor (typosquat), or
// "no CVE was ever filed, but this is still a bad idea" opinions
// (unmaintained/outdated). buildFinding() below still reads this DB
// synchronously for the offline/demo-data path (dependencies/page.tsx's
// no-backend fallback) -- it has no live network path to fall back to.
export const NON_CVE_RISK_DB: Record<string, VulnEntry> = {
  // ── Python ────────────────────────────────────────────────────────────────
  "psycopg2":     { risk:"LOW",      type:"outdated",     safeVersion:"2.9.9",  description:"Older psycopg2 misses performance and security backports.", fix:"pip install 'psycopg2>=2.9.9'", license_spdx:"LGPL-3.0", license_risk:"review", license_note:"LGPL — dynamic linking is fine for most deployments.", weekly_downloads:"4M", last_publish:"2024-01-20", health_score:78, exploit_public:false },
  "numpy":        { risk:"LOW",      type:"outdated",     safeVersion:"1.26.4", description:"Older numpy release misses security backports and performance improvements.", fix:"pip install 'numpy>=1.26.4'", license_spdx:"BSD-3-Clause", license_risk:"safe", weekly_downloads:"40M", last_publish:"2024-02-25", health_score:96, exploit_public:false },
  "ml-utils-fast":{ risk:"CRITICAL", type:"hallucinated", description:"Does NOT exist on PyPI. AI hallucinated this name — any published version executes arbitrary code on install.", fix:"Remove import. Use scikit-learn or numpy instead.", license_spdx:undefined, license_risk:"block", license_note:"Non-existent package — legal status unknown", is_archived:false, health_score:0, exploit_public:true, exploit_detail:"Zero-day supply chain risk — name squatting trivial" },
  "stripe-client":{ risk:"CRITICAL", type:"typosquatting", description:"Typosquatting the official 'stripe' library. Known malicious package containing a credential harvester.", fix:"Use official 'stripe' package: pip install stripe>=7.0.0", license_spdx:undefined, license_risk:"block", license_note:"Malicious — do not use", health_score:0, exploit_public:true, exploit_detail:"Active credential harvester confirmed in PyPI reports" },

  // ── JavaScript / TypeScript ───────────────────────────────────────────────
  "moment":       { risk:"MEDIUM",  type:"unmaintained", description:"Moment.js is legacy and unmaintained since Sep 2022. AI still recommends it. Use date-fns or dayjs.", fix:"Replace with: npm install date-fns  OR  npm install dayjs", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"15M", last_publish:"2022-04-04", is_deprecated:true, health_score:30, exploit_public:false },
  "colors":       { risk:"HIGH",    type:"unmaintained", description:"Maintainer intentionally published malicious versions (infinite loop). Blacklisted by many registries.", fix:"Replace with: npm install chalk  OR  npm install picocolors", license_spdx:"MIT", license_risk:"review", license_note:"Intentional sabotage history — avoid in production", is_deprecated:true, health_score:10, exploit_public:true, exploit_detail:"v1.4.44-liberty-2 is intentionally malicious" },

  // ── C# ────────────────────────────────────────────────────────────────────
  "Newtonsoft.Json": { risk:"MEDIUM", type:"outdated", safeVersion:"13.0.3", description:"Older Newtonsoft.Json misses deserialization security hardening.", fix:"<PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />", license_spdx:"MIT", license_risk:"safe", weekly_downloads:"300M", last_publish:"2023-10-19", health_score:78, exploit_public:false },
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

// Shared between the offline/demo path (buildFinding, sync) and the live
// OSV-backed path (deriveFindings, async) below -- a NON_CVE_RISK_DB hit
// means the same thing regardless of which path produced it.
function nonCveEntryToFinding(pkg: string, entry: VulnEntry, eco: LangEcosystem, repo: string, filePath: string, prNumber: number, scanId: string, aiPct: number, isTransitive: boolean, pulledBy?: string): DepFinding {
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

/** Offline/demo-data path ONLY (dependencies/page.tsx's no-backend
 *  fallback) -- synchronous, so it can run in the browser with zero network
 *  calls. The live path (every real request) is deriveFindings() below,
 *  which additionally cross-references OSV.dev and the npm registry. */
export function buildFinding(pkg: string, eco: LangEcosystem, repo: string, filePath: string, prNumber: number, scanId: string, aiPct: number, isTransitive = false, pulledBy?: string): DepFinding | null {
  const entry = NON_CVE_RISK_DB[pkg];
  if (!entry) return null;
  if (entry.type === "safe") return null;
  return nonCveEntryToFinding(pkg, entry, eco, repo, filePath, prNumber, scanId, aiPct, isTransitive, pulledBy);
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

interface DeclaredPackage { name: string; version: string }

// Manifest files declare dependencies (and, unlike a source import
// statement, an actual version spec) directly — parse those instead of
// scanning for import statements. pom.xml/build.gradle coordinates carry no
// parseable version today, so those report "" (package-wide OSV lookup).
function manifestPackages(filePath: string, content: string): DeclaredPackage[] | null {
  const name = filePath.toLowerCase();
  if (name.endsWith("package.json"))     return parsePackageJson(content).map(p => ({ name: p.name, version: p.version }));
  if (name.endsWith("requirements.txt")) return parseRequirementsTxt(content).map(p => ({ name: p.name, version: p.version }));
  if (name.endsWith("go.mod"))           return parseGoMod(content).map(p => ({ name: p.name, version: p.version }));
  if (name.endsWith("pom.xml"))          return parsePomXml(content).map(coord => ({ name: coord, version: "" }));
  if (name.endsWith("build.gradle") || name.endsWith("build.gradle.kts")) return parseBuildGradle(content).map(coord => ({ name: coord, version: "" }));
  return null;
}

/** Strips range operators (npm's ^/~/>=/etc., Python's ==/>=/~=/etc.) down
 *  to a bare version OSV can query against. "*"/"" query package-wide.
 *  Using the lower bound of a range (rather than resolving the actual
 *  installed version, which would need lockfile parsing -- deferred) biases
 *  toward over-reporting older, more heavily-CVE'd versions -- the correct
 *  direction to err for a security tool, not the incorrect one. */
function versionForOsvQuery(raw: string): string {
  if (!raw || raw === "*") return "";
  const firstToken = raw.trim().split(/\s+/)[0];
  return firstToken.replace(/^[\^~=<>!]+/, "");
}

interface PackageOccurrence {
  pkg: string; version: string; eco: LangEcosystem;
  repo: string; filePath: string; prNumber: number; scanId: string; aiPct: number;
  isTransitive: boolean; pulledBy?: string;
}

const SEVERITY_ORDER: Record<OsvVulnerability["severity"], number> = { LOW:0, MEDIUM:1, HIGH:2, CRITICAL:3 };

function pickWorstVuln(vulns: OsvVulnerability[]): OsvVulnerability | undefined {
  return vulns.reduce<OsvVulnerability | undefined>(
    (worst, v) => (!worst || SEVERITY_ORDER[v.severity] > SEVERITY_ORDER[worst.severity]) ? v : worst,
    undefined,
  );
}

function liveFindingFor(
  occ: PackageOccurrence,
  osvResults: Map<string, OsvVulnerability[]>,
  licenses: Map<string, string | null>,
): DepFinding {
  const nonCve = NON_CVE_RISK_DB[occ.pkg];
  if (nonCve && nonCve.type !== "safe") {
    return nonCveEntryToFinding(occ.pkg, nonCve, occ.eco, occ.repo, occ.filePath, occ.prNumber, occ.scanId, occ.aiPct, occ.isTransitive, occ.pulledBy);
  }

  const osvEco  = OSV_ECOSYSTEM[occ.eco];
  const version = versionForOsvQuery(occ.version);
  const vulns   = osvEco ? osvResults.get(`${osvEco}|${occ.pkg}|${version}`) ?? [] : [];
  const worst   = pickWorstVuln(vulns);

  const license = licenses.get(occ.pkg) ?? undefined;
  const licClass = classifyLicense(license);
  const id = `${occ.scanId}::${occ.filePath}::${occ.pkg}${occ.isTransitive?"-t":""}`;
  const base = {
    id, package_name: occ.pkg, ecosystem: occ.eco, manager: ECO_MANAGER[occ.eco],
    repo: occ.repo, file_path: occ.filePath, pr_number: occ.prNumber, scan_id: occ.scanId,
    ai_introduced: occ.aiPct > 0.4, is_transitive: occ.isTransitive, pulled_by: occ.pulledBy,
    license_spdx: license ?? licClass.label, license_risk: licClass.risk, license_note: licClass.note,
    is_archived: false, is_deprecated: false,
  };

  if (worst) {
    return {
      ...base,
      version_used:   occ.version || "unknown",
      latest_version: worst.fixedIn,
      risk:           worst.severity,
      type:           occ.isTransitive ? "transitive" : "vulnerable",
      description:    worst.summary || `${worst.id} affects this package version.`,
      fix:            worst.fixedIn ? `Update ${occ.pkg} to ${worst.fixedIn} or later` : undefined,
      cve:            worst.aliases.find(a => a.startsWith("CVE-")) ?? worst.id,
      exploit_public: false,
      health_score:   50,
    };
  }

  // Clean package -- synthesize a `safe` finding so SBOM export lists every
  // declared package, not just the flagged ones (a free side effect of this
  // restructuring, not extra work -- generateSPDX/generateCycloneDX already
  // just serialize whatever's in the findings array).
  return {
    ...base,
    version_used:   occ.version || "unknown",
    risk:           "SAFE",
    type:           occ.isTransitive ? "transitive" : "safe",
    description:    "No known vulnerabilities found via OSV.dev.",
    exploit_public: false,
    health_score:   85,
  };
}

/**
 * The live, server-side findings pipeline (api/dependencies/route.ts) --
 * cross-references every declared/imported package against NON_CVE_RISK_DB
 * (hallucinated/typosquat/unmaintained-with-no-CVE) and, for everything
 * else, a live OSV.dev vulnerability lookup + npm registry license lookup.
 * NON_CVE_RISK_DB takes precedence: OSV can't know about a package that
 * doesn't exist or a real package's abandonment status.
 */
export async function deriveFindings(scans: ScanForDeps[]): Promise<DepFinding[]> {
  const occurrences: PackageOccurrence[] = [];
  for (const scan of scans) {
    for (const file of scan.files) {
      if (!file.content) continue;
      const eco = detectEcosystem(file.file_path);
      if (eco === "unknown") continue;
      const declared = manifestPackages(file.file_path, file.content);
      const refs: DeclaredPackage[] = declared ?? parseImports(file.content, eco).map(name => ({ name, version: "" }));
      for (const ref of refs) {
        occurrences.push({ pkg: ref.name, version: ref.version, eco, repo: scan.repo, filePath: file.file_path, prNumber: scan.pr_number, scanId: scan.scan_id, aiPct: file.ai_percentage, isTransitive: false });
        for (const transitive of TRANSITIVE_MAP[ref.name] ?? []) {
          occurrences.push({ pkg: transitive, version: "", eco, repo: scan.repo, filePath: file.file_path, prNumber: scan.pr_number, scanId: scan.scan_id, aiPct: file.ai_percentage, isTransitive: true, pulledBy: ref.name });
        }
      }
    }
  }

  const lookups = new Map<string, OsvLookup>();
  for (const occ of occurrences) {
    if (NON_CVE_RISK_DB[occ.pkg]) continue;
    const osvEco = OSV_ECOSYSTEM[occ.eco];
    if (!osvEco) continue;
    const version = versionForOsvQuery(occ.version);
    lookups.set(`${osvEco}|${occ.pkg}|${version}`, { ecosystem: osvEco, name: occ.pkg, version });
  }
  // osvClient/npmLicense already fail open internally (never throw, per
  // their own contract) -- this second layer guards against a regression
  // there taking down the whole dependency report instead of just degrading
  // it, matching this codebase's established fail-open philosophy.
  let osvResults = new Map<string, OsvVulnerability[]>();
  if (lookups.size > 0) {
    try {
      osvResults = await lookupVulnerabilities(Array.from(lookups.values()));
    } catch { /* degrade: every package below falls through to a "safe" finding */ }
  }

  // License: npm only this phase (OSV has no license data regardless).
  const licenseTargets = new Map<string, string>();
  for (const occ of occurrences) {
    if (NON_CVE_RISK_DB[occ.pkg]) continue;
    if (occ.eco !== "javascript" && occ.eco !== "typescript") continue;
    if (!licenseTargets.has(occ.pkg)) licenseTargets.set(occ.pkg, versionForOsvQuery(occ.version));
  }
  const licenses = new Map<string, string | null>();
  try {
    await mapWithConcurrency(Array.from(licenseTargets.entries()), 8, async ([pkg, version]) => {
      licenses.set(pkg, await lookupNpmLicense(pkg, version || undefined));
    });
  } catch { /* degrade: findings render with an unknown license instead of failing */ }

  const findings: DepFinding[] = [];
  const seen = new Set<string>();
  for (const occ of occurrences) {
    const f = liveFindingFor(occ, osvResults, licenses);
    if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); }
  }
  return findings;
}
