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

import { parsePackageJson, parseRequirementsTxt, parseGoMod, parseComposerJson, parseCsproj } from "@/lib/depAnalysis";
import { lookupVulnerabilities, OSV_ECOSYSTEM, type OsvLookup, type OsvVulnerability } from "@/lib/osvClient";
import { lookupNpmLicense } from "@/lib/npmLicense";
import { mapWithConcurrency } from "@/lib/github";
import { isDockerfilePath } from "@/lib/scannableFiles";
import { extractFromImageRefs } from "@/lib/containerDockerfile";
import { matchBaseImageProfile, packagesForProfile } from "@/lib/baseImageProfiles";
import { analyzeDependencyReachability, type DepReachability } from "@/lib/depReachability";
import {
  compareVersions, lockfileKind, parseCargoToml, parseGemfile, parseLockfile, parsePipfile, parsePyproject,
  type LockEcosystem, type LockedPackage,
} from "@/lib/lockfiles";

// ── Types ──────────────────────────────────────────────────────────────────────

export type DepRisk       = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE";
export type DepType       = "vulnerable" | "unmaintained" | "hallucinated" | "typosquatting" | "outdated" | "transitive" | "safe";
// "docker" -- Decision 2, base-image OS packages -- is deliberately its own
// ecosystem, not folded into an existing one: its OSV query ecosystem
// (Alpine:v3.19/Debian:12/etc, carried per-occurrence via
// PackageOccurrence.osvEcosystemOverride) is release-qualified and doesn't
// fit OSV_ECOSYSTEM's flat LangEcosystem-keyed table below.
export type LangEcosystem = "python" | "javascript" | "typescript" | "go" | "java" | "rust" | "ruby" | "csharp" | "php" | "docker" | "unknown";
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
  /** For a package with a known vulnerability: is its code used, and reachably (see depReachability.ts)? */
  reachability?: DepReachability;
  /** Runtime dependency, or only used to develop / test / build (lower priority). */
  scope?: "runtime" | "dev";
  /** Where version_used comes from: the lockfile (exactly what's installed), the manifest's range (its lowest
   *  allowed version is what was checked), or nothing (an import, or no version given -- every version checked). */
  version_source?: "lockfile" | "manifest" | "none";
  /** The manifest's version range, when version_used was resolved from a lockfile or taken from that range. */
  version_range?: string;
  /** Every advisory affecting this version, worst first (`cve` / `risk` / `description` are the worst one's). */
  advisories?: Array<{ id: string; aliases: string[]; severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"; summary?: string; fixedIn?: string }>;
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
  java:"maven", rust:"cargo", ruby:"bundler", csharp:"NuGet", php:"composer",
  docker:"OS package", unknown:"unknown",
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
    } else if (eco === "csharp") {
      // Namespace prefix only (e.g. "Newtonsoft.Json") -- a `using` directive alone can't reliably
      // identify the exact NuGet package id, so this never matches a curated NuGet-id-keyed DB entry
      // (same caveat as the Java branch above). Best-effort signal only; parseCsproj is the real
      // source of truth for CVE matching when a .csproj is present.
      const m = t.match(/^using\s+(?:static\s+)?([\w.]+)\s*;/);
      if (m) { const parts = m[1].split("."); if (parts.length >= 2) pkgs.add(parts.slice(0, 2).join(".")); else pkgs.add(parts[0]); }
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

interface DeclaredPackage { name: string; version: string; dev?: boolean }

// Manifest files declare dependencies (and, unlike a source import
// statement, an actual version spec) directly — parse those instead of
// scanning for import statements. pom.xml/build.gradle coordinates carry no
// parseable version today, so those report "" (package-wide OSV lookup).
export function manifestPackages(filePath: string, content: string): DeclaredPackage[] | null {
  const name = filePath.toLowerCase();
  const b = name.split("/").pop()!;
  if (b === "package.json")              return parsePackageJson(content).map(p => ({ name: p.name, version: p.version, dev: p.dev }));
  if (/(^|[-_.])requirements([-_.][\w-]+)?\.txt$/.test(b)) {
    const dev = /dev|test|lint|doc/.test(b);
    return parseRequirementsTxt(content).map(p => ({ name: p.name, version: p.version === "*" ? "" : p.version, dev }));
  }
  if (b === "go.mod")                    return parseGoMod(content).map(p => ({ name: p.name, version: p.version, dev: false }));
  if (b === "pom.xml")                   return parsePomXml(content).map(coord => ({ name: coord, version: "" }));
  if (b === "build.gradle" || b === "build.gradle.kts") return parseBuildGradle(content).map(coord => ({ name: coord, version: "" }));
  if (b === "composer.json")             return parseComposerJson(content).map(p => ({ name: p.name, version: p.version, dev: p.dev }));
  if (b.endsWith(".csproj"))             return parseCsproj(content).map(p => ({ name: p.name, version: p.version, dev: false }));
  if (b === "cargo.toml")                return parseCargoToml(content);
  if (b === "gemfile")                   return parseGemfile(content);
  if (b === "pyproject.toml")            return parsePyproject(content);
  if (b === "pipfile")                   return parsePipfile(content);
  return null;
}

/** Ecosystem of a manifest the scanner understands (detectEcosystem guesses from names; this is exact). */
function manifestEcosystem(filePath: string): LangEcosystem {
  const b = filePath.toLowerCase().split("/").pop()!;
  if (b === "pipfile" || b === "pyproject.toml" || b.endsWith(".txt")) return "python";
  if (b === "gemfile") return "ruby";
  if (b === "cargo.toml") return "rust";
  return detectEcosystem(filePath);
}

const LOCK_FOR: Partial<Record<LangEcosystem, LockEcosystem>> = { javascript: "npm", typescript: "npm", python: "python", rust: "rust", ruby: "ruby", php: "php" };
const ECO_FOR_LOCK: Record<LockEcosystem, LangEcosystem> = { npm: "javascript", python: "python", rust: "rust", ruby: "ruby", php: "php" };
const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
/** Normalised name for matching a manifest entry to a lockfile entry (PyPI names are case/[-_.]-insensitive). */
const lockKey = (eco: LockEcosystem, name: string) => (eco === "python" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name);

/** Imports that are part of the language, never packages -- looked up as packages they produced false findings
 *  (PyPI and npm both have packages named after stdlib modules). */
const NODE_BUILTINS = new Set(["assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process", "punycode", "querystring", "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib"]);
const PY_STDLIB = new Set(["abc", "argparse", "array", "ast", "asyncio", "base64", "binascii", "bisect", "builtins", "bz2", "calendar", "cmath", "codecs", "collections", "concurrent", "configparser", "contextlib", "contextvars", "copy", "csv", "ctypes", "dataclasses", "datetime", "decimal", "difflib", "dis", "email", "enum", "errno", "faulthandler", "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt", "getpass", "gettext", "glob", "gzip", "hashlib", "heapq", "hmac", "html", "http", "imaplib", "importlib", "inspect", "io", "ipaddress", "itertools", "json", "keyword", "linecache", "locale", "logging", "lzma", "math", "mimetypes", "multiprocessing", "numbers", "operator", "os", "pathlib", "pickle", "platform", "pprint", "profile", "queue", "random", "re", "sched", "secrets", "select", "selectors", "shelve", "shlex", "shutil", "signal", "smtplib", "socket", "socketserver", "sqlite3", "ssl", "stat", "statistics", "string", "struct", "subprocess", "sys", "sysconfig", "tarfile", "tempfile", "textwrap", "threading", "time", "timeit", "tkinter", "token", "tokenize", "tomllib", "traceback", "types", "typing", "unicodedata", "unittest", "urllib", "uuid", "venv", "warnings", "weakref", "webbrowser", "xml", "xmlrpc", "zipfile", "zipimport", "zlib", "__future__"]);
export function isBuiltinImport(name: string, eco: LangEcosystem): boolean {
  if (eco === "javascript" || eco === "typescript") return name.startsWith("node:") || NODE_BUILTINS.has(name.split("/")[0]);
  if (eco === "python") return PY_STDLIB.has(name.split(".")[0]);
  return false;
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
  dev?: boolean;
  versionSource?: "lockfile" | "manifest" | "none";
  versionRange?: string;
  // Decision 2: the exact, release-qualified OSV ecosystem string
  // (e.g. "Alpine:v3.19") for a base-image OS package occurrence --
  // bypasses OSV_ECOSYSTEM's flat LangEcosystem-keyed lookup below, since
  // baseImageProfiles.ts's curated profile already carries the precise
  // string OSV needs. Unset for every other ecosystem.
  osvEcosystemOverride?: string;
}

const SEVERITY_ORDER: Record<OsvVulnerability["severity"], number> = { LOW:0, MEDIUM:1, HIGH:2, CRITICAL:3 };

function pickWorstVuln(vulns: OsvVulnerability[]): OsvVulnerability | undefined {
  return vulns.reduce<OsvVulnerability | undefined>(
    (worst, v) => (!worst || SEVERITY_ORDER[v.severity] > SEVERITY_ORDER[worst.severity]) ? v : worst,
    undefined,
  );
}

/** A NON_CVE_RISK_DB entry that applies to this occurrence. "Outdated" only applies when the version in use is
 *  known and older than the safe one -- it used to fire for any version, flagging up-to-date packages. */
export function nonCveFor(pkg: string, version: string): VulnEntry | null {
  const e = NON_CVE_RISK_DB[pkg];
  if (!e || e.type === "safe") return null;
  if (e.type === "outdated") {
    const v = versionForOsvQuery(version);
    return v && e.safeVersion && compareVersions(v, e.safeVersion) < 0 ? e : null;
  }
  return e;
}

/** The lowest version that fixes EVERY advisory (the worst one's fix can leave others open); undefined when any
 *  advisory has no fixed version. */
export function fixingVersion(vulns: readonly OsvVulnerability[]): string | undefined {
  if (vulns.length === 0 || vulns.some(v => !v.fixedIn)) return undefined;
  return vulns.map(v => v.fixedIn!).reduce((a, b) => (compareVersions(a, b) >= 0 ? a : b));
}

function liveFindingFor(
  occ: PackageOccurrence,
  osvResults: Map<string, OsvVulnerability[]>,
  licenses: Map<string, string | null>,
): DepFinding {
  const where = {
    scope: occ.dev ? "dev" as const : "runtime" as const,
    version_source: occ.versionSource ?? (occ.version ? "manifest" as const : "none" as const),
    version_range: occ.versionRange,
  };
  const nonCve = nonCveFor(occ.pkg, occ.version);
  if (nonCve) {
    return { ...nonCveEntryToFinding(occ.pkg, nonCve, occ.eco, occ.repo, occ.filePath, occ.prNumber, occ.scanId, occ.aiPct, occ.isTransitive, occ.pulledBy), ...where };
  }

  const osvEco  = occ.osvEcosystemOverride ?? OSV_ECOSYSTEM[occ.eco];
  const version = versionForOsvQuery(occ.version);
  const vulns   = osvEco ? osvResults.get(`${osvEco}|${occ.pkg}|${version}`) ?? [] : [];
  const worst   = pickWorstVuln(vulns);

  const license = licenses.get(occ.pkg) ?? undefined;
  const licClass = classifyLicense(license);
  const id = occ.isTransitive
    ? `${occ.scanId}::${occ.filePath}::${occ.pkg}@${occ.version}-t`
    : `${occ.scanId}::${occ.filePath}::${occ.pkg}`;
  const base = {
    id, package_name: occ.pkg, ecosystem: occ.eco, manager: ECO_MANAGER[occ.eco],
    repo: occ.repo, file_path: occ.filePath, pr_number: occ.prNumber, scan_id: occ.scanId,
    ai_introduced: occ.aiPct > 0.4, is_transitive: occ.isTransitive, pulled_by: occ.pulledBy,
    license_spdx: license ?? licClass.label, license_risk: licClass.risk, license_note: licClass.note,
    is_archived: false, is_deprecated: false,
    ...where,
  };

  if (worst) {
    const fixIn = fixingVersion(vulns);
    const sorted = [...vulns].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
    return {
      ...base,
      version_used:   occ.version || "unknown",
      latest_version: fixIn ?? worst.fixedIn,
      risk:           worst.severity,
      type:           occ.isTransitive ? "transitive" : "vulnerable",
      description:    (worst.summary || `${worst.id} affects this package version.`) + (vulns.length > 1 ? ` (+${vulns.length - 1} more advisor${vulns.length === 2 ? "y" : "ies"})` : ""),
      fix:            fixIn ? `Update ${occ.pkg} to ${fixIn} or later${vulns.length > 1 ? ` (fixes all ${vulns.length} advisories)` : ""}`
        : worst.fixedIn ? `Update ${occ.pkg} to ${worst.fixedIn} or later (fixes the most severe; ${vulns.filter(v => !v.fixedIn).length} advisor${vulns.filter(v => !v.fixedIn).length === 1 ? "y has" : "ies have"} no fix yet)`
        : undefined,
      cve:            worst.aliases.find(a => a.startsWith("CVE-")) ?? worst.id,
      advisories:     sorted.map(v => ({ id: v.id, aliases: v.aliases, severity: v.severity, summary: v.summary, fixedIn: v.fixedIn })),
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

/** Reachability of a vulnerable occurrence in its own scan's files: the package itself, with every vulnerable
 * function its advisories name; a transitive package through the direct dependency that pulls it in. */
function reachabilityFor(
  occ: PackageOccurrence, osvResults: Map<string, OsvVulnerability[]>,
  files: ScanForDeps["files"], memo: Map<string, DepReachability>,
): DepReachability {
  const key = `${occ.scanId}|${occ.eco}|${occ.pkg}|${occ.pulledBy ?? ""}|${occ.version}`;
  const hit = memo.get(key);
  if (hit) return hit;
  let result: DepReachability;
  if (occ.isTransitive && occ.pulledBy) {
    const parent = analyzeDependencyReachability(occ.pulledBy, occ.eco, files);
    result = { ...parent, via: occ.pulledBy, summary: `Pulled in by ${occ.pulledBy}: ${parent.summary}` };
  } else {
    const osvEco = occ.osvEcosystemOverride ?? OSV_ECOSYSTEM[occ.eco];
    const vulns = osvEco ? osvResults.get(`${osvEco}|${occ.pkg}|${versionForOsvQuery(occ.version)}`) ?? [] : [];
    // Symbols only count when EVERY advisory names them: one advisory without a list could be in any function.
    const symbols = vulns.length && vulns.every(v => v.affectedSymbols?.length) ? vulns.flatMap(v => v.affectedSymbols!) : [];
    result = analyzeDependencyReachability(occ.pkg, occ.eco, files, symbols);
  }
  memo.set(key, result);
  return result;
}

/** Locked packages read per lockfile, at most (a monorepo lockfile can list tens of thousands). */
export const MAX_LOCKED_PER_FILE = 5000;

/**
 * Every package a scan's files declare, with the most exact version available:
 *   1. Manifests (package.json, requirements*.txt, pyproject.toml, Pipfile, go.mod, pom.xml, build.gradle,
 *      composer.json, *.csproj, Cargo.toml, Gemfile). A declared package's version comes from the nearest lockfile
 *      of the same ecosystem (same directory or an ancestor) when there is one -- exactly what's installed --
 *      otherwise from the manifest's range (its lowest allowed version is what gets checked).
 *   2. Lockfiles: every other locked package is a transitive dependency, at its locked version (including an
 *      older nested copy of a direct dependency). This replaces a hard-coded "axios pulls in follow-redirects"
 *      table, which checked made-up transitives with no version against every advisory ever filed.
 *   3. Imports, only for a language with no manifest or lockfile in the scan -- never standard-library or built-in
 *      modules (stdlib names like "json" or "path" exist as unrelated public packages).
 */
export function packageOccurrences(scan: ScanForDeps): PackageOccurrence[] {
  const out: PackageOccurrence[] = [];
  const common = (f: ScanForDeps["files"][number]) => ({ repo: scan.repo, prNumber: scan.pr_number, scanId: scan.scan_id, aiPct: f.ai_percentage });
  const files = scan.files.filter(f => !!f.content);

  interface Lock { path: string; dir: string; eco: LockEcosystem; packages: LockedPackage[]; file: ScanForDeps["files"][number] }
  const locks: Lock[] = [];
  for (const f of files) {
    const lf = lockfileKind(f.file_path) ? parseLockfile(f.file_path, f.content!) : null;
    if (lf) locks.push({ path: f.file_path, dir: dirOf(f.file_path), eco: lf.ecosystem, packages: lf.packages.slice(0, MAX_LOCKED_PER_FILE), file: f });
  }
  const nearestLock = (dir: string, eco: LockEcosystem): Lock | undefined =>
    locks.filter(l => l.eco === eco && (l.dir === "" || dir === l.dir || dir.startsWith(`${l.dir}/`))).sort((a, b) => b.dir.length - a.dir.length)[0];

  const manifests: Array<{ file: ScanForDeps["files"][number]; eco: LangEcosystem; refs: DeclaredPackage[] }> = [];
  for (const f of files) {
    if (lockfileKind(f.file_path)) continue;
    const refs = manifestPackages(f.file_path, f.content!);
    if (refs) manifests.push({ file: f, eco: manifestEcosystem(f.file_path), refs });
  }

  // 1. Declared packages, resolved through the nearest lockfile.
  const pickedFromLock = new Map<Lock, Set<string>>();
  for (const m of manifests) {
    const leco = LOCK_FOR[m.eco];
    const lock = leco ? nearestLock(dirOf(m.file.file_path), leco) : undefined;
    for (const ref of m.refs) {
      let version = ref.version, source: PackageOccurrence["versionSource"] = ref.version ? "manifest" : "none";
      if (lock && leco) {
        const matches = lock.packages.filter(p => lockKey(leco, p.name) === lockKey(leco, ref.name));
        const pick = matches.find(p => p.direct) ?? matches.find(p => p.direct === undefined && !p.parent) ?? matches[0];
        if (pick) {
          version = pick.version; source = "lockfile";
          const picked = pickedFromLock.get(lock) ?? new Set<string>();
          picked.add(`${pick.name}@${pick.version}`);
          pickedFromLock.set(lock, picked);
        }
      }
      out.push({
        pkg: ref.name, version, eco: m.eco, filePath: m.file.file_path, isTransitive: false, dev: ref.dev,
        versionSource: source, versionRange: ref.version || undefined, ...common(m.file),
      });
    }
  }

  // 2. Everything else in each lockfile.
  for (const lock of locks) {
    const picked = pickedFromLock.get(lock) ?? new Set<string>();
    const hasManifest = manifests.some(m => LOCK_FOR[m.eco] === lock.eco && nearestLock(dirOf(m.file.file_path), lock.eco) === lock);
    for (const p of lock.packages) {
      if (picked.has(`${p.name}@${p.version}`)) continue;
      // With a manifest, anything it didn't declare is transitive; without one, trust the lockfile's own flag.
      const direct = !hasManifest && p.direct === true;
      out.push({
        pkg: p.name, version: p.version, eco: ECO_FOR_LOCK[lock.eco], filePath: lock.path, isTransitive: !direct,
        pulledBy: p.parent, dev: p.dev, versionSource: "lockfile", ...common(lock.file),
      });
    }
  }

  // 3. Imports, for languages nothing declares.
  const covered = new Set<LangEcosystem>();
  for (const m of manifests) covered.add(m.eco);
  for (const l of locks) covered.add(ECO_FOR_LOCK[l.eco]);
  if (covered.has("javascript") || covered.has("typescript")) { covered.add("javascript"); covered.add("typescript"); }
  for (const f of files) {
    if (lockfileKind(f.file_path) || manifestPackages(f.file_path, f.content!)) continue;
    const eco = detectEcosystem(f.file_path);
    if (eco === "unknown" || covered.has(eco)) continue;
    for (const name of parseImports(f.content!, eco)) {
      if (isBuiltinImport(name, eco)) continue;
      out.push({ pkg: name, version: "", eco, filePath: f.file_path, isTransitive: false, versionSource: "none", ...common(f) });
    }
  }
  return out;
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

      // Decision 2: base-image OS packages -- a structurally different
      // source shape from every other ecosystem here (not a dependency
      // manifest or import statement, a Dockerfile FROM line resolved
      // through baseImageProfiles.ts's curated OS-release mapping).
      // Handled as its own branch ahead of detectEcosystem's normal
      // dispatch, since "docker" isn't a real source detectEcosystem/
      // manifestPackages/parseImports know how to route on their own.
      if (isDockerfilePath(file.file_path)) {
        for (const { ref } of extractFromImageRefs(file.content)) {
          const profile = matchBaseImageProfile(ref);
          if (!profile) continue; // not in the curated table -- silently skip, never guess
          for (const pkg of packagesForProfile(profile)) {
            occurrences.push({
              pkg, version: "", eco: "docker",
              repo: scan.repo, filePath: file.file_path, prNumber: scan.pr_number, scanId: scan.scan_id,
              aiPct: file.ai_percentage, isTransitive: false,
              osvEcosystemOverride: profile.osvEcosystem,
            });
          }
        }
      }
    }
    // Manifests, lockfiles and (only where there are neither) imports.
    occurrences.push(...packageOccurrences(scan));
  }

  const lookups = new Map<string, OsvLookup>();
  for (const occ of occurrences) {
    if (nonCveFor(occ.pkg, occ.version)) continue;
    const osvEco = occ.osvEcosystemOverride ?? OSV_ECOSYSTEM[occ.eco];
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
    if (nonCveFor(occ.pkg, occ.version)) continue;
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
  const filesByScan = new Map(scans.map(s => [s.scan_id, s.files]));
  const reachMemo = new Map<string, DepReachability>();
  for (const occ of occurrences) {
    const f = liveFindingFor(occ, osvResults, licenses);
    if (seen.has(f.id)) continue;
    seen.add(f.id);
    // Only a real advisory makes reachability worth a verdict: it ranks WHICH vulnerable packages to fix first.
    if (f.cve && f.risk !== "SAFE") f.reachability = reachabilityFor(occ, osvResults, filesByScan.get(occ.scanId) ?? [], reachMemo);
    findings.push(f);
  }
  return findings;
}
