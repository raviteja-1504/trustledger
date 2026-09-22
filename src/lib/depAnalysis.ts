/**
 * TrustLedger Dependency Manifest Parsers
 *
 * Parses package.json / requirements.txt / go.mod / composer.json / *.csproj (pom.xml/build.gradle
 * live in dependencyScan.ts instead, alongside the coordinate-string shape their parsers return)
 * into a plain list of declared packages (name + raw version spec). CVE/typosquat/reputation risk
 * analysis lives in dependencyScan.ts, which cross-references these against a live OSV.dev lookup
 * (src/lib/osvClient.ts) — this file no longer carries its own hardcoded vulnerability catalog.
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export interface PackageRef {
  name:    string;
  version: string;  // raw version spec e.g. "^1.2.3" or "*"
  dev:     boolean;
}

// ── Package.json / lockfile parsers ───────────────────────────────────────────

export function parsePackageJson(content: string): PackageRef[] {
  try {
    const pkg = JSON.parse(content) as Record<string, unknown>;
    const deps   = (pkg.dependencies    as Record<string, string>) ?? {};
    const devDeps = (pkg.devDependencies as Record<string, string>) ?? {};
    const refs: PackageRef[] = [];
    for (const [name, version] of Object.entries(deps))   refs.push({ name, version: String(version), dev: false });
    for (const [name, version] of Object.entries(devDeps)) refs.push({ name, version: String(version), dev: true });
    return refs;
  } catch { return []; }
}

export function parseRequirementsTxt(content: string): PackageRef[] {
  return content.split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#") && !l.startsWith("-"))
    .map(l => {
      const [nameVer] = l.split(";");
      // The comparator (==, >=, ~=, !=...) is captured together with the
      // version, not discarded -- an exact "==2.31.0" pin and a ">=2.31.0"
      // range aren't the same claim about what's actually installed, and
      // downstream OSV lookups need to tell them apart.
      const m = nameVer.match(/^([A-Za-z0-9_.\-[\]]+)\s*([=<>!~]+.*)?$/);
      return m ? { name: m[1].toLowerCase(), version: m[2]?.trim() ?? "*", dev: false } : null;
    })
    .filter((p): p is PackageRef => p !== null);
}

export function parseGoMod(content: string): PackageRef[] {
  return content.split("\n")
    .filter(l => /^\s+\S+\s+v/.test(l))
    .map(l => {
      const parts = l.trim().split(/\s+/);
      return parts.length >= 2 ? { name: parts[0], version: parts[1], dev: false } : null;
    })
    .filter((p): p is PackageRef => p !== null);
}

/** composer.json's require/require-dev -- same shape as package.json's dependencies/devDependencies,
 * with one composer-specific wrinkle: the "php" (and any "ext-*") entry is a platform/runtime
 * requirement, not a real Packagist package, and would 404 every OSV/Packagist lookup downstream. */
export function parseComposerJson(content: string): PackageRef[] {
  try {
    const pkg = JSON.parse(content) as Record<string, unknown>;
    const deps    = (pkg.require     as Record<string, string>) ?? {};
    const devDeps = (pkg["require-dev"] as Record<string, string>) ?? {};
    const isPlatformPkg = (name: string) => name === "php" || name.startsWith("ext-") || name.startsWith("lib-") || name === "composer-plugin-api" || name === "composer-runtime-api";
    const refs: PackageRef[] = [];
    for (const [name, version] of Object.entries(deps))    if (!isPlatformPkg(name)) refs.push({ name, version: String(version), dev: false });
    for (const [name, version] of Object.entries(devDeps)) if (!isPlatformPkg(name)) refs.push({ name, version: String(version), dev: true });
    return refs;
  } catch { return []; }
}

/** .csproj's <PackageReference Include="Name" Version="x.y.z" /> (both the
 * self-closing and open/close element forms -- both appear in real-world projects). A
 * <PackageReference Include="Name" /> with no Version (floating/central-package-management
 * reference) reports "*", the same "query package-wide" convention every other parser here uses
 * for an unpinned dependency. Regex-based, same reasoning as this codebase's existing
 * parsePomXml/parseBuildGradle: the element shape is simple and consistent enough not to need a
 * real XML parser. */
export function parseCsproj(content: string): PackageRef[] {
  const refs: PackageRef[] = [];
  const re = /<PackageReference\b([^>]*?)(\/>|>([\s\S]*?)<\/PackageReference>)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    const attrs = m[1];
    const body = m[3] ?? "";
    const name = /\bInclude\s*=\s*"([^"]+)"/.exec(attrs)?.[1] ?? /\bInclude\s*=\s*'([^']+)'/.exec(attrs)?.[1];
    if (!name) continue;
    // Version is usually an attribute, but MSBuild also allows a nested <Version> child element.
    const version = /\bVersion\s*=\s*"([^"]+)"/.exec(attrs)?.[1] ?? /\bVersion\s*=\s*'([^']+)'/.exec(attrs)?.[1]
      ?? /<Version>\s*([^<]+?)\s*<\/Version>/.exec(body)?.[1] ?? "*";
    refs.push({ name, version, dev: false });
  }
  return refs;
}

