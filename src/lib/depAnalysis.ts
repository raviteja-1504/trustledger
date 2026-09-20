/**
 * TrustLedger Dependency Manifest Parsers
 *
 * Parses package.json / requirements.txt / go.mod into a plain list of
 * declared packages (name + raw version spec). CVE/typosquat/reputation
 * risk analysis lives in dependencyScan.ts, which cross-references these
 * against a live OSV.dev lookup (src/lib/osvClient.ts) — this file no
 * longer carries its own hardcoded vulnerability catalog.
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

