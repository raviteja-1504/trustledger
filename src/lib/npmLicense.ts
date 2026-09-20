/**
 * npm registry license lookup — the one ecosystem OSV has no license data
 * for at all (a separate concern from vulnerability data regardless of the
 * OSV integration). Mirrors phantom-deps/page.tsx's existing npm-registry
 * fetch convention. Server-side only — not subject to the page CSP.
 */

import { cached, cacheKeys, TTL } from "@/lib/cache";

const NPM_REGISTRY = "https://registry.npmjs.org";
const FETCH_TIMEOUT_MS = 8000;

interface NpmPackageMeta { license?: string | { type?: string } }

function extractLicense(meta: NpmPackageMeta): string | null {
  if (!meta.license) return null;
  return typeof meta.license === "string" ? meta.license : meta.license.type ?? null;
}

async function fetchJson(url: string): Promise<NpmPackageMeta | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!res.ok) return null;
    return await res.json() as NpmPackageMeta;
  } catch {
    // Fail open — same convention as github.ts/osvClient.ts: a transient
    // registry blip shouldn't block the whole dependency report.
    return null;
  }
}

/**
 * Looks up an npm package's SPDX license string. Tries the exact version
 * first, falling back to the unversioned (latest metadata) endpoint when
 * that version isn't found — a 404 on one version doesn't mean the package
 * itself doesn't exist. Returns null (not "unknown") on any failure so
 * callers can distinguish "no data" from a real unknown-license package.
 */
export async function lookupNpmLicense(pkg: string, version?: string): Promise<string | null> {
  return cached(cacheKeys.npmLicense(pkg, version ?? ""), TTL.VULN_INTEL, async () => {
    // npm registry convention for scoped packages: escape only the slash
    // (%2F), leave "@" raw — matches npm-registry-fetch's own escaping.
    const encoded = pkg.startsWith("@") ? pkg.replace("/", "%2F") : encodeURIComponent(pkg);
    if (version) {
      const versioned = await fetchJson(`${NPM_REGISTRY}/${encoded}/${encodeURIComponent(version)}`);
      const lic = versioned && extractLicense(versioned);
      if (lic) return lic;
    }
    const unversioned = await fetchJson(`${NPM_REGISTRY}/${encoded}/latest`);
    return unversioned ? extractLicense(unversioned) : null;
  });
}
