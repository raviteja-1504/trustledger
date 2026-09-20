/**
 * OSV.dev (Open Source Vulnerabilities) client — live CVE/GHSA ground truth,
 * replacing the hand-typed, stale CVE lists this codebase used to carry
 * (see dependencyScan.ts's NON_CVE_RISK_DB for what's intentionally NOT
 * replaced: hallucinated/typosquat/unmaintained signals OSV can't know about).
 *
 * OSV has no batch-detail endpoint — POST /v1/querybatch returns only vuln
 * IDs per query, so a detail fetch per unique ID is required to get
 * severity/summary/aliases. Both steps follow this codebase's github.ts
 * conventions: AbortSignal timeout, try/catch fail-open, mapWithConcurrency
 * for bounded parallelism.
 */

import { mapWithConcurrency } from "@/lib/github";
import { cached, cacheGet, cacheSet, cacheKeys, TTL } from "@/lib/cache";
import type { LangEcosystem } from "@/lib/dependencyScan";

const OSV_API = "https://api.osv.dev";
const QUERY_CHUNK_SIZE = 500;
const DETAIL_CONCURRENCY = 10;
const FETCH_TIMEOUT_MS = 8000;

/** This codebase's ecosystem names → OSV's proper-noun ecosystem strings.
 *  "unknown" and anything unmapped is filtered out by the caller before a
 *  lookup is ever built — never sent to OSV. */
export const OSV_ECOSYSTEM: Partial<Record<LangEcosystem, string>> = {
  javascript: "npm",
  typescript: "npm",
  python:     "PyPI",
  go:         "Go",
  java:       "Maven",
  rust:       "crates.io",
  ruby:       "RubyGems",
  csharp:     "NuGet",
  php:        "Packagist",
};

export interface OsvLookup {
  ecosystem: string;  // an OSV_ECOSYSTEM value, not a LangEcosystem
  name:      string;
  version:   string;  // exact version to check; "" queries package-wide
}

export interface OsvVulnerability {
  id:       string;
  aliases:  string[];   // CVE ids etc.
  summary?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  fixedIn?: string;
}

interface OsvQueryBatchResult { results: Array<{ vulns?: Array<{ id: string }> }> }
interface OsvVulnDetail {
  id: string;
  aliases?: string[];
  summary?: string;
  database_specific?: { severity?: string };
  affected?: Array<{ ranges?: Array<{ events?: Array<{ fixed?: string }> }> }>;
}

function mapSeverity(detail: OsvVulnDetail): OsvVulnerability["severity"] {
  const dbSev = detail.database_specific?.severity?.toUpperCase();
  if (dbSev === "MODERATE") return "MEDIUM"; // GHSA's term for OSV/CVSS's "MEDIUM"
  if (dbSev === "CRITICAL" || dbSev === "HIGH" || dbSev === "MEDIUM" || dbSev === "LOW") return dbSev;
  return "MEDIUM"; // OSV entries without a database_specific.severity still warrant a real, unignorable finding
}

function extractFixedIn(detail: OsvVulnDetail): string | undefined {
  for (const affected of detail.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return undefined;
}

function lookupKey(l: OsvLookup): string {
  return `${l.ecosystem}|${l.name}|${l.version}`;
}

async function fetchVulnDetail(id: string): Promise<OsvVulnerability | null> {
  return cached(cacheKeys.osvVulnId(id), TTL.VULN_INTEL, async () => {
    try {
      const res = await fetch(`${OSV_API}/v1/vulns/${id}`, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
      if (!res.ok) return null;
      const detail = await res.json() as OsvVulnDetail;
      return {
        id:       detail.id,
        aliases:  detail.aliases ?? [],
        summary:  detail.summary,
        severity: mapSeverity(detail),
        fixedIn:  extractFixedIn(detail),
      };
    } catch {
      // Fail open — same reasoning as github.ts's getPRHeadSha: a transient
      // OSV blip shouldn't drop this vuln's detail, callers proceed with
      // what they have rather than the whole lookup failing.
      return null;
    }
  });
}

function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * Looks up vulnerabilities for a batch of (ecosystem, name, version) tuples.
 * Returns a map keyed by `${ecosystem}|${name}|${version}` → matching vulns.
 * Fails open throughout: any OSV failure (network, non-2xx, timeout) yields
 * an empty result for the affected lookups, never throws — callers proceed
 * with the scan rather than losing the whole dependency report over one
 * upstream blip.
 */
export async function lookupVulnerabilities(lookups: OsvLookup[]): Promise<Map<string, OsvVulnerability[]>> {
  const result = new Map<string, OsvVulnerability[]>();
  if (lookups.length === 0) return result;

  // Per-package id cache: which vuln IDs affect this exact (ecosystem, name,
  // version), separate from the per-id detail cache below (a given CVE
  // recurs across many packages/orgs — caching detail by id skips that
  // fetch entirely regardless of which package triggered it).
  const idsByKey = new Map<string, string[]>();
  const uncached: OsvLookup[] = [];
  await Promise.all(lookups.map(async lookup => {
    const hit = await cacheGet<string[]>(cacheKeys.osvPackage(lookup.ecosystem, lookup.name, lookup.version));
    if (hit !== null) idsByKey.set(lookupKey(lookup), hit);
    else uncached.push(lookup);
  }));

  for (const batch of chunk(uncached, QUERY_CHUNK_SIZE)) {
    try {
      const res = await fetch(`${OSV_API}/v1/querybatch`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          queries: batch.map(l => ({
            package: { name: l.name, ecosystem: l.ecosystem },
            version: l.version || undefined,
          })),
        }),
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!res.ok) { batch.forEach(l => idsByKey.set(lookupKey(l), [])); continue; }
      const data = await res.json() as OsvQueryBatchResult;
      batch.forEach((lookup, i) => idsByKey.set(lookupKey(lookup), (data.results[i]?.vulns ?? []).map(v => v.id)));
    } catch {
      // Fail open for this chunk — same reasoning throughout this file.
      batch.forEach(l => idsByKey.set(lookupKey(l), []));
    }
  }

  await Promise.all(uncached.map(l =>
    cacheSet(cacheKeys.osvPackage(l.ecosystem, l.name, l.version), idsByKey.get(lookupKey(l)) ?? [], TTL.VULN_INTEL),
  ));

  const idSet = new Set<string>();
  for (const ids of idsByKey.values()) ids.forEach(id => idSet.add(id));

  const details = new Map<string, OsvVulnerability>();
  await mapWithConcurrency(Array.from(idSet), DETAIL_CONCURRENCY, async id => {
    const detail = await fetchVulnDetail(id);
    if (detail) details.set(id, detail);
  });

  for (const lookup of lookups) {
    const key = lookupKey(lookup);
    const ids = idsByKey.get(key) ?? [];
    result.set(key, ids.map(id => details.get(id)).filter((v): v is OsvVulnerability => v !== undefined));
  }

  return result;
}
