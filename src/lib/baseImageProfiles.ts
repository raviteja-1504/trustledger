/**
 * Curated base-image -> OS-release mapping for Container security's
 * base-image CVE lookup (Decision 2).
 *
 * Confirmed against OSV.dev's real, documented API
 * (google.github.io/osv.dev/api): Debian/Alpine/Ubuntu are genuine,
 * live-queryable OSV ecosystems via the exact same osvClient.ts
 * lookupVulnerabilities() already used for npm/PyPI/Go/etc, given a
 * release-qualified ecosystem string ("Alpine:v3.19", "Debian:12",
 * "Ubuntu:22.04:LTS") and an OS package name. There is no OSV.dev endpoint
 * that takes a bare `image:tag` and returns CVEs directly -- confirmed by
 * checking OSV.dev's real API docs directly, not assumed.
 *
 * Deliberately does NOT curate exact bundled package VERSIONS per image
 * tag -- confirmed there is no free API that hands back a real
 * installed-package inventory for an arbitrary image without pulling and
 * extracting its layers (infeasible in this app's serverless environment).
 * Packages are queried package-wide (version ""), the same convention this
 * codebase already uses for pom.xml/build.gradle coordinates with no
 * parseable version (see dependencyScan.ts's manifestPackages) -- OSV then
 * reports every known vulnerability for that package within that OS
 * release, regardless of exact bundled sub-version. Real, live CVE data,
 * not a fabricated version number.
 *
 * The image-tag -> OS-release mapping below IS a verifiable fact (which OS
 * each official Docker Hub image documents itself as building on), not a
 * guess -- unlike a package version, this doesn't go stale between image
 * patch releases within the same OS major/LTS line. It's necessarily a
 * curated snapshot of common tags, not arbitrary-image resolution (a real,
 * separate undertaking needing a registry-crawling backend this app
 * doesn't have -- see the plan's "explicitly out of scope").
 */

export type OsEcosystem = "Alpine" | "Debian" | "Ubuntu";

export interface OsReleaseProfile {
  ecosystem:    OsEcosystem;
  osvEcosystem: string; // the exact, release-qualified OSV ecosystem string
}

// Image tag as it would literally appear after a Dockerfile's FROM
// (lowercase, no registry prefix, no digest) -> OS release profile.
export const BASE_IMAGE_PROFILES: Record<string, OsReleaseProfile> = {
  "node:22-alpine": { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.20" },
  "node:20-alpine": { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.19" },
  "node:18-alpine": { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.19" },
  "node:22":        { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "node:20":        { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "node:18":        { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "python:3.13-alpine": { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.20" },
  "python:3.12-alpine": { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.19" },
  "python:3.11-alpine": { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.19" },
  "python:3.13-slim":   { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "python:3.12-slim":   { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "python:3.11-slim":   { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "python:3.12":        { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "python:3.11":        { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "postgres:16":  { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "postgres:15":  { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "postgres:14":  { ecosystem: "Debian", osvEcosystem: "Debian:11" },
  "redis:7":         { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "redis:7-alpine":  { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.19" },
  "redis:alpine":    { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.19" },
  "nginx:1.27":        { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "nginx:1.25":        { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "nginx:1.25-alpine": { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.19" },
  "nginx:alpine":      { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.19" },
  "nginx:latest":      { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "alpine:3.20":  { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.20" },
  "alpine:3.19":  { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.19" },
  "alpine:3.18":  { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.18" },
  "alpine:latest": { ecosystem: "Alpine", osvEcosystem: "Alpine:v3.20" },
  "ubuntu:24.04": { ecosystem: "Ubuntu", osvEcosystem: "Ubuntu:24.04:LTS" },
  "ubuntu:22.04": { ecosystem: "Ubuntu", osvEcosystem: "Ubuntu:22.04:LTS" },
  "ubuntu:20.04": { ecosystem: "Ubuntu", osvEcosystem: "Ubuntu:20.04:LTS" },
  "debian:12":       { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "debian:12-slim":  { ecosystem: "Debian", osvEcosystem: "Debian:12" },
  "debian:11":       { ecosystem: "Debian", osvEcosystem: "Debian:11" },
};

// A small, well-known set of OS packages present in virtually any image
// built on the given ecosystem -- confirmed via each distro's own base
// package set (Alpine's musl/busybox/openssl, Debian/Ubuntu's
// libc6/openssl/zlib1g/bash/coreutils/curl), not an image-specific guess.
// Queried package-wide (no version, see this module's own docblock), so
// OSV reports every known vulnerability for that OS release's build of the
// package.
const PACKAGES_BY_ECOSYSTEM: Record<OsEcosystem, string[]> = {
  Alpine: ["openssl", "musl", "busybox", "zlib", "libcrypto3", "libssl3"],
  Debian: ["openssl", "libc6", "zlib1g", "bash", "coreutils", "curl"],
  Ubuntu: ["openssl", "libc6", "zlib1g", "bash", "coreutils", "curl"],
};

/** Matches a Dockerfile FROM image reference (e.g. "node:20-alpine",
 * "docker.io/library/postgres:16") against the curated table -- strips a
 * trailing digest and any registry/namespace prefix before comparing. */
export function matchBaseImageProfile(imageRef: string): OsReleaseProfile | null {
  const withoutDigest = imageRef.split("@")[0];
  const parts = withoutDigest.split("/");
  const lastSegment = (parts[parts.length - 1] ?? "").toLowerCase();
  return BASE_IMAGE_PROFILES[lastSegment] ?? null;
}

export function packagesForProfile(profile: OsReleaseProfile): string[] {
  return PACKAGES_BY_ECOSYSTEM[profile.ecosystem];
}
