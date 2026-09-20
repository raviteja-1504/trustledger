/**
 * Terraform (HCL) misconfiguration detectors — IaC security Phase 3.
 *
 * Regex/line-window over raw content, matching this codebase's own
 * established first-pass detector style (the same style every OWASP
 * detector in scanner.ts used before any AST engine existed for a
 * language) — not a real HCL parser. Two checks need more than a bare
 * single-line regex and use extractHclResourceBlocks() below, a brace-depth
 * block extractor; every other check is a direct single-line regex, the
 * same precision WEAK_CRYPTO_RE/INSECURE_RANDOM_RE already accept
 * elsewhere in scanner.ts.
 *
 * Registered via detectorRegistry (see iacDetectors.ts), not scanner.ts's
 * core inline array. Same-file only -- a `module "x" { source =
 * "./modules/s3" }` block referencing a bucket defined in another file is
 * not resolved, matching this codebase's existing cross-file scoping
 * precedent elsewhere (deferred, not silently mishandled).
 */

import type { ScanIndicator } from "./scanner";

export interface HclBlockRange { name: string; start: number; end: number } // 0-indexed, inclusive

const RESOURCE_HEADER_RE = /^\s*resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{/;

/**
 * Finds every `resource "TYPE" "NAME" { ... }` block of the given type and
 * its line range, via brace-depth counting from the header line to the
 * point depth returns to zero. Accepted imprecision: doesn't special-case
 * braces inside string literals or comments (a `#` comment containing a
 * literal "{" would miscount) -- consistent with this codebase's existing
 * "good enough" regex philosophy elsewhere, not attempting a real parser.
 */
export function extractHclResourceBlocks(lines: string[], resourceType: string): HclBlockRange[] {
  const blocks: HclBlockRange[] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = RESOURCE_HEADER_RE.exec(lines[i]);
    if (!m || m[1] !== resourceType) continue;
    let depth = 0;
    let end = i;
    for (let j = i; j < lines.length; j++) {
      for (const ch of lines[j]) {
        if (ch === "{") depth++;
        else if (ch === "}") depth--;
      }
      end = j;
      if (depth === 0) break;
    }
    blocks.push({ name: m[2], start: i, end });
  }
  return blocks;
}

// ── iac-s3-public-acl ────────────────────────────────────────────────────────

const S3_PUBLIC_ACL_RE = /\bacl\s*=\s*"public-read(-write)?"/;

export function findS3PublicAcl(content: string): ScanIndicator[] {
  const lines = content.split("\n");
  return lines.flatMap((line, i) => S3_PUBLIC_ACL_RE.test(line) ? [{
    id: "iac-s3-public-acl", label: "Public S3 Bucket ACL", severity: "critical" as const, line: i + 1, confidence: 90,
    detail: "Bucket ACL grants public read access to anyone on the internet — use a bucket policy with least privilege instead.",
  }] : []);
}

// ── iac-open-ingress ─────────────────────────────────────────────────────────

const CIDR_OPEN_RE = /cidr_blocks\s*=\s*\[[^\]]*"(0\.0\.0\.0\/0|::\/0)"/;
const INGRESS_HEADER_RE = /^\s*ingress\s*\{/;
const EGRESS_HEADER_RE = /^\s*egress\s*\{/;
const SG_RULE_TYPE_RE = /^\s*type\s*=\s*"(ingress|egress)"/;

/** Walks backward from `idx` looking for the nearest ingress/egress context
 * marker -- either an inline `ingress {`/`egress {` block header (the
 * classic aws_security_group shape) or a `type = "ingress"`/`"egress"`
 * attribute (the newer standalone aws_security_group_rule/
 * aws_vpc_security_group_ingress_rule shape). No marker found nearby means
 * "don't guess" -- egress-to-anywhere is normal and not itself a finding,
 * so an unclear context is treated as egress (no finding), the safe
 * direction for this specific check (unlike most of this codebase's
 * recall-biased checks). */
function isWithinIngressContext(lines: string[], idx: number): boolean {
  for (let j = idx; j >= Math.max(0, idx - 15); j--) {
    if (INGRESS_HEADER_RE.test(lines[j])) return true;
    if (EGRESS_HEADER_RE.test(lines[j])) return false;
    const m = SG_RULE_TYPE_RE.exec(lines[j]);
    if (m) return m[1] === "ingress";
  }
  return false;
}

export function findOpenIngress(content: string): ScanIndicator[] {
  const lines = content.split("\n");
  const found: ScanIndicator[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (!CIDR_OPEN_RE.test(lines[i])) continue;
    if (!isWithinIngressContext(lines, i)) continue;
    found.push({
      id: "iac-open-ingress", label: "Open Ingress Rule", severity: "high", line: i + 1, confidence: 85,
      detail: "Security group ingress rule allows traffic from 0.0.0.0/0 (or ::/0) — verify this is intentional for a public-facing service.",
    });
  }
  return found;
}

// ── iac-unencrypted-storage ───────────────────────────────────────────────────

const ENCRYPTION_INLINE_RE = /server_side_encryption_configuration/;
const BUCKET_REF_RE = /\bbucket\s*=\s*aws_s3_bucket\.([\w-]+)\./;
const STORAGE_ENCRYPTED_TRUE_RE = /\bstorage_encrypted\s*=\s*true\b/;

export function findUnencryptedStorage(content: string): ScanIndicator[] {
  const lines = content.split("\n");
  const found: ScanIndicator[] = [];

  // Same-file cross-reference: a bucket referenced by a separate
  // aws_s3_bucket_server_side_encryption_configuration resource (the
  // provider v4+ style) counts as encrypted, same as an inline block
  // (the pre-v4 style) -- both real Terraform AWS provider shapes.
  const encryptedBucketRefs = new Set<string>();
  for (const block of extractHclResourceBlocks(lines, "aws_s3_bucket_server_side_encryption_configuration")) {
    for (let j = block.start; j <= block.end; j++) {
      const m = BUCKET_REF_RE.exec(lines[j]);
      if (m) encryptedBucketRefs.add(m[1]);
    }
  }

  for (const block of extractHclResourceBlocks(lines, "aws_s3_bucket")) {
    const blockLines = lines.slice(block.start, block.end + 1);
    if (blockLines.some(l => ENCRYPTION_INLINE_RE.test(l)) || encryptedBucketRefs.has(block.name)) continue;
    found.push({
      id: "iac-unencrypted-storage", label: "Unencrypted Storage", severity: "medium", line: block.start + 1, confidence: 75,
      detail: `S3 bucket '${block.name}' has no server-side encryption configured (inline or via a separate aws_s3_bucket_server_side_encryption_configuration resource).`,
    });
  }

  for (const block of extractHclResourceBlocks(lines, "aws_db_instance")) {
    const blockLines = lines.slice(block.start, block.end + 1);
    if (blockLines.some(l => STORAGE_ENCRYPTED_TRUE_RE.test(l))) continue;
    found.push({
      id: "iac-unencrypted-storage", label: "Unencrypted Storage", severity: "medium", line: block.start + 1, confidence: 75,
      detail: `RDS instance '${block.name}' does not set storage_encrypted = true.`,
    });
  }

  return found;
}

// ── iac-iam-wildcard ─────────────────────────────────────────────────────────

const IAM_WILDCARD_RE = /(?:"(?:Action|Resource)"\s*:\s*"\*")|(?:\b(?:actions|resources)\s*=\s*\[[^\]]*"\*")/;

export function findIamWildcard(content: string): ScanIndicator[] {
  const lines = content.split("\n");
  return lines.flatMap((line, i) => IAM_WILDCARD_RE.test(line) ? [{
    id: "iac-iam-wildcard", label: "Overly Permissive IAM Policy", severity: "high" as const, line: i + 1, confidence: 80,
    detail: "IAM statement grants '*' action or resource — scope this to the specific actions/resources actually needed (least privilege).",
  }] : []);
}

// ── iac-public-db ────────────────────────────────────────────────────────────

const PUBLICLY_ACCESSIBLE_RE = /\bpublicly_accessible\s*=\s*true\b/;

export function findPublicDb(content: string): ScanIndicator[] {
  const lines = content.split("\n");
  const found: ScanIndicator[] = [];
  for (const block of extractHclResourceBlocks(lines, "aws_db_instance")) {
    for (let j = block.start; j <= block.end; j++) {
      if (PUBLICLY_ACCESSIBLE_RE.test(lines[j])) {
        found.push({
          id: "iac-public-db", label: "Publicly Accessible Database", severity: "critical", line: j + 1, confidence: 90,
          detail: `RDS instance '${block.name}' is publicly accessible from the internet.`,
        });
        break;
      }
    }
  }
  return found;
}
