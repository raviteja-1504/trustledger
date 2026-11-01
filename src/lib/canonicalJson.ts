/**
 * Canonical JSON: object keys sorted at every level, no whitespace, undefined properties dropped. The exact bytes
 * every TrustLedger signature covers (Trust Records, signed reports, audit exports). Client-safe, so the /verify page
 * rebuilds the same bytes in the browser; scripts/verify-trust-record.mjs carries a copy that must stay identical.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).filter(k => obj[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}
