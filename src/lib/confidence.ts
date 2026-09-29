/**
 * One vocabulary for how sure a finding is, used everywhere a finding is shown or exported.
 *
 * The number (0-100) says how specific the match was; the level is what a reader acts on:
 *  - Confirmed: a value was traced from real request input to the sink, or the match is unambiguous.
 *  - Likely:    a traced flow from a parameter treated as untrusted (no request read seen), or a strong pattern.
 *  - Possible:  a pattern that is often, but not always, a real issue -- review it.
 *  - Weak:      a hint worth a glance, frequently benign.
 * Client-safe: no imports.
 */

export type ConfidenceLevel = "confirmed" | "likely" | "possible" | "weak";

export const CONFIDENCE_LABEL: Record<ConfidenceLevel, string> = {
  confirmed: "Confirmed", likely: "Likely", possible: "Possible", weak: "Weak signal",
};

export const CONFIDENCE_DESC: Record<ConfidenceLevel, string> = {
  confirmed: "Traced from real request input to the sink, or an unambiguous match.",
  likely: "Traced from a parameter treated as untrusted, or a strong pattern match.",
  possible: "A pattern that is often a real issue. Review it.",
  weak: "A hint worth a glance. Frequently benign.",
};

export interface ConfidenceInput { confidence?: number; sourceExpr?: string; sourceAssumed?: boolean }

/** The level for a finding, or null when it carries no confidence at all (e.g. AI-provenance signals). */
export function confidenceLevel(f: ConfidenceInput): ConfidenceLevel | null {
  const traced = !!f.sourceExpr;
  if (traced && f.sourceAssumed) return "likely";
  if (f.confidence == null) return traced ? "confirmed" : null;
  if ((traced && f.confidence >= 90) || f.confidence >= 95) return "confirmed";
  if (f.confidence >= 75) return "likely";
  if (f.confidence >= 50) return "possible";
  return "weak";
}
