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

export interface ConfidenceReasonInput extends ConfidenceInput {
  sinkExpr?: string;
  flow?: {
    hops?: number;
    crossesFiles?: boolean;
    source?: { assumed?: boolean; inputKind?: string };
    sanitizers?: Array<{ call: string; protectsSink?: boolean }>;
  };
  reachability?: "unreachable" | "reachable" | "tainted-path" | "entry-point" | "unknown";
  codeCategory?: "application" | "third_party" | "test_code";
  supportingDetectors?: string[];
}

/**
 * Why a finding has the confidence it has, in a sentence a reviewer can check: what was traced, what was assumed, what was seen
 * on the way, and what lowers it. Built only from fields the finding already carries, so it can never claim more than the scan found.
 */
export function confidenceReason(f: ConfidenceReasonInput): string | null {
  const level = confidenceLevel(f);
  if (!level) return null;
  const parts: string[] = [];
  const traced = !!f.sourceExpr;
  if (traced && f.flow?.source?.assumed) {
    parts.push("The value comes from a parameter the analysis treated as untrusted; no request read or framework binding was seen");
  } else if (traced) {
    const kind = f.flow?.source?.inputKind;
    const hops = f.flow?.hops ?? 0;
    const src = f.sourceExpr!.length > 40 ? `${f.sourceExpr!.slice(0, 40)}…` : f.sourceExpr!;
    parts.push(`\`${src}\` (${kind ? `a ${kind.toLowerCase()}` : "request input"}) was traced to ${f.sinkExpr ? `\`${f.sinkExpr}\`` : "the sink"}${hops > 0 ? ` through ${hops} step${hops === 1 ? "" : "s"}` : " directly"}${f.flow?.crossesFiles ? ", across files" : ""}`);
  } else {
    parts.push("Found by matching a code pattern; no value was traced from an input to this line");
  }
  const sans = f.flow?.sanitizers ?? [];
  const stands = sans.filter(s => s.protectsSink === false);
  if (stands.length) parts.push(`${stands.map(s => `\`${s.call}\``).join(", ")} runs on the way but does not protect this kind of sink`);
  else if (sans.length) parts.push(`${sans.map(s => `\`${s.call}\``).join(", ")} runs on the way`);
  if (f.supportingDetectors && f.supportingDetectors.length > 0) parts.push(`${f.supportingDetectors.length + 1} independent detectors agree`);
  if (f.reachability === "unreachable") parts.push("the call graph found no path to this code from an entry point, which lowers its priority");
  if (f.codeCategory === "test_code") parts.push("it is in test code");
  if (f.codeCategory === "third_party") parts.push("it is in vendored or minified code");
  return `${parts.join("; ")}.`;
}
