/**
 * What the rule catalog says beyond "here is a fix": when to fix it, the fix as steps, how to know it worked, what
 * is related. Pure and client-safe, built only from what a catalog rule already carries.
 */
import type { CatalogRule, RuleDetection } from "./ruleCatalog";

export type RuleSeverity = NonNullable<CatalogRule["severity"]>;

/** When a finding of this severity should be dealt with, as a team would put it to a developer. */
export const SEVERITY_GUIDANCE: Record<RuleSeverity, { when: string; sla: string }> = {
  critical: { when: "Before merging: this can lead to full compromise with little effort.", sla: "Same day" },
  high: { when: "Before the next release: serious and plausibly exploitable.", sla: "Within a week" },
  medium: { when: "Plan it into upcoming work: it needs a specific condition to exploit.", sla: "Within a month" },
  low: { when: "When convenient: hardening or hygiene.", sla: "Within a quarter" },
};
export const guidanceFor = (severity: CatalogRule["severity"]) => (severity ? SEVERITY_GUIDANCE[severity] : null);

export const EFFORT_LABEL: Record<"low" | "medium" | "high", string> = {
  low: "Quick fix: a few lines",
  medium: "Moderate: touches one component or its callers",
  high: "Larger change: plan the work",
};

/** How to confirm a fix, which depends on how the rule detects the problem. */
export function verifySteps(detection: RuleDetection): string[] {
  const rescan = "Push the fix (or rescan the pull request) and confirm this rule no longer appears for the file.";
  if (detection === "data-flow") return [
    "Re-read the finding's data flow: the fix should break the path between the input and the dangerous call, not just rename a variable.",
    rescan,
    "Add a test that sends the malicious input and shows it is neutralised.",
  ];
  if (detection === "configuration") return [
    "Apply the change to the configuration file the finding points at.",
    rescan,
    "If the setting is overridden elsewhere (a deploy pipeline, an environment), check the effective value there too.",
  ];
  return [
    "Make the change at the line the finding points at.",
    rescan,
    "If the match is wrong for your code, mark the finding a false positive in the review page with a reason, rather than leaving it open.",
  ];
}

/** The fix description as steps: its sentences, up to `max`. A single sentence stays one step. */
export function fixSteps(description: string, max = 5): string[] {
  const parts = description.replace(/\s+/g, " ").trim().split(/(?<=[.!?])\s+(?=[A-Z`"'(])/).filter(Boolean);
  return parts.slice(0, max);
}

/** Other rules about the same weakness (same CWE), for when this one is not quite the right match. */
export function relatedRules<R extends { id: string; cwe: string | null; title: string }>(rule: R, rules: readonly R[], max = 5): R[] {
  if (!rule.cwe) return [];
  return rules.filter(r => r.id !== rule.id && r.cwe === rule.cwe).slice(0, max);
}

/** The CWE id as a link target ("CWE-89" -> its MITRE page), or null. */
export const cweUrl = (cwe: string | null): string | null => {
  const n = cwe?.match(/\d+/)?.[0];
  return n ? `https://cwe.mitre.org/data/definitions/${n}.html` : null;
};
