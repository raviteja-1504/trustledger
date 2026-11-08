/**
 * Violations, alerts and incidents are tabs of one Threats page. The old addresses (/violations, /alerts, /incidents)
 * are linked from emails, Slack messages, the audit log and bookmarks, so each redirects to its tab and keeps any
 * query string.
 */
export type ThreatTab = "overview" | "violations" | "alerts" | "incidents";
export const THREAT_TABS: readonly ThreatTab[] = ["overview", "violations", "alerts", "incidents"];

export function tabFromSearch(search: string): ThreatTab {
  const t = new URLSearchParams(search).get("tab");
  return (THREAT_TABS as readonly string[]).includes(t ?? "") ? (t as ThreatTab) : "overview";
}

/** `/threats?tab=alerts&x=y`; the overview is the default tab, so it has no `tab`. */
export function threatsHref(tab: ThreatTab, extra: Record<string, string | string[] | undefined> = {}): string {
  const q = new URLSearchParams();
  if (tab !== "overview") q.set("tab", tab);
  for (const [k, v] of Object.entries(extra)) {
    if (k === "tab" || v === undefined) continue;
    for (const one of Array.isArray(v) ? v : [v]) q.append(k, one);
  }
  const s = q.toString();
  return s ? `/threats?${s}` : "/threats";
}
