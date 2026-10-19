/**
 * Review debt: how long unreviewed HIGH/CRITICAL findings have actually been waiting, weighted by severity.
 *
 *   debt = Σ hours_waiting × weight      (CRITICAL × 10, HIGH × 4)
 *
 * hours_waiting is measured from when the finding was opened (violations.created_at), and the debt grows by
 * Σ weight every hour until each finding is signed off or resolved. Pure, client-safe.
 */

export const DEBT_WEIGHT = { CRITICAL: 10, HIGH: 4 } as const;

export interface DebtFinding {
  id: string;
  file_path: string;
  risk_score: string;
  status: string;
  created_at: string;
  sla_deadline: string | null;
  scan_id: string;
  repo: string;
  pr_number: number | null;
}

export interface DebtItem extends DebtFinding {
  hours: number;
  weight: number;
  debt: number;
  overdue: boolean;
}

export function computeReviewDebt(findings: readonly DebtFinding[], resolvedKeys: ReadonlySet<string>, now = Date.now()) {
  const items: DebtItem[] = [];
  for (const f of findings) {
    const sev = f.risk_score.toUpperCase();
    if (sev !== "CRITICAL" && sev !== "HIGH") continue;
    if (f.status !== "open" && f.status !== "in_review") continue;
    const prefix = sev === "CRITICAL" ? "crit" : "high";
    if (resolvedKeys.has(`${prefix}::${f.scan_id}::${f.file_path}`)) continue;   // resolved on the violations page
    const hours = Math.max(0, (now - Date.parse(f.created_at)) / 3600_000);
    const weight = DEBT_WEIGHT[sev];
    items.push({ ...f, hours, weight, debt: hours * weight, overdue: !!f.sla_deadline && Date.parse(f.sla_deadline) < now });
  }
  items.sort((a, b) => b.debt - a.debt);
  return {
    items,
    total: items.reduce((a, i) => a + i.debt, 0),
    /** Debt added per hour while nothing changes. */
    perHour: items.reduce((a, i) => a + i.weight, 0),
    oldestHours: items.reduce((m, i) => Math.max(m, i.hours), 0),
    overdue: items.filter(i => i.overdue).length,
    critical: items.filter(i => i.weight === DEBT_WEIGHT.CRITICAL).length,
  };
}
