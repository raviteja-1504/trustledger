export type AuditEventType =
  | "scan_complete" | "attestation"   | "merge_blocked"
  | "policy_violation" | "policy_change" | "secret_detected"
  | "integration_connected" | "user_added" | "sla_breach";

export interface AuditEventConfig {
  label:  string;
  icon:   string;
  bg:     string;
  text:   string;
  border: string;
  dot:    string;
}

export const EVENT_CONFIG: Record<AuditEventType, AuditEventConfig> = {
  scan_complete:         { label:"Scan",         icon:"scan",    bg:"#eef2ff", text:"#4338ca", border:"#c7d2fe", dot:"#6366f1" },
  attestation:           { label:"Attestation",  icon:"check",   bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", dot:"#22c55e" },
  merge_blocked:         { label:"Blocked",      icon:"block",   bg:"#fff1f2", text:"#be123c", border:"#fecdd3", dot:"#ef4444" },
  policy_violation:      { label:"Violation",    icon:"warn",    bg:"#fffbeb", text:"#b45309", border:"#fde68a", dot:"#f59e0b" },
  sla_breach:            { label:"SLA Breach",   icon:"clock",   bg:"#fff1f2", text:"#be123c", border:"#fecdd3", dot:"#f97316" },
  policy_change:         { label:"Policy",       icon:"gear",    bg:"#f8fafc", text:"#475569", border:"#e2e8f0", dot:"#94a3b8" },
  secret_detected:       { label:"Secret",       icon:"secret",  bg:"#ede9fe", text:"#6d28d9", border:"#ddd6fe", dot:"#7c3aed" },
  integration_connected: { label:"Integration",  icon:"plug",    bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", dot:"#10b981" },
  user_added:            { label:"User",         icon:"user",    bg:"#eff6ff", text:"#1d4ed8", border:"#bfdbfe", dot:"#3b82f6" },
};

export const EVENT_SOC2: Partial<Record<AuditEventType, string[]>> = {
  scan_complete:         ["CC7.2"],
  attestation:           ["CC6.1","CC8.1"],
  merge_blocked:         ["CC8.1","CC6.1"],
  policy_violation:      ["CC7.2","CC8.1"],
  policy_change:         ["CC8.1"],
  secret_detected:       ["CC7.2","CC6.2"],
  integration_connected: ["CC6.2"],
  user_added:            ["CC6.2"],
  sla_breach:            ["CC7.2","A1.2"],
};
