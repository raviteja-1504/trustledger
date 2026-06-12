export type AuditEventType =
  | "scan_complete" | "attestation"   | "merge_blocked"
  | "policy_violation" | "policy_change" | "secret_detected"
  | "integration_connected" | "user_added" | "sla_breach";

export interface AuditEvent {
  id:          string;
  type:        AuditEventType;
  timestamp:   string;
  repo?:       string;
  actor?:      string;
  description: string;
  detail?:     string;
  metadata?:   Record<string, string>;
  scan_id?:    string;
  pr_number?:  number;
  severity:    "info" | "warning" | "critical";
}

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

export function makeMockEvents(org: string): AuditEvent[] {
  const o = org;
  function ago(daysBack: number, hhmm: string): string {
    const now = new Date();
    const d = new Date(now);
    d.setUTCDate(d.getUTCDate() - daysBack);
    const [h, m, s = "00"] = hhmm.split(":");
    d.setUTCHours(Number(h), Number(m), Number(s), 0);
    // A "daysBack ago" timestamp should never land in the future — if hhmm
    // hasn't happened yet today (UTC), push it back one more day.
    if (d.getTime() > now.getTime()) d.setUTCDate(d.getUTCDate() - 1);
    return d.toISOString().replace(/\.\d{3}Z$/, "Z");
  }
  return [
    { id:"a01", type:"scan_complete",   timestamp:ago(0,"14:32:18"), repo:`${o}/payments-api`,    severity:"critical", scan_id:"sc_mock_001", pr_number:482, description:"Scan completed — PR #482", detail:"8 files scanned. CRITICAL risk overall. card_validator.py flagged at 91% AI with SQL injection + hardcoded secret signals.", metadata:{ "Files":"8", "Risk":"CRITICAL", "Avg AI%":"71%", "Duration":"1.2s" } },
    { id:"a02", type:"secret_detected", timestamp:ago(0,"14:32:20"), repo:`${o}/payments-api`,    severity:"critical", scan_id:"sc_mock_001", pr_number:482, description:"Hardcoded Stripe API key detected", detail:"Production credential sk_live_51Hx2••• found in src/processors/card_validator.py line 8. Treat as compromised — rotate immediately.", metadata:{ "File":"card_validator.py", "Line":"8", "Pattern":"sk_live_*", "CVE":"CVE-2021-42013" } },
    { id:"a03", type:"merge_blocked",   timestamp:ago(0,"14:32:22"), repo:`${o}/payments-api`,    severity:"critical", scan_id:"sc_mock_001", pr_number:482, description:"Merge blocked — 2 unattested CRITICAL files", detail:"Standard policy requires attestation before merge. card_validator.py and stripe_client.py are CRITICAL risk and have not been reviewed.", metadata:{ "Policy":"Standard", "Blocked files":"2", "SLA":"24h" } },
    { id:"a04", type:"attestation",     timestamp:ago(0,"13:18:44"), repo:`${o}/auth-service`,    severity:"info",     scan_id:"sc_mock_002", pr_number:341, actor:`alice@${o}.io`, description:"File attested by alice", detail:"src/oauth/token_exchange.ts attested with PGP signature. HIGH risk, 68% AI content.", metadata:{ "File":"token_exchange.ts", "Risk":"HIGH", "AI%":"68%", "Algorithm":"SHA-256 / RSA-4096" } },
    { id:"a05", type:"scan_complete",   timestamp:ago(0,"10:05:00"), repo:`${o}/fraud-detection`, severity:"critical", scan_id:"sc_mock_003", pr_number:219, description:"Scan completed — PR #219", detail:"5 files scanned. CRITICAL overall. models/risk_scorer.ts at 83% AI with eval/exec signal.", metadata:{ "Files":"5", "Risk":"CRITICAL", "Avg AI%":"58%", "Duration":"0.9s" } },
    { id:"a06", type:"secret_detected", timestamp:ago(0,"10:05:02"), repo:`${o}/fraud-detection`, severity:"critical", scan_id:"sc_mock_003", pr_number:219, description:"Hardcoded DB password detected", detail:"Pattern 'prod_password_*' matched in src/database/connection.py line 23. This is a production credential — rotate and remove immediately.", metadata:{ "File":"connection.py", "Line":"23", "Pattern":"prod_password_*" } },
    { id:"a07", type:"policy_violation",timestamp:ago(0,"10:05:05"), repo:`${o}/fraud-detection`, severity:"warning",  scan_id:"sc_mock_003", pr_number:219, description:"Policy violation — unattested CRITICAL file", detail:"models/risk_scorer.ts (CRITICAL, 83% AI) has not been attested. SLA: 24 hours from detection.", metadata:{ "File":"risk_scorer.ts", "Risk":"CRITICAL", "SLA deadline":"2026-05-27T10:05:00Z" } },
    { id:"a08", type:"attestation",     timestamp:ago(1,"16:30:00"), repo:`${o}/fraud-detection`, severity:"info",     scan_id:"sc_mock_003", pr_number:218, actor:`bob@${o}.io`, description:"File attested by bob", detail:"src/rules/velocity_check.py (HIGH risk, 62% AI) attested. Reviewer confirmed no SQL injection patterns.", metadata:{ "File":"velocity_check.py", "Risk":"HIGH", "AI%":"62%" } },
    { id:"a09", type:"attestation",     timestamp:ago(1,"14:10:00"), repo:`${o}/fraud-detection`, severity:"info",     scan_id:"sc_mock_003", pr_number:218, actor:`carol@${o}.io`, description:"File attested by carol", detail:"src/utils/feature_extractor.py (LOW risk, 38% AI) attested. No security concerns identified.", metadata:{ "File":"feature_extractor.py", "Risk":"LOW", "AI%":"38%" } },
    { id:"a10", type:"scan_complete",   timestamp:ago(1,"11:00:00"), repo:`${o}/auth-service`,    severity:"warning",  scan_id:"sc_mock_002", pr_number:341, description:"Scan completed — PR #341", detail:"4 files scanned. HIGH risk overall. token_exchange.ts at 68% AI with JWT bypass pattern.", metadata:{ "Files":"4", "Risk":"HIGH", "Avg AI%":"44%", "Duration":"0.7s" } },
    { id:"a11", type:"secret_detected", timestamp:ago(1,"09:22:00"), repo:`${o}/auth-service`,    severity:"critical", scan_id:"sc_mock_002", pr_number:341, description:"Hardcoded JWT signing secret detected", detail:"jwt_secret_prod_2024 found in src/auth/token_service.py line 14. JWT tokens can be forged if this secret is exposed.", metadata:{ "File":"token_service.py", "Line":"14", "CVE":"CVE-2022-21449" } },
    { id:"a12", type:"sla_breach",      timestamp:ago(1,"08:00:00"), repo:`${o}/payments-api`,    severity:"critical", scan_id:"sc_mock_001", pr_number:479, description:"SLA breach — stripe_client.py unattested 48h+", detail:"stripe_client.py (HIGH risk) detected 3 days ago and has exceeded the 48-hour attestation SLA. Escalating to security lead.", metadata:{ "File":"stripe_client.py", "Hours overdue":"2", "Owner":"Unassigned" } },
    { id:"a13", type:"attestation",     timestamp:ago(2,"17:30:00"), repo:`${o}/auth-service`,    severity:"info",     scan_id:"sc_mock_002", pr_number:338, actor:`alice@${o}.io`, description:"Secret remediation confirmed by alice", detail:"SendGrid API key (sec_004) confirmed rotated and moved to AWS Secrets Manager.", metadata:{ "Secret ID":"sec_004", "Action":"Rotated + Vaulted" } },
    { id:"a14", type:"scan_complete",   timestamp:ago(2,"16:20:00"), repo:`${o}/risk-engine`,     severity:"info",     scan_id:"sc_mock_004", pr_number:88, description:"Scan completed — PR #88", detail:"4 files scanned. MEDIUM risk. All files below 50% AI content. No injection or secret patterns detected.", metadata:{ "Files":"4", "Risk":"MEDIUM", "Avg AI%":"41%", "Duration":"0.6s" } },
    { id:"a15", type:"attestation",     timestamp:ago(2,"10:30:00"), repo:`${o}/payments-api`,    severity:"info",     scan_id:"sc_mock_001", pr_number:477, actor:`carol@${o}.io`, description:"File attested by carol", detail:"src/api/refund_handler.py (MEDIUM risk, 55% AI) attested. Reviewer confirmed parameterised refund logic.", metadata:{ "File":"refund_handler.py", "Risk":"MEDIUM", "AI%":"55%" } },
    { id:"a16", type:"policy_change",   timestamp:ago(3,"09:00:00"), severity:"info", actor:`admin@${o}.io`, description:"Policy updated — Standard", detail:"Merge gate for HIGH-risk files now requires 1 reviewer attestation (previously 0).", metadata:{ "Changed by":"admin", "Old threshold":"0", "New threshold":"1", "Effective":"Immediately" } },
    { id:"a17", type:"integration_connected", timestamp:ago(3,"08:45:00"), severity:"info", actor:`admin@${o}.io`, description:"GitHub App installed", detail:`TrustLedger GitHub App connected to ${o} organisation. 5 repositories added to scanning scope.`, metadata:{ "Org":o, "Repos added":"5", "Installed by":"admin" } },
    { id:"a18", type:"scan_complete",   timestamp:ago(4,"14:00:00"), repo:`${o}/data-platform`,   severity:"warning",  scan_id:"sc_mock_005", pr_number:103, description:"Scan completed — PR #103", detail:"6 files scanned. HIGH risk. etl_runner.py (65% AI) has eval/exec pattern. s3_client.py has hardcoded AWS key.", metadata:{ "Files":"6", "Risk":"HIGH", "Avg AI%":"62%", "Duration":"1.1s" } },
    { id:"a19", type:"secret_detected", timestamp:ago(4,"14:00:05"), repo:`${o}/data-platform`,   severity:"critical", scan_id:"sc_mock_005", pr_number:103, description:"Hardcoded AWS access key detected", detail:"AKIA••••••••••••••••EXAMPLE found in src/storage/s3_client.py line 19. AWS credentials exposed.", metadata:{ "File":"s3_client.py", "Line":"19", "Pattern":"AKIA*" } },
    { id:"a20", type:"user_added",      timestamp:ago(4,"08:30:00"), severity:"info", actor:`admin@${o}.io`, description:"Team member added — carol", detail:`carol@${o}.io added as Security Reviewer. Can now attest HIGH/CRITICAL-risk files across all repos.`, metadata:{ "User":`carol@${o}.io`, "Role":"Security Reviewer", "Added by":"admin" } },
    { id:"a21", type:"attestation",     timestamp:ago(5,"15:45:00"), repo:`${o}/risk-engine`,     severity:"info",     scan_id:"sc_mock_004", pr_number:85, actor:`bob@${o}.io`, description:"File attested by bob", detail:"src/engines/scoring_engine.py (LOW risk, 28% AI) attested.", metadata:{ "File":"scoring_engine.py", "Risk":"LOW", "AI%":"28%" } },
    { id:"a22", type:"scan_complete",   timestamp:ago(5,"11:20:00"), repo:`${o}/auth-service`,    severity:"info",     scan_id:"sc_mock_002", pr_number:336, description:"Scan completed — PR #336", detail:"3 files scanned. LOW risk overall. Avg AI content 22%.", metadata:{ "Files":"3", "Risk":"LOW", "Avg AI%":"22%", "Duration":"0.5s" } },
    { id:"a23", type:"policy_violation",timestamp:ago(5,"09:10:00"), repo:`${o}/data-platform`,   severity:"warning",  scan_id:"sc_mock_005", pr_number:101, description:"Policy violation — AI content threshold exceeded", detail:"PR #101 in data-platform has average AI content of 81%, exceeding the org threshold of 80%.", metadata:{ "PR":"#101", "AI%":"81%", "Threshold":"80%" } },
    { id:"a24", type:"scan_complete",   timestamp:ago(6,"16:00:00"), repo:`${o}/payments-api`,    severity:"info",     scan_id:"sc_mock_001", pr_number:471, description:"Scan completed — PR #471", detail:"5 files scanned. MEDIUM risk. currency_formatter.py at 21% AI — below threshold.", metadata:{ "Files":"5", "Risk":"MEDIUM", "Avg AI%":"34%", "Duration":"0.8s" } },
    { id:"a25", type:"attestation",     timestamp:ago(6,"14:00:00"), repo:`${o}/payments-api`,    severity:"info",     scan_id:"sc_mock_001", pr_number:471, actor:`alice@${o}.io`, description:"Batch attestation by alice — 3 files", detail:"alice attested 3 files in PR #471: refund_handler.py, transaction.py, currency_formatter.py. All MEDIUM risk.", metadata:{ "Files attested":"3", "Risk":"MEDIUM", "Method":"Bulk attest" } },
  ];
}
