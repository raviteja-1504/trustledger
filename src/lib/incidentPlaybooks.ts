/**
 * Incident response playbook templates — shared between the client
 * (src/app/incidents/page.tsx, for display) and the server (api/incidents
 * POST, and lib/autoIncidents.ts) so a real DB incident is created with its
 * playbook checklist already populated, instead of only ever existing in
 * the browser that happened to create it.
 */

export type IncidentType = "secret-exposed" | "supply-chain" | "rce-pattern" | "auth-bypass" | "data-breach" | "policy-violation";

export interface PlaybookStepTemplate {
  step: number;
  action: string;
  owner: string;
  duration: string;
}

export const PLAYBOOK_TEMPLATES: Record<IncidentType, { name: string; steps: PlaybookStepTemplate[] }> = {
  "secret-exposed": {
    name:"Exposed Credential Response",
    steps:[
      { step:1, action:"Immediately rotate the exposed credential in the issuing system (Stripe, AWS, etc.)", owner:"Security Lead",    duration:"<15 min" },
      { step:2, action:"Revoke all active sessions using the compromised credential",                        owner:"Security Lead",    duration:"<30 min" },
      { step:3, action:"Audit logs for unauthorized access using the exposed credential",                    owner:"SecOps",           duration:"<1 hour" },
      { step:4, action:"Remove secret from source code and git history (git-filter-repo)",                   owner:"Developer",        duration:"<2 hours" },
      { step:5, action:"Force-push cleaned history and notify all affected team members",                    owner:"Tech Lead",        duration:"<3 hours" },
      { step:6, action:"Add secret scanning pre-commit hook and CI/CD gate",                                 owner:"DevOps",           duration:"<4 hours" },
      { step:7, action:"File incident report and notify affected parties per regulatory requirements",       owner:"CISO",             duration:"<24 hours" },
      { step:8, action:"Conduct post-mortem — why was the secret in code and how to prevent recurrence",    owner:"Security Lead",    duration:"<1 week" },
    ],
  },
  "supply-chain": {
    name:"Supply Chain Attack Response",
    steps:[
      { step:1, action:"Immediately pull the affected package from all environments",                        owner:"DevOps",           duration:"<15 min" },
      { step:2, action:"Identify all systems where the malicious package was installed",                     owner:"Security Lead",    duration:"<1 hour" },
      { step:3, action:"Assume all systems with the package are compromised — begin forensics",              owner:"SecOps",           duration:"<2 hours" },
      { step:4, action:"Revoke all credentials on affected systems",                                         owner:"Security Lead",    duration:"<2 hours" },
      { step:5, action:"Alert team and deploy clean images from trusted snapshots",                          owner:"DevOps",           duration:"<4 hours" },
      { step:6, action:"Report to package registry (PyPI, npm) and upstream maintainer",                    owner:"CISO",             duration:"<4 hours" },
      { step:7, action:"Update dependency allowlist and add verification checks",                            owner:"DevOps",           duration:"<8 hours" },
      { step:8, action:"Full regulatory notification if customer data may have been exposed",                owner:"Legal/CISO",       duration:"<72 hours" },
    ],
  },
  "rce-pattern": {
    name:"RCE Vulnerability Response",
    steps:[
      { step:1, action:"Assess if the vulnerable code path is reachable from an untrusted input",           owner:"Developer",        duration:"<30 min" },
      { step:2, action:"If reachable: take affected service offline until patched",                          owner:"DevOps",           duration:"<1 hour" },
      { step:3, action:"Apply emergency patch — replace eval/exec with safe alternative",                   owner:"Developer",        duration:"<2 hours" },
      { step:4, action:"Scan all logs for exploitation attempts against the affected endpoint",              owner:"SecOps",           duration:"<4 hours" },
      { step:5, action:"Deploy patched version with enhanced monitoring",                                    owner:"DevOps",           duration:"<6 hours" },
      { step:6, action:"Run full vulnerability scan against all repos for similar patterns",                 owner:"Security Lead",    duration:"<8 hours" },
      { step:7, action:"Update CI/CD to block eval/exec patterns in future code",                           owner:"DevOps",           duration:"<24 hours" },
    ],
  },
  "auth-bypass": {
    name:"Authentication Bypass Response",
    steps:[
      { step:1, action:"Identify all endpoints affected by the bypass — check access logs",                  owner:"SecOps",           duration:"<1 hour" },
      { step:2, action:"Force-expire all active sessions across affected services",                          owner:"Security Lead",    duration:"<1 hour" },
      { step:3, action:"Apply emergency hotfix — add proper authentication checks",                          owner:"Developer",        duration:"<3 hours" },
      { step:4, action:"Audit affected endpoints for unauthorized data access",                              owner:"SecOps",           duration:"<4 hours" },
      { step:5, action:"Notify affected users if their data may have been accessed",                         owner:"Legal/CISO",       duration:"<24 hours" },
      { step:6, action:"Comprehensive authentication audit across all services",                             owner:"Security Lead",    duration:"<1 week" },
    ],
  },
  "data-breach": {
    name:"Data Breach Response",
    steps:[
      { step:1, action:"Immediately isolate affected systems to prevent further data exfiltration",          owner:"SecOps",           duration:"<30 min" },
      { step:2, action:"Identify and scope the breach — what data, how much, what period",                  owner:"Security Lead",    duration:"<2 hours" },
      { step:3, action:"Preserve forensic evidence — snapshot logs before rotation",                        owner:"SecOps",           duration:"<2 hours" },
      { step:4, action:"Notify executive team and legal counsel",                                            owner:"CISO",             duration:"<4 hours" },
      { step:5, action:"Regulatory notification (GDPR: 72h, CCPA: 45d, PCI-DSS: immediate)",               owner:"Legal/CISO",       duration:"<72 hours" },
      { step:6, action:"Notify affected individuals",                                                        owner:"Legal",            duration:"<30 days" },
      { step:7, action:"Full post-incident forensic report",                                                 owner:"Security Lead",    duration:"<1 month" },
    ],
  },
  "policy-violation": {
    name:"Policy Violation Response",
    steps:[
      { step:1, action:"Block the PR/merge that triggered the violation",                                    owner:"TrustLedger",      duration:"Auto" },
      { step:2, action:"Notify the code author and their manager",                                           owner:"Security Lead",    duration:"<1 hour" },
      { step:3, action:"Conduct risk assessment — is the violation exploitable in current context",          owner:"Security Reviewer",duration:"<4 hours" },
      { step:4, action:"Require security training completion before merge is unblocked",                     owner:"Security Lead",    duration:"<24 hours" },
      { step:5, action:"Update detection rules if this is a new pattern",                                    owner:"Security Lead",    duration:"<48 hours" },
    ],
  },
};
