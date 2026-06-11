/**
 * TrustLedger local test seed — v3
 *
 * Provides realistic data across every localStorage key so all sidebar
 * pages render correctly without a live backend.
 *
 * Usage:
 *   Navigate to /seed  → auto-applies and redirects to /dashboard
 *   applySeed()        — programmatic apply
 *   clearSeed()        — removes all keys, live API resumes
 */

// Org slug — picks up the env var baked in at build time
const ORG = process.env.NEXT_PUBLIC_ORG ?? "acmecorp";

// Reference date helpers
const TODAY   = new Date();
const D  = (offsetMs: number) => new Date(TODAY.getTime() + offsetMs).toISOString();
const DAYS  = (n: number) => n * 86_400_000;
const HOURS = (n: number) => n * 3_600_000;
const ds    = (iso: string) => iso.split("T")[0]; // ISO → date-only string

// ── Dashboard snapshot ─────────────────────────────────────────────────────────

const DASHBOARD = {
  repos: [
    { repo:`${ORG}/payments-api`,        ai_pct:0.74, attestation_rate:0.82, last_scan:D(-HOURS(3)),  scan_count:41, file_count:231, latest_scan_id:"sc_001" },
    { repo:`${ORG}/auth-service`,         ai_pct:0.41, attestation_rate:0.96, last_scan:D(-HOURS(7)),  scan_count:33, file_count:178, latest_scan_id:"sc_002" },
    { repo:`${ORG}/fraud-detection`,      ai_pct:0.68, attestation_rate:0.61, last_scan:D(-HOURS(28)), scan_count:24, file_count:156, latest_scan_id:"sc_003" },
    { repo:`${ORG}/risk-engine`,          ai_pct:0.33, attestation_rate:0.94, last_scan:D(-HOURS(52)), scan_count:18, file_count:104, latest_scan_id:"sc_004" },
    { repo:`${ORG}/data-platform`,        ai_pct:0.71, attestation_rate:0.48, last_scan:D(-HOURS(13)), scan_count:23, file_count:150, latest_scan_id:"sc_013" },
    { repo:`${ORG}/ml-platform`,          ai_pct:0.83, attestation_rate:0.39, last_scan:D(-HOURS(12)), scan_count:13, file_count:119, latest_scan_id:"sc_006" },
    { repo:`${ORG}/api-gateway`,          ai_pct:0.55, attestation_rate:0.77, last_scan:D(-HOURS(6)),  scan_count:20, file_count:131, latest_scan_id:"sc_007" },
    { repo:`${ORG}/user-service`,         ai_pct:0.47, attestation_rate:0.85, last_scan:D(-HOURS(18)), scan_count:16, file_count:97,  latest_scan_id:"sc_008" },
    { repo:`${ORG}/notification-service`, ai_pct:0.62, attestation_rate:0.58, last_scan:D(-HOURS(35)), scan_count:11, file_count:74,  latest_scan_id:"sc_009" },
    { repo:`${ORG}/order-service`,        ai_pct:0.58, attestation_rate:0.72, last_scan:D(-HOURS(9)),  scan_count:15, file_count:89,  latest_scan_id:"sc_010" },
    { repo:`${ORG}/billing-service`,      ai_pct:0.45, attestation_rate:0.88, last_scan:D(-HOURS(14)), scan_count:12, file_count:67,  latest_scan_id:"sc_011" },
    { repo:`${ORG}/cli-tools`,            ai_pct:0.72, attestation_rate:0.51, last_scan:D(-HOURS(22)), scan_count:8,  file_count:43,  latest_scan_id:"sc_012" },
  ],
  overall_ai_pct: 0.60,
  attestation_rate: 0.71,
  unattested_deploy_count: 9,
  scan_count: 233,
  file_count: 1437,
  risk_trend: [
    { date:"2026-01-15", high_count:32, critical_count:13, medium_count:44 },
    { date:"2026-02-01", high_count:28, critical_count:11, medium_count:39 },
    { date:"2026-02-15", high_count:25, critical_count:10, medium_count:35 },
    { date:"2026-03-01", high_count:22, critical_count:8,  medium_count:31 },
    { date:"2026-03-15", high_count:19, critical_count:7,  medium_count:28 },
    { date:"2026-04-01", high_count:17, critical_count:6,  medium_count:24 },
    { date:"2026-04-15", high_count:14, critical_count:5,  medium_count:20 },
    { date:"2026-05-01", high_count:12, critical_count:4,  medium_count:16 },
    { date:"2026-05-15", high_count:9,  critical_count:3,  medium_count:12 },
    { date:"2026-05-31", high_count:7,  critical_count:2,  medium_count:9  },
  ],
  top_risk_files: [
    // payments-api — 4 files
    { repo:`${ORG}/payments-api`,        file_path:"src/processors/card_validator.py",        ai_pct:0.95, risk_score:"CRITICAL", attested:false, scan_id:"sc_001", pr_number:524 },
    { repo:`${ORG}/payments-api`,        file_path:"src/gateway/stripe_client.py",            ai_pct:0.79, risk_score:"HIGH",     attested:false, scan_id:"sc_001", pr_number:524 },
    { repo:`${ORG}/payments-api`,        file_path:"src/middleware/auth_check.ts",             ai_pct:0.66, risk_score:"HIGH",     attested:false, scan_id:"sc_001", pr_number:524 },
    { repo:`${ORG}/payments-api`,        file_path:"src/services/payment_service.ts",         ai_pct:0.84, risk_score:"HIGH",     attested:false, scan_id:"sc_001", pr_number:524 },
    // auth-service
    { repo:`${ORG}/auth-service`,         file_path:"src/auth/token_service.py",               ai_pct:0.77, risk_score:"HIGH",     attested:false, scan_id:"sc_002", pr_number:388 },
    // fraud-detection — 3 files
    { repo:`${ORG}/fraud-detection`,      file_path:"models/risk_scorer.ts",                   ai_pct:0.89, risk_score:"CRITICAL", attested:false, scan_id:"sc_003", pr_number:261 },
    { repo:`${ORG}/fraud-detection`,      file_path:"src/database/connection.py",              ai_pct:0.73, risk_score:"HIGH",     attested:false, scan_id:"sc_003", pr_number:261 },
    { repo:`${ORG}/fraud-detection`,      file_path:"src/models/anomaly_detector.py",          ai_pct:0.68, risk_score:"MEDIUM",   attested:false, scan_id:"sc_003", pr_number:261 },
    // data-platform — 2 files
    { repo:`${ORG}/data-platform`,        file_path:"src/connectors/bigquery_writer.ts",       ai_pct:0.85, risk_score:"HIGH",     attested:false, scan_id:"sc_005", pr_number:131 },
    { repo:`${ORG}/data-platform`,        file_path:"src/pipelines/etl_runner.py",             ai_pct:0.67, risk_score:"HIGH",     attested:false, scan_id:"sc_005", pr_number:131 },
    // data-platform — large mixed human/AI files (PR 107, feat/customer-sync-v2)
    { repo:`${ORG}/data-platform`,        file_path:"src/pipelines/customer_data_sync.py",     ai_pct:0.45, risk_score:"HIGH",     attested:false, scan_id:"sc_013", pr_number:107 },
    { repo:`${ORG}/data-platform`,        file_path:"src/connectors/order_export_client.ts",   ai_pct:0.40, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_013", pr_number:107 },
    // ml-platform — 3 files
    { repo:`${ORG}/ml-platform`,          file_path:"src/models/inference_engine.py",          ai_pct:0.93, risk_score:"CRITICAL", attested:false, scan_id:"sc_006", pr_number:97  },
    { repo:`${ORG}/ml-platform`,          file_path:"src/training/data_pipeline.py",           ai_pct:0.87, risk_score:"HIGH",     attested:false, scan_id:"sc_006", pr_number:97  },
    { repo:`${ORG}/ml-platform`,          file_path:"src/serving/model_server.py",             ai_pct:0.81, risk_score:"HIGH",     attested:false, scan_id:"sc_006", pr_number:97  },
    // notification-service — 2 files
    { repo:`${ORG}/notification-service`, file_path:"src/providers/email_sender.py",           ai_pct:0.78, risk_score:"HIGH",     attested:false, scan_id:"sc_009", pr_number:44  },
    { repo:`${ORG}/notification-service`, file_path:"src/templates/render_engine.ts",          ai_pct:0.64, risk_score:"MEDIUM",   attested:false, scan_id:"sc_009", pr_number:44  },
    // order-service (Go)
    { repo:`${ORG}/order-service`,        file_path:"pkg/orders/handler.go",                   ai_pct:0.87, risk_score:"CRITICAL", attested:false, scan_id:"sc_010", pr_number:78  },
    { repo:`${ORG}/order-service`,        file_path:"internal/db/queries.go",                  ai_pct:0.71, risk_score:"HIGH",     attested:false, scan_id:"sc_010", pr_number:78  },
    // billing-service (Java)
    { repo:`${ORG}/billing-service`,      file_path:"src/main/java/billing/PaymentProcessor.java", ai_pct:0.82, risk_score:"HIGH", attested:false, scan_id:"sc_011", pr_number:53  },
    { repo:`${ORG}/billing-service`,      file_path:"src/main/java/billing/InvoiceService.java",   ai_pct:0.64, risk_score:"MEDIUM", attested:false, scan_id:"sc_011", pr_number:53 },
    // cli-tools (Rust)
    { repo:`${ORG}/cli-tools`,            file_path:"src/crypto/hash.rs",                      ai_pct:0.76, risk_score:"HIGH",     attested:false, scan_id:"sc_012", pr_number:31  },
    { repo:`${ORG}/cli-tools`,            file_path:"src/net/http_client.rs",                  ai_pct:0.69, risk_score:"MEDIUM",   attested:false, scan_id:"sc_012", pr_number:31  },
    // already attested (clean examples)
    { repo:`${ORG}/api-gateway`,          file_path:"src/middleware/auth_interceptor.ts",      ai_pct:0.81, risk_score:"HIGH",     attested:true,  scan_id:"sc_007", pr_number:217 },
    { repo:`${ORG}/risk-engine`,          file_path:"src/scoring/ml_pipeline.ts",              ai_pct:0.74, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_004", pr_number:101 },
    { repo:`${ORG}/user-service`,         file_path:"src/handlers/profile_update.ts",          ai_pct:0.61, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_008", pr_number:183 },
  ],
};

// ── Per-feature seed data ──────────────────────────────────────────────────────

const SEED: Record<string, unknown> = {

  // ── Violations ───────────────────────────────────────────────────────────────
  "tl_violation_statuses": {
    [`crit::sc_001::src/processors/card_validator.py`]:        "open",
    [`high::sc_001::src/gateway/stripe_client.py`]:            "open",
    [`high::sc_001::src/middleware/auth_check.ts`]:             "open",
    [`high::sc_001::src/services/payment_service.ts`]:         "open",
    [`high::sc_002::src/auth/token_service.py`]:               "open",
    [`crit::sc_003::models/risk_scorer.ts`]:                   "open",
    [`high::sc_003::src/database/connection.py`]:              "open",
    [`med::sc_003::src/models/anomaly_detector.py`]:           "open",
    [`high::sc_005::src/connectors/bigquery_writer.ts`]:       "open",
    [`high::sc_005::src/pipelines/etl_runner.py`]:             "open",
    [`crit::sc_006::src/models/inference_engine.py`]:          "open",
    [`high::sc_006::src/training/data_pipeline.py`]:           "open",
    [`high::sc_006::src/serving/model_server.py`]:             "open",
    [`high::sc_009::src/providers/email_sender.py`]:           "open",
    [`med::sc_009::src/templates/render_engine.ts`]:           "open",
    [`crit::sc_010::pkg/orders/handler.go`]:                   "open",
    [`high::sc_010::internal/db/queries.go`]:                  "open",
    [`high::sc_011::src/main/java/billing/PaymentProcessor.java`]: "open",
    [`med::sc_011::src/main/java/billing/InvoiceService.java`]: "open",
    [`high::sc_012::src/crypto/hash.rs`]:                      "open",
    [`med::sc_012::src/net/http_client.rs`]:                   "open",
    [`high::sc_013::src/pipelines/customer_data_sync.py`]:     "open",
  },
  "tl_violation_assignees": {
    [`crit::sc_001::src/processors/card_validator.py`]:        `alice@${ORG}.io`,
    [`high::sc_001::src/gateway/stripe_client.py`]:            `dave@${ORG}.io`,
    [`crit::sc_003::models/risk_scorer.ts`]:                   `carol@${ORG}.io`,
    [`crit::sc_006::src/models/inference_engine.py`]:          `bob@${ORG}.io`,
    [`high::sc_002::src/auth/token_service.py`]:               `alice@${ORG}.io`,
    [`high::sc_005::src/connectors/bigquery_writer.ts`]:       `dave@${ORG}.io`,
    [`high::sc_009::src/providers/email_sender.py`]:           `eve@${ORG}.io`,
    [`high::sc_013::src/pipelines/customer_data_sync.py`]:     `diana@${ORG}.io`,
  },

  // ── Alerts ───────────────────────────────────────────────────────────────────
  "tl_alerts_state": {
    statuses: {
      "alert_p1_001": "firing",
      "alert_p1_002": "firing",
      "alert_p2_001": "acknowledged",
      "alert_p2_002": "acknowledged",
      "alert_p3_001": "snoozed",
      "alert_p3_002": "firing",
      "alert_p4_001": "resolved",
      "alert_p4_002": "resolved",
      "alert_p4_003": "resolved",
    },
    ackBy: {
      "alert_p2_001": `alice@${ORG}.io`,
      "alert_p2_002": `bob@${ORG}.io`,
    },
    snoozeUntil: {
      "alert_p3_001": D(HOURS(18)),
    },
    resolvedAt: {
      "alert_p4_001": D(-HOURS(4)),
      "alert_p4_002": D(-HOURS(9)),
      "alert_p4_003": D(-HOURS(36)),
    },
    notes: {
      "alert_p2_001": ["Investigating — confirmed AI pattern. Dev team notified. PR #524 blocked."],
      "alert_p2_002": ["Hallucinated package import confirmed removed. Allowlist PR in review."],
      "alert_p3_001": ["Low severity — snoozed pending sprint planning. Will address in next cycle."],
    },
    history: {
      "alert_p1_001": [
        { action:"Alert created",      at:D(-HOURS(2)) },
        { action:"Auto-escalated P1",  at:D(-HOURS(1.9)) },
      ],
      "alert_p4_001": [
        { action:"Alert created",       at:D(-HOURS(24)) },
        { action:`Resolved by alice`,   at:D(-HOURS(4)) },
      ],
    },
  },

  // ── Secrets ───────────────────────────────────────────────────────────────────
  "tl_secret_status": {},
  "tl_secret_total": "11",

  // ── Incidents ────────────────────────────────────────────────────────────────
  "tl_incidents": [
    {
      id:"INC-2026-001", severity:"P1", type:"secret-exposed", status:"active",
      affected_repo:`${ORG}/payments-api`, affected_file:"src/processors/card_validator.py",
      detected_at: D(-HOURS(2.5)),
      title:"Production Stripe API key committed to payments-api repo",
      description:"TrustLedger detected a live Stripe production API key (sk_live_51Hx2...) in card_validator.py. The key was accessible to all repo contributors for approximately 2 hours before detection.",
      impact:"Potential unauthorized charge creation. Key is being rotated. Audit logs show no exploitation yet but must be treated as compromised.",
      timeline:[
        { time:D(-HOURS(2.5)),  action:"Secret detected by TrustLedger scan",             actor:"TrustLedger" },
        { time:D(-HOURS(2.48)), action:"P1 alert fired — merge gate blocked",              actor:"TrustLedger" },
        { time:D(-HOURS(2.1)),  action:"On-call security lead paged",                      actor:"PagerDuty" },
        { time:D(-HOURS(1.8)),  action:"Incident declared — alice assigned as lead",       actor:`alice@${ORG}.io` },
        { time:D(-HOURS(1.2)),  action:"Stripe notified, rotation initiated",              actor:`alice@${ORG}.io` },
      ],
      playbook:[
        { step:1, action:"Rotate Stripe key immediately in Stripe Dashboard",             owner:`alice@${ORG}.io`, duration:"<15 min",  completed:true  },
        { step:2, action:"Revoke all active sessions using compromised key",              owner:`alice@${ORG}.io`, duration:"<30 min",  completed:true  },
        { step:3, action:"Audit Stripe logs for unauthorized charges (last 48h)",         owner:"SecOps",           duration:"<2 hours", completed:false },
        { step:4, action:"Remove secret from source and purge git history",               owner:`dave@${ORG}.io`,  duration:"<3 hours", completed:false },
        { step:5, action:"Force-push cleaned history and notify all committers",          owner:`dave@${ORG}.io`,  duration:"<4 hours", completed:false },
        { step:6, action:"Add secret scanning gate to all PR checks",                    owner:"DevOps",           duration:"<8 hours", completed:false },
        { step:7, action:"File incident report — notify payment processor per PCI-DSS",  owner:`alice@${ORG}.io`, duration:"<24 hours",completed:false },
      ],
      stakeholders:[`alice@${ORG}.io`,`ciso@${ORG}.io`,`legal@${ORG}.io`,`payments-oncall@${ORG}.io`],
    },
    {
      id:"INC-2026-002", severity:"P1", type:"supply-chain", status:"contained",
      affected_repo:`${ORG}/fraud-detection`, affected_file:"models/requirements.txt",
      detected_at:  D(-HOURS(20)),
      contained_at: D(-HOURS(17)),
      title:"Hallucinated package 'ml-utils-fast' — typosquatting attack surface exposed",
      description:"AI-generated requirements.txt imported ml-utils-fast which does not exist on PyPI. An attacker could register this package name with malicious code that would execute on next `pip install`. Package removed within 3 hours of detection.",
      impact:"Package removed before exploitation. No malicious code installed. Developer awareness training scheduled.",
      timeline:[
        { time:D(-HOURS(20)),   action:"Hallucinated package detected by dep scanner",    actor:"TrustLedger" },
        { time:D(-HOURS(19.9)), action:"P1 supply-chain alert created",                   actor:"TrustLedger" },
        { time:D(-HOURS(19)),   action:"Checked PyPI — package not yet registered",       actor:`carol@${ORG}.io` },
        { time:D(-HOURS(18)),   action:"PR blocked, developer notified, package removed", actor:`alice@${ORG}.io` },
        { time:D(-HOURS(17)),   action:"Incident contained — monitoring active 48h",      actor:`alice@${ORG}.io` },
      ],
      playbook:[
        { step:1, action:"Remove package from all environments immediately",              owner:"DevOps",            duration:"<15 min", completed:true  },
        { step:2, action:"Verify no malicious package registered on PyPI/npm",            owner:`carol@${ORG}.io`,  duration:"<1 hour", completed:true  },
        { step:3, action:"Check if package was installed on any system",                  owner:"SecOps",            duration:"<2 hours",completed:true  },
        { step:4, action:"Register defensive package on PyPI to prevent squatting",      owner:"DevOps",            duration:"<4 hours",completed:false },
        { step:5, action:"Add ml-utils-fast and variants to package denylist",           owner:"DevOps",            duration:"<8 hours",completed:false },
      ],
      stakeholders:[`alice@${ORG}.io`,`bob@${ORG}.io`,`ciso@${ORG}.io`],
      related_cve:"CVE-2024-3094",
    },
    {
      id:"INC-2026-003", severity:"P2", type:"rce-pattern", status:"resolved",
      affected_repo:`${ORG}/fraud-detection`,
      detected_at:  D(-DAYS(6)),
      resolved_at:  D(-DAYS(5)),
      title:"eval() RCE pattern in risk_scorer.ts — patched with mathjs",
      description:"AI-generated code in risk_scorer.ts used eval() on a formula string for dynamic scoring rules. While the code path had no external input vector, the pattern is CRITICAL if a future change adds user input. Patched with mathjs sandbox.",
      impact:"Low exploitability — internal-only path. No evidence of exploitation. Proactive patch applied within 24h.",
      root_cause:"AI assistant generated eval() as the simplest formula evaluator. Training data included legacy JavaScript that used eval() before safe alternatives existed.",
      lesson_learned:"Added eval/exec/new Function to pre-commit lint rules. All AI-generated dynamic code now requires a comment explaining why execution is safe.",
      timeline:[
        { time:D(-DAYS(6)),              action:"eval() detected in scan",                     actor:"TrustLedger" },
        { time:D(-DAYS(6)+HOURS(2)),     action:"Assessed: internal-only, low exploitability", actor:`carol@${ORG}.io` },
        { time:D(-DAYS(5)+HOURS(4)),     action:"Patch merged — mathjs sandbox replaces eval()",actor:`bob@${ORG}.io` },
        { time:D(-DAYS(5)+HOURS(6)),     action:"Lint rule added to CI, incident resolved",    actor:`alice@${ORG}.io` },
      ],
      playbook:[
        { step:1, action:"Assess reachability — is this path callable externally?",            owner:"Developer",        duration:"<30 min", completed:true },
        { step:2, action:"Replace eval() with mathjs sandbox or allowlist approach",           owner:"Developer",        duration:"<4 hours",completed:true },
        { step:3, action:"Audit logs for any suspicious formula strings (last 90d)",           owner:"SecOps",           duration:"<2 hours",completed:true },
        { step:4, action:"Add eval/exec/new Function to pre-commit lint rules",               owner:"DevOps",           duration:"<8 hours",completed:true },
      ],
      stakeholders:[`carol@${ORG}.io`,`bob@${ORG}.io`],
    },
    {
      id:"INC-2026-004", severity:"P2", type:"auth-bypass", status:"post-mortem",
      affected_repo:`${ORG}/auth-service`,
      detected_at:  D(-DAYS(12)),
      resolved_at:  D(-DAYS(10)),
      title:"OAuth2 implicit flow in AI-generated auth — deprecated pattern with token exposure risk",
      description:"Code review caught an AI-generated OAuth2 implementation using the implicit flow (deprecated 2019, RFC 9700). Access tokens were returned in URL fragments, exposing them in browser history and server logs. Pattern was caught in review before production deployment.",
      impact:"Caught before production. 3 internal test environments cleaned. PKCE migration completed for auth-service. No user tokens compromised.",
      lesson_learned:"OAuth implicit flow added to TrustLedger AI risk pattern catalog. All AI code touching OAuth/JWT now requires security_reviewer attestation.",
      timeline:[
        { time:D(-DAYS(12)),             action:"AI reviewer flagged OAuth implicit flow in PR", actor:`carol@${ORG}.io` },
        { time:D(-DAYS(11)),             action:"Incident declared — scope: auth-service",       actor:`alice@${ORG}.io` },
        { time:D(-DAYS(10)+HOURS(3)),    action:"PKCE migration PR merged",                      actor:`bob@${ORG}.io` },
        { time:D(-DAYS(10)),             action:"Incident resolved — post-mortem scheduled",     actor:`alice@${ORG}.io` },
      ],
      playbook:[
        { step:1, action:"Audit all OAuth endpoints for implicit flow usage",                   owner:"SecOps",           duration:"<2 hours",completed:true },
        { step:2, action:"Force-expire all tokens issued via implicit flow",                    owner:"Security Lead",    duration:"<1 hour", completed:true },
        { step:3, action:"Apply PKCE migration to all OAuth flows",                            owner:`bob@${ORG}.io`,   duration:"<1 day",  completed:true },
        { step:4, action:"Add OAuth implicit flow to AI code pattern denylist",               owner:"Security Lead",    duration:"<4 hours",completed:true },
        { step:5, action:"Comprehensive auth audit — verify no other deprecated patterns",    owner:"Security Lead",    duration:"<1 week", completed:false },
      ],
      stakeholders:[`carol@${ORG}.io`,`bob@${ORG}.io`,`alice@${ORG}.io`],
    },
    {
      id:"INC-2026-005", severity:"P3", type:"policy-violation", status:"active",
      affected_repo:`${ORG}/ml-platform`,
      detected_at: D(-HOURS(1)),
      title:"ml-platform: 3 CRITICAL files deployed without attestation (policy breach)",
      description:"3 CRITICAL-severity AI-generated files bypassed the attestation gate. Investigation shows the GitHub App merge gate was temporarily misconfigured during a platform upgrade. All 3 files have 90%+ AI content.",
      impact:"Compliance posture degraded. 3 unreviewed CRITICAL files in production. No security incident yet but SLA clock started.",
      timeline:[
        { time:D(-HOURS(1)),   action:"Unattested CRITICAL files detected in prod branch", actor:"TrustLedger" },
        { time:D(-HOURS(0.9)), action:"Policy violation incident auto-created",            actor:"TrustLedger" },
      ],
      playbook:[
        { step:1, action:"Block further deployments from ml-platform until resolved",    owner:"TrustLedger",       duration:"Auto",     completed:true  },
        { step:2, action:"Investigate merge gate misconfiguration — fix or rollback",    owner:"DevOps",            duration:"<2 hours", completed:false },
        { step:3, action:"Assign security reviewer to each CRITICAL file",              owner:"Security Lead",     duration:"<4 hours", completed:false },
        { step:4, action:"Complete attestation for all 3 files via PR review",          owner:`alice@${ORG}.io`,  duration:"<8 hours", completed:false },
        { step:5, action:"Audit: check for similar bypass in other repos last 30d",     owner:"SecOps",            duration:"<24 hours",completed:false },
      ],
      stakeholders:[`alice@${ORG}.io`,`devops@${ORG}.io`,`ciso@${ORG}.io`],
    },
    {
      id:"INC-2026-006", severity:"P3", type:"policy-violation", status:"active",
      affected_repo:`${ORG}/notification-service`,
      detected_at: D(-HOURS(35)),
      title:"notification-service: unattested HIGH-risk email template contains injectable pattern",
      description:"email_sender.py uses string interpolation to compose HTML email bodies with user-supplied data. This pattern risks both XSS (if rendered in webmail) and email injection. File AI content is 78%, generated by Copilot autocompletion.",
      impact:"Email injection/XSS risk in transactional notification emails. Blocked in staging — not yet in production.",
      timeline:[
        { time:D(-HOURS(35)),  action:"XSS/injection pattern detected in AI-generated code", actor:"TrustLedger" },
        { time:D(-HOURS(34.8)),action:"HIGH alert fired, PR#44 blocked",                      actor:"TrustLedger" },
        { time:D(-HOURS(34)),  action:"Assigned to eve for review",                           actor:`alice@${ORG}.io` },
      ],
      playbook:[
        { step:1, action:"Replace string interpolation with parameterised email template engine", owner:`eve@${ORG}.io`,  duration:"<4 hours", completed:false },
        { step:2, action:"Add HTML encoding to all user-supplied template variables",             owner:`eve@${ORG}.io`,  duration:"<2 hours", completed:false },
        { step:3, action:"Security review and attest the fixed file",                            owner:`alice@${ORG}.io`,duration:"<8 hours", completed:false },
      ],
      stakeholders:[`eve@${ORG}.io`,`alice@${ORG}.io`,`devops@${ORG}.io`],
    },
  ],

  // ── Risk Register ─────────────────────────────────────────────────────────────
  "tl_risk_register": {
    overrides: {},
    manuals: [
      {
        id:"risk_001", auto_derived:false, _manual:true,
        title:"AI-generated code in critical payment flows lacks mandatory security review",
        description:"payments-api has 74% average AI content. 4 unattested CRITICAL/HIGH files currently in production.",
        category:"ai-code", likelihood:4, impact:5, residual_likelihood:2, residual_impact:3,
        treatment:"mitigate", status:"open",
        owner:`alice@${ORG}.io`,
        due_date: ds(D(DAYS(7))),
        mitigation:"Enforce dual-reviewer attestation for all payment files. AI% gate: block merges >70% AI. Add TrustLedger scan to deployment pipeline.",
        identified_at: ds(D(-DAYS(32))),
        notes:["Escalated to CISO 2026-05-28. Priority: Q2.", "4 files currently unattested — SLA breach risk."],
      },
      {
        id:"risk_002", auto_derived:false, _manual:true,
        title:"AI-hallucinated package imports create typosquatting attack surface",
        description:"AI models recommend non-existent packages. Attackers monitoring PyPI/npm can register these names with malicious code.",
        category:"supply-chain", likelihood:3, impact:5, residual_likelihood:1, residual_impact:2,
        treatment:"mitigate", status:"mitigating",
        owner:`bob@${ORG}.io`,
        due_date: ds(D(DAYS(14))),
        mitigation:"Package allowlist implemented for payments-api and auth-service. Automated PyPI/npm existence check running in CI for 7/9 repos.",
        identified_at: ds(D(-DAYS(48))),
        notes:["INC-2026-002 was direct realization of this risk.", "CI check 78% deployed. ml-platform and notification-service unprotected."],
      },
      {
        id:"risk_003", auto_derived:false, _manual:true,
        title:"Hardcoded credentials committed by AI-assisted development",
        description:"AI code assistants regularly embed placeholder credentials (API keys, JWT secrets, DB passwords) that developers accidentally commit.",
        category:"secrets", likelihood:5, impact:5, residual_likelihood:1, residual_impact:2,
        treatment:"mitigate", status:"mitigating",
        owner:`carol@${ORG}.io`,
        due_date: ds(D(DAYS(3))),
        mitigation:"TrustLedger secret scanner deployed across all repos. Pre-commit hooks deployed to 7/9 repos.",
        identified_at: ds(D(-DAYS(21))),
        notes:["INC-2026-001 is ACTIVE realization of this risk.", "OVERDUE — ml-platform and notification-service pre-commit hooks still pending DevOps capacity."],
      },
      {
        id:"risk_004", auto_derived:false, _manual:true,
        title:"AI training data poisoning affecting future code generation quality",
        description:"Adversarial actors deliberately commit subtly vulnerable code to public repos. AI models trained on this data reproduce similar patterns in generated code.",
        category:"ai-code", likelihood:2, impact:5, residual_likelihood:2, residual_impact:4,
        treatment:"accept", status:"accepted",
        owner:`alice@${ORG}.io`,
        due_date: ds(D(DAYS(90))),
        mitigation:"No industry-wide solution. TrustLedger scanning as compensating control. Subscribe to AI security advisories.",
        identified_at: ds(D(-DAYS(63))),
        notes:["Accepted by CISO 2026-05-01 for Q2. Revisit in Q3 review."],
      },
      {
        id:"risk_005", auto_derived:false, _manual:true,
        title:"OAuth2 implicit flow and deprecated auth patterns in AI-generated code",
        description:"AI models trained on pre-2019 code generate OAuth2 implicit flow implementations (deprecated RFC 9700). Access tokens exposed in browser history.",
        category:"access", likelihood:3, impact:4, residual_likelihood:1, residual_impact:2,
        treatment:"mitigate", status:"mitigating",
        owner:`bob@${ORG}.io`,
        due_date: ds(D(-DAYS(1))),
        mitigation:"PKCE migration completed for auth-service. fraud-detection and ml-platform migrations blocked by feature freeze.",
        identified_at: ds(D(-DAYS(27))),
        related_cve:"CVE-2024-38219",
        notes:["OVERDUE — fraud-detection and ml-platform PKCE migrations 3 days late.", "Feature freeze ends 2026-06-07 — schedule migration immediately after."],
      },
      {
        id:"risk_006", auto_derived:false, _manual:true,
        title:"Container escape via AI-generated Dockerfile WORKDIR patterns",
        description:"AI tools generate Dockerfile WORKDIR patterns that access /proc/self/fd/, exploitable via runc CVE-2024-21626 (CVSS 9.6). Affected runc < 1.1.12.",
        category:"infrastructure", likelihood:1, impact:4, residual_likelihood:1, residual_impact:1,
        treatment:"transfer", status:"closed",
        owner:`bob@${ORG}.io`,
        due_date: ds(D(-DAYS(30))),
        mitigation:"Transferred to Platform team. runc upgraded to 1.1.12 across all environments.",
        identified_at: ds(D(-DAYS(92))),
        related_cve:"CVE-2024-21626",
        notes:["CLOSED 2026-05-01 — runc 1.1.12 deployed. No further action required."],
      },
      {
        id:"risk_007", auto_derived:false, _manual:true,
        title:"ml-platform repo: 83% AI content with only 39% attestation — highest risk in org",
        description:"ml-platform is the highest-risk repository: 83% AI content (above 80% CRITICAL threshold), only 39% attestation coverage, and 3 unattested CRITICAL files in production.",
        category:"ai-code", likelihood:4, impact:5, residual_likelihood:2, residual_impact:4,
        treatment:"mitigate", status:"open",
        owner:`alice@${ORG}.io`,
        due_date: ds(D(DAYS(5))),
        mitigation:"Assign dedicated security reviewer for ml-platform. Mandatory attestation gate for all PRs. Reduce AI content target to <70%.",
        identified_at: ds(D(-DAYS(5))),
        notes:["URGENT — INC-2026-005 created from this risk.", "Recommend temporary deployment freeze until attestation reaches 80%."],
      },
      {
        id:"risk_008", auto_derived:false, _manual:true,
        title:"notification-service: XSS injection via AI-generated HTML email templates",
        description:"email_sender.py uses raw string interpolation with user-supplied data in HTML email bodies. This is a classic XSS vector in webmail clients and email injection risk.",
        category:"ai-code", likelihood:3, impact:3, residual_likelihood:1, residual_impact:2,
        treatment:"mitigate", status:"open",
        owner:`eve@${ORG}.io`,
        due_date: ds(D(DAYS(3))),
        mitigation:"Migrate to parameterised template engine (Jinja2/Handlebars). Add HTML encoding to all user variables.",
        identified_at: ds(D(-HOURS(35))),
        notes:["INC-2026-006 is open realization of this risk.", "Blocked in staging — not yet in production."],
      },
    ],
  },

  // ── Evidence ──────────────────────────────────────────────────────────────────
  "tl_evidence_state": {
    "CC6.1": { collected:true,  notes:"Quarterly access control review completed. 198 attestation records exported from TrustLedger Audit Trail.",  collectedAt:"2026-05-01T10:00:00Z", expiry:"2026-08-01T00:00:00Z" },
    "CC6.2": { collected:false, notes:"GitHub OAuth token log needs to be exported from Audit Trail for the full audit period." },
    "CC6.6": { collected:true,  notes:"EXPIRED — anti-malware evidence from Q1 2025 no longer valid. Recollect required before August audit.",        collectedAt:"2025-11-01T10:00:00Z", expiry:"2026-04-30T00:00:00Z" },
    "CC6.7": { collected:true,  notes:"TLS 1.3 enforced across all endpoints. Certificate inventory exported. External scan evidence attached.",         collectedAt:"2026-05-10T10:00:00Z", expiry:"2026-09-01T00:00:00Z" },
    "CC7.1": { collected:false, notes:"Annual vulnerability assessment delayed — auditor scheduling conflict. Rescheduled to 2026-07-15." },
    "CC7.2": { collected:true,  notes:"198 automated scans across 9 repos this period. TrustLedger scan log exported as evidence pack.",               collectedAt:"2026-05-20T10:00:00Z", expiry:"2026-08-20T00:00:00Z" },
    "CC8.1": { collected:true,  notes:"Attestation coverage at 71%. Change management log tamper-evident via TrustLedger audit trail.",                  collectedAt:"2026-04-15T10:00:00Z", expiry:"2026-09-15T00:00:00Z" },
    "CC9.1": { collected:false, notes:"Business continuity plan update pending CISO sign-off." },
    "Art.9":  { collected:true,  notes:"AI risk management system documented. Risk register covers all 9 scanned AI systems.", collectedAt:"2026-05-05T10:00:00Z", expiry:"2026-11-05T00:00:00Z" },
    "Art.10": { collected:true,  notes:"AI provenance captured for all 1,238 scanned files. Lineage traceable to commit hash.",  collectedAt:"2026-05-20T10:00:00Z", expiry:"2026-11-20T00:00:00Z" },
    "Art.13": { collected:false, notes:"AI transparency statement 70% complete. Legal review pending. ETA: 2026-06-15." },
    "Art.14": { collected:true,  notes:"Human oversight policy enforced: all CRITICAL files require designated reviewer before merge.",  collectedAt:"2026-05-15T10:00:00Z", expiry:"2026-08-15T00:00:00Z" },
    "Art.17": { collected:true,  notes:"198 quality assessments completed. Continuous monitoring active across all repos.",  collectedAt:"2026-05-25T10:00:00Z", expiry:"2026-08-25T00:00:00Z" },
    "Req 6.3":  { collected:true,  notes:"Vulnerability management covers CVSS ≥7.0. Monthly scan results, SBOM exports attached.",  collectedAt:"2026-05-01T10:00:00Z", expiry:"2026-08-01T00:00:00Z" },
    "Req 6.4":  { collected:true,  notes:"Dual-reviewer attestation: 82% coverage on payment-path code changes this quarter.",   collectedAt:"2026-05-20T10:00:00Z", expiry:"2026-08-20T00:00:00Z" },
    "Req 11.3": { collected:false, notes:"External pen test vendor contract expired. New QSA onboarding. Pen test scheduled 2026-09-01." },
  },

  // ── Compliance exceptions ────────────────────────────────────────────────────
  "tl_exceptions_state": [
    {
      id:"exc_001", control_id:"CC7.1", framework_id:"soc2",
      title:"Annual vulnerability assessment — auditor scheduling delay",
      description:"Annual VA delayed due to auditor calendar conflict during peak season. Internal TrustLedger VA completed as interim compensating control.",
      risk_accepted:true, owner:"CISO",
      due_date:"2026-07-15",
      remediation:"External VA rescheduled for 2026-07-15. Internal assessment report available on request.",
      created_at:"2026-04-01T10:00:00Z",
      status:"open",
    },
    {
      id:"exc_002", control_id:"Req 11.3", framework_id:"pcidss",
      title:"PCI-DSS QSA pen test — vendor contract expired",
      description:"SecurityMetrics QSA contract expired 2026-05-01. New vendor contract signed 2026-05-25. Pen test scheduled Q3 2026.",
      risk_accepted:true, owner:"VP Engineering",
      due_date: ds(D(-DAYS(1))),
      remediation:"New vendor contract signed. Pen test scheduled for 2026-09-01. Internal pentest completed as compensating control.",
      created_at:"2026-03-15T10:00:00Z",
      status:"in-progress",
    },
    {
      id:"exc_003", control_id:"Art.13", framework_id:"euai",
      title:"EU AI Act transparency statement — pending legal sign-off",
      description:"AI transparency documentation 70% complete. Legal team reviewing disclosure language per recital 47 requirements.",
      risk_accepted:false, owner:"DPO",
      due_date:"2026-08-15",
      remediation:"Interim AI transparency statement published on developer portal. Full document ETA 2026-06-30.",
      created_at:"2026-05-01T10:00:00Z",
      status:"open",
    },
  ],

  // ── Posture/analytics supporting data ──────────────────────────────────────
  "tl_dep_vuln_count": "11",

  // ── Security policy ──────────────────────────────────────────────────────────
  "tl_org_policy": {
    name:"Security Policy v1.4",
    block_on_critical:true,
    block_on_high:false,
    block_on_medium:false,
    attestations_critical:2,
    attestations_high:1,
    attestations_medium:1,
    ai_flag_threshold:0.5,
    require_designated_reviewer:true,
    slack_webhook:"",
    alert_email:`security@${ORG}.io`,
    notify_critical:true,
    notify_scan_complete:false,
    notify_weekly_digest:true,
  },

  // ── Team members ─────────────────────────────────────────────────────────────
  // Note: all emails referenced in incidents / violations / shadow-ai must appear here
  "tl_team_members": [
    { id:"tm_001", name:"Alice Chen",      email:`alice@${ORG}.io`,   role:"security_reviewer", github:"alice-chen",  joined:"2025-01-15", active:true  },
    { id:"tm_002", name:"Bob Martinez",    email:`bob@${ORG}.io`,     role:"developer",          github:"bobm",        joined:"2025-03-01", active:true  },
    { id:"tm_003", name:"Carol Williams",  email:`carol@${ORG}.io`,   role:"admin",              github:"carol-w",     joined:"2024-06-01", active:true  },
    { id:"tm_004", name:"Dave Kim",        email:`dave@${ORG}.io`,    role:"developer",          github:"davekim",     joined:"2025-07-15", active:true  },
    { id:"tm_005", name:"Eve Thompson",    email:`eve@${ORG}.io`,     role:"security_reviewer",  github:"eve-t",       joined:"2026-01-10", active:true  },
    { id:"tm_006", name:"Frank Liu",       email:`frank@${ORG}.io`,   role:"developer",          github:"frank-l",     joined:"2026-03-01", active:true  },
    { id:"tm_007", name:"Charlie Nguyen",  email:`charlie@${ORG}.io`, role:"developer",          github:"charlie-n",   joined:"2025-09-01", active:true  },
    { id:"tm_008", name:"Diana Okonkwo",   email:`diana@${ORG}.io`,   role:"developer",          github:"diana-o",     joined:"2025-11-15", active:true  },
  ],

  // ── API keys ──────────────────────────────────────────────────────────────────
  "tl_api_keys": [
    { id:"key_001", name:"CI/CD Pipeline — GitHub Actions",       prefix:"tl_ci_", created:"2026-01-15", lastUsed:D(-HOURS(1)),  active:true,  scopes:["scan","report"] },
    { id:"key_002", name:"GitHub Actions Security Bot",           prefix:"tl_gh_", created:"2026-02-01", lastUsed:D(-HOURS(6)),  active:true,  scopes:["scan","attest"] },
    { id:"key_003", name:"SIEM Integration (Splunk)",             prefix:"tl_si_", created:"2026-03-10", lastUsed:D(-DAYS(16)),  active:false, scopes:["report"] },
    { id:"key_004", name:"Compliance Dashboard (Armanino audit)", prefix:"tl_au_", created:"2026-04-01", lastUsed:D(-DAYS(3)),   active:true,  scopes:["report","dashboard"] },
    { id:"key_005", name:"Slack Security Bot",                    prefix:"tl_sl_", created:"2026-05-12", lastUsed:D(-HOURS(2)),  active:true,  scopes:["report"] },
  ],

  // ── Local activity (audit trail + dashboard recent activity) ─────────────────
  "tl_local_activity": [
    // Today
    { type:"attestation", timestamp:D(-HOURS(0.5)),  repo:`${ORG}/api-gateway`,          pr_number:217, scan_id:"sc_007", overall_risk:"HIGH",     file_count:0, total_ai_pct:0.81, file_path:"src/middleware/auth_interceptor.ts",      reviewer_email:`alice@${ORG}.io` },
    { type:"attestation", timestamp:D(-HOURS(12)),   repo:`${ORG}/data-platform`,        pr_number:107, scan_id:"sc_013", overall_risk:"MEDIUM",   file_count:0, total_ai_pct:0.40, file_path:"src/connectors/order_export_client.ts",   reviewer_email:`charlie@${ORG}.io` },
    { type:"scan",        timestamp:D(-HOURS(13)),   repo:`${ORG}/data-platform`,        pr_number:107, scan_id:"sc_013", overall_risk:"HIGH",     file_count:2, total_ai_pct:0.43, file_path:"", reviewer_email:"" },
    { type:"attestation", timestamp:D(-HOURS(1.2)),  repo:`${ORG}/risk-engine`,           pr_number:101, scan_id:"sc_004", overall_risk:"MEDIUM",   file_count:0, total_ai_pct:0.74, file_path:"src/scoring/ml_pipeline.ts",              reviewer_email:`bob@${ORG}.io` },
    { type:"attestation", timestamp:D(-HOURS(2.1)),  repo:`${ORG}/user-service`,          pr_number:183, scan_id:"sc_008", overall_risk:"MEDIUM",   file_count:0, total_ai_pct:0.61, file_path:"src/handlers/profile_update.ts",          reviewer_email:`eve@${ORG}.io` },
    { type:"scan",        timestamp:D(-HOURS(3)),    repo:`${ORG}/payments-api`,          pr_number:524, scan_id:"sc_001", overall_risk:"CRITICAL", file_count:8, total_ai_pct:0.74, file_path:"", reviewer_email:"" },
    { type:"scan",        timestamp:D(-HOURS(6)),    repo:`${ORG}/api-gateway`,           pr_number:217, scan_id:"sc_007", overall_risk:"HIGH",     file_count:4, total_ai_pct:0.55, file_path:"", reviewer_email:"" },
    { type:"scan",        timestamp:D(-HOURS(7)),    repo:`${ORG}/auth-service`,          pr_number:388, scan_id:"sc_002", overall_risk:"HIGH",     file_count:3, total_ai_pct:0.41, file_path:"", reviewer_email:"" },
    { type:"scan",        timestamp:D(-HOURS(9)),    repo:`${ORG}/order-service`,         pr_number:78,  scan_id:"sc_010", overall_risk:"CRITICAL", file_count:5, total_ai_pct:0.58, file_path:"", reviewer_email:"" },
    { type:"scan",        timestamp:D(-HOURS(12)),   repo:`${ORG}/ml-platform`,           pr_number:97,  scan_id:"sc_006", overall_risk:"CRITICAL", file_count:6, total_ai_pct:0.83, file_path:"", reviewer_email:"" },
    { type:"scan",        timestamp:D(-HOURS(14)),   repo:`${ORG}/billing-service`,       pr_number:53,  scan_id:"sc_011", overall_risk:"HIGH",     file_count:4, total_ai_pct:0.45, file_path:"", reviewer_email:"" },
    { type:"scan",        timestamp:D(-HOURS(18)),   repo:`${ORG}/user-service`,          pr_number:183, scan_id:"sc_008", overall_risk:"MEDIUM",   file_count:5, total_ai_pct:0.47, file_path:"", reviewer_email:"" },
    { type:"scan",        timestamp:D(-HOURS(22)),   repo:`${ORG}/cli-tools`,             pr_number:31,  scan_id:"sc_012", overall_risk:"HIGH",     file_count:3, total_ai_pct:0.72, file_path:"", reviewer_email:"" },
    // Yesterday
    { type:"attestation", timestamp:D(-HOURS(26)),   repo:`${ORG}/risk-engine`,           pr_number:98,  scan_id:"sc_004", overall_risk:"LOW",      file_count:0, total_ai_pct:0.28, file_path:"src/utils/date_helpers.ts",               reviewer_email:`charlie@${ORG}.io` },
    { type:"scan",        timestamp:D(-HOURS(28)),   repo:`${ORG}/fraud-detection`,       pr_number:261, scan_id:"sc_003", overall_risk:"CRITICAL", file_count:7, total_ai_pct:0.68, file_path:"", reviewer_email:"" },
    { type:"scan",        timestamp:D(-HOURS(35)),   repo:`${ORG}/notification-service`,  pr_number:44,  scan_id:"sc_009", overall_risk:"HIGH",     file_count:4, total_ai_pct:0.62, file_path:"", reviewer_email:"" },
    { type:"attestation", timestamp:D(-HOURS(38)),   repo:`${ORG}/auth-service`,          pr_number:385, scan_id:"sc_002", overall_risk:"HIGH",     file_count:0, total_ai_pct:0.77, file_path:"src/sessions/refresh_handler.ts",         reviewer_email:`alice@${ORG}.io` },
    { type:"scan",        timestamp:D(-HOURS(41)),   repo:`${ORG}/data-platform`,         pr_number:131, scan_id:"sc_005", overall_risk:"HIGH",     file_count:5, total_ai_pct:0.71, file_path:"", reviewer_email:"" },
    // 2 days ago
    { type:"attestation", timestamp:D(-HOURS(52)),   repo:`${ORG}/api-gateway`,           pr_number:214, scan_id:"sc_007", overall_risk:"MEDIUM",   file_count:0, total_ai_pct:0.52, file_path:"src/rate_limiter/token_bucket.ts",        reviewer_email:`bob@${ORG}.io` },
    { type:"scan",        timestamp:D(-HOURS(54)),   repo:`${ORG}/risk-engine`,           pr_number:101, scan_id:"sc_004", overall_risk:"MEDIUM",   file_count:3, total_ai_pct:0.33, file_path:"", reviewer_email:"" },
    { type:"attestation", timestamp:D(-HOURS(58)),   repo:`${ORG}/fraud-detection`,       pr_number:258, scan_id:"sc_003", overall_risk:"HIGH",     file_count:0, total_ai_pct:0.73, file_path:"src/database/connection.py",              reviewer_email:`carol@${ORG}.io` },
    { type:"scan",        timestamp:D(-HOURS(62)),   repo:`${ORG}/user-service`,          pr_number:181, scan_id:"sc_008", overall_risk:"LOW",      file_count:2, total_ai_pct:0.39, file_path:"", reviewer_email:"" },
    // 3 days ago
    { type:"attestation", timestamp:D(-HOURS(74)),   repo:`${ORG}/payments-api`,          pr_number:521, scan_id:"sc_001", overall_risk:"CRITICAL", file_count:0, total_ai_pct:0.95, file_path:"src/processors/refund_processor.py",      reviewer_email:`alice@${ORG}.io` },
    { type:"scan",        timestamp:D(-HOURS(78)),   repo:`${ORG}/ml-platform`,           pr_number:94,  scan_id:"sc_006", overall_risk:"HIGH",     file_count:4, total_ai_pct:0.79, file_path:"", reviewer_email:"" },
    { type:"attestation", timestamp:D(-HOURS(82)),   repo:`${ORG}/notification-service`,  pr_number:41,  scan_id:"sc_009", overall_risk:"MEDIUM",   file_count:0, total_ai_pct:0.58, file_path:"src/queue/retry_handler.py",              reviewer_email:`diana@${ORG}.io` },
  ],
};

// ── Secrets findings ──────────────────────────────────────────────────────────

const SECRETS_FINDINGS = [
  { id:"sec_001", severity:"CRITICAL", type:"api_key",       label:"Stripe API Key (live)",        file_path:"src/processors/card_validator.py",    repo:`${ORG}/payments-api`,        line_number:8,  masked_value:"sk_live_51Hx2••••••••",     context:'STRIPE_KEY = "sk_live_51Hx2trustledger_demo"',                pr_number:524, scan_id:"sc_001", detected_at:D(-HOURS(3)),   status:"open"     },
  { id:"sec_002", severity:"CRITICAL", type:"jwt_secret",    label:"JWT Signing Secret",           file_path:"src/auth/token_service.py",           repo:`${ORG}/auth-service`,         line_number:14, masked_value:"jwt_secret_prod_••••••",    context:'JWT_SECRET = "jwt_secret_prod_2024"',                         pr_number:388, scan_id:"sc_002", detected_at:D(-HOURS(7)),   status:"open"     },
  { id:"sec_003", severity:"CRITICAL", type:"db_password",   label:"Database Password",            file_path:"src/database/connection.py",          repo:`${ORG}/fraud-detection`,      line_number:23, masked_value:"prod_password_••••",        context:'DB_PASSWORD = "prod_password_2024"',                          pr_number:261, scan_id:"sc_003", detected_at:D(-HOURS(28)),  status:"open"     },
  { id:"sec_004", severity:"HIGH",     type:"api_key",       label:"SendGrid API Key",             file_path:"src/notifications/email_client.ts",   repo:`${ORG}/auth-service`,         line_number:5,  masked_value:"SG.••••••••••••••••",       context:'const SENDGRID_KEY = "SG.Gm9kXtestABCDEFGHIJKLMNOP"',        pr_number:385, scan_id:"sc_002", detected_at:D(-HOURS(38)),  status:"open"     },
  { id:"sec_005", severity:"HIGH",     type:"private_key",   label:"RSA Private Key",              file_path:"src/crypto/signing.py",               repo:`${ORG}/payments-api`,        line_number:3,  masked_value:"-----BEGIN RSA PRIVATE••",  context:'SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEow..."',  pr_number:521, scan_id:"sc_001", detected_at:D(-HOURS(74)),  status:"open"     },
  { id:"sec_006", severity:"HIGH",     type:"oauth_token",   label:"GitHub OAuth Token",           file_path:"src/integrations/github_client.ts",   repo:`${ORG}/data-platform`,       line_number:11, masked_value:"ghp_••••••••••••••••••",    context:'const GITHUB_TOKEN = "ghp_16C7e42F292c6912E6";',             pr_number:131, scan_id:"sc_005", detected_at:D(-HOURS(41)),  status:"open"     },
  { id:"sec_007", severity:"HIGH",     type:"api_key",       label:"OpenAI API Key",               file_path:"src/models/inference_engine.py",      repo:`${ORG}/ml-platform`,         line_number:7,  masked_value:"sk-proj-••••••••••••",      context:'OPENAI_API_KEY = "sk-proj-trustledger-demo-key-here"',        pr_number:97,  scan_id:"sc_006", detected_at:D(-HOURS(12)),  status:"open"     },
  { id:"sec_008", severity:"MEDIUM",   type:"webhook_url",   label:"Slack Webhook URL",            file_path:"src/alerts/slack_notifier.py",        repo:`${ORG}/risk-engine`,         line_number:7,  masked_value:"hooks.slack.com/services/T••••", context:'SLACK_WEBHOOK = "https://hooks.slack.com/services/T001/B001/xyz"', pr_number:101, scan_id:"sc_004", detected_at:D(-HOURS(52)), status:"open" },
  { id:"sec_009", severity:"MEDIUM",   type:"api_key",       label:"AWS Access Key ID",            file_path:"src/storage/s3_client.py",            repo:`${ORG}/data-platform`,       line_number:19, masked_value:"AKIA••••••••••••••",        context:'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"',                    pr_number:129, scan_id:"sc_005", detected_at:D(-HOURS(96)),  status:"resolved" },
  { id:"sec_010", severity:"HIGH",     type:"db_password",   label:"Legacy CRM Database Password", file_path:"src/pipelines/customer_data_sync.py", repo:`${ORG}/data-platform`,       line_number:32, masked_value:"crm_legacy_pw_••••••",      context:'LEGACY_DB_PASSWORD = "crm_legacy_pw_2024!"',                  pr_number:107, scan_id:"sc_013", detected_at:D(-HOURS(13)),  status:"open"     },
  { id:"sec_011", severity:"HIGH",     type:"api_key",       label:"Fulfillment Partner API Key",  file_path:"src/connectors/order_export_client.ts",repo:`${ORG}/data-platform`,       line_number:246,masked_value:"ff_live_••••••••••••",       context:'const FULFILLMENT_API_KEY = "ff_live_8f3e9c2a1b7d4e6f9012";', pr_number:107, scan_id:"sc_013", detected_at:D(-HOURS(13)),  status:"open"     },
];

// ── Threat intel ──────────────────────────────────────────────────────────────

const THREAT_INTEL = [
  { id:"TI-001", cve:"CVE-2024-23897", severity:"CRITICAL", category:"ai-generated",  status:"active",     cvss:9.8, published:"2024-01-24", last_updated:D(-DAYS(11)), in_your_codebase:true,  exploit_available:true,  exploit_in_wild:true,  ai_specific:true, relevance_score:94, affected_languages:["java","python"],           title:"Jenkins CLI arbitrary file read via AI-generated argument parsing",               affected_pattern:"CLI argument parsing with direct file path construction",        mitigation:"Replace direct file path construction with validated Path objects. Update Jenkins to 2.442+.",             references:["https://nvd.nist.gov/vuln/detail/CVE-2024-23897"] },
  { id:"TI-002", cve:"CVE-2024-21626", severity:"CRITICAL", category:"zero-day",      status:"active",     cvss:8.6, published:"2024-02-01", last_updated:D(-DAYS(6)),  in_your_codebase:false, exploit_available:true,  exploit_in_wild:true,  ai_specific:true, relevance_score:71, affected_languages:["dockerfile"],              title:"runc container escape via AI-generated Dockerfile WORKDIR patterns",              affected_pattern:"Dockerfile WORKDIR with /proc path access",                     mitigation:"Upgrade runc to 1.1.12+. Audit all AI-generated Dockerfiles.",                                            references:["https://nvd.nist.gov/vuln/detail/CVE-2024-21626"] },
  { id:"TI-003", cve:"CVE-2024-3094",  severity:"CRITICAL", category:"supply-chain",  status:"monitoring", cvss:10.0,published:"2024-03-29", last_updated:D(-DAYS(3)),  in_your_codebase:false, exploit_available:true,  exploit_in_wild:true,  ai_specific:true, relevance_score:88, affected_languages:["python","go","rust","c"], title:"XZ Utils backdoor — AI package recommendation threat pattern",                    affected_pattern:"AI-recommended system utility imports without provenance check", mitigation:"Verify all AI-recommended packages against signed releases. Enable SBOM scanning.",                         references:["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"] },
  { id:"TI-004", cve:"CVE-2024-38219", severity:"HIGH",     category:"ai-generated",  status:"active",     cvss:8.8, published:"2024-08-13", last_updated:D(-DAYS(5)),  in_your_codebase:true,  exploit_available:true,  exploit_in_wild:false, ai_specific:true, relevance_score:82, affected_languages:["typescript","javascript"], title:"Remote code execution via AI-generated unvalidated fetch() URL pattern",          affected_pattern:"Unvalidated URL in fetch() from AI-completed code",             mitigation:"Validate all URLs before passing to fetch(). Use Content Security Policy.",                               references:["https://nvd.nist.gov/vuln/detail/CVE-2024-38219"] },
  { id:"TI-005", cve:"CVE-2024-37084", severity:"HIGH",     category:"ai-generated",  status:"active",     cvss:9.8, published:"2024-07-24", last_updated:D(-DAYS(8)),  in_your_codebase:true,  exploit_available:true,  exploit_in_wild:false, ai_specific:true, relevance_score:79, affected_languages:["java","python"],           title:"RCE via AI-generated shell command pattern with string interpolation",            affected_pattern:"AI-generated shell.execute() with string interpolation",        mitigation:"Never pass user-controlled data to shell commands. Use parameterised task execution.",                     references:["https://nvd.nist.gov/vuln/detail/CVE-2024-37084"] },
  { id:"TI-006", cve:"CVE-2024-4577",  severity:"HIGH",     category:"ai-generated",  status:"active",     cvss:9.8, published:"2024-06-06", last_updated:D(-DAYS(14)), in_your_codebase:false, exploit_available:true,  exploit_in_wild:true,  ai_specific:true, relevance_score:67, affected_languages:["php"],                    title:"PHP CGI argument injection via AI-generated query string parsing",                affected_pattern:"Unsanitised query string in PHP exec() context",                mitigation:"Upgrade PHP to 8.1.29+, 8.2.20+, or 8.3.8+.",                                                            references:["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"] },
  { id:"TI-007", cve:"CVE-2024-6387",  severity:"CRITICAL", category:"zero-day",      status:"monitoring", cvss:8.1, published:"2024-07-01", last_updated:D(-DAYS(2)),  in_your_codebase:false, exploit_available:true,  exploit_in_wild:false, ai_specific:false,relevance_score:73, affected_languages:["c","cpp"],                title:"OpenSSH regreSSHion — AI-generated server configuration pattern",                 affected_pattern:"SSH server configs from AI scaffolding",                        mitigation:"Upgrade OpenSSH to 9.8p1+. Disable LoginGraceTime or set to 0.",                                          references:["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"] },
  { id:"TI-008", cve:undefined,        severity:"HIGH",     category:"emerging",       status:"monitoring", cvss:7.5, published:"2025-01-15", last_updated:D(-DAYS(1)),  in_your_codebase:true,  exploit_available:false, exploit_in_wild:false, ai_specific:true, relevance_score:91, affected_languages:["typescript","python"],    title:"AI Model Prompt Injection in Code-Generated API Handlers",                       affected_pattern:"LLM API calls in AI-generated backend code without input sanitisation", mitigation:"Sanitise all user input before passing to LLM APIs. Implement output validation.",                         references:[] },
  { id:"TI-009", cve:undefined,        severity:"MEDIUM",   category:"credential",     status:"active",     cvss:6.5, published:"2025-02-20", last_updated:D(-DAYS(4)),  in_your_codebase:true,  exploit_available:false, exploit_in_wild:false, ai_specific:true, relevance_score:84, affected_languages:["python","typescript"],    title:"Hardcoded secrets in AI-generated configuration files",                           affected_pattern:"Inline secret assignment in AI-autocompleted config blocks",    mitigation:"Use secret managers. Add pre-commit hooks for secret detection. Rotate all exposed credentials.",          references:[] },
  { id:"TI-010", cve:undefined,        severity:"MEDIUM",   category:"supply-chain",   status:"monitoring", cvss:5.9, published:"2025-03-10", last_updated:D(-DAYS(0)),  in_your_codebase:true,  exploit_available:false, exploit_in_wild:false, ai_specific:true, relevance_score:76, affected_languages:["typescript","python","go"],"title":"Slopsquatting — AI-hallucinated npm package names registered by attackers",    affected_pattern:"npm install of AI-suggested packages without registry verification", mitigation:"Verify all AI-suggested package names exist on npm before installing. Use phantom-dep scanning.",            references:[] },
];

// ── Compliance calendar ────────────────────────────────────────────────────────

function futureDate(daysFromNow: number) { return new Date(Date.now() + daysFromNow * 86_400_000).toISOString().split("T")[0]; }
function pastDate(daysAgo: number)       { return new Date(Date.now() - daysAgo   * 86_400_000).toISOString().split("T")[0]; }

const COMPLIANCE_CALENDAR = [
  { id:"soc2-prep",    title:"SOC 2 Type II Audit Preparation",       framework:"SOC 2",    type:"review",      date:futureDate(30),  status:"upcoming",    owner:`alice@${ORG}.io`,  notes:"Gather evidence for all TSCs" },
  { id:"soc2-audit",   title:"SOC 2 Type II Audit Window Opens",       framework:"SOC 2",    type:"audit",       date:futureDate(60),  status:"upcoming",    owner:`alice@${ORG}.io` },
  { id:"soc2-report",  title:"SOC 2 Report Delivery Deadline",         framework:"SOC 2",    type:"deadline",    date:futureDate(79),  status:"upcoming",    owner:`alice@${ORG}.io` },
  { id:"euai-review",  title:"EU AI Act High-Risk Assessment Review",   framework:"EU AI Act",type:"review",      date:futureDate(44),  status:"upcoming",    owner:`bob@${ORG}.io` },
  { id:"euai-deadline",title:"EU AI Act Compliance Deadline",           framework:"EU AI Act",type:"deadline",    date:futureDate(60),  status:"upcoming" },
  { id:"pci-q2",       title:"PCI-DSS Quarterly Scan Review",           framework:"PCI-DSS",  type:"review",      date:futureDate(28),  status:"in-progress", owner:`alice@${ORG}.io` },
  { id:"pci-cert",     title:"PCI-DSS Certificate Expiry",              framework:"PCI-DSS",  type:"cert-expiry", date:futureDate(81),  status:"upcoming",    notes:"Renew with SecurityMetrics QSA" },
  { id:"pci-audit",    title:"PCI-DSS Annual QSA Assessment",           framework:"PCI-DSS",  type:"audit",       date:futureDate(92),  status:"upcoming" },
  { id:"int-policy",   title:"Security Policy Annual Review",           framework:"Internal", type:"review",      date:futureDate(28),  status:"in-progress", owner:`alice@${ORG}.io` },
  { id:"int-training", title:"Security Awareness Training Deadline",    framework:"Internal", type:"deadline",    date:futureDate(44),  status:"upcoming" },
  { id:"int-pentest",  title:"Annual Penetration Test",                 framework:"Internal", type:"audit",       date:futureDate(121), status:"upcoming" },
  { id:"done-soc1",    title:"SOC 2 Type I Audit Completed",            framework:"SOC 2",    type:"audit",       date:pastDate(91),    status:"completed",   notes:"Clean opinion received" },
  { id:"done-pci-q1",  title:"PCI-DSS Q1 Scan Review",                  framework:"PCI-DSS",  type:"review",      date:pastDate(61),    status:"completed" },
  { id:"done-training",title:"Security Training — Spring 2026",         framework:"Internal", type:"review",      date:pastDate(14),    status:"completed",   notes:"All 8 team members completed" },
];

// ── Phantom packages ───────────────────────────────────────────────────────────
// Real packages vs hallucinated/slopsquatting packages (aiPr: true = AI-generated PR introduced it)

const PHANTOM_PACKAGES = [
  // Real, well-known packages — verified on public npm
  { name:"react",                  version:"^18.0.0",  source:`payments-api/package.json`,         aiPr:false },
  { name:"next",                   version:"^13.5.0",  source:`payments-api/package.json`,         aiPr:false },
  { name:"@supabase/supabase-js",  version:"^2.0.0",  source:`auth-service/package.json`,         aiPr:false },
  { name:"zod",                    version:"^3.22.0",  source:`payments-api/package.json`,         aiPr:true  },
  { name:"stripe",                 version:"^13.0.0",  source:`payments-api/package.json`,         aiPr:true  },
  { name:"axios",                  version:"^1.6.0",   source:`fraud-detection/package.json`,      aiPr:true  },
  { name:"express",                version:"^4.18.0",  source:`risk-engine/package.json`,          aiPr:false },
  { name:"typescript",             version:"^5.0.0",   source:`auth-service/package.json`,         aiPr:false },
  // Real packages introduced by AI PRs — exist on npm, lower risk but still need review
  { name:"jsonwebtoken",           version:"^9.0.0",   source:`auth-service/package.json`,         aiPr:true  },
  { name:"nodemailer",             version:"^6.9.0",   source:`notification-service/package.json`, aiPr:true  },
  { name:"helmet",                 version:"^7.1.0",   source:`api-gateway/package.json`,          aiPr:true  },
  { name:"validator",              version:"^13.11.0", source:`payments-api/package.json`,         aiPr:true  },
  { name:"winston",                version:"^3.11.0",  source:`data-platform/package.json`,        aiPr:true  },
  { name:"jwt-refresh-helper",     version:"^1.4.2",   source:`auth-service/package.json`,         aiPr:true  },
  // Private / internal packages — scoped to org registry, not public npm
  { name:`@${ORG}/payments-core`,  version:"^4.1.0",   source:`payments-api/package.json`,         aiPr:false },
  { name:`@${ORG}/auth-helpers`,   version:"^2.3.1",   source:`auth-service/package.json`,         aiPr:true  },
  { name:`@${ORG}/risk-models`,    version:"^1.0.5",   source:`fraud-detection/package.json`,      aiPr:true  },
  { name:`${ORG}-shared-utils`,    version:"^3.0.0",   source:`api-gateway/package.json`,          aiPr:false },
  // Truly hallucinated by AI — don't exist anywhere (slopsquatting risk)
  // Scoped under fictitious org scopes so they can never collide with a real npm package
  { name:"@stripe-internal/webhook-utils",          version:"^1.2.0", source:`payments-api/package.json`,    aiPr:true },
  { name:"@frauddetect-ai/score-engine",            version:"^3.1.0", source:`fraud-detection/package.json`, aiPr:true },
  { name:"@data-platform-internal/bigquery-stream-writer", version:"^2.0.0", source:`data-platform/package.json`, aiPr:true },
];

// ── Shadow AI detections ───────────────────────────────────────────────────────
// All developers reference team members defined in tl_team_members

const SHADOW_AI_DETECTIONS = [
  { repo:`${ORG}/payments-api`,        file:"src/validators/card_validator.py",    tool:"chatgpt",        confidence:0.84, dev:`alice@${ORG}.io`,   date:D(-HOURS(4))  },
  { repo:`${ORG}/payments-api`,        file:"src/api/payment_routes.ts",           tool:"github-copilot", confidence:0.79, dev:`bob@${ORG}.io`,     date:D(-HOURS(6))  },
  { repo:`${ORG}/fraud-detection`,     file:"models/risk_scorer.ts",               tool:"gemini",         confidence:0.71, dev:`charlie@${ORG}.io`, date:D(-HOURS(30)) },
  { repo:`${ORG}/fraud-detection`,     file:"pkg/fraud/detector.go",               tool:"claude",         confidence:0.66, dev:`diana@${ORG}.io`,   date:D(-HOURS(31)) },
  { repo:`${ORG}/auth-service`,        file:"src/auth/jwt_handler.py",             tool:"codewhisperer",  confidence:0.58, dev:`eve@${ORG}.io`,     date:D(-HOURS(55)) },
  { repo:`${ORG}/auth-service`,        file:"src/middleware/rate_limit.ts",        tool:"github-copilot", confidence:0.82, dev:`alice@${ORG}.io`,   date:D(-HOURS(56)) },
  { repo:`${ORG}/risk-engine`,         file:"src/scoring/model.py",                tool:"chatgpt",        confidence:0.73, dev:`frank@${ORG}.io`,   date:D(-HOURS(76)) },
  { repo:`${ORG}/data-platform`,       file:"src/connectors/bigquery_writer.ts",   tool:"cursor",         confidence:0.61, dev:`charlie@${ORG}.io`, date:D(-HOURS(77)) },
  { repo:`${ORG}/data-platform`,       file:"src/etl/transform_pipeline.py",       tool:"gemini",         confidence:0.69, dev:`diana@${ORG}.io`,   date:D(-HOURS(102))},
  // PR 107 — large mixed human/AI files (customer-sync-v2)
  { repo:`${ORG}/data-platform`,       file:"src/pipelines/customer_data_sync.py",   tool:"claude",       confidence:0.45, dev:`diana@${ORG}.io`,   date:D(-HOURS(13)) },
  { repo:`${ORG}/data-platform`,       file:"src/connectors/order_export_client.ts", tool:"cursor",       confidence:0.40, dev:`charlie@${ORG}.io`, date:D(-HOURS(13)) },
  { repo:`${ORG}/payments-api`,        file:"tests/test_payment_flow.py",          tool:"chatgpt",        confidence:0.77, dev:`bob@${ORG}.io`,     date:D(-HOURS(103))},
  { repo:`${ORG}/notification-service`,file:"src/providers/email_sender.py",       tool:"github-copilot", confidence:0.81, dev:`eve@${ORG}.io`,     date:D(-HOURS(35)) },
  { repo:`${ORG}/ml-platform`,         file:"src/models/inference_engine.py",      tool:"cursor",         confidence:0.91, dev:`dave@${ORG}.io`,    date:D(-HOURS(12)) },
  { repo:`${ORG}/user-service`,        file:"src/handlers/profile_update.ts",      tool:"claude",         confidence:0.55, dev:`charlie@${ORG}.io`, date:D(-HOURS(18)) },
  // order-service (Go)
  { repo:`${ORG}/order-service`,       file:"pkg/orders/handler.go",               tool:"github-copilot", confidence:0.87, dev:`frank@${ORG}.io`,   date:D(-HOURS(9))  },
  { repo:`${ORG}/order-service`,       file:"internal/db/queries.go",              tool:"chatgpt",        confidence:0.71, dev:`diana@${ORG}.io`,   date:D(-HOURS(10)) },
  { repo:`${ORG}/order-service`,       file:"pkg/middleware/auth.go",              tool:"cursor",         confidence:0.59, dev:`bob@${ORG}.io`,     date:D(-HOURS(11)) },
  // billing-service (Java)
  { repo:`${ORG}/billing-service`,     file:"src/main/java/billing/PaymentProcessor.java", tool:"cursor", confidence:0.82, dev:`charlie@${ORG}.io`, date:D(-HOURS(14)) },
  { repo:`${ORG}/billing-service`,     file:"src/main/java/billing/InvoiceService.java",   tool:"gemini", confidence:0.64, dev:`bob@${ORG}.io`,     date:D(-HOURS(15)) },
  { repo:`${ORG}/billing-service`,     file:"src/test/java/billing/PaymentProcessorTest.java", tool:"chatgpt", confidence:0.73, dev:`frank@${ORG}.io`, date:D(-HOURS(16)) },
  // cli-tools (Rust)
  { repo:`${ORG}/cli-tools`,           file:"src/crypto/hash.rs",                  tool:"claude",         confidence:0.76, dev:`dave@${ORG}.io`,    date:D(-HOURS(22)) },
  { repo:`${ORG}/cli-tools`,           file:"src/net/http_client.rs",              tool:"chatgpt",        confidence:0.69, dev:`frank@${ORG}.io`,   date:D(-HOURS(23)) },
  { repo:`${ORG}/cli-tools`,           file:"src/cli/main.rs",                     tool:"github-copilot", confidence:0.58, dev:`eve@${ORG}.io`,     date:D(-HOURS(24)) },
];

// ── Public API ─────────────────────────────────────────────────────────────────

export function applySeed(): void {
  if (typeof window === "undefined") return;
  Object.entries(SEED).forEach(([k, v]) => localStorage.setItem(k, JSON.stringify(v)));
  localStorage.setItem("tl_notif_snapshot",       JSON.stringify(DASHBOARD));
  localStorage.setItem("tl_secrets_findings",     JSON.stringify(SECRETS_FINDINGS));
  localStorage.setItem("tl_threat_intel",         JSON.stringify(THREAT_INTEL));
  localStorage.setItem("tl_compliance_calendar",  JSON.stringify(COMPLIANCE_CALENDAR));
  localStorage.setItem("tl_phantom_packages",     JSON.stringify(PHANTOM_PACKAGES));
  localStorage.setItem("tl_shadow_ai_detections", JSON.stringify(SHADOW_AI_DETECTIONS));
  localStorage.setItem("tl_force_seed", "1");
}

export function clearSeed(): void {
  if (typeof window === "undefined") return;
  [
    "tl_notif_snapshot", "tl_force_seed",
    "tl_violation_statuses", "tl_violation_assignees",
    "tl_alerts_state", "tl_secret_status", "tl_secret_total",
    "tl_incidents", "tl_risk_register",
    "tl_evidence_state", "tl_exceptions_state",
    "tl_dep_vuln_count", "tl_org_policy",
    "tl_team_members", "tl_api_keys",
    "tl_local_activity", "tl_evidence_owners",
    "tl_evidence_dues", "tl_violation_notes",
    "tl_violation_escalations",
    "tl_secrets_findings", "tl_threat_intel",
    "tl_compliance_calendar", "tl_phantom_packages",
    "tl_shadow_ai_detections",
  ].forEach(k => localStorage.removeItem(k));
}
