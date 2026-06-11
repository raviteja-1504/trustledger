"use client";

import { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import InfoTooltip from "@/components/InfoTooltip";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { api } from "@/lib/api";

// ── Types ──────────────────────────────────────────────────────────────────────

type SecretSeverity = "CRITICAL" | "HIGH" | "MEDIUM";
type SecretType = "api_key" | "jwt_secret" | "db_password" | "private_key" | "oauth_token" | "webhook_url";
type SecretStatus = "open" | "resolved";

interface SecretFinding {
  id: string;
  severity: SecretSeverity;
  type: SecretType;
  label: string;
  file_path: string;
  repo: string;
  line_number: number;
  masked_value: string;
  context: string;
  pr_number: number;
  scan_id: string;
  detected_at: string;
  status: SecretStatus;
  resolved_by?: string;
  resolved_at?: string;
}

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Mock findings ──────────────────────────────────────────────────────────────

const MOCK_FINDINGS: SecretFinding[] = [
  {
    id: "sec_001", severity: "CRITICAL", type: "api_key", label: "Stripe API Key",
    file_path: "src/processors/card_validator.py", repo: `${ORG}/payments-api`,
    line_number: 8, masked_value: "sk_live_51Hx2••••••••••••••••",
    context: 'STRIPE_KEY = "sk_live_51Hx2trustledger_demo"',
    pr_number: 524, scan_id: "sc_mock_001", detected_at: "2026-05-26T14:32:00Z", status: "open",
  },
  {
    id: "sec_002", severity: "CRITICAL", type: "jwt_secret", label: "JWT Signing Secret",
    file_path: "src/auth/token_service.py", repo: `${ORG}/auth-service`,
    line_number: 14, masked_value: "jwt_secret_prod_••••••••",
    context: 'JWT_SECRET = "jwt_secret_prod_2024"',
    pr_number: 341, scan_id: "sc_mock_002", detected_at: "2026-05-25T09:20:00Z", status: "open",
  },
  {
    id: "sec_003", severity: "CRITICAL", type: "db_password", label: "Database Password",
    file_path: "src/database/connection.py", repo: `${ORG}/fraud-detection`,
    line_number: 23, masked_value: "prod_password_••••",
    context: 'DB_PASSWORD = "prod_password_2024"',
    pr_number: 219, scan_id: "sc_mock_003", detected_at: "2026-05-25T11:05:00Z", status: "open",
  },
  {
    id: "sec_004", severity: "HIGH", type: "api_key", label: "SendGrid API Key",
    file_path: "src/notifications/email_client.ts", repo: `${ORG}/auth-service`,
    line_number: 5, masked_value: "SG.••••••••••••••••••••••",
    context: 'const SENDGRID_KEY = "SG.Gm9kXtestABCDEFGHIJKLMNOP"',
    pr_number: 338, scan_id: "sc_mock_002", detected_at: "2026-05-24T16:00:00Z", status: "open",
  },
  {
    id: "sec_005", severity: "HIGH", type: "private_key", label: "RSA Private Key",
    file_path: "src/crypto/signing.py", repo: `${ORG}/payments-api`,
    line_number: 3, masked_value: "-----BEGIN RSA PRIVATE KEY-----••••",
    context: 'SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEow..."',
    pr_number: 477, scan_id: "sc_mock_001", detected_at: "2026-05-24T10:10:00Z", status: "open",
  },
  {
    id: "sec_006", severity: "HIGH", type: "oauth_token", label: "GitHub OAuth Token",
    file_path: "src/integrations/github_client.ts", repo: `${ORG}/data-platform`,
    line_number: 11, masked_value: "ghp_••••••••••••••••••••",
    context: 'const GITHUB_TOKEN = "ghp_16C7e42F292c6912E6";',
    pr_number: 103, scan_id: "sc_mock_005", detected_at: "2026-05-23T14:45:00Z", status: "open",
  },
  {
    id: "sec_007", severity: "MEDIUM", type: "webhook_url", label: "Slack Webhook URL",
    file_path: "src/alerts/slack_notifier.py", repo: `${ORG}/risk-engine`,
    line_number: 7, masked_value: "https://hooks.slack.com/services/T00••••/B00••••/••••",
    context: 'SLACK_WEBHOOK = "https://hooks.slack.com/services/T001/B001/xyz"',
    pr_number: 88, scan_id: "sc_mock_004", detected_at: "2026-05-22T09:30:00Z", status: "open",
  },
  {
    id: "sec_008", severity: "MEDIUM", type: "api_key", label: "AWS Access Key",
    file_path: "src/storage/s3_client.py", repo: `${ORG}/data-platform`,
    line_number: 19, masked_value: "AKIA••••••••••••••••",
    context: 'AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"',
    pr_number: 101, scan_id: "sc_mock_005", detected_at: "2026-05-21T12:00:00Z", status: "open",
  },
];

const STORAGE_KEY = "tl_secret_status";

// ── Secret detection patterns ──────────────────────────────────────────────────

interface PatternRule { re: RegExp; label: string; type: SecretType; severity: SecretSeverity }

const SECRET_PATTERNS: PatternRule[] = [
  // Payment / billing
  { re:/sk_live_[a-zA-Z0-9_]{24,}/,                                    label:"Stripe Live Key",       type:"api_key",     severity:"CRITICAL" },
  { re:/sk_test_[a-zA-Z0-9_]{24,}/,                                    label:"Stripe Test Key",       type:"api_key",     severity:"HIGH"     },
  { re:/rk_live_[a-zA-Z0-9_]{24,}/,                                    label:"Stripe Restricted Key", type:"api_key",     severity:"CRITICAL" },

  // AWS
  { re:/AKIA[A-Z0-9]{16}/,                                             label:"AWS Access Key ID",     type:"api_key",     severity:"CRITICAL" },
  { re:/(?<![A-Za-z0-9/+])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/,    label:"AWS Secret Key",        type:"api_key",     severity:"CRITICAL" },

  // GitHub / GitLab
  { re:/ghp_[a-zA-Z0-9]{36}/,                                         label:"GitHub Personal Token", type:"oauth_token", severity:"HIGH"     },
  { re:/ghs_[a-zA-Z0-9]{36}/,                                         label:"GitHub Actions Token",  type:"oauth_token", severity:"HIGH"     },
  { re:/github_pat_[a-zA-Z0-9_]{82}/,                                 label:"GitHub Fine-grained PAT",type:"oauth_token", severity:"HIGH"    },
  { re:/glpat-[a-zA-Z0-9_-]{20}/,                                     label:"GitLab Personal Token", type:"oauth_token", severity:"HIGH"     },

  // Email services
  { re:/SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,}/,                label:"SendGrid API Key",       type:"api_key",     severity:"HIGH"     },
  { re:/key-[a-zA-Z0-9]{32}/,                                         label:"Mailgun API Key",        type:"api_key",     severity:"HIGH"     },

  // Private keys
  { re:/-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,             label:"Private Key",            type:"private_key", severity:"CRITICAL" },
  { re:/-----BEGIN CERTIFICATE-----/,                                  label:"TLS Certificate",        type:"private_key", severity:"MEDIUM"   },

  // Auth / JWT
  { re:/jwt[_-]?secret[\s"'`=:]+["'`]?[a-zA-Z0-9_!@#$%^&*]{12,}/i,  label:"JWT Signing Secret",    type:"jwt_secret",  severity:"CRITICAL" },
  { re:/secret[_-]?key[\s"'`=:]+["'`]?[a-zA-Z0-9_!@#$%^&*]{12,}/i,  label:"Application Secret",    type:"jwt_secret",  severity:"CRITICAL" },

  // Database
  { re:/(?:db|database)[_-]?pass(?:word)?[\s"'`=:]+["'`]?[^\s"'`]{6,}/i, label:"DB Password",       type:"db_password", severity:"CRITICAL" },
  { re:/(?:mysql|postgres|mongodb):\/\/[^:]+:([^@/\s]+)@/i,           label:"DB Connection String",  type:"db_password", severity:"CRITICAL" },

  // Communication
  { re:/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24,}/, label:"Slack Webhook", type:"webhook_url", severity:"MEDIUM" },
  { re:/xox[baprs]-[0-9]{12}-[0-9A-Za-z-]{24,}/,                     label:"Slack Token",            type:"oauth_token", severity:"HIGH"     },
  { re:/T[a-zA-Z0-9]{8}[./][a-zA-Z0-9]{8}[./][a-zA-Z0-9_-]{27}/,    label:"Twilio Auth Token",     type:"oauth_token", severity:"HIGH"     },

  // Cloud / Google
  { re:/AIza[0-9A-Za-z_-]{35}/,                                       label:"Google API Key",         type:"api_key",     severity:"HIGH"     },
  { re:/"type":\s*"service_account"/,                                  label:"Google Service Account", type:"api_key",     severity:"CRITICAL" },

  // Generic high-value patterns (must come last to avoid false positives)
  { re:/(?:password|passwd|pwd)\s*=\s*["'`][^"'`\s]{8,}["'`]/i,      label:"Hardcoded Password",     type:"db_password", severity:"HIGH"     },
  { re:/(?:api[_-]?key|apikey)\s*=\s*["'`][a-zA-Z0-9_\-]{16,}["'`]/i, label:"Generic API Key",      type:"api_key",     severity:"MEDIUM"   },
];

function detectSecretsInContent(content: string, file_path: string, repo: string, scan_id: string, pr_number: number, ts: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split("\n");
  lines.forEach((line, idx) => {
    for (const p of SECRET_PATTERNS) {
      const m = line.match(p.re);
      if (!m) continue;
      const raw = m[0];
      const masked = raw.slice(0, Math.min(8, raw.length)) + "•".repeat(Math.max(4, raw.length - 8));
      findings.push({
        id: `sec_live_${scan_id}_${idx}`,
        severity: p.severity, type: p.type, label: p.label,
        file_path, repo, line_number: idx + 1,
        masked_value: masked,
        context: line.trim().slice(0, 120).replace(raw, masked),
        pr_number, scan_id,
        detected_at: ts, status: "open",
      });
      break; // one match per line
    }
  });
  return findings;
}

// ── Icons ──────────────────────────────────────────────────────────────────────

function SecretIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  );
}

function ExternalIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
      <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
    </svg>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const SEV: Record<SecretSeverity, { bg: string; text: string; border: string; dot: string }> = {
  CRITICAL: { bg: "#ede9fe", text: "#5b21b6", border: "#c4b5fd", dot: "#7c3aed" },
  HIGH:     { bg: "#ffedd5", text: "#7c2d12", border: "#fed7aa", dot: "#f97316" },
  MEDIUM:   { bg: "#fef3c7", text: "#78350f", border: "#fde68a", dot: "#f59e0b" },
};

const TYPE_LABELS: Record<SecretType, string> = {
  api_key:     "API Key",
  jwt_secret:  "JWT Secret",
  db_password: "DB Password",
  private_key: "Private Key",
  oauth_token: "OAuth Token",
  webhook_url: "Webhook URL",
};

function timeAgo(iso: string) {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60)   return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400)return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function SecretsPage() {
  const [findings, setFindings] = useState<SecretFinding[]>([]);
  const [filterSev,    setFilterSev]    = useState<SecretSeverity | "all">("all");
  const [filterStatus, setFilterStatus] = useState<SecretStatus | "all">("all");
  const [filterRepo,   setFilterRepo]   = useState("all");
  const [expanded,     setExpanded]     = useState<string | null>(null);

  // Load seed findings → live scan detections → MOCK_FINDINGS fallback
  useEffect(() => {
    const isSeed = typeof window !== "undefined" && localStorage.getItem("tl_force_seed") === "1";

    // Status overrides (resolved/open) — applied on top of whatever base we load
    const raw  = (() => { try { return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}") as Record<string, SecretStatus>; } catch { return {} as Record<string, SecretStatus>; } })();
    const saved = Object.fromEntries(Object.entries(raw).filter(([,v]) => v === "resolved")) as Record<string, SecretStatus>;
    const applyOverrides = (data: SecretFinding[]) =>
      data.map(f => saved[f.id] ? { ...f, status: saved[f.id] as SecretStatus } : f);

    // 1. Seed mode — load from tl_secrets_findings
    if (isSeed) {
      try {
        const seedRaw = localStorage.getItem("tl_secrets_findings");
        const seedFindings = seedRaw ? JSON.parse(seedRaw) as SecretFinding[] : MOCK_FINDINGS;
        const merged = applyOverrides(seedFindings);
        setFindings(merged);
        localStorage.setItem("tl_secret_total", String(merged.length));
      } catch {
        setFindings(applyOverrides(MOCK_FINDINGS));
      }
      return;
    }

    // 2. Not seed mode — start empty, populate from live scan data only
    setFindings([]);
    localStorage.setItem("tl_secret_total", "0");

    (async () => {
      try {
        const data = await api.dashboard(ORG, 90);
        const scanIds = data.repos.filter(r => r.latest_scan_id).slice(0, 5).map(r => r.latest_scan_id);
        const results = await Promise.allSettled(scanIds.map(id => api.getScan(id)));
        const existingKeys = new Set<string>();
        const liveFindings: SecretFinding[] = [];

        results.forEach(r => {
          if (r.status !== "fulfilled" || !r.value) return;
          const scan = r.value;
          scan.files.forEach(file => {
            const hasSecretIndicator = file.risk_indicators.some(ri =>
              ri.toLowerCase().includes("secret") || ri.toLowerCase().includes("credential") || ri.toLowerCase().includes("hardcoded")
            );
            if (!hasSecretIndicator && !file.content) return;
            const key = `${scan.scan_id}::${file.file_path}`;
            if (existingKeys.has(key)) return;
            existingKeys.add(key);

            if (file.content) {
              const detected = detectSecretsInContent(file.content, file.file_path, scan.repo, scan.scan_id, scan.pr_number, scan.timestamp);
              liveFindings.push(...detected);
            } else if (hasSecretIndicator) {
              liveFindings.push({
                id: `sec_ri_${scan.scan_id}_${file.file_path.replace(/\W/g,"_")}`,
                severity: file.risk_score === "CRITICAL" ? "CRITICAL" : "HIGH",
                type: "api_key", label: "Hardcoded Secret (risk indicator)",
                file_path: file.file_path, repo: scan.repo,
                line_number: 0, masked_value: "•••••••••••••••",
                context: `[Detected via risk_indicator in ${file.file_path} — content not available]`,
                pr_number: scan.pr_number, scan_id: scan.scan_id,
                detected_at: scan.timestamp, status: "open",
              });
            }
          });
        });

        if (liveFindings.length > 0) {
          const merged = liveFindings.map(f => saved[f.id] ? { ...f, status: saved[f.id] } : f);
          setFindings(merged);
          localStorage.setItem("tl_secret_total", String(merged.length));
        }
      } catch { /* offline — keep empty */ }
    })();
  }, []);

  function setStatus(id: string, status: SecretStatus) {
    setFindings(prev => {
      const next = prev.map(f => f.id === id ? {
        ...f, status,
        resolved_by: status === "resolved" ? (() => { try { const m = JSON.parse(localStorage.getItem("tl_team_members") ?? "[]"); return m[0]?.email ?? `reviewer@${ORG}.io`; } catch { return `reviewer@${ORG}.io`; } })() : undefined,
        resolved_at: status === "resolved" ? new Date().toISOString() : undefined,
      } : f);
      // Only persist non-default (resolved) overrides — saves "open" as default avoids
      // old live-finding IDs accumulating across sessions and inflating resolved count
      const overrides: Record<string, SecretStatus> = {};
      next.forEach(f => { if (f.status !== "open") overrides[f.id] = f.status; });
      localStorage.setItem(STORAGE_KEY, JSON.stringify(overrides));
      window.dispatchEvent(new Event("tl:badge"));
      return next;
    });
  }

  const repos = useMemo(() => Array.from(new Set(findings.map(f => f.repo))), [findings]);

  // Explicit per-value filter — avoids any string comparison edge cases
  function matchesSev(f: SecretFinding): boolean {
    if (filterSev === "all")      return true;
    if (filterSev === "CRITICAL") return f.severity === "CRITICAL";
    if (filterSev === "HIGH")     return f.severity === "HIGH";
    if (filterSev === "MEDIUM")   return f.severity === "MEDIUM";
    return true;
  }
  function matchesStatus(f: SecretFinding): boolean {
    if (filterStatus === "all")      return true;
    if (filterStatus === "open")     return f.status === "open";
    if (filterStatus === "resolved") return f.status === "resolved";
    return true;
  }
  function matchesRepo(f: SecretFinding): boolean {
    return filterRepo === "all" || f.repo === filterRepo;
  }

  // bySevRepo: severity + repo filtered (for counts shown in tabs)
  const bySevRepo = findings.filter(f => matchesSev(f) && matchesRepo(f));
  // filtered: full filter including status (for the table)
  const filtered  = bySevRepo.filter(f => matchesStatus(f));

  const open     = bySevRepo.filter(f => f.status === "open").length;
  const critical = bySevRepo.filter(f => f.severity === "CRITICAL" && f.status === "open").length;
  const resolved = bySevRepo.filter(f => f.status === "resolved").length;

  function exportCSV() {
    const rows = [
      ["Severity","Type","File","Repository","Line","Status","Detected","Resolved By"],
      ...filtered.map(f => [
        f.severity, TYPE_LABELS[f.type], f.file_path, f.repo,
        String(f.line_number), f.status, f.detected_at,
        f.resolved_by ?? "",
      ]),
    ];
    const csv = rows.map(r => r.map(c => `"${c}"`).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = "trustledger-secrets.csv";
    a.click();
  }

  return (
    <AuthGuard>
      <PageSkeleton rows={5} cards={4}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center text-rose-600"
                style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)" }}>
                <SecretIcon />
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Secret Scanner</h1>
              {open > 0 && (
                <span className="text-xs font-black text-white bg-rose-500 px-2 py-0.5 rounded-full">
                  {open} open
                </span>
              )}
            </div>
            <p className="text-sm text-gray-400 mt-0.5">
              Hardcoded credentials detected in AI-generated code — review and remediate before production.
            </p>
          </div>
          <button onClick={exportCSV}
            className="flex items-center gap-1.5 px-3 py-2 text-sm font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            Export CSV
          </button>
        </div>

        {/* Summary cards */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Detected",  value: bySevRepo.length, color: "#6366f1", bg: "#eef2ff", info: { title: "Total Detected",  description: "All hardcoded credentials found across scanned repos — API keys, passwords, tokens, secrets. Every occurrence is flagged regardless of whether it's already been rotated." } },
            { label: "Critical Open",   value: critical,        color: "#7c3aed", bg: "#ede9fe", info: { title: "Critical Open",   description: "CRITICAL-severity secrets (production API keys, DB passwords, JWT signing secrets) that are still in 'Open' status and haven't been rotated." } },
            { label: "Open",            value: open,            color: "#ef4444", bg: "#fef2f2", info: { title: "Open Secrets",    description: "All secrets not yet marked as resolved. Click a finding and choose 'Resolved' once the credential has been rotated and removed from source." } },
            { label: "Resolved",        value: resolved,        color: "#10b981", bg: "#f0fdf4", info: { title: "Resolved",        description: "Secrets confirmed rotated and removed from source code. Mark resolved only after the credential is invalidated in the issuing system (Stripe, AWS, etc.)." } },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-4 border"
              style={{ background: s.bg, borderColor: s.color + "30" }}>
              <p className="text-2xl font-black tabular-nums" style={{ color: s.color }}>{s.value}</p>
              <div className="flex items-center gap-1.5 mt-1">
                <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                <InfoTooltip title={s.info.title} description={s.info.description} position="top" />
              </div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="animate-fade-up flex flex-wrap items-center gap-2">
          {/* Status with counts */}
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {([
              { val:"all",      label:`All (${bySevRepo.length})` },
              { val:"open",     label:`Open (${open})` },
              { val:"resolved", label:`Resolved (${resolved})` },
            ] as const).map(s => (
              <button key={s.val} onClick={() => setFilterStatus(s.val)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                  filterStatus === s.val ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
                }`}>
                {s.label}
              </button>
            ))}
          </div>
          {/* Severity */}
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","CRITICAL","HIGH","MEDIUM"] as const).map(s => (
              <button key={s} onClick={() => setFilterSev(s)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                  filterSev === s ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
                }`}>
                {s === "all" ? "All Severity" : s}
              </button>
            ))}
          </div>
          {/* Repo */}
          <select value={filterRepo} onChange={e => setFilterRepo(e.target.value)}
            className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400">
            <option value="all">All Repos</option>
            {repos.map(r => <option key={r} value={r}>{r.split("/").pop()}</option>)}
          </select>
          <span className="text-xs text-gray-400 ml-auto">
            {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
          </span>
        </div>

        {/* Findings table */}
        <div className="animate-fade-up section-card overflow-hidden">

          {filtered.filter(f => matchesSev(f) && matchesStatus(f) && matchesRepo(f)).length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <div className="w-12 h-12 rounded-2xl bg-emerald-50 flex items-center justify-center text-emerald-500">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
              </div>
              <p className="text-sm font-bold text-gray-700">
                {bySevRepo.length > 0 ? "All findings in this view are resolved" : "No findings match this filter"}
              </p>
              <p className="text-xs text-gray-400">
                {bySevRepo.length > 0
                  ? <button onClick={() => setFilterStatus("all")} className="text-indigo-600 hover:underline">Show all {bySevRepo.length} finding{bySevRepo.length > 1 ? "s" : ""}</button>
                  : "Try adjusting the severity or status filter"
                }
              </p>
            </div>
          ) : (
            <div>
              {/* Column headers */}
              <div className="grid items-center px-5 py-2.5 border-b border-gray-100 text-[10px] font-black uppercase tracking-widest text-gray-400"
                style={{ gridTemplateColumns: "100px 120px 1fr 120px 90px 110px" }}>
                <span>Severity</span><span>Type</span><span>File / Repo</span>
                <span>Detected</span><span>PR</span><span>Status</span>
              </div>

              <div className="divide-y divide-gray-50">
                {filtered.filter(f => matchesSev(f) && matchesStatus(f) && matchesRepo(f)).map(f => {
                  const sev    = SEV[f.severity];
                  const isOpen = expanded === f.id;
                  return (
                    <div key={f.id}>
                      <div
                        className="grid items-center px-5 py-3.5 cursor-pointer transition-colors hover:bg-gray-50/70"
                        style={{ gridTemplateColumns: "100px 120px 1fr 120px 90px 110px" }}
                        onClick={() => setExpanded(isOpen ? null : f.id)}
                      >
                        {/* Severity */}
                        <span className="inline-flex items-center gap-1.5 text-[11px] font-bold px-2 py-0.5 rounded-full w-fit"
                          style={{ background: sev.bg, color: sev.text, border: `1px solid ${sev.border}` }}>
                          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: sev.dot }} />
                          {f.severity}
                        </span>

                        {/* Type */}
                        <span className="text-xs font-semibold text-gray-600">{TYPE_LABELS[f.type]}</span>

                        {/* File */}
                        <div className="min-w-0 pr-3">
                          <p className="text-[11px] font-mono font-semibold text-gray-800 truncate">
                            {f.file_path.split("/").pop()}
                            <span className="text-gray-400 font-normal">:{f.line_number}</span>
                          </p>
                          <p className="text-[10px] text-gray-400 mt-0.5">{f.repo.split("/").pop()}</p>
                        </div>

                        {/* Detected */}
                        <span className="text-xs text-gray-400 tabular-nums">{timeAgo(f.detected_at)}</span>

                        {/* PR */}
                        <Link href={`/pr/${f.scan_id}`} onClick={e => e.stopPropagation()}
                          className="text-xs font-bold text-indigo-600 hover:text-indigo-800 flex items-center gap-1 w-fit">
                          #{f.pr_number} <ExternalIcon />
                        </Link>

                        {/* Status + Resolve action */}
                        <div className="flex flex-col gap-1" onClick={e => e.stopPropagation()}>
                          {f.status === "open" ? (
                            <button
                              onClick={() => setStatus(f.id, "resolved")}
                              className="text-[11px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-lg hover:bg-emerald-100 transition-colors whitespace-nowrap flex items-center gap-1">
                              <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                              Resolve
                            </button>
                          ) : (
                            <>
                              <span className="text-[11px] font-bold text-emerald-700 flex items-center gap-1">
                                <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                                Resolved
                              </span>
                              <button
                                onClick={() => setStatus(f.id, "open")}
                                className="text-[10px] text-gray-400 hover:text-rose-600 transition-colors whitespace-nowrap">
                                Re-open
                              </button>
                            </>
                          )}
                        </div>
                      </div>

                      {/* Expanded detail */}
                      {isOpen && (
                        <div className="px-5 pb-4 border-b border-gray-100"
                          style={{ background: "linear-gradient(90deg,rgba(248,250,252,0.9),rgba(248,250,252,0.3))" }}>
                          <div className="space-y-3">
                            {/* Code context */}
                            <div>
                              <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-1.5">Detected Pattern</p>
                              <div className="bg-gray-900 rounded-xl px-4 py-3 font-mono text-xs">
                                <p className="text-gray-500 mb-1">
                                  <span className="text-gray-600 select-none">{f.file_path}:{f.line_number}  </span>
                                </p>
                                <p>
                                  <span className="text-rose-400">{f.context.split("=")[0].trim()}</span>
                                  <span className="text-gray-400"> = </span>
                                  <span className="text-amber-300">"{f.masked_value}"</span>
                                </p>
                              </div>
                            </div>
                            {/* Remediation */}
                            <div className="bg-indigo-50 border border-indigo-100 rounded-xl px-4 py-3">
                              <p className="text-[10px] font-bold uppercase tracking-widest text-indigo-600 mb-1.5">Remediation</p>
                              <p className="text-xs text-indigo-800 leading-relaxed">
                                Move this value to an environment variable or secrets manager (AWS Secrets Manager, Vault, etc.).
                                Rotate the credential immediately — treat it as compromised.
                                Never commit credentials to source code, even in test or demo files.
                              </p>
                            </div>
                            {/* Resolved info */}
                            {f.status === "resolved" && f.resolved_by && (
                              <p className="text-xs text-emerald-700 flex items-center gap-1.5">
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                                Resolved by <strong>{f.resolved_by}</strong> · {timeAgo(f.resolved_at!)}
                              </p>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Info banner */}
        <div className="animate-fade-up flex items-start gap-3 bg-amber-50 border border-amber-200 rounded-xl px-4 py-3">
          <svg className="shrink-0 mt-0.5 text-amber-600" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <p className="text-xs text-amber-800 leading-relaxed">
            <span className="font-bold">Treat every detected secret as compromised</span> — even if not yet in production.
            Rotate credentials immediately and use environment variables or a secrets manager going forward.
            TrustLedger scans for patterns including Stripe, AWS, GitHub, JWT, SSH, and database credential formats.
          </p>
        </div>

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
