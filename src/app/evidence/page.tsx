"use client";

import { useState, useMemo, useEffect, useCallback } from "react";
import InfoTooltip from "@/components/InfoTooltip";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { api } from "@/lib/api";
import { readSeed } from "@/lib/offlineData";
import type { DashboardData } from "@/types";
import { authedFetch } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";

// ── Types ──────────────────────────────────────────────────────────────────────

type EvidenceType   = "scan-log" | "attestation" | "report" | "policy" | "screenshot" | "audit-trail" | "config";
type EvidenceStatus = "collected" | "pending" | "expired" | "not-required";

interface EvidenceItem {
  id: string;
  control_id: string;
  type: EvidenceType;
  title: string;
  description: string;
  status: EvidenceStatus;
  collected_at?: string;
  expires_at?: string;       // ISO — warn when < 30 days, error when past
  link?: string;
  auto_collect?: boolean;    // derived automatically from dashboard data
  notes?: string[];
}

interface Control {
  id: string;
  label: string;
  description: string;
  evidence: EvidenceItem[];
  weight: number;            // importance weighting for readiness score
}

interface FrameworkDef {
  id: string;
  name: string;
  shortName: string;
  color: string;
  gradient: string;
  headerBg: string;
  nextAudit?: string;
  auditor?: string;
  controls: Control[];
}

// ── Persistence ────────────────────────────────────────────────────────────────

const EVIDENCE_KEY = "tl_evidence_state";

interface EvidenceOverride {
  status: EvidenceStatus;
  collected_at?: string;
  note?: string;
}

function loadOverrides(): Record<string, EvidenceOverride> {
  try { return JSON.parse(localStorage.getItem(EVIDENCE_KEY) ?? "{}"); }
  catch { return {}; }
}
function saveOverrides(o: Record<string, EvidenceOverride>) {
  localStorage.setItem(EVIDENCE_KEY, JSON.stringify(o));
}

// ── Readiness grade ────────────────────────────────────────────────────────────

function readinessGrade(pct: number): { grade:string; color:string; bg:string } {
  if (pct >= 90) return { grade:"A", color:"#15803d", bg:"#f0fdf4" };
  if (pct >= 75) return { grade:"B", color:"#1d4ed8", bg:"#eff6ff" };
  if (pct >= 60) return { grade:"C", color:"#b45309", bg:"#fffbeb" };
  if (pct >= 40) return { grade:"D", color:"#c2410c", bg:"#fff7ed" };
  return              { grade:"F", color:"#be123c", bg:"#fef2f2" };
}

// ── Remediation steps per evidence type ───────────────────────────────────────

const COLLECTION_GUIDE: Record<EvidenceType, { steps: string[]; sources: string[] }> = {
  "scan-log":   {
    steps: ["Navigate to Audit Trail → Export scan logs for the audit period", "Filter by date range and export as JSON/CSV", "Attach the export file as evidence"],
    sources: ["Audit Trail page", "API: GET /api/v1/repos/activity"],
  },
  "attestation":{
    steps: ["Go to Audit Trail and filter by type=attestation", "Export attestation records for the period", "Verify reviewer emails and timestamps are present"],
    sources: ["Audit Trail page", "Reports → Attestation Records section"],
  },
  "report":     {
    steps: ["Open Reports and select the relevant framework", "Set the audit date range and generate", "Download the signed PDF and attach here"],
    sources: ["Reports page", "Select framework → Generate PDF"],
  },
  "policy":     {
    steps: ["Export current policy from Settings → Security Policy", "Include version, approval date, and approver", "Keep a copy in your document management system"],
    sources: ["Settings → Security Policy tab"],
  },
  "screenshot": {
    steps: ["Take a screenshot of the relevant UI showing the control in action", "Annotate the screenshot with date and control ID", "Crop to show only the relevant section"],
    sources: ["Dashboard", "GitHub PR status checks", "CI/CD pipeline logs"],
  },
  "audit-trail":{
    steps: ["Navigate to Audit Trail → select the full period", "Export as JSON to capture cryptographic event hashes", "Verify the chain is intact (no gaps in event sequence)"],
    sources: ["Audit Trail page → Export JSON"],
  },
  "config":     {
    steps: ["Screenshot or export the relevant configuration screen", "Include all settings fields — not just the changed ones", "Document who changed it and when"],
    sources: ["Settings page", "GitHub App settings", "CI/CD environment variables"],
  },
};

// ── Evidence freshness ────────────────────────────────────────────────────────

function freshnessBadge(collectedAt?: string): { label: string; color: string; bg: string } | null {
  if (!collectedAt) return null;
  const days = Math.floor((Date.now() - new Date(collectedAt).getTime()) / 86400000);
  if (days <= 7)   return { label:`${days}d old`,    color:"#15803d", bg:"#f0fdf4" };
  if (days <= 30)  return { label:`${days}d old`,    color:"#1d4ed8", bg:"#eff6ff" };
  if (days <= 90)  return { label:`${days}d old`,    color:"#b45309", bg:"#fffbeb" };
  return               { label:`${days}d old`,    color:"#be123c", bg:"#fff1f2" };
}

// ── Evidence catalog builder — uses real data where available ─────────────────

function buildFrameworks(data: DashboardData | null, auditStart: string, auditEnd: string): FrameworkDef[] {
  const sc     = data?.scan_count          ?? 51;
  const fc     = data?.file_count          ?? 431;
  const repos  = data?.repos.length        ?? 5;
  const attPct = Math.round((data?.attestation_rate ?? 0.78) * 100);
  const attCount = data ? Math.round(data.attestation_rate * data.top_risk_files.length) : 29;
  const total  = data?.top_risk_files.length ?? 37;
  const blocked= data?.unattested_deploy_count ?? 3;
  const now    = new Date().toISOString().split("T")[0];
  const expiry = new Date(new Date(auditEnd).getTime() + 365 * 86400_000).toISOString().split("T")[0]; // 12-month validity

  return [
    {
      id:"soc2", name:"SOC 2 Type II", shortName:"SOC 2",
      color:"#6366f1", gradient:"linear-gradient(135deg,#6366f1,#7c3aed)",
      headerBg:"linear-gradient(135deg,#0f172a,#1e1b4b)",
      nextAudit:"2026-08-20", auditor:"Armanino LLP",
      controls: [
        {
          id:"CC6.1", label:"Logical Access Controls", weight:25,
          description:"AI-authored changes reviewed only by authorised personnel",
          evidence:[
            { id:"e-cc61-1", control_id:"CC6.1", type:"attestation", auto_collect:true, link:"/audit",
              title:`${attCount} signed attestation records`,
              description:`PGP-signed reviewer attestations across ${sc} scans in audit period ${auditStart} → ${auditEnd}`,
              status:attCount>0?"collected":"pending", collected_at:attCount>0?now:undefined, expires_at:expiry },
            { id:"e-cc61-2", control_id:"CC6.1", type:"policy", link:"/settings",
              title:"Attestation policy document v1.2",
              description:"Standard policy defining reviewer requirements and merge gate rules",
              status:"collected", collected_at:"2026-05-01", expires_at:expiry },
            { id:"e-cc61-3", control_id:"CC6.1", type:"audit-trail", auto_collect:true, link:"/audit",
              title:"GitHub App merge gate log",
              description:`Audit trail of policy gate decisions — ${blocked} merge${blocked===1?"":"s"} blocked by unattested-file policy`,
              status:"collected", collected_at:now, expires_at:expiry },
          ],
        },
        {
          id:"CC6.2", label:"Authentication", weight:20,
          description:"Reviewer identity verified via GitHub OAuth flow",
          evidence:[
            { id:"e-cc62-1", control_id:"CC6.2", type:"scan-log", auto_collect:true, link:"/audit",
              title:`${sc} reviewer sessions with GitHub token`,
              description:"API log showing OAuth token verified for each attestation call",
              status:sc>0?"collected":"pending", collected_at:sc>0?now:undefined, expires_at:expiry },
            { id:"e-cc62-2", control_id:"CC6.2", type:"config", auto_collect:true, link:"/settings",
              title:`GitHub App OAuth configuration — ${repos} repo${repos===1?"":"s"} connected`,
              description:"GitHub App installation showing required scopes and permission model",
              status:repos>0?"collected":"pending", collected_at:repos>0?now:undefined, expires_at:expiry },
          ],
        },
        {
          id:"CC7.2", label:"System Monitoring", weight:20,
          description:"Continuous AI content scanning on every pull request",
          evidence:[
            { id:"e-cc72-1", control_id:"CC7.2", type:"scan-log", auto_collect:true, link:"/audit",
              title:`${sc} automated scan logs across ${repos} repos`,
              description:`Full scan output per PR during ${auditStart} → ${auditEnd}`,
              status:sc>0?"collected":"pending", collected_at:sc>0?now:undefined, expires_at:expiry },
            { id:"e-cc72-2", control_id:"CC7.2", type:"report", link:"/reports",
              title:"SOC 2 Compliance Report — signed PDF",
              description:"Cryptographically-signed evidence package covering audit period",
              status:"pending" },
          ],
        },
        {
          id:"CC8.1", label:"Change Management", weight:25,
          description:"All changes formally attested prior to deployment",
          evidence:[
            { id:"e-cc81-1", control_id:"CC8.1", type:"attestation", auto_collect:true, link:"/reports",
              title:`Attestation rate: ${attPct}% (${attCount}/${total} files)`,
              description:"Evidence of attestation coverage across audit period",
              status:attPct>=80?"collected":attPct>0?"pending":"pending",
              collected_at:attPct>0?now:undefined, expires_at:expiry },
            { id:"e-cc81-2", control_id:"CC8.1", type:"audit-trail", link:"/audit",
              title:"Tamper-evident change management log",
              description:"Immutable event log of all scan and attestation events",
              status:"collected", auto_collect:true, collected_at:now, expires_at:expiry },
            { id:"e-cc81-3", control_id:"CC8.1", type:"audit-trail", auto_collect:true, link:"/audit",
              title:`${blocked} blocked deploy log${blocked===1?"":"s"}`,
              description:`Audit trail evidence of ${blocked} merges blocked by policy gate (unattested files)`,
              status:blocked>0?"collected":"not-required", collected_at:blocked>0?now:undefined, expires_at:expiry },
          ],
        },
        {
          id:"A1.2", label:"Availability", weight:10,
          description:"Audit trail retained and accessible for ≥ 12 months",
          evidence:[
            { id:"e-a12-1", control_id:"A1.2", type:"audit-trail", auto_collect:true, link:"/audit",
              title:`${fc} audit records — full retention`,
              description:"Complete scan + attestation history in TrustLedger",
              status:fc>0?"collected":"pending", collected_at:fc>0?now:undefined, expires_at:expiry },
          ],
        },
      ],
    },
    {
      id:"euai", name:"EU Artificial Intelligence Act", shortName:"EU AI Act",
      color:"#3b82f6", gradient:"linear-gradient(135deg,#3b82f6,#0891b2)",
      headerBg:"linear-gradient(135deg,#0f172a,#0c2340)",
      nextAudit:"2026-07-15",
      controls: [
        {
          id:"Art.9", label:"Risk Management System", weight:25,
          description:"Continuous AI risk identification, evaluation and mitigation",
          evidence:[
            { id:"e-art9-1", control_id:"Art.9", type:"report", link:"/reports?fw=EU+AI+Act",
              title:"EU AI Act compliance report",
              description:"Risk management system documentation for audit period",
              status:"pending" },
            { id:"e-art9-2", control_id:"Art.9", type:"scan-log", auto_collect:true, link:"/vulnerabilities",
              title:`${sc} risk classification assessments`,
              description:"CRITICAL/HIGH/MEDIUM/LOW classification per file per PR",
              status:sc>0?"collected":"pending", collected_at:sc>0?now:undefined, expires_at:expiry },
          ],
        },
        {
          id:"Art.10", label:"Data Governance", weight:20,
          description:"Training data provenance documented per scanned file",
          evidence:[
            { id:"e-art10-1", control_id:"Art.10", type:"audit-trail", auto_collect:true, link:"/audit",
              title:`${fc} files with provenance records`,
              description:"AI provenance captured per file across all scanned repos",
              status:fc>0?"collected":"pending", collected_at:fc>0?now:undefined, expires_at:expiry },
          ],
        },
        {
          id:"Art.13", label:"Transparency", weight:20,
          description:"AI-generated code percentage disclosed at PR level",
          evidence:[
            { id:"e-art13-1", control_id:"Art.13", type:"scan-log", auto_collect:true, link:"/audit",
              title:`AI% disclosed for all ${sc} pull requests`,
              description:"ai_percentage field logged for each PR scan — auditable evidence",
              status:sc>0?"collected":"pending", collected_at:sc>0?now:undefined, expires_at:expiry },
          ],
        },
        {
          id:"Art.14", label:"Human Oversight", weight:25,
          description:"Human reviewer mandated for all CRITICAL-risk AI files",
          evidence:[
            { id:"e-art14-1", control_id:"Art.14", type:"attestation", auto_collect:true, link:"/audit",
              title:`${attCount} human reviewer sign-offs recorded`,
              description:"Named reviewer attestations for HIGH/CRITICAL AI files",
              status:attCount>0?"collected":"pending", collected_at:attCount>0?now:undefined, expires_at:expiry },
            { id:"e-art14-2", control_id:"Art.14", type:"policy", link:"/settings",
              title:"Human oversight policy — Standard v1.2",
              description:"Policy requiring CRITICAL file review before merge",
              status:"pending" },
          ],
        },
        {
          id:"Art.17", label:"Quality Management", weight:10,
          description:"Post-market monitoring via continuous automated scanning",
          evidence:[
            { id:"e-art17-1", control_id:"Art.17", type:"scan-log", auto_collect:true, link:"/audit",
              title:`${sc} quality assessments — continuous monitoring`,
              description:"Automated scan executed on every PR submission",
              status:sc>0?"collected":"pending", collected_at:sc>0?now:undefined, expires_at:expiry },
          ],
        },
      ],
    },
    {
      id:"pcidss", name:"PCI DSS v4.0", shortName:"PCI-DSS",
      color:"#10b981", gradient:"linear-gradient(135deg,#10b981,#0d9488)",
      headerBg:"linear-gradient(135deg,#0f172a,#042f2e)",
      nextAudit:"2026-08-22", auditor:"QSA — SecurityMetrics",
      controls: [
        {
          id:"6.2.4", label:"Prevention of Software Attacks", weight:30,
          description:"AI code screened for injection and logic vulnerabilities",
          evidence:[
            { id:"e-624-1", control_id:"6.2.4", type:"scan-log", auto_collect:true, link:"/vulnerabilities",
              title:`${sc} vulnerability signal scans`,
              description:"SQL injection, eval/exec, JWT bypass detection log per PR",
              status:sc>0?"collected":"pending", collected_at:sc>0?now:undefined, expires_at:expiry },
            { id:"e-624-2", control_id:"6.2.4", type:"report", link:"/reports?fw=PCI-DSS",
              title:"PCI-DSS compliance report — Req 6.4",
              description:"Signed evidence package for payment system code changes",
              status:"pending" },
          ],
        },
        {
          id:"6.3.2", label:"Software Inventory", weight:25,
          description:"AI-authored code logged per file and pull request",
          evidence:[
            { id:"e-632-1", control_id:"6.3.2", type:"audit-trail", auto_collect:true, link:"/reports",
              title:`${fc} AI code inventory records (AIBOM)`,
              description:"Full AI Bill of Materials covering all scanned files",
              status:fc>0?"collected":"pending", collected_at:fc>0?now:undefined, expires_at:expiry },
          ],
        },
        {
          id:"6.4.2", label:"Change Control Process", weight:30,
          description:"Payment-system changes require dual-reviewer attestation",
          evidence:[
            { id:"e-642-1", control_id:"6.4.2", type:"attestation", auto_collect:true, link:"/audit",
              title:`${attPct}% dual-review compliance`,
              description:"Attestation records for payment-path code changes",
              status:attPct>=90?"collected":attPct>=50?"pending":"pending",
              collected_at:attPct>=50?now:undefined, expires_at:expiry },
            { id:"e-642-2", control_id:"6.4.2", type:"audit-trail", auto_collect:true, link:"/audit",
              title:`${blocked} blocked merge log${blocked===1?"":"s"}`,
              description:"Audit trail evidence of policy gate preventing unattested payment code from merging",
              status:blocked>0?"collected":"not-required", collected_at:blocked>0?now:undefined, expires_at:expiry },
          ],
        },
        {
          id:"6.4.3", label:"Payment Page Security", weight:15,
          description:"AI content in payment paths flagged for mandatory review",
          evidence:[
            { id:"e-643-1", control_id:"6.4.3", type:"scan-log", auto_collect:true, link:"/violations",
              title:"Payment path AI content monitoring",
              description:"High-risk AI files in payment-related repos flagged and tracked",
              status:sc>0?"collected":"pending", collected_at:sc>0?now:undefined, expires_at:expiry },
          ],
        },
      ],
    },
  ];
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const TYPE_CONFIG: Record<EvidenceType, { label:string; icon:string; bg:string; text:string }> = {
  "scan-log":   { label:"Scan Log",    icon:"scan",   bg:"#eef2ff", text:"#4338ca" },
  "attestation":{ label:"Attestation", icon:"check",  bg:"#f0fdf4", text:"#15803d" },
  "report":     { label:"Report",      icon:"doc",    bg:"#f0fdf4", text:"#15803d" },
  "policy":     { label:"Policy",      icon:"shield", bg:"#eff6ff", text:"#1d4ed8" },
  "screenshot": { label:"Screenshot",  icon:"img",    bg:"#fafafa", text:"#374151" },
  "audit-trail":{ label:"Audit Trail", icon:"list",   bg:"#f5f3ff", text:"#6d28d9" },
  "config":     { label:"Config",      icon:"gear",   bg:"#f8fafc", text:"#475569" },
};

const STATUS_CONFIG: Record<EvidenceStatus, { bg:string; text:string; border:string; label:string }> = {
  collected:    { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", label:"Collected"    },
  pending:      { bg:"#fffbeb", text:"#b45309", border:"#fde68a", label:"Pending"      },
  expired:      { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", label:"Expired"      },
  "not-required":{ bg:"#f8fafc", text:"#475569", border:"#e2e8f0", label:"N/A"          },
};

function EvidenceIcon({ icon }: { icon: string }) {
  const icons: Record<string, JSX.Element> = {
    scan:  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
    check: <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>,
    doc:   <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>,
    shield:<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
    img:   <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>,
    list:  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>,
    gear:  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>,
  };
  return icons[icon] ?? null;
}

function fmtDate(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return `${d.getDate()} ${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getMonth()]} ${d.getFullYear()}`;
}

function daysUntil(iso?: string) {
  if (!iso) return null;
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
}

function evidenceExpiry(item: EvidenceItem, override?: EvidenceOverride): EvidenceStatus {
  const status = override?.status ?? item.status;
  if (status !== "collected") return status;
  if (item.expires_at && new Date(item.expires_at) < new Date()) return "expired";
  return "collected";
}

function matchesFilter(item: { title: string; description: string; resolvedStatus: EvidenceStatus; control_id?: string }, search: string, filterStatus: EvidenceStatus | "all"): boolean {
  if (filterStatus !== "all" && item.resolvedStatus !== filterStatus) return false;
  const q = search.trim().toLowerCase();
  if (!q) return true;
  return item.title.toLowerCase().includes(q) || item.description.toLowerCase().includes(q) || (item.control_id?.toLowerCase().includes(q) ?? false);
}

// ── Page ───────────────────────────────────────────────────────────────────────

interface TeamMember { email: string; name: string | null; role: string; github_login: string | null; }

export default function EvidencePage() {
  const { profile } = useAuth();
  const orgName = profile?.org_name || profile?.org_slug || "your organisation";
  const orgSlug = profile?.org_slug || "";

  const [data,          setData]          = useState<DashboardData | null>(null);
  const [teamMembers,   setTeamMembers]   = useState<TeamMember[]>([]);
  const [auditStart,    setAuditStart]    = useState(() => {
    const d = new Date(); d.setMonth(d.getMonth() - 3);
    return d.toISOString().split("T")[0];
  });
  const [auditEnd,      setAuditEnd]      = useState(() => new Date().toISOString().split("T")[0]);
  const [activeFw,      setActiveFw]      = useState("soc2");
  const [overrides,     setOverrides]     = useState<Record<string, EvidenceOverride>>({});
  const [owners,        setOwners]        = useState<Record<string, string>>({});
  const [dueDates,      setDueDates]      = useState<Record<string, string>>({});
  const [uploadId,      setUploadId]      = useState<string | null>(null);
  const [uploadNote,    setUploadNote]    = useState("");
  const [uploadUrl,     setUploadUrl]     = useState("");
  const [uploadFile,    setUploadFile]    = useState<File | null>(null);
  const [uploading,     setUploading]     = useState(false);
  const [uploadOwner,   setUploadOwner]   = useState("");
  const [showGuide,     setShowGuide]     = useState<string | null>(null);
  const [search,        setSearch]        = useState("");
  const [filterStatus,  setFilterStatus]  = useState<EvidenceStatus | "all">("all");
  const [refreshing,    setRefreshing]    = useState(false);
  const [view,          setView]          = useState<"controls" | "gaps" | "owners">("controls");
  const [dragOver,      setDragOver]      = useState(false);

  useEffect(() => {
    setOverrides(loadOverrides());
    try { setOwners(JSON.parse(localStorage.getItem("tl_evidence_owners") ?? "{}")); } catch {}
    try { setDueDates(JSON.parse(localStorage.getItem("tl_evidence_dues") ?? "{}")); } catch {}
  }, []);

  // Fetch real team members for owner dropdowns
  useEffect(() => {
    if (!profile?.org_id) return;
    authedFetch<{ members: TeamMember[] }>("/api/team")
      .then(r => setTeamMembers((r.members ?? []).filter(m => m.email)))
      .catch(() => {});
  }, [profile?.org_id]);

  const getOwners = useCallback((): string[] =>
    teamMembers.length > 0 ? teamMembers.map(m => m.email) : [],
  [teamMembers]);

  const getMemberName = useCallback((email: string): string => {
    const m = teamMembers.find(t => t.email === email);
    return m?.name || email.split("@")[0];
  }, [teamMembers]);

  const fetchData = useCallback(async (spinner = false) => {
    if (spinner) setRefreshing(true);
    const seed = readSeed();
    const d = seed ?? await api.dashboard(orgSlug || "orgSlug", 90).catch(() => null);
    if (d) setData(d);
    if (spinner) setRefreshing(false);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgSlug]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const frameworks = useMemo(() => buildFrameworks(data, auditStart, auditEnd), [data, auditStart, auditEnd]);
  const fw = frameworks.find(f => f.id === activeFw) ?? frameworks[0];

  // Apply overrides + expiry check
  const resolvedItems = useCallback((items: EvidenceItem[]): Array<EvidenceItem & { resolvedStatus: EvidenceStatus }> =>
    items.map(item => ({
      ...item,
      resolvedStatus: evidenceExpiry(item, overrides[item.id]),
    })), [overrides]);

  // Readiness score per framework
  const readiness = useMemo(() => frameworks.map(f => {
    const allItems = f.controls.flatMap(c => c.evidence);
    const weighted = f.controls.reduce((s, c) => {
      const items  = resolvedItems(c.evidence).filter(i => i.resolvedStatus !== "not-required");
      const colled = items.filter(i => i.resolvedStatus === "collected").length;
      return s + (items.length > 0 ? (colled / items.length) * c.weight : c.weight);
    }, 0);
    const totalWeight = f.controls.reduce((s, c) => s + c.weight, 0);
    const pct = Math.round((weighted / totalWeight) * 100);
    const pending = allItems.filter(i => (overrides[i.id]?.status ?? i.status) === "pending").length;
    const expired = allItems.filter(i => evidenceExpiry(i, overrides[i.id]) === "expired").length;
    return { id:f.id, pct, pending, expired };
  }), [frameworks, overrides, resolvedItems]);

  const fwReadiness = readiness.find(r => r.id === activeFw) ?? readiness[0];
  const grade = readinessGrade(fwReadiness?.pct ?? 0);

  // Gap analysis — sorted by urgency (expired first, then nearest due date, then control weight)
  const gaps = useMemo(() =>
    fw.controls.flatMap(c =>
      resolvedItems(c.evidence)
        .filter(i => i.resolvedStatus !== "collected" && i.resolvedStatus !== "not-required")
        .map(i => ({ ...i, control_label:c.label, control_id:c.id, control_weight:c.weight }))
    )
    .filter(g => matchesFilter(g, search, filterStatus))
    .sort((a, b) => {
      if (a.resolvedStatus === "expired" && b.resolvedStatus !== "expired") return -1;
      if (b.resolvedStatus === "expired" && a.resolvedStatus !== "expired") return 1;
      const da = dueDates[a.id], db = dueDates[b.id];
      if (da && db) return da.localeCompare(db);
      if (da) return -1;
      if (db) return 1;
      return b.control_weight - a.control_weight;
    }),
  [fw, resolvedItems, search, filterStatus, dueDates]);

  const expiredGaps = gaps.filter(g => g.resolvedStatus === "expired").length;
  const dueSoonGaps = gaps.filter(g => { const d = dueDates[g.id] ? daysUntil(dueDates[g.id]) : null; return d !== null && d <= 14; }).length;

  async function markCollected(id: string) {
    setUploading(true);
    let storedUrl = uploadUrl.trim();

    // Upload file to Supabase Storage if one is attached
    if (uploadFile && profile?.org_id) {
      try {
        const form = new FormData();
        form.append("file",  uploadFile);
        form.append("path",  `${activeFw}/${id}`);
        form.append("label", uploadNote.trim() || uploadFile.name);
        const { data: { session } } = await import("@/lib/supabase").then(m => m.supabase.auth.getSession());
        const res = await fetch("/api/storage", {
          method:  "POST",
          headers: session?.access_token ? { Authorization: `Bearer ${session.access_token}` } : {},
          body:    form,
        });
        if (res.ok) {
          const uploaded = await res.json() as { url: string };
          storedUrl = uploaded.url ?? storedUrl;
        }
      } catch { /* non-fatal — fall through */ }
    }

    const note = uploadNote.trim() + (storedUrl ? `\nURL: ${storedUrl}` : "");
    const ownr = uploadOwner || undefined;
    const next = { ...overrides, [id]: { status:"collected" as EvidenceStatus, collected_at:new Date().toISOString().split("T")[0], note:note||undefined } };
    setOverrides(next); saveOverrides(next);
    if (ownr) {
      const no = { ...owners, [id]: ownr };
      setOwners(no); localStorage.setItem("tl_evidence_owners", JSON.stringify(no));
    }
    setUploadId(null); setUploadNote(""); setUploadUrl(""); setUploadOwner(""); setUploadFile(null); setUploading(false);
  }

  function markPending(id: string) {
    const next = { ...overrides, [id]: { status:"pending" as EvidenceStatus } };
    setOverrides(next); saveOverrides(next);
  }

  function setOwner(id: string, email: string) {
    const next = { ...owners, [id]: email };
    setOwners(next); localStorage.setItem("tl_evidence_owners", JSON.stringify(next));
  }

  function setDueDate(id: string, date: string) {
    const next = { ...dueDates, [id]: date };
    setDueDates(next); localStorage.setItem("tl_evidence_dues", JSON.stringify(next));
  }

  function bulkCollect(ids: string[]) {
    const now = new Date().toISOString().split("T")[0];
    const next = { ...overrides };
    ids.forEach(id => { next[id] = { status:"collected" as EvidenceStatus, collected_at:now }; });
    setOverrides(next); saveOverrides(next);
  }

  function exportPackage() {
    const pkg = {
      generated_at: new Date().toISOString(),
      orgSlug: orgName,
      audit_period: { start: auditStart, end: auditEnd },
      frameworks: frameworks.map(f => ({
        id: f.id,
        name: f.name,
        readiness_pct: readiness.find(r=>r.id===f.id)?.pct ?? 0,
        controls: f.controls.map(c => ({
          id: c.id,
          label: c.label,
          evidence: resolvedItems(c.evidence).map(i => ({
            id: i.id,
            type: i.type,
            title: i.title,
            status: i.resolvedStatus,
            collected_at: overrides[i.id]?.collected_at ?? i.collected_at,
            note: overrides[i.id]?.note,
          })),
        })),
      })),
    };
    const blob = new Blob([JSON.stringify(pkg, null, 2)], { type:"application/json" });
    Object.assign(document.createElement("a"), {
      href: URL.createObjectURL(blob),
      download: `evidence-package-${orgSlug}-${auditStart}.json`,
    }).click();
  }

  // Shared evidence row renderer — used by both Controls and Gaps views
  function renderEvidenceRow(ev: EvidenceItem & { resolvedStatus: EvidenceStatus }, controlBadge?: { id: string; label: string }) {
    const typeCfg  = TYPE_CONFIG[ev.type];
    const statCfg  = STATUS_CONFIG[ev.resolvedStatus];
    const expDays  = daysUntil(ev.expires_at);
    const isUpload = uploadId === ev.id;
    const override = overrides[ev.id];
    return (
      <div key={ev.id} className="px-5 py-3 hover:bg-gray-50/50 transition-colors">
        <div className="flex items-center gap-4">
          {/* Type icon */}
          <div className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
            style={{ background:typeCfg.bg, color:typeCfg.text }}>
            <EvidenceIcon icon={typeCfg.icon} />
          </div>

          {/* Info */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              {controlBadge && (
                <>
                  <span className="text-[10px] font-black font-mono px-2 py-0.5 rounded shrink-0" style={{ background:`${fw.color}10`, color:fw.color }}>{controlBadge.id}</span>
                  <span className="text-[10px] text-gray-500 shrink-0">{controlBadge.label}</span>
                </>
              )}
              <p className="text-[11px] font-semibold text-gray-800 truncate">{ev.title}</p>
              {ev.auto_collect && (
                <span className="text-[8px] font-bold text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-100">AUTO</span>
              )}
              {(() => { const fb = freshnessBadge(override?.collected_at ?? ev.collected_at); return fb ? <span className="text-[8px] font-bold px-1.5 py-0.5 rounded-full" style={{ color:fb.color, background:fb.bg }}>{fb.label}</span> : null; })()}
            </div>
            <p className="text-[10px] text-gray-400 mt-0.5 truncate">{ev.description}</p>
            {override?.note && (
              <p className="text-[9px] text-indigo-600 italic mt-0.5 truncate">📎 {override.note}</p>
            )}
            {/* Owner + due date row */}
            <div className="flex items-center gap-3 mt-1.5 flex-wrap">
              <select value={owners[ev.id] ?? ""} onChange={e => setOwner(ev.id, e.target.value)}
                className="text-[9px] bg-transparent border-none outline-none text-gray-400 hover:text-indigo-600 cursor-pointer max-w-[160px]">
                <option value="">Assign owner…</option>
                {getOwners().map(o => <option key={o} value={o}>{getMemberName(o)}</option>)}
              </select>
              {owners[ev.id] && (
                <span className="inline-flex items-center gap-1 text-[9px] text-indigo-600 font-medium bg-indigo-50 px-1.5 py-0.5 rounded-full">
                  <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                  {getMemberName(owners[ev.id])}
                </span>
              )}
              {ev.resolvedStatus === "pending" && (
                <input type="date" value={dueDates[ev.id] ?? ""} onChange={e => setDueDate(ev.id, e.target.value)}
                  className="text-[9px] border-none outline-none bg-transparent text-gray-400 hover:text-rose-500 cursor-pointer" />
              )}
              {dueDates[ev.id] && (() => { const d = daysUntil(dueDates[ev.id]); return d !== null && d <= 14 ? <span className="text-[9px] font-bold text-rose-600">Due in {d}d</span> : null; })()}
            </div>
          </div>

          {/* Meta + Actions */}
          <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
            {(override?.collected_at ?? ev.collected_at) && (
              <span className="text-[9px] text-gray-400 font-mono">{fmtDate(override?.collected_at ?? ev.collected_at)}</span>
            )}
            {ev.resolvedStatus === "collected" && expDays !== null && expDays <= 90 && (
              <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${expDays<=30?"text-rose-600 bg-rose-50 border border-rose-200":"text-amber-600 bg-amber-50 border border-amber-200"}`}>
                {expDays<=0?"Expired":`Exp. ${expDays}d`}
              </span>
            )}
            <span className="text-[9px] font-bold px-2 py-0.5 rounded-full border"
              style={{ background:statCfg.bg, color:statCfg.text, borderColor:statCfg.border }}>
              {statCfg.label}
            </span>
            {ev.link && ev.resolvedStatus !== "not-required" && (
              <Link href={ev.link} className="text-[10px] font-bold text-indigo-500 hover:text-indigo-700 transition-colors">View →</Link>
            )}
            {/* Guide button */}
            {COLLECTION_GUIDE[ev.type] && (
              <button onClick={() => setShowGuide(showGuide === ev.id ? null : ev.id)}
                className="text-[9px] font-bold text-gray-400 hover:text-indigo-600 px-1.5 py-0.5 rounded transition-colors">
                {showGuide === ev.id ? "Hide guide" : "How to collect"}
              </button>
            )}
            {(ev.resolvedStatus === "pending" || ev.resolvedStatus === "expired") && !ev.auto_collect && (
              <button onClick={() => { setUploadId(isUpload?null:ev.id); setUploadNote(""); setUploadUrl(""); setUploadOwner(""); }}
                className="text-[10px] font-bold text-emerald-600 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-lg hover:bg-emerald-100 transition-colors whitespace-nowrap">
                {isUpload?"Cancel":"Collect"}
              </button>
            )}
            {ev.resolvedStatus === "collected" && !ev.auto_collect && (
              <button onClick={() => markPending(ev.id)}
                className="text-[9px] font-semibold text-gray-400 hover:text-rose-600 hover:bg-rose-50 px-2 py-0.5 rounded-lg transition-colors">
                Revoke
              </button>
            )}
          </div>
        </div>

        {/* Collection guide */}
        {showGuide === ev.id && COLLECTION_GUIDE[ev.type] && (
          <div className="mt-3 ml-11 bg-indigo-50 border border-indigo-100 rounded-xl p-3 space-y-2">
            <p className="text-[10px] font-black text-indigo-800 uppercase tracking-wider">How to collect this evidence</p>
            <div className="space-y-1">
              {COLLECTION_GUIDE[ev.type].steps.map((s, i) => (
                <div key={i} className="flex items-start gap-2">
                  <span className="shrink-0 w-4 h-4 rounded-full bg-indigo-100 text-indigo-600 text-[8px] font-black flex items-center justify-center mt-0.5">{i+1}</span>
                  <span className="text-[10px] text-indigo-700">{s}</span>
                </div>
              ))}
            </div>
            <p className="text-[9px] text-indigo-500"><span className="font-bold">Sources:</span> {COLLECTION_GUIDE[ev.type].sources.join(" · ")}</p>
          </div>
        )}

        {/* Rich collect form */}
        {isUpload && (
          <div className="mt-3 ml-11 bg-emerald-50 border border-emerald-100 rounded-xl p-3 space-y-2">
            <p className="text-[10px] font-bold text-emerald-800">Collect Evidence — {ev.title}</p>
            <input value={uploadNote} onChange={e => setUploadNote(e.target.value)}
              placeholder="Description: e.g. Uploaded to SharePoint, attached to Jira TL-42…"
              className="w-full text-xs border border-emerald-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-emerald-400 bg-white" />
            <input value={uploadUrl} onChange={e => setUploadUrl(e.target.value)}
              placeholder="URL (optional): SharePoint link, Jira ticket, S3 path…"
              className="w-full text-xs border border-emerald-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-emerald-400 bg-white" />
            {/* Drag-drop file upload zone */}
            <label
              className={`flex flex-col items-center justify-center gap-1.5 rounded-xl border-2 border-dashed cursor-pointer transition-all py-5 ${
                dragOver ? "border-emerald-400 bg-emerald-50" : "border-emerald-200 bg-white hover:border-emerald-300"
              }`}
              onDragOver={e => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={e => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) setUploadFile(f); }}
            >
              {uploadFile ? (
                <>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                  <span className="text-xs font-semibold text-emerald-700">{uploadFile.name}</span>
                  <span className="text-[10px] text-emerald-500">{(uploadFile.size / 1024).toFixed(0)} KB · click to change</span>
                </>
              ) : (
                <>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#6ee7b7" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                  <span className="text-xs text-gray-500">Drag & drop or <span className="text-emerald-600 font-semibold">browse</span></span>
                  <span className="text-[10px] text-gray-400">PDF · PNG · JPG · CSV · DOCX · TXT</span>
                </>
              )}
              <input type="file" className="sr-only" accept=".pdf,.png,.jpg,.csv,.xlsx,.docx,.txt"
                onChange={e => setUploadFile(e.target.files?.[0] ?? null)} />
            </label>
            {uploadFile && (
              <div className="flex items-center gap-2">
                <p className="text-[9px] text-emerald-600 flex-1">
                  {profile?.org_id ? "File will be uploaded to Supabase Storage (evidence vault)." : "File will be recorded locally."}
                </p>
                <button type="button" onClick={() => setUploadFile(null)} className="text-[9px] text-gray-400 hover:text-gray-600">✕ Remove</button>
              </div>
            )}
            <div className="flex gap-2">
              <select value={uploadOwner} onChange={e => setUploadOwner(e.target.value)}
                className="flex-1 text-xs border border-emerald-200 rounded-lg px-3 py-2 focus:outline-none bg-white">
                <option value="">Collected by (optional)…</option>
                {getOwners().map(o => <option key={o} value={o}>{getMemberName(o)} ({o})</option>)}
              </select>
              <button onClick={() => markCollected(ev.id)} disabled={uploading}
                className="text-xs font-bold text-white px-4 py-2 rounded-lg transition-colors shrink-0 disabled:opacity-60"
                style={{ background:"linear-gradient(135deg,#10b981,#059669)" }}>
                {uploading ? "Uploading…" : "✓ Confirm"}
              </button>
            </div>
          </div>
        )}
      </div>
    );
  }

  // Overall stats across active framework
  const allItems      = fw.controls.flatMap(c => c.evidence);
  const collected     = allItems.filter(i => (overrides[i.id]?.status ?? i.status) === "collected").length;
  const pending       = allItems.filter(i => (overrides[i.id]?.status ?? i.status) === "pending").length;
  const expired       = allItems.filter(i => evidenceExpiry(i, overrides[i.id]) === "expired").length;
  const notRequired   = allItems.filter(i => (overrides[i.id]?.status ?? i.status) === "not-required").length;
  const total         = allItems.length - notRequired;
  const completePct   = Math.round((collected / Math.max(total, 1)) * 100);

  return (
    <AuthGuard>
      <PageSkeleton rows={4} cards={3}>
      <div className="max-w-7xl mx-auto space-y-6 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-0.5">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background:"rgba(16,185,129,0.1)", border:"1px solid rgba(16,185,129,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                  <line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Evidence Locker</h1>
              <span className="text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-2 py-0.5 rounded-full">{orgName}</span>
              {gaps.length > 0 && (
                <span className="text-xs font-black text-white bg-amber-500 px-2 py-0.5 rounded-full">{gaps.length} gap{gaps.length !== 1 ? "s" : ""}</span>
              )}
            </div>
            <p className="text-sm text-gray-400">
              Compliance evidence for {orgName} — auto-collected from live scans, manually verified by your team.
            </p>
            {/* Live stats bar */}
            {data && (
              <div className="flex items-center gap-4 mt-2 flex-wrap">
                {[
                  { label: "Scans",       value: data.scan_count,                               color: "text-indigo-600" },
                  { label: "Files",        value: data.file_count,                               color: "text-gray-600"   },
                  { label: "Attested",     value: `${Math.round(data.attestation_rate * 100)}%`, color: "text-emerald-600" },
                  { label: "Repos",        value: data.repos.length,                             color: "text-violet-600" },
                  { label: "Unblocked",    value: data.unattested_deploy_count === 0 ? "All" : `${data.unattested_deploy_count} blocked`, color: data.unattested_deploy_count === 0 ? "text-emerald-600" : "text-rose-600" },
                ].map(s => (
                  <div key={s.label} className="flex items-center gap-1">
                    <span className={`text-xs font-black tabular-nums ${s.color}`}>{s.value}</span>
                    <span className="text-[10px] text-gray-400">{s.label}</span>
                  </div>
                ))}
                <span className="text-[10px] text-gray-300">· live</span>
              </div>
            )}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <button onClick={() => fetchData(true)} disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-50 transition-all shadow-sm">
              <svg className={refreshing?"animate-spin":""} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
              </svg>
              Refresh
            </button>
            <Link href="/reports"
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-bold text-white rounded-xl transition-all shadow-sm"
              style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow:"0 2px 10px rgba(99,102,241,0.35)" }}>
              Generate Report
            </Link>
            <button onClick={exportPackage}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-xl hover:bg-emerald-100 transition-all shadow-sm">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Export Package
            </button>
          </div>
        </div>

        {/* Audit period picker */}
        <div className="animate-fade-up flex flex-wrap items-center gap-3 bg-white border border-gray-200 rounded-2xl px-5 py-3 shadow-sm">
          <span className="text-xs font-black text-gray-500 uppercase tracking-wider shrink-0">Audit Period</span>
          <div className="flex items-center gap-2">
            <label className="text-[10px] font-semibold text-gray-400">From</label>
            <input type="date" value={auditStart} onChange={e => setAuditStart(e.target.value)}
              className="text-xs text-gray-700 border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
          </div>
          <span className="text-gray-300 font-mono">→</span>
          <div className="flex items-center gap-2">
            <label className="text-[10px] font-semibold text-gray-400">To</label>
            <input type="date" value={auditEnd} onChange={e => setAuditEnd(e.target.value)}
              className="text-xs text-gray-700 border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
          </div>
          <span className="ml-auto text-[10px] text-gray-400">
            Evidence auto-collected from {auditStart} → {auditEnd}
          </span>
        </div>

        {/* Framework selector */}
        <div className="animate-fade-up grid grid-cols-1 sm:grid-cols-3 gap-3">
          {frameworks.map(f => {
            const r = readiness.find(x => x.id === f.id)!;
            const g = readinessGrade(r.pct);
            const active = activeFw === f.id;
            const nextDays = daysUntil(f.nextAudit);
            return (
              <button key={f.id} onClick={() => setActiveFw(f.id)}
                className="rounded-2xl overflow-hidden border-2 text-left transition-all"
                style={{ borderColor: active ? f.color : "rgba(226,232,240,0.8)", boxShadow: active ? `0 4px 20px ${f.color}25` : "none" }}>
                <div className="px-4 py-3" style={{ background: f.headerBg }}>
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-[10px] font-bold text-white/40 uppercase tracking-widest">{f.name}</p>
                    {f.nextAudit && nextDays !== null && !Number.isNaN(nextDays) && (
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${nextDays <= 30 ? "text-rose-300 bg-rose-900/30" : "text-white/30 bg-white/10"}`}>
                        Audit in {nextDays}d
                      </span>
                    )}
                  </div>
                  <div className="flex items-center justify-between">
                    <p className="text-base font-black text-white">{f.shortName}</p>
                    <div className="flex items-center gap-2">
                      <span className="text-2xl font-black" style={{ color: g.color === "#15803d" ? "#34d399" : g.color === "#1d4ed8" ? "#93c5fd" : "#fcd34d" }}>{g.grade}</span>
                      <span className="text-sm font-bold text-white/60 tabular-nums">{r.pct}%</span>
                    </div>
                  </div>
                  <div className="mt-2 h-1.5 rounded-full overflow-hidden bg-white/10">
                    <div className="h-full rounded-full" style={{ width:`${r.pct}%`, background: f.gradient }} />
                  </div>
                </div>
                <div className="px-4 py-2 bg-white flex items-center gap-4 text-[10px]">
                  <span className="text-emerald-600 font-bold">{frameworks.find(x=>x.id===f.id)!.controls.flatMap(c=>c.evidence).filter(i=>(overrides[i.id]?.status??i.status)==="collected").length} collected</span>
                  {r.pending > 0 && <span className="text-amber-600 font-bold">{r.pending} pending</span>}
                  {r.expired > 0 && <span className="text-rose-600 font-bold">{r.expired} expired</span>}
                  {f.auditor && <span className="text-gray-400 ml-auto truncate">{f.auditor}</span>}
                </div>
              </button>
            );
          })}
        </div>

        {/* View toggle + completeness */}
        <div className="animate-fade-up rounded-2xl overflow-hidden border border-gray-200"
          style={{ background:"linear-gradient(135deg,rgba(99,102,241,0.04),rgba(16,185,129,0.03))" }}>
          <div className="px-6 py-4 flex items-center gap-6 flex-wrap">
            <div className="flex items-center gap-3">
              <span className="text-3xl font-black tabular-nums" style={{ color: fw.color }}>{completePct}%</span>
              <div>
                <div className="flex items-center gap-1.5">
                  <p className="text-xs font-bold text-gray-800">Evidence complete</p>
                  <InfoTooltip title="Evidence Completeness" description="Percentage of required evidence items collected for this framework. AUTO items are collected automatically from live scan data. Pending items require manual upload." formula={"collected ÷ (total − not_required) × 100"} position="bottom" />
                </div>
                <p className="text-[10px] text-gray-400">{collected} collected · {pending} pending · {expired>0?`${expired} expired ·`:""} {notRequired} N/A</p>
              </div>
            </div>
            <div className="flex-1 min-w-[140px]">
              <div className="h-2 rounded-full overflow-hidden bg-gray-100">
                <div className="h-full rounded-full transition-all duration-700"
                  style={{ width:`${completePct}%`, background: fw.gradient }} />
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <div className="flex gap-0.5 bg-gray-100 p-0.5 rounded-xl">
                {(["controls","gaps","owners"] as const).map(v => (
                  <button key={v} onClick={() => setView(v)}
                    className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${view===v?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                    {v === "controls" ? "Controls" : v === "gaps" ? `Gaps${gaps.length > 0 ? ` (${gaps.length})` : ""}` : "Owners"}
                  </button>
                ))}
              </div>
            </div>
          </div>
          {view !== "owners" && (
            <div className="px-6 pb-4 flex items-center gap-3 flex-wrap">
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search evidence by title, description, or control…"
                className="flex-1 min-w-[200px] text-xs border border-gray-200 rounded-lg px-3 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-300" />
              <select value={filterStatus} onChange={e => setFilterStatus(e.target.value as EvidenceStatus | "all")}
                className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-300">
                <option value="all">All statuses</option>
                <option value="collected">Collected</option>
                <option value="pending">Pending</option>
                <option value="expired">Expired</option>
                <option value="not-required">N/A</option>
              </select>
              {(search || filterStatus !== "all") && (
                <button onClick={() => { setSearch(""); setFilterStatus("all"); }}
                  className="text-[11px] font-semibold text-gray-400 hover:text-indigo-600 transition-colors">
                  Clear
                </button>
              )}
            </div>
          )}
        </div>

        {/* Gap analysis view */}
        {view === "gaps" && (
          <div className="animate-fade-up space-y-3">
            {gaps.length === 0 ? (
              <div className="section-card py-14 text-center">
                <div className="w-12 h-12 rounded-2xl bg-emerald-50 flex items-center justify-center text-emerald-500 mx-auto mb-3">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                  </svg>
                </div>
                <p className="text-sm font-bold text-emerald-700">All evidence collected for {fw.shortName}</p>
                <p className="text-xs text-gray-400 mt-1">Ready for auditor review</p>
              </div>
            ) : (
              <>
                {/* Urgency summary */}
                <div className="flex items-center gap-3 flex-wrap text-[11px] font-semibold px-1">
                  <span className="text-gray-500">{gaps.length} gap{gaps.length!==1?"s":""} — sorted by urgency</span>
                  {expiredGaps > 0 && <span className="text-rose-600">{expiredGaps} expired</span>}
                  {dueSoonGaps > 0 && <span className="text-amber-600">{dueSoonGaps} due within 14 days</span>}
                  {fw.nextAudit && (() => { const d = daysUntil(fw.nextAudit); return d !== null && d > 0 ? <span className="ml-auto text-gray-400 font-medium">Next audit in {d}d ({fmtDate(fw.nextAudit)})</span> : null; })()}
                </div>
                <div className="section-card overflow-hidden divide-y divide-gray-50">
                  {gaps.map(gap => renderEvidenceRow(gap, { id: gap.control_id, label: gap.control_label }))}
                </div>
              </>
            )}
          </div>
        )}

        {/* Owners assignment view */}
        {view === "owners" && (
          <div className="animate-fade-up space-y-3">
            {fw.controls.flatMap(c => resolvedItems(c.evidence)).filter(i => i.resolvedStatus !== "not-required").map(ev => (
              <div key={ev.id} className="section-card p-4 flex items-center gap-4">
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-bold text-gray-900 truncate">{ev.title}</p>
                  <p className="text-[10px] text-gray-400 truncate">{ev.description}</p>
                </div>
                <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border shrink-0`}
                  style={{ background:STATUS_CONFIG[ev.resolvedStatus].bg, color:STATUS_CONFIG[ev.resolvedStatus].text, borderColor:STATUS_CONFIG[ev.resolvedStatus].border }}>
                  {STATUS_CONFIG[ev.resolvedStatus].label}
                </span>
                <select
                  value={owners[ev.id] ?? ""}
                  onChange={e => {
                    const next = { ...owners, [ev.id]: e.target.value };
                    setOwners(next);
                    try { localStorage.setItem("tl_evidence_owners", JSON.stringify(next)); } catch {}
                  }}
                  className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-300 bg-white shrink-0 w-40">
                  <option value="">Unassigned</option>
                  {getOwners().map(o => <option key={o} value={o}>{getMemberName(o)} ({o})</option>)}
                </select>
              </div>
            ))}
          </div>
        )}

        {/* Controls + evidence view */}
        {view === "controls" && (
          <div className="animate-fade-up space-y-4">
            {fw.controls.every(ctrl => resolvedItems(ctrl.evidence).filter(i => matchesFilter(i, search, filterStatus)).length === 0) && (
              <div className="section-card py-14 text-center">
                <p className="text-sm font-bold text-gray-500">No evidence matches your search</p>
                <p className="text-xs text-gray-400 mt-1">Try a different search term or status filter</p>
                <button onClick={() => { setSearch(""); setFilterStatus("all"); }}
                  className="mt-3 text-xs font-bold text-indigo-600 hover:text-indigo-700">Clear filters</button>
              </div>
            )}
            {fw.controls.map(ctrl => {
              const items       = resolvedItems(ctrl.evidence);
              const ctrlColl    = items.filter(i => i.resolvedStatus === "collected").length;
              const ctrlTotal   = items.filter(i => i.resolvedStatus !== "not-required").length;
              const ctrlPct     = Math.round((ctrlColl / Math.max(ctrlTotal, 1)) * 100);
              const allDone     = ctrlColl === ctrlTotal && ctrlTotal > 0;
              const displayItems = items.filter(i => matchesFilter(i, search, filterStatus));
              if (displayItems.length === 0) return null;
              return (
                <div key={ctrl.id} className="section-card overflow-hidden">
                  {/* Control header */}
                  <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-100"
                    style={{ background: allDone ? "rgba(240,253,244,0.6)" : "rgba(248,250,252,0.8)" }}>
                    <div className="flex items-center gap-3">
                      <span className="text-[11px] font-black font-mono px-2.5 py-1 rounded-lg"
                        style={{ background:`${fw.color}10`, color:fw.color, border:`1px solid ${fw.color}25` }}>
                        {ctrl.id}
                      </span>
                      <div>
                        <p className="text-sm font-bold text-gray-900">{ctrl.label}</p>
                        <p className="text-[10px] text-gray-400 mt-0.5">{ctrl.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full overflow-hidden bg-gray-100">
                          <div className="h-full rounded-full" style={{ width:`${ctrlPct}%`, background: fw.gradient }} />
                        </div>
                        <span className="text-[10px] font-black tabular-nums" style={{ color:fw.color }}>{ctrlColl}/{ctrlTotal}</span>
                      </div>
                      {!allDone && ctrlTotal > ctrlColl && (
                        <button
                          onClick={() => bulkCollect(items.filter(i => i.resolvedStatus === "pending" && !i.auto_collect).map(i => i.id))}
                          className="text-[10px] font-bold text-indigo-600 bg-indigo-50 border border-indigo-200 px-2.5 py-1 rounded-lg hover:bg-indigo-100 transition-colors whitespace-nowrap">
                          Collect All Pending
                        </button>
                      )}
                      {allDone && (
                        <div className="w-5 h-5 rounded-full bg-emerald-500 flex items-center justify-center">
                          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Evidence items */}
                  <div className="divide-y divide-gray-50">
                    {displayItems.map(ev => renderEvidenceRow(ev))}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Info note */}
        <div className="animate-fade-up flex items-start gap-3 bg-indigo-50 border border-indigo-100 rounded-xl px-4 py-3">
          <svg className="shrink-0 mt-0.5 text-indigo-500" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <p className="text-xs text-indigo-800 leading-relaxed">
            <span className="font-bold">AUTO</span>-tagged evidence is collected automatically from live scan data (scan counts, attestation records, audit trail).
            Evidence marked <span className="font-bold">Pending</span> requires manual upload — click "Collect" to mark it and add a storage note.
            Evidence is valid for 12 months from the audit period end date; the locker warns when items approach expiry.
          </p>
        </div>

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
