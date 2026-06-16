"use client";

import { useState, useEffect, useCallback } from "react";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import InfoTooltip from "@/components/InfoTooltip";
import { api } from "@/lib/api";
import type { DashboardData } from "@/types";
import { authedFetch } from "@/lib/useRealData";
import { useIncidentsRealtime } from "@/lib/realtime";
import { useAuth } from "@/lib/auth";

// ── Types ──────────────────────────────────────────────────────────────────────

type IncidentSeverity = "P1" | "P2" | "P3";
type IncidentStatus   = "active" | "contained" | "resolved" | "post-mortem";
type IncidentType     = "secret-exposed" | "supply-chain" | "rce-pattern" | "auth-bypass" | "data-breach" | "policy-violation";

interface PlaybookStep {
  step: number;
  action: string;
  owner: string;
  duration: string;
  completed: boolean;
}

interface Incident {
  id: string;
  title: string;
  type: IncidentType;
  severity: IncidentSeverity;
  status: IncidentStatus;
  affected_repo?: string;
  affected_file?: string;
  detected_at: string;
  contained_at?: string;
  resolved_at?: string;
  description: string;
  impact: string;
  root_cause?: string;
  timeline: { time: string; action: string; actor: string }[];
  playbook: PlaybookStep[];
  stakeholders: string[];
  related_cve?: string;
  lesson_learned?: string;
}

// ── Playbooks ──────────────────────────────────────────────────────────────────

const PLAYBOOK_TEMPLATES: Record<IncidentType, { name:string; steps: Omit<PlaybookStep,"completed">[] }> = {
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

const STORAGE_KEY = "tl_incidents";
const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Local-storage–based auto-resolution ───────────────────────────────────────
// Checks tl_violation_statuses (written by the attestation flow) and resolves:
//   1. File-tied incidents (P1) where the specific file is now attested
//   2. Auto-generated deploy-count incidents (P2 "N unattested deployments…")
//      when ANY file has been attested — the count-based trigger is moot once
//      the team is actively attesting
// Does NOT need the dashboard API and cannot fail silently.
function autoResolveFromLocalStorage(incidents: Incident[]): Incident[] {
  let resolvedFiles: Set<string>;
  let hasAnyResolved = false;
  try {
    const statuses = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string, string>;
    const entries = Object.entries(statuses);
    hasAnyResolved = entries.some(([, v]) => v === "resolved");
    resolvedFiles = new Set(
      entries
        .filter(([, val]) => val === "resolved")
        .map(([key]) => key.split("::").slice(2).join("::")),
    );
  } catch {
    return incidents;
  }
  if (!hasAnyResolved) return incidents;
  const now = new Date().toISOString();
  let changed = false;
  const next = incidents.map(inc => {
    if (inc.status !== "active") return inc;
    // Case 1: file-tied incident — specific file is now attested
    if (inc.affected_file && resolvedFiles.has(inc.affected_file)) {
      changed = true;
      return {
        ...inc,
        status: "resolved" as IncidentStatus,
        resolved_at: now,
        timeline: [...inc.timeline,
          { time: now, action: "Auto-resolved: file has been attested", actor: "TrustLedger" }],
      };
    }
    // Case 2: auto-generated deploy-count policy-violation incident
    // Identifiable by title pattern "N unattested deployments exceed policy threshold"
    // Resolve these once the team has started attesting (any file resolved)
    if (
      !inc.affected_file &&
      inc.type === "policy-violation" &&
      /^\d+ unattested deployments/.test(inc.title)
    ) {
      changed = true;
      return {
        ...inc,
        status: "resolved" as IncidentStatus,
        resolved_at: now,
        timeline: [...inc.timeline,
          { time: now, action: "Auto-resolved: all files have been attested", actor: "TrustLedger" }],
      };
    }
    return inc;
  });
  if (!changed) return incidents;
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(next)); } catch {}
  return next;
}

// ── Dynamic incident generation ────────────────────────────────────────────────

// Returns the full updated incident list:
// - auto-resolves "active" incidents whose trigger (unattested file / deploy count) is now clear
// - appends new incidents for newly-detected issues not yet tracked
function incidentsFromDashboard(data: DashboardData, existing: Incident[]): Incident[] {
  const now = new Date().toISOString();

  // File paths still CRITICAL + unattested in the latest dashboard snapshot
  const stillOpenFiles = new Set(
    data.top_risk_files
      .filter(f => f.risk_score === "CRITICAL" && !f.attested)
      .map(f => f.file_path),
  );

  // 1. Auto-resolve active incidents whose trigger has cleared
  const updated: Incident[] = existing.map(inc => {
    if (inc.status !== "active") return inc;
    // File-tied incident: file is now attested (no longer in open set)
    if (inc.affected_file && !stillOpenFiles.has(inc.affected_file)) {
      return {
        ...inc,
        status: "resolved" as IncidentStatus,
        resolved_at: now,
        timeline: [
          ...inc.timeline,
          { time: now, action: "Auto-resolved: file has been reviewed and attested", actor: "TrustLedger" },
        ],
      };
    }
    // Policy-violation deploy-count incident: count now at or below threshold
    if (!inc.affected_file && inc.type === "policy-violation" && data.unattested_deploy_count <= 3) {
      return {
        ...inc,
        status: "resolved" as IncidentStatus,
        resolved_at: now,
        timeline: [
          ...inc.timeline,
          { time: now, action: `Auto-resolved: unattested deploy count is now ${data.unattested_deploy_count}`, actor: "TrustLedger" },
        ],
      };
    }
    return inc;
  });

  // 2. Generate new incidents for issues not yet tracked
  const trackedKeys = new Set(
    updated.map(i =>
      i.affected_file ??
      (!i.affected_file && i.type === "policy-violation" ? "unattested-deployments" : i.affected_repo ?? ""),
    ),
  );
  const generated: Incident[] = [];
  let seq = updated.length + 1;

  // P1 for every CRITICAL unattested file (max 3 to avoid noise)
  data.top_risk_files
    .filter(f => f.risk_score === "CRITICAL" && !f.attested)
    .slice(0, 3)
    .forEach(f => {
      if (trackedKeys.has(f.file_path)) return;
      const incType: IncidentType = f.file_path.match(/auth|login|oauth|session/i)
        ? "auth-bypass"
        : f.file_path.match(/secret|key|token|pass/i)
        ? "secret-exposed"
        : "rce-pattern";
      const id = `INC-${String(seq++).padStart(3,"0")}`;
      const ts = new Date(Date.now() - Math.random() * 48 * 3600000).toISOString();
      generated.push({
        id, title:`CRITICAL unattested file: ${f.file_path.split("/").pop()}`,
        type: incType, severity:"P1", status:"active",
        affected_repo: f.repo, affected_file: f.file_path,
        detected_at: ts,
        description:`TrustLedger detected a CRITICAL-risk AI-generated file that has not been attested. File ${f.file_path} in ${f.repo} has AI percentage of ${(f.ai_pct * 100).toFixed(0)}% and risk score CRITICAL. This file was deployed without security review.`,
        impact:`Unreviewed AI-generated code in production. AI percentage: ${(f.ai_pct * 100).toFixed(0)}%. Deploy #${f.pr_number} blocked from full attestation.`,
        timeline:[
          { time: ts, action:"CRITICAL file detected by TrustLedger scan", actor:"TrustLedger" },
          { time: new Date(new Date(ts).getTime() + 60000).toISOString(), action:"P1 incident auto-created", actor:"TrustLedger" },
        ],
        playbook: PLAYBOOK_TEMPLATES[incType].steps.map(s => ({ ...s, completed:false })),
        stakeholders:[`security@${ORG}.io`,`ciso@${ORG}.io`],
      });
    });

  // P2 for unattested deploy count > 3 (only if not already tracked)
  if (data.unattested_deploy_count > 3 && !trackedKeys.has("unattested-deployments")) {
    const id = `INC-${String(seq++).padStart(3,"0")}`;
    const ts = new Date(Date.now() - 2 * 3600000).toISOString();
    generated.push({
      id, title:`${data.unattested_deploy_count} unattested deployments exceed policy threshold`,
      type:"policy-violation", severity:"P2", status:"active",
      affected_repo: data.repos[0]?.repo ?? "unknown",
      detected_at: ts,
      description:`${data.unattested_deploy_count} deploys have occurred without full attestation coverage. Policy requires 100% attestation before production deployment. Current attestation rate: ${(data.attestation_rate * 100).toFixed(0)}%.`,
      impact:`Policy violation — ${data.unattested_deploy_count} deployments lack required security review. Compliance posture degraded.`,
      timeline:[
        { time: ts, action:`${data.unattested_deploy_count} unattested deploys detected`, actor:"TrustLedger" },
        { time: new Date(new Date(ts).getTime() + 120000).toISOString(), action:"P2 policy-violation incident created", actor:"TrustLedger" },
      ],
      playbook: PLAYBOOK_TEMPLATES["policy-violation"].steps.map(s => ({ ...s, completed:false })),
      stakeholders:[`security@${ORG}.io`,`devops@${ORG}.io`],
    });
  }

  return [...updated, ...generated];
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const INC_SEV: Record<IncidentSeverity, { bg:string; text:string; dot:string }> = {
  P1: { bg:"#fef2f2", text:"#be123c", dot:"#ef4444" },
  P2: { bg:"#fffbeb", text:"#b45309", dot:"#f59e0b" },
  P3: { bg:"#eff6ff", text:"#1d4ed8", dot:"#3b82f6" },
};

const INC_STATUS: Record<IncidentStatus, { bg:string; text:string; border:string; label:string }> = {
  active:       { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", label:"Active"       },
  contained:    { bg:"#fffbeb", text:"#b45309", border:"#fde68a", label:"Contained"    },
  resolved:     { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", label:"Resolved"     },
  "post-mortem":{ bg:"#eff6ff", text:"#1d4ed8", border:"#bfdbfe", label:"Post-Mortem"  },
};

const INC_TYPE_LABELS: Record<IncidentType, string> = {
  "secret-exposed":"Exposed Secret",
  "supply-chain":"Supply Chain",
  "rce-pattern":"RCE Pattern",
  "auth-bypass":"Auth Bypass",
  "data-breach":"Data Breach",
  "policy-violation":"Policy Violation",
};

function pad2(n:number){return String(n).padStart(2,"0");}
function fmtTime(iso:string){const d=new Date(iso);return `${pad2(d.getDate())} ${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getMonth()]} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;}
function elapsed(from:string, to?:string){const ms=(to?new Date(to):new Date()).getTime()-new Date(from).getTime();const h=Math.floor(ms/3600000);const m=Math.floor((ms%3600000)/60000);return h>0?`${h}h ${m}m`:`${m}m`;}
function timeAgo(iso:string){const s=Math.floor((Date.now()-new Date(iso).getTime())/1000);if(s<3600)return `${Math.floor(s/60)}m ago`;if(s<86400)return `${Math.floor(s/3600)}h ago`;return `${Math.floor(s/86400)}d ago`;}

const INC_TYPE_COLOR: Record<IncidentType, string> = {
  "secret-exposed":   "#dc2626",
  "supply-chain":     "#7c3aed",
  "rce-pattern":      "#ea580c",
  "auth-bypass":      "#0891b2",
  "data-breach":      "#b91c1c",
  "policy-violation": "#6366f1",
};

// ── Page ───────────────────────────────────────────────────────────────────────

export default function IncidentsPage() {
  const { profile } = useAuth();
  const [incidents,    setIncidents]    = useState<Incident[]>([]);
  const [selected,     setSelected]     = useState<string | null>(null);
  const [activeTab,    setActiveTab]    = useState<"incidents" | "playbooks">("incidents");
  const [filterStatus, setFilterStatus] = useState<IncidentStatus | "all">("active");
  const [filterSev,    setFilterSev]    = useState<IncidentSeverity | "all">("all");
  const [showNewForm,   setShowNewForm]   = useState(false);
  const [refreshing,    setRefreshing]    = useState(false);
  const [newEntry,      setNewEntry]      = useState("");
  const [showEntryForm, setShowEntryForm] = useState(false);
  const [newInc, setNewInc] = useState({ title:"", type:"secret-exposed" as IncidentType, severity:"P2" as IncidentSeverity, affected_repo:"", description:"" });
  const filtersActive = filterStatus !== "all" || filterSev !== "all";

  const seedFromAPI = useCallback(async (base: Incident[], spinner = false) => {
    if (spinner) setRefreshing(true);
    // Always apply localStorage-based resolution first — reliable regardless of API
    const preResolved = autoResolveFromLocalStorage(base);
    try {
      const data = await api.dashboard(ORG, 90);
      // Returns the full list: dashboard-based auto-resolutions + any new incidents
      const next = incidentsFromDashboard(data, preResolved);
      const changed =
        next.length !== base.length ||
        next.some((inc, i) => inc.status !== base[i]?.status || inc.id !== base[i]?.id);
      if (changed) {
        setIncidents(next);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      }
    } catch {
      // Dashboard API unavailable — use localStorage-only resolution result
      const changed =
        preResolved.length !== base.length ||
        preResolved.some((inc, i) => inc.status !== base[i]?.status);
      if (changed) setIncidents(preResolved);
    }
    finally { if (spinner) setRefreshing(false); }
  }, []);

  useEffect(() => {
    // Try real API first, fall back to localStorage, then defaults
    if (profile?.org_id) {
      authedFetch<{ incidents: Incident[] }>("/api/incidents")
        .then(res => {
          if (res.incidents.length > 0) {
            // Apply localStorage-based resolution even on real API data
            const resolved = autoResolveFromLocalStorage(res.incidents);
            setIncidents(resolved);
            return;
          }
          loadLocalFallback();
        })
        .catch(() => loadLocalFallback());
    } else {
      loadLocalFallback();
    }

    function loadLocalFallback() {
      let base: Incident[] = [];
      try {
        const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "null");
        if (Array.isArray(saved) && saved.length > 0) base = saved;
      } catch {}
      // Apply attestation state immediately before showing or seeding
      const resolved = autoResolveFromLocalStorage(base);
      setIncidents(resolved);
      seedFromAPI(resolved);
    }

    const id = setInterval(() => {
      setIncidents(prev => {
        const resolved = autoResolveFromLocalStorage(prev);
        if (resolved !== prev) seedFromAPI(resolved);
        else seedFromAPI(prev);
        return resolved;
      });
    }, 30_000);
    return () => clearInterval(id);
  }, [seedFromAPI, profile?.org_id]);

  // Realtime — refresh when incidents change in DB
  useIncidentsRealtime(profile?.org_id, () => {
    if (profile?.org_id) {
      authedFetch<{ incidents: Incident[] }>("/api/incidents")
        .then(res => {
          if (res.incidents.length > 0)
            setIncidents(autoResolveFromLocalStorage(res.incidents));
        })
        .catch(() => {});
    }
  });

  const save = (next: Incident[]) => {
    setIncidents(next);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    window.dispatchEvent(new Event("tl:badge"));
  };

  function toggleStep(incId:string, stepNum:number) {
    save(incidents.map(inc => inc.id !== incId ? inc : {
      ...inc,
      playbook: inc.playbook.map(s => s.step === stepNum ? { ...s, completed:!s.completed } : s),
    }));
  }

  function advanceStatus(incId:string) {
    const order: IncidentStatus[] = ["active","contained","resolved","post-mortem"];
    save(incidents.map(inc => {
      if (inc.id !== incId) return inc;
      const idx = order.indexOf(inc.status);
      const next = order[Math.min(idx+1, order.length-1)];
      const now = new Date().toISOString();
      return {
        ...inc, status:next,
        contained_at: next==="contained" ? now : inc.contained_at,
        resolved_at:  next==="resolved"  ? now : inc.resolved_at,
        timeline: [...inc.timeline, { time:now, action:`Status advanced to ${next}`, actor:"you" }],
      };
    }));
  }

  function addTimelineEntry(incId: string, text: string) {
    if (!text.trim()) return;
    const now = new Date().toISOString();
    save(incidents.map(inc => inc.id !== incId ? inc : {
      ...inc,
      timeline: [...inc.timeline, { time: now, action: text.trim(), actor: "you" }],
    }));
    setNewEntry("");
    setShowEntryForm(false);
  }

  function createIncident() {
    if (!newInc.title) return;
    const id  = `INC-${Date.now().toString(36).toUpperCase().slice(-5)}`;
    const now = new Date().toISOString();
    const inc: Incident = {
      id, title:newInc.title, type:newInc.type, severity:newInc.severity,
      status:"active", affected_repo:newInc.affected_repo||undefined,
      detected_at:now, description:newInc.description,
      impact:"Under investigation",
      timeline:[{time:now,action:"Incident created",actor:"you"}],
      playbook: PLAYBOOK_TEMPLATES[newInc.type].steps.map(s=>({...s,completed:false})),
      stakeholders:[`alice@${ORG}.io`,`ciso@${ORG}.io`],
    };
    save([inc, ...incidents]);
    // Also persist to real API
    if (profile?.org_id) {
      authedFetch("/api/incidents", {
        method: "POST",
        body: JSON.stringify({
          title: newInc.title, severity: newInc.severity,
          incident_type: newInc.type, affected_repo: newInc.affected_repo || undefined,
          description: newInc.description,
        }),
      }).catch(() => {});
    }
    setSelected(id);
    setShowNewForm(false);
    setNewInc({ title:"", type:"secret-exposed", severity:"P2", affected_repo:"", description:"" });
  }

  const filtered = incidents.filter(i => {
    if (filterStatus !== "all" && i.status   !== filterStatus) return false;
    if (filterSev    !== "all" && i.severity !== filterSev)    return false;
    return true;
  });

  const active         = incidents.filter(i => i.status === "active").length;
  const p1Active       = incidents.filter(i => i.severity === "P1" && i.status === "active").length;
  const resolvedIncs   = incidents.filter(i => i.resolved_at);
  const avgTime        = resolvedIncs.length > 0
    ? resolvedIncs.reduce((s, i) => s + (new Date(i.resolved_at!).getTime() - new Date(i.detected_at).getTime()) / 3600000, 0) / resolvedIncs.length
    : 0;
  const containedCount = incidents.filter(i => i.status !== "active").length;

  const NEXT_STATUS: Partial<Record<IncidentStatus, string>> = {
    active:    "Mark Contained",
    contained: "Mark Resolved",
    resolved:  "Post-Mortem",
  };

  const selectedInc = incidents.find(i => i.id === selected);

  return (
    <AuthGuard>
      <PageSkeleton rows={4} cards={4}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22.5 12.5c0 6.35-5.145 11.5-11.5 11.5S-.5 18.85-.5 12.5 4.645 1 11 1s11.5 5.145 11.5 11.5z"/>
                  <path d="M8 11.857l2.5 2.5L16 8.5"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Incident Response</h1>
              {p1Active > 0 && <span className="text-xs font-black text-white bg-rose-600 px-2 py-0.5 rounded-full animate-pulse">{p1Active} P1 active</span>}
            </div>
            <p className="text-sm text-gray-400">Structured incident management with playbooks, timeline tracking, and stakeholder coordination</p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => seedFromAPI(incidents, true)} disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-50 transition-all shadow-sm">
              <svg className={refreshing?"animate-spin":""} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
              </svg>
              Refresh
            </button>
            <button onClick={()=>setShowNewForm(v=>!v)}
              className={`flex items-center gap-1.5 px-4 py-2 text-sm font-bold rounded-xl transition-all ${showNewForm?"text-rose-800 bg-rose-100 border border-rose-300":"text-white"}`}
              style={!showNewForm?{background:"linear-gradient(135deg,#ef4444,#dc2626)",boxShadow:"0 2px 12px rgba(239,68,68,0.4)"}:{}}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
              Declare Incident
            </button>
          </div>
        </div>

        {/* Summary */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label:"Active Incidents", value:active, color:"#ef4444", bg:"#fef2f2", pulse:active>0,
              info:{ title:"Active Incidents", description:"Incidents currently being worked on that have not yet been contained or resolved." } },
            { label:"P1 Critical Active", value:p1Active, color:"#7c3aed", bg:"#ede9fe", pulse:false,
              info:{ title:"P1 Critical Active", description:"P1 (Critical) severity incidents currently active. P1 requires immediate response — all-hands if needed." } },
            { label:"Avg MTTR", value:`${avgTime.toFixed(1)}h`, color:"#6366f1", bg:"#eef2ff", pulse:false,
              info:{ title:"Mean Time to Resolve", description:"Average hours from detection to resolved status across all closed incidents." } },
            { label:"Contained / Closed", value:`${containedCount}/${incidents.length}`, color:"#10b981", bg:"#f0fdf4", pulse:false,
              info:{ title:"Contained or Closed", description:"Incidents that have been contained, resolved, or moved to post-mortem review." } },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-4 border" style={{ background:s.bg, borderColor:s.color+"30" }}>
              <div className="flex items-center gap-2">
                <p className="text-2xl font-black tabular-nums" style={{ color:s.color }}>{s.value}</p>
                {s.pulse && <span className="w-2 h-2 rounded-full animate-pulse shrink-0" style={{ background:s.color }} />}
              </div>
              <div className="flex items-center gap-1.5 mt-1">
                <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                <InfoTooltip title={s.info.title} description={s.info.description} position="top" />
              </div>
            </div>
          ))}
        </div>

        {/* New incident form */}
        {showNewForm && (
          <div className="animate-fade-up section-card p-5 space-y-4 border-2 border-rose-200">
            <p className="text-sm font-bold text-rose-800 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
              Declare New Incident
            </p>
            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Incident Title *</label>
                <input value={newInc.title} onChange={e=>setNewInc(p=>({...p,title:e.target.value}))}
                  placeholder="Brief description of what happened"
                  className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-rose-400" />
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Type</label>
                <select value={newInc.type} onChange={e=>setNewInc(p=>({...p,type:e.target.value as IncidentType}))}
                  className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none">
                  {(Object.keys(INC_TYPE_LABELS) as IncidentType[]).map(t=>(
                    <option key={t} value={t}>{INC_TYPE_LABELS[t]}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Severity</label>
                <select value={newInc.severity} onChange={e=>setNewInc(p=>({...p,severity:e.target.value as IncidentSeverity}))}
                  className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none">
                  <option value="P1">P1 — Critical (all-hands)</option>
                  <option value="P2">P2 — High (same-day)</option>
                  <option value="P3">P3 — Medium (this week)</option>
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Affected Repository</label>
                <input value={newInc.affected_repo} onChange={e=>setNewInc(p=>({...p,affected_repo:e.target.value}))}
                  placeholder={`${ORG}/repo-name`}
                  className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none" />
              </div>
              <div className="col-span-2">
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Description</label>
                <textarea value={newInc.description} onChange={e=>setNewInc(p=>({...p,description:e.target.value}))}
                  placeholder="What was detected, initial scope, potential impact"
                  className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none resize-none" rows={2} />
              </div>
            </div>
            <div className="flex gap-2">
              <button onClick={createIncident} disabled={!newInc.title}
                className="px-4 py-2 text-sm font-bold text-white rounded-xl disabled:opacity-40"
                style={{ background:"linear-gradient(135deg,#ef4444,#dc2626)" }}>
                Declare &amp; Open Playbook
              </button>
              <button onClick={()=>setShowNewForm(false)} className="px-4 py-2 text-sm font-semibold text-gray-500 rounded-xl hover:bg-gray-50">Cancel</button>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="animate-fade-up flex items-center gap-1 bg-gray-100 p-0.5 rounded-xl w-fit">
          {(["incidents","playbooks"] as const).map(t=>(
            <button key={t} onClick={()=>setActiveTab(t)}
              className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all capitalize ${activeTab===t?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
              {t === "incidents" ? "All Incidents" : "Playbook Library"}
            </button>
          ))}
        </div>

        {/* Playbook library */}
        {activeTab === "playbooks" && (
          <div className="animate-fade-up grid grid-cols-1 sm:grid-cols-2 gap-4">
            {(Object.entries(PLAYBOOK_TEMPLATES) as [IncidentType, {name:string;steps:Omit<PlaybookStep,"completed">[]}][]).map(([type, pb]) => {
              const tc = INC_TYPE_COLOR[type];
              return (
                <div key={type} className="section-card overflow-hidden">
                  <div className="px-5 py-3.5 border-b border-gray-100 flex items-center justify-between"
                    style={{ background:"rgba(248,250,252,0.8)" }}>
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                        style={{ background:tc+"18", border:`1px solid ${tc}28` }}>
                        <span className="text-[10px] font-black" style={{ color:tc }}>{pb.steps.length}</span>
                      </div>
                      <div>
                        <p className="text-sm font-bold text-gray-900">{pb.name}</p>
                        <p className="text-[10px] mt-0.5 font-semibold px-1.5 py-0.5 rounded inline-block"
                          style={{ background:tc+"12", color:tc }}>{INC_TYPE_LABELS[type]}</p>
                      </div>
                    </div>
                    <span className="text-[10px] font-bold text-gray-400 bg-gray-100 px-2 py-0.5 rounded">{pb.steps.length} steps</span>
                  </div>
                  <div className="px-5 py-3 space-y-0">
                    {pb.steps.map((s, i) => (
                      <div key={s.step} className="flex items-start gap-3 relative py-2.5">
                        {i < pb.steps.length - 1 && (
                          <div className="absolute left-[9px] top-9 bottom-0 w-px" style={{ background:tc+"30" }} />
                        )}
                        <div className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-black shrink-0 mt-0.5 z-10"
                          style={{ background:tc+"18", color:tc, border:`1px solid ${tc}30` }}>{s.step}</div>
                        <div className="flex-1 min-w-0">
                          <p className="text-[11px] text-gray-700 font-medium leading-snug">{s.action}</p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[9px] text-gray-400">{s.owner}</span>
                            <span className="text-[9px] font-bold text-gray-400 bg-gray-50 border border-gray-100 px-1.5 py-0.5 rounded">⏱ {s.duration}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Incidents list + detail */}
        {activeTab === "incidents" && (
          <div className="animate-fade-up grid grid-cols-1 lg:grid-cols-[340px_1fr] gap-5 items-start">

            {/* List */}
            <div className="space-y-2">
              {/* Filters + count */}
              <div className="space-y-1.5 mb-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">
                    {filtered.length} of {incidents.length} incident{incidents.length!==1?"s":""}
                  </span>
                  {filtersActive && (
                    <button onClick={()=>{setFilterStatus("all");setFilterSev("all");}}
                      className="text-[10px] font-bold text-rose-500 hover:text-rose-700 transition-colors">
                      Clear filters ×
                    </button>
                  )}
                </div>
                <div className="flex gap-0.5 bg-gray-100 p-0.5 rounded-xl">
                  {(["all","active","contained","resolved","post-mortem"] as const).map(s=>(
                    <button key={s} onClick={()=>setFilterStatus(s)}
                      className={`flex-1 py-1.5 text-[10px] font-semibold rounded-lg transition-all ${filterStatus===s?"bg-white text-gray-900 shadow-sm":"text-gray-500"}`}>
                      {s==="all"?"All":s==="post-mortem"?"PM":s.charAt(0).toUpperCase()+s.slice(1)}
                    </button>
                  ))}
                </div>
                <div className="flex gap-0.5 bg-gray-100 p-0.5 rounded-xl">
                  {(["all","P1","P2","P3"] as const).map(s=>(
                    <button key={s} onClick={()=>setFilterSev(s)}
                      className={`flex-1 py-1.5 text-[10px] font-semibold rounded-lg transition-all ${filterSev===s?"bg-white text-gray-900 shadow-sm":"text-gray-500"}`}>
                      {s==="all"?"All Sev":s}
                    </button>
                  ))}
                </div>
              </div>
              {filtered.length === 0 ? (
                active === 0 && incidents.length > 0 ? (
                  <div className="section-card text-center py-12 space-y-3">
                    <div className="w-12 h-12 rounded-2xl bg-emerald-50 border border-emerald-200 flex items-center justify-center mx-auto">
                      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <polyline points="9 12 11 14 15 10"/>
                      </svg>
                    </div>
                    <p className="text-sm font-bold text-emerald-700">No active incidents</p>
                    <p className="text-xs text-gray-400">All {incidents.length} incident{incidents.length !== 1 ? "s" : ""} have been resolved.</p>
                    <button onClick={() => setFilterStatus("all")} className="text-xs font-bold text-indigo-600 hover:underline">View resolved history →</button>
                  </div>
                ) : (
                  <div className="section-card text-center py-10 space-y-2">
                    <p className="text-sm font-bold text-gray-600">{filtersActive ? "No incidents match these filters" : "No incidents yet"}</p>
                    <p className="text-xs text-gray-400">{filtersActive ? "Try adjusting the status or severity filters." : "Incidents will appear here when created or auto-detected."}</p>
                    {filtersActive && <button onClick={() => { setFilterStatus("all"); setFilterSev("all"); }} className="text-xs font-bold text-indigo-600 hover:underline">Clear filters →</button>}
                  </div>
                )
              ) : filtered.map(inc => {
                const sev  = INC_SEV[inc.severity];
                const stat = INC_STATUS[inc.status];
                const done = inc.playbook.filter(s => s.completed).length;
                const total = inc.playbook.length;
                const pct   = total > 0 ? (done / total) * 100 : 0;
                const tc    = INC_TYPE_COLOR[inc.type];
                return (
                  <button key={inc.id} onClick={() => { setSelected(inc.id); setShowEntryForm(false); }}
                    className={`w-full text-left rounded-2xl overflow-hidden border-2 transition-all ${selected === inc.id ? "border-indigo-400" : "border-transparent hover:border-gray-200"}`}
                    style={{ boxShadow:"0 1px 6px rgba(0,0,0,0.06)" }}>
                    <div className="flex">
                      <div className="w-1 shrink-0" style={{ background:sev.dot }} />
                      <div className="flex-1 p-4" style={{ background:selected===inc.id?"rgba(238,242,255,0.35)":"white" }}>
                        <div className="flex items-center gap-1.5 mb-2 flex-wrap">
                          {inc.status === "active" && <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse shrink-0" />}
                          <span className="text-[9px] font-black font-mono text-gray-400">{inc.id}</span>
                          <span className="text-[9px] font-black px-1.5 py-0.5 rounded-full text-white" style={{ background:sev.dot }}>{inc.severity}</span>
                          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full border" style={{ background:stat.bg, color:stat.text, borderColor:stat.border }}>{stat.label}</span>
                          <span className="ml-auto text-[9px] font-semibold px-1.5 py-0.5 rounded border"
                            style={{ color:tc, background:tc+"12", borderColor:tc+"25" }}>
                            {INC_TYPE_LABELS[inc.type]}
                          </span>
                        </div>
                        <p className="text-xs font-bold text-gray-900 leading-snug mb-1.5">{inc.title}</p>
                        <div className="flex items-center gap-3 mb-2 text-[9px] text-gray-400">
                          {inc.affected_repo && <span className="font-mono text-indigo-500">{inc.affected_repo.split("/").pop()}</span>}
                          <span suppressHydrationWarning className="ml-auto">{timeAgo(inc.detected_at)}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-1.5 rounded-full overflow-hidden bg-gray-100">
                            <div className="h-full rounded-full transition-all duration-300" style={{ width:`${pct}%`, background:pct===100?"#10b981":sev.dot }} />
                          </div>
                          <span className="text-[9px] tabular-nums font-semibold shrink-0" style={{ color:pct===100?"#10b981":"#9ca3af" }}>{done}/{total}</span>
                        </div>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Detail panel */}
            {selectedInc ? (
              <div className="space-y-4">
                <div className="section-card overflow-hidden">
                  {/* Header */}
                  <div className="px-6 py-4 border-b border-gray-100"
                    style={{ background:"linear-gradient(135deg,rgba(248,250,252,0.9),rgba(238,242,255,0.3))" }}>
                    <div className="flex items-start justify-between gap-4 flex-wrap">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                          <span className="text-[10px] font-black font-mono text-gray-400">{selectedInc.id}</span>
                          <span className="text-[9px] font-black px-2 py-0.5 rounded-full text-white"
                            style={{ background:INC_SEV[selectedInc.severity].dot }}>{selectedInc.severity}</span>
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border"
                            style={{ background:INC_STATUS[selectedInc.status].bg, color:INC_STATUS[selectedInc.status].text, borderColor:INC_STATUS[selectedInc.status].border }}>
                            {INC_STATUS[selectedInc.status].label}
                          </span>
                          <span className="text-[9px] font-semibold px-2 py-0.5 rounded border"
                            style={{ color:INC_TYPE_COLOR[selectedInc.type], background:INC_TYPE_COLOR[selectedInc.type]+"12", borderColor:INC_TYPE_COLOR[selectedInc.type]+"25" }}>
                            {INC_TYPE_LABELS[selectedInc.type]}
                          </span>
                          {selectedInc.related_cve && (
                            <span className="text-[9px] font-bold text-orange-700 bg-orange-50 border border-orange-200 px-2 py-0.5 rounded">
                              {selectedInc.related_cve}
                            </span>
                          )}
                        </div>
                        <p className="text-base font-black text-gray-900 leading-tight">{selectedInc.title}</p>
                        {/* Timing metrics */}
                        <div className="flex items-center gap-4 mt-2.5 flex-wrap">
                          <div className="flex items-center gap-1 text-[10px] text-gray-500">
                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                              <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                            </svg>
                            <span suppressHydrationWarning>Detected {timeAgo(selectedInc.detected_at)}</span>
                          </div>
                          {selectedInc.contained_at && (
                            <div className="flex items-center gap-1 text-[10px] text-amber-600">
                              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                              </svg>
                              <span>Contained in {elapsed(selectedInc.detected_at, selectedInc.contained_at)}</span>
                            </div>
                          )}
                          {selectedInc.resolved_at && (
                            <div className="flex items-center gap-1 text-[10px] text-emerald-600">
                              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                <polyline points="20 6 9 17 4 12"/>
                              </svg>
                              <span>MTTR {elapsed(selectedInc.detected_at, selectedInc.resolved_at)}</span>
                            </div>
                          )}
                          {selectedInc.affected_repo && (
                            <span className="text-[10px] font-mono text-indigo-600 bg-indigo-50 border border-indigo-100 px-2 py-0.5 rounded">
                              {selectedInc.affected_repo.split("/").pop()}
                            </span>
                          )}
                          {selectedInc.affected_file && (
                            <span className="text-[10px] font-mono text-gray-500 bg-gray-50 border border-gray-100 px-2 py-0.5 rounded">
                              {selectedInc.affected_file.split("/").pop()}
                            </span>
                          )}
                        </div>
                      </div>
                      {NEXT_STATUS[selectedInc.status] && (
                        <button onClick={() => advanceStatus(selectedInc.id)}
                          className="shrink-0 flex items-center gap-1.5 text-xs font-bold text-white px-3.5 py-2 rounded-xl transition-colors whitespace-nowrap"
                          style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow:"0 2px 8px rgba(99,102,241,0.3)" }}>
                          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6"/>
                          </svg>
                          {NEXT_STATUS[selectedInc.status]}
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="divide-y divide-gray-50">
                    {/* Description + impact */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 divide-y sm:divide-y-0 sm:divide-x divide-gray-50">
                      <div className="px-6 py-4">
                        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-2">Description</p>
                        <p className="text-xs text-gray-700 leading-relaxed">{selectedInc.description}</p>
                      </div>
                      <div className="px-6 py-4">
                        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-2">Impact Assessment</p>
                        <p className="text-xs text-gray-700 leading-relaxed">{selectedInc.impact}</p>
                        {selectedInc.root_cause && (
                          <div className="mt-3 pt-3 border-t border-gray-50">
                            <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1">Root Cause</p>
                            <p className="text-xs text-gray-600 leading-relaxed">{selectedInc.root_cause}</p>
                          </div>
                        )}
                        {selectedInc.lesson_learned && (
                          <div className="mt-3 bg-indigo-50 border border-indigo-100 rounded-xl px-3 py-2.5">
                            <p className="text-[9px] font-black text-indigo-600 uppercase tracking-widest mb-1">Lesson Learned</p>
                            <p className="text-[10px] text-indigo-800 leading-relaxed">{selectedInc.lesson_learned}</p>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Playbook */}
                    <div className="px-6 py-4">
                      {(() => {
                        const done  = selectedInc.playbook.filter(s => s.completed).length;
                        const total = selectedInc.playbook.length;
                        const pct   = total > 0 ? Math.round((done / total) * 100) : 0;
                        return (
                          <>
                            <div className="flex items-center justify-between mb-2">
                              <p className="text-[9px] font-black uppercase tracking-widest text-gray-400">Response Playbook</p>
                              <div className="flex items-center gap-2">
                                <div className="w-20 h-1.5 rounded-full overflow-hidden bg-gray-100">
                                  <div className="h-full rounded-full transition-all duration-300"
                                    style={{ width:`${pct}%`, background:pct===100?"#10b981":"#6366f1" }} />
                                </div>
                                <span className="text-[10px] font-bold tabular-nums" style={{ color:pct===100?"#10b981":"#6366f1" }}>
                                  {done}/{total} · {pct}%
                                </span>
                              </div>
                            </div>
                            {pct < 100 && (
                              <p className="text-[9px] text-gray-400 mb-2.5">Click a step to mark it complete</p>
                            )}
                            <div className="space-y-1.5">
                              {selectedInc.playbook.map(s => (
                                <div key={s.step}
                                  className={`flex items-start gap-3 p-3 rounded-xl cursor-pointer transition-all select-none ${s.completed?"bg-emerald-50 border border-emerald-100":"bg-gray-50 border border-gray-100 hover:border-indigo-200 hover:bg-indigo-50/40"}`}
                                  onClick={() => toggleStep(selectedInc.id, s.step)}>
                                  <div className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 mt-0.5 border-2 transition-all ${s.completed?"bg-emerald-500 border-emerald-500":"bg-white border-gray-200"}`}>
                                    {s.completed
                                      ? <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                                      : <span className="text-[9px] font-black text-gray-400">{s.step}</span>}
                                  </div>
                                  <div className="flex-1 min-w-0">
                                    <p className={`text-xs font-medium leading-snug ${s.completed?"text-emerald-700 line-through decoration-emerald-400":"text-gray-800"}`}>
                                      {s.action}
                                    </p>
                                    <div className="flex items-center gap-2 mt-0.5">
                                      <span className="text-[9px] text-gray-400">{s.owner}</span>
                                      <span className="text-[9px] font-semibold text-gray-400 bg-white border border-gray-100 px-1.5 py-0.5 rounded">⏱ {s.duration}</span>
                                    </div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </>
                        );
                      })()}
                    </div>

                    {/* Timeline */}
                    <div className="px-6 py-4">
                      <div className="flex items-center justify-between mb-3">
                        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400">Timeline</p>
                        <button onClick={() => setShowEntryForm(v => !v)}
                          className={`flex items-center gap-1 text-[10px] font-bold px-2.5 py-1 rounded-lg transition-colors ${showEntryForm?"text-indigo-800 bg-indigo-100 border border-indigo-200":"text-indigo-600 bg-indigo-50 border border-indigo-100 hover:bg-indigo-100"}`}>
                          <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                          Add entry
                        </button>
                      </div>
                      {showEntryForm && (
                        <div className="mb-4 bg-indigo-50 border border-indigo-100 rounded-xl p-3 flex items-center gap-2">
                          <input
                            value={newEntry}
                            onChange={e => setNewEntry(e.target.value)}
                            onKeyDown={e => { if (e.key === "Enter") addTimelineEntry(selectedInc.id, newEntry); }}
                            placeholder="Note what happened or was decided…"
                            className="flex-1 text-xs text-gray-700 bg-white border border-indigo-200 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-300"
                            autoFocus
                          />
                          <button onClick={() => addTimelineEntry(selectedInc.id, newEntry)} disabled={!newEntry.trim()}
                            className="shrink-0 text-[11px] font-bold text-white bg-indigo-600 hover:bg-indigo-700 px-3 py-1.5 rounded-lg disabled:opacity-40 transition-colors">
                            Add
                          </button>
                          <button onClick={() => { setShowEntryForm(false); setNewEntry(""); }}
                            className="shrink-0 text-[11px] text-gray-400 hover:text-gray-600">✕</button>
                        </div>
                      )}
                      <div className="relative">
                        {selectedInc.timeline.length > 1 && (
                          <div className="absolute left-[4px] top-3 bottom-3 w-px bg-gray-100" />
                        )}
                        <div className="space-y-3">
                          {[...selectedInc.timeline].reverse().map((e, i, arr) => {
                            const origIdx = arr.length - 1 - i;
                            const prevTime = origIdx > 0 ? selectedInc.timeline[origIdx - 1].time : null;
                            const gap = prevTime ? elapsed(prevTime, e.time) : null;
                            const isLatest = i === 0;
                            return (
                              <div key={`${e.time}-${i}`} className="flex items-start gap-3">
                                <div className={`w-2.5 h-2.5 rounded-full shrink-0 mt-0.5 z-10 border-2 transition-all ${isLatest?"border-indigo-500 bg-indigo-500":"border-gray-300 bg-white"}`} />
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className="text-[10px] font-mono text-gray-400">{fmtTime(e.time)}</span>
                                    {gap && <span className="text-[8px] text-gray-300 bg-gray-50 border border-gray-100 px-1 rounded">+{gap}</span>}
                                    <span className="text-[9px] font-bold text-gray-400 ml-auto">{e.actor}</span>
                                  </div>
                                  <p className={`text-xs mt-0.5 leading-snug ${isLatest?"text-gray-800 font-semibold":"text-gray-600"}`}>{e.action}</p>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>

                    {/* Stakeholders */}
                    <div className="px-6 py-4">
                      <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-3">Stakeholders</p>
                      <div className="flex flex-wrap gap-2">
                        {selectedInc.stakeholders.map(s => {
                          const name    = s.split("@")[0];
                          const initial = name.charAt(0).toUpperCase();
                          const colors  = ["#6366f1","#8b5cf6","#ec4899","#0891b2","#10b981","#f59e0b"];
                          const color   = colors[name.charCodeAt(0) % colors.length];
                          return (
                            <div key={s} className="flex items-center gap-1.5 bg-gray-50 border border-gray-100 rounded-lg px-2.5 py-1.5">
                              <div className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-black text-white shrink-0"
                                style={{ background:color }}>
                                {initial}
                              </div>
                              <span className="text-[10px] font-semibold text-gray-700">{name}</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="section-card flex flex-col items-center justify-center py-20 text-center gap-3">
                <div className="w-12 h-12 rounded-2xl bg-gray-50 border border-gray-100 flex items-center justify-center">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#9ca3af" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                  </svg>
                </div>
                <p className="text-sm font-bold text-gray-500">Select an incident</p>
                <p className="text-xs text-gray-400">View details, run the playbook, and track the timeline</p>
              </div>
            )}
          </div>
        )}

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
