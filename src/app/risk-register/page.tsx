"use client";

import { useState, useMemo, useEffect, useCallback } from "react";
import InfoTooltip from "@/components/InfoTooltip";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { api } from "@/lib/api";
import { readSeed } from "@/lib/offlineData";
import type { DashboardData, ScanResult } from "@/types";
import { patchDataWithAttestations } from "@/lib/trustScore";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Types ──────────────────────────────────────────────────────────────────────

type RiskStatus    = "open" | "mitigating" | "accepted" | "closed";
type RiskCategory  = "ai-code" | "supply-chain" | "secrets" | "compliance" | "access" | "infrastructure";
type TreatmentType = "mitigate" | "accept" | "transfer" | "avoid";

interface RiskItem {
  id: string;
  title: string;
  description: string;
  category: RiskCategory;
  likelihood: 1|2|3|4|5;
  impact:     1|2|3|4|5;
  residual_likelihood?: 1|2|3|4|5;
  residual_impact?:     1|2|3|4|5;
  status: RiskStatus;
  treatment: TreatmentType;
  owner: string;
  due_date?: string;
  mitigation: string;
  related_cve?: string;
  related_link?: string;
  identified_at: string;
  auto_derived: boolean;     // derived from scan data vs manually entered
  notes: string[];
}

// ── Persistence ────────────────────────────────────────────────────────────────

const RISK_KEY = "tl_risk_register";

interface PersistedRisk {
  status?:       RiskStatus;
  treatment?:    TreatmentType;
  owner?:        string;
  due_date?:     string;
  mitigation?:   string;
  residual_likelihood?: 1|2|3|4|5;
  residual_impact?:     1|2|3|4|5;
  notes?:        string[];
  closed_at?:    string;
}

interface ManualRisk extends RiskItem { _manual: true }

interface PersistStore {
  overrides: Record<string, PersistedRisk>;
  manuals:   ManualRisk[];
}

function loadStore(): PersistStore {
  try {
    const raw = JSON.parse(localStorage.getItem(RISK_KEY) ?? "null");
    if (!raw) return { overrides:{}, manuals:[] };
    // dev-seed writes a plain array — treat it as the manuals list
    if (Array.isArray(raw)) return { overrides:{}, manuals: raw as ManualRisk[] };
    return { overrides: raw.overrides ?? {}, manuals: Array.isArray(raw.manuals) ? raw.manuals : [] };
  } catch { return { overrides:{}, manuals:[] }; }
}
function saveStore(s: PersistStore) { localStorage.setItem(RISK_KEY, JSON.stringify(s)); }

// ── Derive risks from scan data ────────────────────────────────────────────────

function deriveRisks(data: DashboardData, scans: ScanResult[]): RiskItem[] {
  const now  = new Date().toISOString().split("T")[0];
  const risks: RiskItem[] = [];

  // From top_risk_files
  const critUnatt = data.top_risk_files.filter(f => f.risk_score === "CRITICAL" && !f.attested);
  const highUnatt = data.top_risk_files.filter(f => f.risk_score === "HIGH"     && !f.attested);

  if (critUnatt.length > 0) {
    risks.push({
      id:"DR-CRIT-UNATT", auto_derived:true, status:"open", treatment:"mitigate",
      category:"ai-code", likelihood:5, impact:5,
      title:`${critUnatt.length} CRITICAL file${critUnatt.length>1?"s":""} unattested — merge blocked`,
      description:`${critUnatt.map(f=>f.file_path.split("/").pop()).join(", ")} flagged CRITICAL (avg ${(critUnatt.reduce((s,f)=>s+f.ai_pct,0)/critUnatt.length*100).toFixed(0)}% AI). Policy gate is blocking deploys.`,
      owner:`alice@${ORG}.io`, due_date:new Date(Date.now()+86400000).toISOString().split("T")[0],
      mitigation:"Assign reviewer to each CRITICAL file. Attest via /pr/{scan_id} before merge deadline.",
      identified_at:now, notes:[],
    });
  }

  if (highUnatt.length > 0) {
    risks.push({
      id:"DR-HIGH-UNATT", auto_derived:true, status:"open", treatment:"mitigate",
      category:"ai-code", likelihood:4, impact:4,
      title:`${highUnatt.length} HIGH-risk file${highUnatt.length>1?"s":""} awaiting attestation`,
      description:`${highUnatt.map(f=>f.file_path.split("/").pop()).join(", ")} flagged HIGH. 48h SLA window applies.`,
      owner:`carol@${ORG}.io`, due_date:new Date(Date.now()+2*86400000).toISOString().split("T")[0],
      mitigation:"Schedule security review. Attest via the PR detail page within SLA window.",
      identified_at:now, notes:[],
    });
  }

  // Hardcoded secrets from risk_indicators
  const secretFiles = scans.flatMap(s => s.files.filter(f => f.risk_indicators.includes("hardcoded-secret")));
  if (secretFiles.length > 0) {
    risks.push({
      id:"DR-SECRETS", auto_derived:true, status:"open", treatment:"mitigate",
      category:"secrets", likelihood:5, impact:5,
      residual_likelihood:2, residual_impact:3,
      title:`${secretFiles.length} hardcoded credential${secretFiles.length>1?"s":""} detected`,
      description:`${secretFiles.map(f=>f.file_path.split("/").pop()).join(", ")} contain API keys, passwords, or tokens in source. Treat as compromised.`,
      owner:`alice@${ORG}.io`, due_date:new Date(Date.now()+86400000).toISOString().split("T")[0],
      mitigation:"Rotate all exposed credentials immediately. Move to AWS Secrets Manager or HashiCorp Vault. Add gitleaks pre-commit hook.",
      related_cve:"CVE-2021-42013", related_link:"/secrets",
      identified_at:now, notes:[],
    });
  }

  // Eval/exec
  const evalFiles = scans.flatMap(s => s.files.filter(f => f.risk_indicators.includes("eval-exec")));
  if (evalFiles.length > 0) {
    risks.push({
      id:"DR-EVAL-EXEC", auto_derived:true, status:"mitigating", treatment:"mitigate",
      category:"ai-code", likelihood:4, impact:5,
      residual_likelihood:2, residual_impact:4,
      title:`eval()/exec() RCE pattern in ${evalFiles.length} file${evalFiles.length>1?"s":""}`,
      description:`${evalFiles.map(f=>f.file_path.split("/").pop()).join(", ")} use eval/exec on potentially user-controlled input. Full server compromise if exploited.`,
      owner:`carol@${ORG}.io`, due_date:new Date(Date.now()+3*86400000).toISOString().split("T")[0],
      mitigation:"Replace eval/exec with safe alternatives: ast.literal_eval for Python, mathjs sandbox for JS expressions.",
      related_cve:"CVE-2021-44228", related_link:"/vulnerabilities",
      identified_at:now, notes:[],
    });
  }

  // SQL injection
  const sqlFiles = scans.flatMap(s => s.files.filter(f => f.risk_indicators.includes("sql-injection")));
  if (sqlFiles.length > 0) {
    risks.push({
      id:"DR-SQL-INJECT", auto_derived:true, status:"open", treatment:"mitigate",
      category:"ai-code", likelihood:5, impact:5,
      residual_likelihood:1, residual_impact:2,
      title:`SQL Injection pattern in ${sqlFiles.length} file${sqlFiles.length>1?"s":""}`,
      description:`${sqlFiles.map(f=>f.file_path.split("/").pop()).join(", ")} use f-string or string concatenation in SQL queries, bypassing parameterisation.`,
      owner:`alice@${ORG}.io`, due_date:new Date(Date.now()+5*86400000).toISOString().split("T")[0],
      mitigation:"Replace all dynamic SQL with SQLAlchemy ORM or parameterised queries. Add Semgrep rule to CI.",
      related_cve:"CVE-2023-20052", related_link:"/vulnerabilities",
      identified_at:now, notes:[],
    });
  }

  // JWT bypass
  const jwtFiles = scans.flatMap(s => s.files.filter(f => f.risk_indicators.includes("jwt-none-alg")));
  if (jwtFiles.length > 0) {
    risks.push({
      id:"DR-JWT-BYPASS", auto_derived:true, status:"mitigating", treatment:"mitigate",
      category:"ai-code", likelihood:4, impact:5,
      residual_likelihood:1, residual_impact:3,
      title:`JWT 'none' algorithm bypass in ${jwtFiles.length} file${jwtFiles.length>1?"s":""}`,
      description:`${jwtFiles.map(f=>f.file_path.split("/").pop()).join(", ")} accept the insecure 'none' JWT algorithm, enabling token forgery.`,
      owner:`carol@${ORG}.io`, due_date:new Date(Date.now()+2*86400000).toISOString().split("T")[0],
      mitigation:"Upgrade PyJWT to >= 2.8.0. Whitelist only HS256. Add CI lint rule.",
      related_cve:"CVE-2022-21449", related_link:"/vulnerabilities",
      identified_at:now, notes:[],
    });
  }

  // Deploy blocked
  if (data.unattested_deploy_count > 0) {
    risks.push({
      id:"DR-DEPLOY-BLOCK", auto_derived:true, status:"open", treatment:"mitigate",
      category:"compliance", likelihood:4, impact:4,
      title:`${data.unattested_deploy_count} deploy${data.unattested_deploy_count>1?"s":""} blocked — SLA exposure`,
      description:`${data.unattested_deploy_count} deployment${data.unattested_deploy_count>1?"s":""} currently blocked by policy gate. Prolonged blockage risks SLA breach and SOC 2 CC8.1 findings.`,
      owner:`alice@${ORG}.io`, due_date:new Date(Date.now()+86400000).toISOString().split("T")[0],
      mitigation:"Prioritise attestation of blocking files. Consider SLA escalation process for high-priority releases.",
      related_link:"/violations",
      identified_at:now, notes:[],
    });
  }

  // Low attestation repos
  data.repos.filter(r => r.attestation_rate < 0.6).forEach(r => {
    risks.push({
      id:`DR-LOW-ATT-${r.repo.replace("/","-")}`, auto_derived:true, status:"open", treatment:"mitigate",
      category:"compliance", likelihood:3, impact:4,
      title:`Low attestation — ${r.repo.split("/").pop()} at ${Math.round(r.attestation_rate*100)}%`,
      description:`${r.repo.split("/").pop()} attestation coverage (${Math.round(r.attestation_rate*100)}%) is below the 60% compliance threshold. Audit risk for SOC 2 CC8.1.`,
      owner:`david@${ORG}.io`, due_date:new Date(Date.now()+7*86400000).toISOString().split("T")[0],
      mitigation:"Assign dedicated security reviewer. Batch-attest LOW and MEDIUM files. Target ≥80% before audit.",
      related_link:"/violations",
      identified_at:now, notes:[],
    });
  });

  return risks;
}

// ── Offline fallback ───────────────────────────────────────────────────────────

const OFFLINE_RISKS: RiskItem[] = [
  { id:"RR-001", auto_derived:false, status:"open", treatment:"mitigate", likelihood:5, impact:5, category:"ai-code", owner:`alice@${ORG}.io`, due_date:"2026-06-10", mitigation:"Replace all dynamic SQL with SQLAlchemy ORM. Enforce pre-commit hook.", related_cve:"CVE-2023-20052", related_link:"/vulnerabilities", identified_at:"2026-05-24", notes:[], title:"SQL Injection via AI-generated query construction", description:"AI assistants consistently produce SQL queries using f-string interpolation. Three instances in payments-api.", residual_likelihood:1, residual_impact:2 },
  { id:"RR-002", auto_derived:false, status:"open", treatment:"mitigate", likelihood:5, impact:5, category:"secrets", owner:`alice@${ORG}.io`, due_date:"2026-05-28", mitigation:"Rotate credentials. Migrate to AWS Secrets Manager. Add gitleaks hook.", related_cve:"CVE-2021-42013", related_link:"/secrets", identified_at:"2026-05-26", notes:[], title:"Hardcoded production credentials in AI-generated code", description:"Stripe API key, JWT secret, and DB password found in source files. Treat as compromised.", residual_likelihood:2, residual_impact:3 },
  { id:"RR-003", auto_derived:false, status:"open", treatment:"mitigate", likelihood:4, impact:5, category:"supply-chain", owner:`bob@${ORG}.io`, due_date:"2026-06-05", mitigation:"Remove import. Add approved package allowlist to CI. Enable Snyk.", identified_at:"2026-05-26", notes:[], title:"Hallucinated package 'ml-utils-fast' — supply chain risk", description:"AI generated an import for a non-existent PyPI package. Attacker could publish malicious code with that name.", related_link:"/dependencies" },
  { id:"RR-004", auto_derived:false, status:"mitigating", treatment:"mitigate", likelihood:4, impact:4, category:"ai-code", owner:`carol@${ORG}.io`, due_date:"2026-06-01", mitigation:"Whitelist only HS256. PR #341 attested. Static analysis rule added to CI.", related_cve:"CVE-2022-21449", related_link:"/vulnerabilities", identified_at:"2026-05-25", notes:["PR #341 attested — token_exchange.ts now safe"], title:"JWT 'none' algorithm bypass in auth-service", description:"AI-generated token_exchange.ts accepts algorithms=['HS256','none'], enabling token forgery.", residual_likelihood:1, residual_impact:3 },
  { id:"RR-005", auto_derived:false, status:"mitigating", treatment:"mitigate", likelihood:4, impact:4, category:"ai-code", owner:`carol@${ORG}.io`, due_date:"2026-06-03", mitigation:"Replace eval with mathjs sandbox. Code review on PR #219.", related_cve:"CVE-2021-44228", related_link:"/vulnerabilities", identified_at:"2026-05-26", notes:[], title:"Arbitrary code execution via eval() in fraud-detection", description:"risk_scorer.ts uses eval() on user-controlled formula strings. Full RCE if exploited.", residual_likelihood:2, residual_impact:4 },
  { id:"RR-006", auto_derived:false, status:"open", treatment:"mitigate", likelihood:3, impact:5, category:"compliance", owner:`alice@${ORG}.io`, due_date:"2026-05-27", mitigation:"Escalate to security lead. Implement SLA enforcement process.", related_link:"/violations", identified_at:"2026-05-24", notes:[], title:"Attestation SLA breaches — HIGH-risk files unreviewed > 48h", description:"stripe_client.py and etl_runner.py exceeded the 48h SLA. Risk SOC 2 CC8.1 control failure." },
  { id:"RR-007", auto_derived:false, status:"open", treatment:"mitigate", likelihood:3, impact:4, category:"supply-chain", owner:`bob@${ORG}.io`, due_date:"2026-06-15", mitigation:"Upgrade to requests>=2.31.0. Add pip-audit to CI.", related_cve:"CVE-2023-32681", related_link:"/dependencies", identified_at:"2026-05-23", notes:[], title:"Vulnerable dependency — requests 2.18.0 (CVE-2023-32681)", description:"AI pinned outdated requests library with open redirect vulnerability." },
  { id:"RR-008", auto_derived:false, status:"accepted", treatment:"accept", likelihood:2, impact:3, category:"ai-code", owner:`david@${ORG}.io`, mitigation:"Accepted with quarterly review. Monitor AI% via dashboard.", identified_at:"2026-05-22", notes:["Formally accepted by CISO 2026-05-22 — low exploitability"], title:"High AI content ratio in data-platform (62%)", description:"data-platform AI content exceeds the 60% warning threshold. Not directly exploitable but indicates insufficient human review." },
  { id:"RR-009", auto_derived:false, status:"closed", treatment:"mitigate", likelihood:2, impact:4, category:"secrets", owner:`alice@${ORG}.io`, mitigation:"Key rotated within 2h. git-filter-repo used to purge history. Monitoring active.", related_link:"/audit", identified_at:"2026-05-24", notes:["Resolved — key rotated and history purged 2026-05-24"], title:"SendGrid API key committed to auth-service branch", description:"SG.Gm9k* key was committed in PR #338. Key rotated and removed from history." },
];

// ── Helpers ────────────────────────────────────────────────────────────────────

function toNum(v: unknown): number {
  if (typeof v === "number") return Math.min(5, Math.max(1, v));
  const map: Record<string,number> = { LOW:1, MEDIUM:3, HIGH:4, CRITICAL:5 };
  return map[String(v).toUpperCase()] ?? 3;
}
function riskScore(r: RiskItem) { return toNum(r.likelihood) * toNum(r.impact); }
function residualScore(r: RiskItem) {
  if (r.residual_likelihood && r.residual_impact) return r.residual_likelihood * r.residual_impact;
  return null;
}

function riskLevel(score: number): { label:string; bg:string; text:string; border:string } {
  if (score >= 20) return { label:"CRITICAL", bg:"#ede9fe", text:"#5b21b6", border:"#c4b5fd" };
  if (score >= 12) return { label:"HIGH",     bg:"#ffedd5", text:"#7c2d12", border:"#fed7aa" };
  if (score >=  6) return { label:"MEDIUM",   bg:"#fef3c7", text:"#78350f", border:"#fde68a" };
  return               { label:"LOW",      bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0" };
}

const STATUS_STYLE: Record<RiskStatus, { bg:string; text:string; border:string; label:string }> = {
  open:       { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", label:"Open"       },
  mitigating: { bg:"#fffbeb", text:"#b45309", border:"#fde68a", label:"Mitigating" },
  accepted:   { bg:"#f0f9ff", text:"#0369a1", border:"#bae6fd", label:"Accepted"   },
  closed:     { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", label:"Closed"     },
};

const TREATMENT_STYLE: Record<TreatmentType, { label:string; color:string }> = {
  mitigate: { label:"Mitigate", color:"#6366f1" },
  accept:   { label:"Accept",   color:"#0369a1" },
  transfer: { label:"Transfer", color:"#b45309" },
  avoid:    { label:"Avoid",    color:"#be123c" },
};

const CAT_LABELS: Record<RiskCategory, string> = {
  "ai-code":"AI Code", "supply-chain":"Supply Chain", "secrets":"Credentials",
  "compliance":"Compliance", "access":"Access Control", "infrastructure":"Infrastructure",
};

const OWNERS = [`alice@${ORG}.io`,`bob@${ORG}.io`,`carol@${ORG}.io`,`david@${ORG}.io`,`eve@${ORG}.io`];

function fmtDate(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return `${d.getDate()} ${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getMonth()]} ${d.getFullYear()}`;
}
function daysLeft(iso?: string) {
  if (!iso) return null;
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
}

// ── Interactive Heat Map ───────────────────────────────────────────────────────

function HeatMap({ risks, onFilter }: { risks: RiskItem[]; onFilter: (l:number,i:number)=>void }) {
  const cell = (l: number, i: number) => {
    const score   = l * i;
    const inCell  = risks.filter(r => r.likelihood===l && r.impact===i && r.status!=="closed");
    const { bg, text } = riskLevel(score);
    return (
      <button key={`${l}-${i}`}
        className="flex items-center justify-center rounded-lg text-[11px] font-black aspect-square transition-all hover:scale-105 hover:ring-2 hover:ring-offset-1 hover:ring-gray-400 active:scale-95"
        style={{ background:inCell.length?bg:"#f1f5f9", color:inCell.length?text:"#94a3b8" }}
        onClick={() => inCell.length && onFilter(l,i)}
        title={inCell.length ? `${inCell.length} risk${inCell.length>1?"s":""} — click to filter` : "No risks"}>
        {inCell.length > 0 ? inCell.length : ""}
      </button>
    );
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1">
        <div className="flex flex-col items-center justify-between h-full shrink-0">
          {[5,4,3,2,1].map(l => (
            <span key={l} className="text-[8px] text-gray-400 font-bold w-4 text-right leading-none py-1">{l}</span>
          ))}
        </div>
        <div className="flex-1 space-y-1">
          <div className="grid grid-cols-5 gap-1">
            {[5,4,3,2,1].flatMap(l => [1,2,3,4,5].map(i => cell(l, i)))}
          </div>
          <div className="grid grid-cols-5 gap-1 mt-1">
            {[1,2,3,4,5].map(i => (
              <span key={i} className="text-[8px] text-gray-400 font-bold text-center">{i}</span>
            ))}
          </div>
        </div>
      </div>
      <div className="flex items-center justify-between text-[8px] text-gray-400 pl-5">
        <span className="font-semibold uppercase tracking-wider">← Impact →</span>
        <div className="flex items-center gap-2">
          {[{l:"LOW",bg:"#f0fdf4",t:"#15803d"},{l:"MED",bg:"#fef3c7",t:"#78350f"},{l:"HIGH",bg:"#ffedd5",t:"#7c2d12"},{l:"CRIT",bg:"#ede9fe",t:"#5b21b6"}].map(x=>(
            <span key={x.l} className="flex items-center gap-0.5">
              <span className="w-2 h-2 rounded-sm" style={{ background:x.bg,border:`1px solid ${x.t}30` }}/>
              <span style={{ color:x.t }} className="font-bold">{x.l}</span>
            </span>
          ))}
        </div>
      </div>
      <p className="text-[9px] text-gray-400 pl-5">Click a cell to filter by that L×I coordinate</p>
    </div>
  );
}

// ── Add Risk Form ──────────────────────────────────────────────────────────────

interface NewRisk {
  title: string; description: string; category: RiskCategory;
  likelihood: number; impact: number; owner: string;
  due_date: string; mitigation: string; treatment: TreatmentType;
  related_cve: string; related_link: string;
}

const BLANK: NewRisk = {
  title:"", description:"", category:"ai-code", likelihood:3, impact:3,
  owner:`alice@${ORG}.io`, due_date:"", mitigation:"", treatment:"mitigate",
  related_cve:"", related_link:"",
};

// ── Page ───────────────────────────────────────────────────────────────────────


export default function RiskRegisterPage() {
  const [store,        setStore]        = useState<PersistStore>({ overrides:{}, manuals:[] });
  const [derivedRisks, setDerivedRisks] = useState<RiskItem[]>(OFFLINE_RISKS);
  const [loading,      setLoading]      = useState(true);
  const [refreshing,   setRefreshing]   = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [filterStatus, setFilterStatus] = useState<RiskStatus | "all">("all");
  const [filterCat,    setFilterCat]    = useState<RiskCategory | "all">("all");
  const [filterOwner,  setFilterOwner]  = useState("all");
  const [heatFilter,   setHeatFilter]   = useState<[number,number]|null>(null);
  const [search,       setSearch]       = useState("");
  const [sortBy,       setSortBy]       = useState<"score" | "due">("score");
  const [expanded,     setExpanded]     = useState<string | null>(null);
  const [showAddForm,  setShowAddForm]  = useState(false);
  const [newRisk,      setNewRisk]      = useState<NewRisk>(BLANK);
  const [noteInput,    setNoteInput]    = useState<Record<string,string>>({});

  useEffect(() => { setStore(loadStore()); }, []);

  const fetchData = useCallback(async (spinner = false) => {
    if (spinner) setRefreshing(true);
    const seed = readSeed();
    const data = seed ?? await api.dashboard(ORG, 90).catch(() => null);
    if (data) {
      const scanPromises = data.repos.filter(r=>r.latest_scan_id).map(r=>api.getScan(r.latest_scan_id).catch(()=>null));
      const scans = (await Promise.all(scanPromises)).filter((s): s is ScanResult => s!==null);
      const derived = deriveRisks(patchDataWithAttestations(data), scans);
      setDerivedRisks(derived.length > 0 ? derived : OFFLINE_RISKS);
      setLastRefreshed(new Date());
    }
    setLoading(false); if (spinner) setRefreshing(false);
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(() => fetchData(), 30_000);
    return () => clearInterval(id);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Merge derived + manual, apply overrides
  const allRisks = useMemo<RiskItem[]>(() => {
    const base = [...derivedRisks, ...store.manuals];
    return base.map(r => {
      const ov = store.overrides[r.id];
      if (!ov) return r;
      return { ...r, ...ov, notes: ov.notes ?? r.notes };
    }).sort((a,b) => riskScore(b) - riskScore(a));
  }, [derivedRisks, store]);

  function updateOverride(id: string, patch: Partial<PersistedRisk>) {
    setStore(prev => {
      const next = { ...prev, overrides: { ...prev.overrides, [id]: { ...prev.overrides[id], ...patch } } };
      saveStore(next);
      return next;
    });
  }

  function addNote(id: string) {
    const text = noteInput[id]?.trim();
    if (!text) return;
    const r = allRisks.find(x=>x.id===id);
    const existing = store.overrides[id]?.notes ?? r?.notes ?? [];
    const date = new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"});
    updateOverride(id, { notes:[...existing, `${date}: ${text}`] });
    setNoteInput(p=>({...p,[id]:""}));
  }

  function addManualRisk() {
    if (!newRisk.title.trim()) return;
    const id = `MR-${Date.now()}`;
    const item: ManualRisk = {
      _manual:true, id, auto_derived:false,
      title:       newRisk.title.trim(),
      description: newRisk.description.trim(),
      category:    newRisk.category,
      likelihood:  newRisk.likelihood as 1|2|3|4|5,
      impact:      newRisk.impact as 1|2|3|4|5,
      status:      "open",
      treatment:   newRisk.treatment,
      owner:       newRisk.owner,
      due_date:    newRisk.due_date || undefined,
      mitigation:  newRisk.mitigation.trim(),
      related_cve: newRisk.related_cve.trim() || undefined,
      related_link:newRisk.related_link.trim() || undefined,
      identified_at:new Date().toISOString().split("T")[0],
      notes:[],
    };
    setStore(prev => {
      const next = { ...prev, manuals:[...prev.manuals, item] };
      saveStore(next);
      return next;
    });
    setNewRisk(BLANK);
    setShowAddForm(false);
  }

  function deleteManual(id: string) {
    setStore(prev => {
      const next = { ...prev, manuals:prev.manuals.filter(m=>m.id!==id) };
      saveStore(next);
      return next;
    });
  }

  const filtered = useMemo(() => {
    const list = allRisks.filter(r => {
      if (filterStatus !== "all" && r.status   !== filterStatus) return false;
      if (filterCat    !== "all" && r.category !== filterCat)    return false;
      if (filterOwner  !== "all" && r.owner    !== filterOwner)  return false;
      if (heatFilter   !== null  && !(r.likelihood===heatFilter[0] && r.impact===heatFilter[1])) return false;
      if (search) { const q=search.toLowerCase(); if (![r.title,r.description,r.id,r.related_cve??""].join(" ").toLowerCase().includes(q)) return false; }
      return true;
    });
    if (sortBy === "score") return list.sort((a,b) => riskScore(b) - riskScore(a));
    return [...list].sort((a,b) => {
      const da = daysLeft(a.due_date), db = daysLeft(b.due_date);
      if (da===null && db===null) return riskScore(b) - riskScore(a);
      if (da===null) return 1;
      if (db===null) return -1;
      return da - db;
    });
  }, [allRisks, filterStatus, filterCat, filterOwner, heatFilter, search, sortBy]);

  const openRisks  = allRisks.filter(r=>r.status==="open").length;
  const overdueRisks = allRisks.filter(r=>r.status!=="closed" && (daysLeft(r.due_date)??Infinity)<0).length;
  const dueSoonRisks = allRisks.filter(r=>{ const d=daysLeft(r.due_date); return r.status!=="closed" && d!==null && d>=0 && d<=7; }).length;
  const critRisks  = allRisks.filter(r=>riskScore(r)>=20&&r.status!=="closed").length;
  const avgInherent= allRisks.filter(r=>r.status!=="closed").length>0
    ? (allRisks.filter(r=>r.status!=="closed").reduce((s,r)=>s+riskScore(r),0)/allRisks.filter(r=>r.status!=="closed").length).toFixed(1)
    : "0";
  const avgResidual= allRisks.filter(r=>r.status!=="closed"&&r.residual_likelihood&&r.residual_impact).length>0
    ? (allRisks.filter(r=>r.status!=="closed"&&r.residual_likelihood&&r.residual_impact).reduce((s,r)=>s+(r.residual_likelihood!*r.residual_impact!),0)/allRisks.filter(r=>r.status!=="closed"&&r.residual_likelihood&&r.residual_impact).length).toFixed(1)
    : "—";

  function exportCSV() {
    const rows = [
      ["ID","Title","Category","Likelihood","Impact","Score","Level","Residual Score","Status","Treatment","Owner","Due","CVE","Identified"],
      ...filtered.map(r=>[r.id,r.title,CAT_LABELS[r.category],r.likelihood,r.impact,riskScore(r),riskLevel(riskScore(r)).label,residualScore(r)??"—",r.status,r.treatment,r.owner,r.due_date??"",r.related_cve??"",r.identified_at]),
    ];
    const blob=new Blob([rows.map(r=>r.map(c=>`"${c}"`).join(",")).join("\n")],{type:"text/csv"});
    Object.assign(document.createElement("a"),{href:URL.createObjectURL(blob),download:"risk-register.csv"}).click();
  }

  const refreshAgo = lastRefreshed ? (() => { const s=Math.floor((Date.now()-lastRefreshed.getTime())/1000); return s<10?"just now":s<60?`${s}s ago`:`${Math.floor(s/60)}m ago`; })() : "";

  return (
    <AuthGuard>
      <PageSkeleton rows={5} cards={4}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Risk Register</h1>
              {openRisks>0&&<span className="text-xs font-black text-white bg-rose-500 px-2 py-0.5 rounded-full">{openRisks} open</span>}
            </div>
            <p className="text-sm text-gray-400">
              Formal ISO 31000 risk log — derived from live scan data + manually entered · auto-refreshes every 30 s
            </p>
          </div>
          <div className="flex flex-col items-end gap-0.5">
            <div className="flex items-center gap-2">
              <button onClick={() => setShowAddForm(v=>!v)}
                className={`flex items-center gap-1.5 px-3 py-2 text-xs font-bold rounded-xl border transition-all shadow-sm ${showAddForm?"text-indigo-800 bg-indigo-100 border-indigo-300":"text-indigo-700 bg-indigo-50 border-indigo-200 hover:bg-indigo-100"}`}>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                Add Risk
              </button>
              <button onClick={exportCSV}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Export
              </button>
              <button onClick={() => fetchData(true)} disabled={refreshing}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-50 transition-all shadow-sm">
                <svg className={refreshing?"animate-spin":""} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                Refresh
              </button>
            </div>
            {refreshAgo&&<span className="text-[9px] text-gray-400">Updated {refreshAgo}</span>}
          </div>
        </div>

        {/* Add Risk form */}
        {showAddForm && (
          <div className="animate-fade-up section-card p-5 space-y-4">
            <p className="text-sm font-bold text-gray-900">Add Manual Risk</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="sm:col-span-2">
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Title *</label>
                <input value={newRisk.title} onChange={e=>setNewRisk(p=>({...p,title:e.target.value}))}
                  placeholder="Brief risk title"
                  className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </div>
              <div className="sm:col-span-2">
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Description</label>
                <textarea value={newRisk.description} onChange={e=>setNewRisk(p=>({...p,description:e.target.value}))}
                  placeholder="Risk description and context"
                  className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400 resize-none" rows={2} />
              </div>
              {[
                { label:"Category", field:"category", options:Object.entries(CAT_LABELS).map(([k,v])=>({value:k,label:v})) },
                { label:"Treatment (ISO 31000)", field:"treatment", options:[{value:"mitigate",label:"Mitigate"},{value:"accept",label:"Accept"},{value:"transfer",label:"Transfer"},{value:"avoid",label:"Avoid"}] },
                { label:"Owner", field:"owner", options:OWNERS.map(o=>({value:o,label:o.split("@")[0]})) },
              ].map(f=>(
                <div key={f.field}>
                  <label className="block text-[10px] font-semibold text-gray-500 mb-1">{f.label}</label>
                  <select value={String((newRisk as unknown as Record<string,string>)[f.field])} onChange={e=>setNewRisk(p=>({...p,[f.field]:e.target.value}))}
                    className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none">
                    {f.options.map(o=><option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              ))}
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Due Date</label>
                <input type="date" value={newRisk.due_date} onChange={e=>setNewRisk(p=>({...p,due_date:e.target.value}))}
                  className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none" />
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Likelihood (1–5)</label>
                <input type="range" min={1} max={5} value={newRisk.likelihood} onChange={e=>setNewRisk(p=>({...p,likelihood:Number(e.target.value)}))}
                  className="w-full" />
                <div className="flex justify-between text-[9px] text-gray-400 mt-0.5">
                  <span>Rare (1)</span><span className="font-bold text-gray-700">{newRisk.likelihood}</span><span>Certain (5)</span>
                </div>
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Impact (1–5)</label>
                <input type="range" min={1} max={5} value={newRisk.impact} onChange={e=>setNewRisk(p=>({...p,impact:Number(e.target.value)}))}
                  className="w-full" />
                <div className="flex justify-between text-[9px] text-gray-400 mt-0.5">
                  <span>Minor (1)</span><span className="font-bold text-gray-700">{newRisk.impact}</span><span>Critical (5)</span>
                </div>
              </div>
              <div className="sm:col-span-2">
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Mitigation Plan</label>
                <textarea value={newRisk.mitigation} onChange={e=>setNewRisk(p=>({...p,mitigation:e.target.value}))}
                  placeholder="Describe the mitigation plan or acceptance rationale"
                  className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400 resize-none" rows={2} />
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 mb-1">Related CVE (optional)</label>
                <input value={newRisk.related_cve} onChange={e=>setNewRisk(p=>({...p,related_cve:e.target.value}))}
                  placeholder="CVE-2023-XXXXX"
                  className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none" />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1 text-xs text-gray-500 bg-gray-50 px-3 py-1.5 rounded-lg border border-gray-200">
                <span>Score:</span>
                <span className="font-black ml-1" style={{ color:riskLevel(newRisk.likelihood*newRisk.impact).text }}>
                  {newRisk.likelihood*newRisk.impact} — {riskLevel(newRisk.likelihood*newRisk.impact).label}
                </span>
              </div>
              <button onClick={addManualRisk} disabled={!newRisk.title.trim()}
                className="px-4 py-2 text-sm font-bold text-white rounded-xl disabled:opacity-40 transition-colors"
                style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
                Add to Register
              </button>
              <button onClick={() => { setShowAddForm(false); setNewRisk(BLANK); }}
                className="px-4 py-2 text-sm font-semibold text-gray-500 hover:text-gray-700 rounded-xl transition-colors">
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Summary + Heat Map */}
        <div className="animate-fade-up grid grid-cols-1 lg:grid-cols-[1fr_240px] gap-5">
          <div className="space-y-3">
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {[
                { label:"Open Risks",   value:openRisks,   color:"#ef4444", bg:"#fef2f2", info:{ title:"Open Risks",      description:"Risks in 'Open' status — identified but not yet being actively mitigated or accepted. Open risks are the primary action list." } },
                { label:"Overdue",      value:overdueRisks,color:"#be123c", bg:"#fff1f2", info:{ title:"Overdue Risks",    description:"Non-closed risks whose due date has passed. These need immediate owner follow-up." } },
                { label:"Critical",     value:critRisks,   color:"#7c3aed", bg:"#ede9fe", info:{ title:"Critical Risks",   description:"Risks with inherent score ≥ 20 (Likelihood × Impact) that are not yet closed. Critical = L×I ≥ 20. Requires immediate executive attention." } },
                { label:"Avg Inherent", value:avgInherent, color:"#f97316", bg:"#fff7ed", info:{ title:"Avg Inherent Risk", description:"Average inherent risk score before any mitigation controls are applied, across all non-closed risks.", formula:"sum(Likelihood × Impact) ÷ non_closed_risks" } },
                { label:"Avg Residual", value:avgResidual, color:"#10b981", bg:"#f0fdf4", info:{ title:"Avg Residual Risk", description:"Average residual risk score after mitigation controls are applied. Residual should be lower than inherent. Only shown for risks with residual values set.", formula:"sum(Residual_L × Residual_I) ÷ risks_with_residual" } },
              ].map(s=>(
                <div key={s.label} className="rounded-2xl p-4 border" style={{ background:s.bg, borderColor:s.color+"30" }}>
                  <p className="text-2xl font-black tabular-nums" style={{ color:s.color }}>{s.value}</p>
                  <div className="flex items-center gap-1.5 mt-1">
                    <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                    <InfoTooltip title={s.info.title} description={s.info.description} formula={s.info.formula} position="top" />
                  </div>
                </div>
              ))}
            </div>
            {heatFilter && (
              <div className="flex items-center gap-2 bg-indigo-50 border border-indigo-200 rounded-xl px-4 py-2.5">
                <span className="text-xs font-bold text-indigo-700">Filtering: L={heatFilter[0]} × I={heatFilter[1]} (score {heatFilter[0]*heatFilter[1]})</span>
                <button onClick={()=>setHeatFilter(null)} className="ml-auto text-xs font-bold text-indigo-600 hover:text-indigo-800">Clear ✕</button>
              </div>
            )}
          </div>
          <div className="section-card p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-1.5">
                <p className="text-[9px] font-black uppercase tracking-widest text-gray-400">Risk Heat Map</p>
                <InfoTooltip title="Risk Heat Map" description="Each cell shows how many open risks fall at that Likelihood × Impact coordinate. Click a cell to filter the list to those risks. Color = severity: green=LOW, amber=MEDIUM, orange=HIGH, violet=CRITICAL." formula={"Score = Likelihood × Impact\nLOW < 6  ·  MEDIUM 6–11\nHIGH 12–19  ·  CRITICAL ≥ 20"} position="right" size="sm" />
              </div>
              <span className="text-[9px] text-gray-400">Y = Likelihood</span>
            </div>
            <HeatMap risks={allRisks} onFilter={(l,i)=>setHeatFilter([l,i])} />
          </div>
        </div>

        {/* Filters */}
        <div className="animate-fade-up flex flex-wrap items-center gap-2">
          <div className="flex items-center rounded-xl border border-gray-200 bg-white overflow-hidden">
            <svg className="ml-3 text-gray-400 shrink-0" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search risks, CVEs…"
              className="px-3 py-2 text-xs text-gray-700 bg-transparent outline-none w-44" />
            {search&&<button onClick={()=>setSearch("")} className="pr-2 text-gray-400 hover:text-gray-600 text-xs">✕</button>}
          </div>
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","open","mitigating","accepted","closed"] as const).map(s=>{
              const count=s==="all"?allRisks.length:allRisks.filter(r=>r.status===s).length;
              return (
                <button key={s} onClick={()=>setFilterStatus(s)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${filterStatus===s?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                  {s==="all"?"All":STATUS_STYLE[s].label}
                  <span className={`text-[9px] font-black px-1 py-0.5 rounded-full ${filterStatus===s?"bg-gray-200 text-gray-700":"bg-gray-200/70 text-gray-500"}`}>{count}</span>
                </button>
              );
            })}
          </div>
          <select value={filterCat} onChange={e=>setFilterCat(e.target.value as RiskCategory|"all")}
            className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
            <option value="all">All Categories</option>
            {(Object.keys(CAT_LABELS) as RiskCategory[]).map(c=><option key={c} value={c}>{CAT_LABELS[c]}</option>)}
          </select>
          <select value={filterOwner} onChange={e=>setFilterOwner(e.target.value)}
            className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
            <option value="all">All Owners</option>
            {OWNERS.map(o=><option key={o} value={o}>{o.split("@")[0]}</option>)}
          </select>
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["score","due"] as const).map(s=>(
              <button key={s} onClick={()=>setSortBy(s)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${sortBy===s?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                {s==="score"?"Sort: Risk Score":"Sort: Due Date"}
              </button>
            ))}
          </div>
          {(search||filterStatus!=="all"||filterCat!=="all"||filterOwner!=="all"||heatFilter)&&(
            <button onClick={()=>{setSearch("");setFilterStatus("all");setFilterCat("all");setFilterOwner("all");setHeatFilter(null);}}
              className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50 transition-colors">
              Clear all
            </button>
          )}
          <span className="text-xs text-gray-400 ml-auto">{filtered.length} risk{filtered.length!==1?"s":""}</span>
        </div>

        {/* Overdue / due-soon banner */}
        {(overdueRisks>0||dueSoonRisks>0)&&(
          <div className="animate-fade-up flex items-center gap-3 flex-wrap text-[11px] font-semibold px-1">
            <span className="text-gray-500">Risk treatment urgency —</span>
            {overdueRisks>0&&<span className="text-rose-600">{overdueRisks} risk{overdueRisks!==1?"s":""} overdue</span>}
            {dueSoonRisks>0&&<span className="text-amber-600">{dueSoonRisks} due within 7 days</span>}
            {sortBy!=="due"&&(
              <button onClick={()=>setSortBy("due")} className="ml-auto text-xs font-bold text-indigo-600 hover:text-indigo-800">
                Sort by due date →
              </button>
            )}
          </div>
        )}

        {/* Risk list */}
        <div className="animate-fade-up space-y-2.5">
          {filtered.length===0 ? (
            <div className="section-card py-14 text-center">
              <p className="text-sm font-bold text-gray-600">No risks match this filter</p>
            </div>
          ) : filtered.map(r => {
            const score  = riskScore(r);
            const level  = riskLevel(score);
            const resS   = residualScore(r);
            const resLev = resS ? riskLevel(resS) : null;
            const stat   = STATUS_STYLE[r.status]   ?? STATUS_STYLE.open;
            const treat  = TREATMENT_STYLE[r.treatment] ?? TREATMENT_STYLE.mitigate;
            const open   = expanded === r.id;
            const dl     = daysLeft(r.due_date);
            const notes  = store.overrides[r.id]?.notes ?? r.notes;
            return (
              <div key={r.id} className="section-card overflow-hidden border-l-4 transition-all hover:shadow-md"
                style={{ borderLeftColor: level.text }}>
                <div className="flex items-start gap-4 px-5 py-4 cursor-pointer"
                  onClick={()=>setExpanded(open?null:r.id)}>
                  {/* Score */}
                  <div className="shrink-0 flex flex-col items-center gap-1.5">
                    <div className="w-12 h-12 rounded-xl flex items-center justify-center text-lg font-black border"
                      style={{ background:level.bg, color:level.text, borderColor:level.border }}>
                      {score}
                    </div>
                    {resS && (
                      <div className="flex items-center gap-1">
                        <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke={resS<score?"#10b981":"#ef4444"} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                          {resS<score?<polyline points="18 15 12 9 6 15"/>:<polyline points="6 9 12 15 18 9"/>}
                        </svg>
                        <span className="text-[9px] font-black" style={{ color:resLev?.text }}>{resS}</span>
                      </div>
                    )}
                    <span className="text-[8px] font-black uppercase tracking-wider" style={{ color:level.text }}>{level.label}</span>
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="text-[10px] font-black font-mono text-gray-400 bg-gray-100 px-2 py-0.5 rounded">{r.id}</span>
                      <span className="text-[10px] font-semibold text-gray-500 bg-gray-50 px-2 py-0.5 rounded border border-gray-200">{CAT_LABELS[r.category] ?? r.category}</span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border"
                        style={{ background:stat.bg, color:stat.text, borderColor:stat.border }}>{stat.label}</span>
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded" style={{ color:treat.color, background:treat.color+"15" }}>{treat.label}</span>
                      {r.auto_derived && <span className="text-[8px] font-bold text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-100">AUTO</span>}
                      {notes.length>0&&<span className="text-[9px] text-gray-400">💬 {notes.length}</span>}
                    </div>
                    <p className="text-sm font-bold text-gray-900">{r.title}</p>
                    {!open&&<p className="text-xs text-gray-500 mt-0.5 truncate">{r.description}</p>}
                    <div className="flex items-center gap-3 mt-1.5 flex-wrap text-[10px]">
                      <span className="text-gray-500 flex items-center gap-1">
                        <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                        {r.owner.split("@")[0]}
                      </span>
                      {dl!==null&&r.status!=="closed"&&(
                        <span className={`font-bold ${dl<0?"text-rose-600":dl<=3?"text-orange-600":"text-gray-400"}`}>
                          {dl<0?`${Math.abs(dl)}d overdue`:dl===0?"Due today":`Due in ${dl}d`}
                        </span>
                      )}
                      {r.related_cve&&<span className="font-mono text-indigo-600">{r.related_cve}</span>}
                      <span className="text-gray-400">L={r.likelihood} × I={r.impact}</span>
                    </div>
                  </div>

                  <svg className="shrink-0 text-gray-300" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
                    style={{ transform:open?"rotate(180deg)":"none", transition:"transform 0.2s" }}>
                    <polyline points="6 9 12 15 18 9"/>
                  </svg>
                </div>

                {/* Expanded */}
                {open&&(
                  <div className="border-t border-gray-100 px-5 py-5 space-y-4" style={{ background:"rgba(248,250,252,0.8)" }}>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1.5">Risk Description</p>
                        <p className="text-xs text-gray-600 leading-relaxed">{r.description}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1.5">Mitigation Plan</p>
                        <p className="text-xs text-gray-600 leading-relaxed">{r.mitigation}</p>
                      </div>
                    </div>

                    {/* Inherent vs residual */}
                    {resS&&(
                      <div className="grid grid-cols-2 gap-3">
                        <div className="rounded-xl px-4 py-3 border" style={{ background:level.bg, borderColor:level.border }}>
                          <p className="text-[9px] font-black uppercase tracking-wider mb-1" style={{ color:level.text }}>Inherent Risk</p>
                          <div className="flex items-end gap-2">
                            <span className="text-2xl font-black" style={{ color:level.text }}>{score}</span>
                            <span className="text-xs font-bold mb-0.5" style={{ color:level.text }}>{level.label}</span>
                          </div>
                          <p className="text-[9px] mt-1" style={{ color:level.text, opacity:0.7 }}>Before mitigation</p>
                        </div>
                        {resLev&&(
                          <div className="rounded-xl px-4 py-3 border" style={{ background:resLev.bg, borderColor:resLev.border }}>
                            <p className="text-[9px] font-black uppercase tracking-wider mb-1" style={{ color:resLev.text }}>Residual Risk</p>
                            <div className="flex items-end gap-2">
                              <span className="text-2xl font-black" style={{ color:resLev.text }}>{resS}</span>
                              <span className="text-xs font-bold mb-0.5 flex items-center gap-1" style={{ color:resLev.text }}>
                                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="18 15 12 9 6 15"/></svg>
                                {resLev.label}
                              </span>
                            </div>
                            <p className="text-[9px] mt-1" style={{ color:resLev.text, opacity:0.7 }}>After mitigation</p>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Controls */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                      <div>
                        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1">Status</p>
                        <select value={r.status} onChange={e=>updateOverride(r.id,{status:e.target.value as RiskStatus})}
                          className="w-full text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-400">
                          {(["open","mitigating","accepted","closed"] as const).map(s=><option key={s} value={s}>{STATUS_STYLE[s].label}</option>)}
                        </select>
                      </div>
                      <div>
                        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1">Treatment</p>
                        <select value={r.treatment} onChange={e=>updateOverride(r.id,{treatment:e.target.value as TreatmentType})}
                          className="w-full text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none">
                          {(["mitigate","accept","transfer","avoid"] as const).map(t=><option key={t} value={t}>{TREATMENT_STYLE[t].label}</option>)}
                        </select>
                      </div>
                      <div>
                        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1">Owner</p>
                        <select value={r.owner} onChange={e=>updateOverride(r.id,{owner:e.target.value})}
                          className="w-full text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none">
                          {OWNERS.map(o=><option key={o} value={o}>{o.split("@")[0]}</option>)}
                        </select>
                      </div>
                      <div>
                        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1">Due Date</p>
                        <input type="date" value={r.due_date??""} onChange={e=>updateOverride(r.id,{due_date:e.target.value})}
                          className="w-full text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none" />
                      </div>
                      <div>
                        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1">Residual L</p>
                        <input type="number" min={1} max={5} value={r.residual_likelihood??""} onChange={e=>updateOverride(r.id,{residual_likelihood:Number(e.target.value) as 1|2|3|4|5})}
                          className="w-full text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none" placeholder="1–5" />
                      </div>
                      <div>
                        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1">Residual I</p>
                        <input type="number" min={1} max={5} value={r.residual_impact??""} onChange={e=>updateOverride(r.id,{residual_impact:Number(e.target.value) as 1|2|3|4|5})}
                          className="w-full text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none" placeholder="1–5" />
                      </div>
                    </div>

                    {/* Notes */}
                    <div>
                      <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Notes</p>
                      {notes.length>0&&(
                        <div className="space-y-1.5 mb-2">
                          {notes.map((n,i)=>(
                            <div key={i} className="text-[11px] text-gray-600 bg-white rounded-lg px-3 py-2 border border-gray-100">{n}</div>
                          ))}
                        </div>
                      )}
                      <div className="flex gap-2">
                        <input value={noteInput[r.id]??""} onChange={e=>setNoteInput(p=>({...p,[r.id]:e.target.value}))}
                          onKeyDown={e=>{if(e.key==="Enter")addNote(r.id);}}
                          placeholder="Add a note (Enter to save)…"
                          className="flex-1 text-xs border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white" />
                        <button onClick={()=>addNote(r.id)}
                          className="text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-3 py-2 rounded-lg hover:bg-indigo-100 transition-colors">
                          Save
                        </button>
                      </div>
                    </div>

                    {/* Links + delete */}
                    <div className="flex items-center gap-3 flex-wrap pt-1 border-t border-gray-100">
                      {r.related_cve&&<Link href="/vulnerabilities" className="text-[10px] font-bold text-indigo-600 bg-indigo-50 border border-indigo-100 px-2.5 py-1 rounded-lg hover:bg-indigo-100">{r.related_cve} ↗</Link>}
                      {r.related_link&&<Link href={r.related_link} className="text-[10px] font-bold text-gray-600 bg-gray-50 border border-gray-200 px-2.5 py-1 rounded-lg hover:bg-gray-100">View Evidence ↗</Link>}
                      <span className="text-[9px] text-gray-400 ml-auto">Identified {fmtDate(r.identified_at)}</span>
                      {!r.auto_derived&&(
                        <button onClick={()=>{if(confirm("Delete this risk?"))deleteManual(r.id);}}
                          className="text-[10px] font-bold text-rose-600 hover:text-rose-800 px-2.5 py-1 rounded-lg hover:bg-rose-50 transition-colors">
                          Delete
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
