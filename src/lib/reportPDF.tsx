/**
 * PDF Report Document — React PDF
 * Generates signed control-evidence reports scoped to a single framework's
 * narrow control set (SOC 2, ISO 27001, PCI DSS, AI code governance; see
 * lib/controlEvidence.ts) -- not a full compliance report. See each
 * framework's scope statement.
 */

import React from "react";
import {
  Document, Page, Text, View, StyleSheet, Image,
} from "@react-pdf/renderer";
import { WORDMARK_PNG_DATA_URI, WORDMARK_ASPECT } from "./brandAssets";
import { FRAMEWORKS, normalizeFrameworkId } from "./controlEvidence";
import { EXCEPTION_INFO, REGISTER_CONTROL, pullKey, type RegisterRow, type ReportChangeRegister } from "./changeRegister";
import { FRAMEWORK_VIEW_TITLE, type FrameworkView } from "./frameworkViews";
import { protectionValue } from "./branchProtection";

// ── Styles ─────────────────────────────────────────────────────────────────────

const S = StyleSheet.create({
  page: { fontFamily:"Helvetica", fontSize:9, padding:40, color:"#1e293b" },

  // Cover
  coverBg:    { position:"absolute", top:0, left:0, right:0, height:200, backgroundColor:"#0f172a" },
  logo:       { marginTop:60, marginBottom:8 },
  coverTitle: { fontSize:14, color:"rgba(255,255,255,0.7)", marginBottom:4 },
  coverOrg:   { fontSize:11, color:"rgba(165,180,252,0.9)", marginBottom:40 },

  // Section
  section:        { marginTop:18 },
  sectionTitle:   { fontSize:11, fontFamily:"Helvetica-Bold", color:"#0f172a",
                    borderBottomWidth:1, borderBottomColor:"#e2e8f0",
                    paddingBottom:4, marginBottom:10 },
  pageHeading:    { fontSize:13, fontFamily:"Helvetica-Bold", color:"#0f172a", marginBottom:4 },
  pageSubheading: { fontSize:8, color:"#64748b", marginBottom:16 },

  // Metric cards
  metricsRow:  { flexDirection:"row", gap:8, marginBottom:12 },
  metricCard:  { flex:1, backgroundColor:"#f8fafc", borderRadius:6,
                 padding:10, borderWidth:1, borderColor:"#e2e8f0" },
  metricValue: { fontSize:18, fontFamily:"Helvetica-Bold", color:"#6366f1" },
  metricLabel: { fontSize:8, color:"#64748b", marginTop:2 },

  // Table
  table:       { borderWidth:1, borderColor:"#e2e8f0", borderRadius:4, overflow:"hidden" },
  tableHead:   { flexDirection:"row", backgroundColor:"#f1f5f9", borderBottomWidth:1, borderBottomColor:"#e2e8f0" },
  tableRow:    { flexDirection:"row", borderBottomWidth:1, borderBottomColor:"#f1f5f9" },
  tableRowAlt: { backgroundColor:"#fafafa" },
  th:          { flex:1, padding:"5 8", fontSize:8, fontFamily:"Helvetica-Bold", color:"#475569" },
  td:          { flex:1, padding:"4 8", fontSize:8, color:"#334155" },

  // Risk badges / text colors
  critical: { color:"#7c3aed", fontFamily:"Helvetica-Bold" },
  high:     { color:"#ea580c", fontFamily:"Helvetica-Bold" },
  medium:   { color:"#d97706", fontFamily:"Helvetica-Bold" },
  low:      { color:"#15803d", fontFamily:"Helvetica-Bold" },

  // Footer
  footer:   { position:"absolute", bottom:24, left:40, right:40,
               flexDirection:"row", justifyContent:"space-between" },
  footerText: { fontSize:7, color:"#94a3b8" },

  // Info
  infoBox: { backgroundColor:"#eff6ff", borderRadius:6, padding:10,
             borderWidth:1, borderColor:"#bfdbfe", marginBottom:12 },
  infoText: { fontSize:8, color:"#1d4ed8", lineHeight:1.5 },

  // Scope & limitations
  scopeBox:   { backgroundColor:"#fffbeb", borderRadius:6, padding:10,
                borderWidth:1, borderColor:"#fde68a", marginBottom:12 },
  scopeLabel: { fontSize:7, fontFamily:"Helvetica-Bold", color:"#92400e", marginBottom:3, letterSpacing:0.5 },
  scopeText:  { fontSize:8, color:"#78350f", lineHeight:1.5 },

  // Report reference
  refBox:   { flexDirection:"row", flexWrap:"wrap", gap:12, backgroundColor:"#f8fafc",
              borderRadius:6, padding:12, borderWidth:1, borderColor:"#e2e8f0", marginBottom:12 },
  refItem:  { width:"31%" },
  refLabel: { fontSize:7, fontFamily:"Helvetica-Bold", color:"#94a3b8", letterSpacing:0.5, marginBottom:2 },
  refValue: { fontSize:8.5, color:"#1e293b", fontFamily:"Helvetica-Bold" },

  // Risk overview bars
  riskBarRow:   { flexDirection:"row", alignItems:"center", marginBottom:8, gap:8 },
  riskBarLabel: { width:60, fontSize:8, fontFamily:"Helvetica-Bold" },
  riskBarTrack: { flex:1, height:8, backgroundColor:"#f1f5f9", borderRadius:4, overflow:"hidden" },
  riskBarFill:  { height:8, borderRadius:4 },
  riskBarCount: { width:32, fontSize:8, textAlign:"right", color:"#475569" },

  // Compliance mapping cards
  ctrlCard:    { borderWidth:1, borderColor:"#e2e8f0", borderRadius:6, padding:10, marginBottom:8 },
  ctrlHeadRow: { flexDirection:"row", justifyContent:"space-between", alignItems:"center", marginBottom:4 },
  ctrlId:      { fontSize:8, fontFamily:"Helvetica-Bold", color:"#6366f1", backgroundColor:"#eef2ff",
                 borderRadius:3, padding:"2 5", marginRight:6 },
  ctrlName:    { fontSize:8.5, fontFamily:"Helvetica-Bold", color:"#1e293b" },
  ctrlEvidenceRow: { fontSize:7.5, color:"#64748b", marginTop:2 },
  statusPass:    { color:"#15803d" },
  statusPartial: { color:"#d97706" },
  statusFail:    { color:"#dc2626" },
  statusNotTested: { color:"#94a3b8" },

  // Gap analysis
  gapOkBox: { backgroundColor:"#ecfdf5", borderRadius:6, padding:10, borderWidth:1, borderColor:"#a7f3d0" },
  gapOkText:{ fontSize:8.5, color:"#065f46", fontFamily:"Helvetica-Bold" },

  // Management assertion
  assertionBox: { borderWidth:1, borderColor:"#e2e8f0", borderRadius:6, overflow:"hidden", marginTop:4 },
  assertionHead:{ backgroundColor:"#f8fafc", padding:10, borderBottomWidth:1, borderBottomColor:"#e2e8f0" },
  assertionBody:{ padding:12 },
  assertionP:   { fontSize:8, color:"#334155", lineHeight:1.6, marginBottom:8 },
  sigLine:      { borderBottomWidth:1, borderBottomColor:"#cbd5e1", height:24, marginBottom:4 },
  sigCaption:   { fontSize:7.5, color:"#64748b" },

  // Signature
  sigBox:   { backgroundColor:"#0f172a", borderRadius:6, padding:10, marginBottom:12 },
  sigLabel: { fontSize:7, color:"#818cf8", marginBottom:3, letterSpacing:0.5 },
  sigValue: { fontSize:8, color:"#a5b4fc", lineHeight:1.4 },
  sigNote:  { fontSize:7, color:"#64748b", marginTop:6, lineHeight:1.4 },
});

// ── Helpers ────────────────────────────────────────────────────────────────────

function riskStyle(risk: string) {
  if (risk === "CRITICAL") return S.critical;
  if (risk === "HIGH")     return S.high;
  if (risk === "MEDIUM")   return S.medium;
  return S.low;
}

function statusStyle(status: string) {
  if (status === "pass")    return S.statusPass;
  if (status === "partial") return S.statusPartial;
  if (status === "fail")    return S.statusFail;
  return S.statusNotTested;
}

// What the evidence shows -- never "satisfied"/"compliant": only an auditor can conclude that.
function statusLabel(status: string) {
  if (status === "pass")    return "EVIDENCE COLLECTED";
  if (status === "partial") return "GAPS FOUND";
  if (status === "fail")    return "FAILING";
  return "NO EVIDENCE YET";
}

// Real production rows have occasionally shown up with a null path (bad
// seed data / a scan record written before a field was required) -- a bare
// .split("/") on that crashes @react-pdf/renderer mid-render, which the API
// route's catch-all then silently swaps for a JSON body still named *.pdf.
function shortPath(p: string | null | undefined) {
  return p ? p.split("/").slice(-2).join("/") : "—";
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-GB", { day:"numeric", month:"short", year:"numeric" });
}

function fmtPct(n: number) { return `${(n * 100).toFixed(1)}%`; }

function PageFooter({ label }: { label: string }) {
  return (
    <View style={S.footer} fixed>
      <Text style={S.footerText}>TrustLedger AI Governance Platform  ·  Confidential  ·  {label}</Text>
      <Text
        style={S.footerText}
        render={({ pageNumber, totalPages }) => `Page ${pageNumber} of ${totalPages}`}
      />
    </View>
  );
}

// ── Report data type ───────────────────────────────────────────────────────────

interface ComplianceControl {
  control_id:   string;
  control_name: string;
  status:       string;
  score:        number;
  /** The control as an auditor writes it up (lib/controlEvidence.ts ControlWriteUp); absent on older payloads. */
  statement?:   string;
  owner?:       string;
  frequency?:   string;
  test?:        string;
  partial?:     string;
  /** basis "current": a state when the report was generated, not evidence across the period. */
  checks:       Array<{ label: string; basis?: string; status: string; summary: string; gaps: string[] }>;
}

/**
 * How a report is signed: Ed25519 over the canonical JSON of its evidence record (verifiable by anyone with the
 * published public key), or HMAC-SHA256 when no Ed25519 key is configured (checkable only by the issuing server).
 * `record_sha256` ties the PDF to the evidence record handed out with it.
 */
export type ReportSignature =
  | { algorithm: "Ed25519"; value: string; key_id: string; public_key_pem: string; signed_content: string; record_sha256: string }
  | { algorithm: "HMAC-SHA256"; value: string; record_sha256: string };

interface GapFile {
  repo:          string;
  pr_number:     number;
  file_path:     string;
  risk_score:    string;
  ai_percentage: number;
}

interface ReportData {
  report_id:     string;
  org:           { name: string; slug: string; github_org: string | null };
  framework:     string;
  /** Normalised id (soc2 | iso27001 | pcidss | aigov) from the evidence engine. */
  framework_id?: string;
  evidence_scope?: { name: string; standard: string; scope: string; status_counts: Record<string, number> };
  period_start:  string;
  period_end:    string;
  generated_at:  string;
  generated_by:  string;
  metrics: {
    total_scans:        number;
    total_files:        number;
    total_attestations: number;
    critical_findings:  number;
    high_risk_files:    number;
    high_risk_reviewed: number;
    independent_reviews: number;
    self_approvals:     number;
    secrets_detected:   number;
    avg_ai_percentage:  number;
  };
  risk_breakdown: { critical: number; high: number; medium: number; low: number };
  gaps:           GapFile[];
  compliance:     ComplianceControl[];
  not_covered?:   readonly string[];
  /** SOC 2 / ISO 27001 / PCI DSS: every pull request merged in the period and the auditor sample (lib/changeRegister.ts). */
  change_register?: ReportChangeRegister;
  /** ISO SoA input / PCI 6.2.4 attack classes / AI governance mappings (lib/frameworkViews.ts). */
  framework_view?: FrameworkView;
  scans:       Array<{ repo_full_name: string; overall_risk: string; total_ai_percentage: number; created_at: string }>;
  attestations: Array<{ file_path: string; risk_score: string; reviewer_email: string; created_at: string }>;
  secrets:      Array<{ file_path: string; severity: string; label: string; status: string; created_at: string }>;
}

// ── Framework metadata ─────────────────────────────────────────────────────────

// Names, standards and scope statements come from lib/controlEvidence.ts (FRAMEWORKS); only who can assess is here.
const ASSESSOR: Record<string, string> = {
  soc2: "Licensed CPA firm (SOC 2 examination)",
  iso27001: "Accredited certification body",
  pcidss: "Qualified Security Assessor (QSA)",
  aigov: "Internal review: not a regulatory framework",
};

// ── Framework view (under Control Evidence) ───────────────────────────────────

function FrameworkViewPdf({ view }: { view: FrameworkView }) {
  const row = (i: number) => [S.tableRow, i % 2 ? S.tableRowAlt : {}];
  return (
    <View style={S.section}>
      <Text style={S.sectionTitle}>4b. {FRAMEWORK_VIEW_TITLE[view.kind]}</Text>
      {view.kind === "iso_soa" && (
        <>
          <Text style={[S.ctrlEvidenceRow, { marginBottom:6 }]}>
            For your Statement of Applicability. Applicability is your decision; TrustLedger supplies the implementation
            and evidence reference where it holds evidence, and says where it holds none.
          </Text>
          <View style={S.table}>
            <View style={S.tableHead}>
              <Text style={[S.th, { flex:0.7 }]}>Control</Text><Text style={[S.th, { flex:1.5 }]}>Title</Text>
              <Text style={[S.th, { flex:3 }]}>Implementation</Text><Text style={[S.th, { flex:1.4 }]}>Evidence reference</Text><Text style={[S.th, { flex:0.9 }]}>Evidence</Text>
            </View>
            {view.rows.map((r, i) => (
              <View key={r.control} style={row(i)} wrap={false}>
                <Text style={[S.td, { flex:0.7 }]}>{r.control}</Text>
                <Text style={[S.td, { flex:1.5 }]}>{r.title}</Text>
                <Text style={[S.td, { flex:3 }]}>{r.implementation}{r.gaps.length ? `\nGaps: ${r.gaps.join("; ")}` : ""}</Text>
                <Text style={[S.td, { flex:1.4 }]}>{r.evidence_reference}</Text>
                <Text style={[S.td, { flex:0.9 }, r.status ? statusStyle(r.status) : S.statusNotTested]}>{r.status ? statusLabel(r.status) : "None"}</Text>
              </View>
            ))}
          </View>
        </>
      )}
      {view.kind === "pci_624" && (
        <View style={S.table}>
          <View style={S.tableHead}>
            <Text style={[S.th, { flex:2 }]}>Attack class (6.2.4)</Text><Text style={[S.th, { flex:2.4 }]}>TrustLedger rules</Text><Text style={[S.th, { flex:2.2 }]}>Where scanning stops</Text>
          </View>
          {view.classes.map((c, i) => (
            <View key={c.key} style={row(i)} wrap={false}>
              <Text style={[S.td, { flex:2 }]}>{c.title}</Text>
              <Text style={[S.td, { flex:2.4 }]}>{c.rules.length ? `${c.rules.length} rules: ${c.rules.join(", ")}` : "Tracked under 6.3.1"}</Text>
              <Text style={[S.td, { flex:2.2 }]}>{c.limits}</Text>
            </View>
          ))}
        </View>
      )}
      {view.kind === "ai_mapping" && (
        <>
          <Text style={[S.ctrlEvidenceRow, { marginBottom:6 }]}>{view.caveat}</Text>
          <View style={S.table}>
            <View style={S.tableHead}>
              <Text style={[S.th, { flex:1.3 }]}>Control</Text><Text style={[S.th, { flex:1.6 }]}>ISO/IEC 42001 Annex A</Text>
              <Text style={[S.th, { flex:1.8 }]}>NIST AI RMF 1.0</Text><Text style={[S.th, { flex:2 }]}>Note</Text>
            </View>
            {view.rows.map((r, i) => (
              <View key={r.control} style={row(i)} wrap={false}>
                <Text style={[S.td, { flex:1.3 }]}>{r.control} {r.name}</Text>
                <Text style={[S.td, { flex:1.6 }]}>{r.iso42001.map(x => `${x.id} ${x.title}`).join("\n") || "—"}</Text>
                <Text style={[S.td, { flex:1.8 }]}>{r.nist_ai_rmf.map(x => `${x.id}: ${x.summary}`).join("\n") || "—"}</Text>
                <Text style={[S.td, { flex:2 }]}>{r.note}</Text>
              </View>
            ))}
          </View>
        </>
      )}
    </View>
  );
}

// ── Change-management register page ───────────────────────────────────────────

const MAX_EXCEPTION_ROWS = 40;

function RegisterTable({ rows }: { rows: RegisterRow[] }) {
  return (
    <View style={S.table}>
      <View style={S.tableHead}>
        <Text style={[S.th, { flex:1.6 }]}>Pull request</Text>
        <Text style={S.th}>Merged</Text>
        <Text style={[S.th, { flex:1.2 }]}>Approved by</Text>
        <Text style={S.th}>Scan</Text>
        <Text style={[S.th, { flex:2 }]}>Exceptions</Text>
      </View>
      {rows.map((r, i) => (
        <View key={pullKey(r.repo, r.number)} style={[S.tableRow, i % 2 ? S.tableRowAlt : {}]} wrap={false}>
          <Text style={[S.td, { flex:1.6 }]}>{r.repo}#{r.number}</Text>
          <Text style={S.td}>{fmtDate(r.merged_at)}</Text>
          <Text style={[S.td, { flex:1.2 }]}>{r.approvals.map(a => a.reviewer).join(", ") || "—"}</Text>
          <Text style={[S.td, r.scan ? riskStyle(r.scan.overall_risk) : {}]}>{r.scan?.overall_risk ?? "none"}</Text>
          <Text style={[S.td, { flex:2 }, r.exceptions.length ? S.statusPartial : S.statusPass]}>
            {r.exceptions.length ? r.exceptions.map(e => EXCEPTION_INFO[e].label).join("; ") : "None"}
          </Text>
        </View>
      ))}
    </View>
  );
}

function ChangeRegisterPage({ register, control, reportId }: { register: ReportChangeRegister; control: string; reportId: string }) {
  const footer = <PageFooter label={reportId.slice(0, 8)} />;
  if ("error" in register) {
    return (
      <Page size="A4" style={S.page}>
        <Text style={S.pageHeading}>5. Change-Management Register ({control})</Text>
        <View style={S.scopeBox}><Text style={S.scopeText}>{register.error}</Text></View>
        {footer}
      </Page>
    );
  }
  const s = register.summary;
  const withExceptions = register.rows.filter(r => r.exceptions.length > 0);
  const byKey = new Map(register.rows.map(r => [pullKey(r.repo, r.number), r]));
  const sampled = register.sample.picked.map(p => byKey.get(pullKey(p.repo, p.number))).filter((r): r is RegisterRow => !!r);
  const notRead = register.coverage.filter(c => !c.read || c.truncated);
  return (
    <Page size="A4" style={S.page} wrap>
      <Text style={S.pageHeading}>5. Change-Management Register ({control})</Text>
      <Text style={S.pageSubheading}>
        Every pull request merged in the period: who approved it before the merge, whether TrustLedger scanned it, and
        whether its HIGH/CRITICAL files were signed off before it merged. The full register, one row per pull request
        with its SHA-256, is in the signed evidence record supplied with this report.
      </Text>

      <View style={S.metricsRow}>
        <View style={S.metricCard}><Text style={S.metricValue}>{s.merged}</Text><Text style={S.metricLabel}>Pull requests merged</Text></View>
        <View style={S.metricCard}><Text style={S.metricValue}>{s.approved_before_merge}</Text><Text style={S.metricLabel}>Approved before merge</Text></View>
        <View style={S.metricCard}><Text style={S.metricValue}>{s.scanned}</Text><Text style={S.metricLabel}>Scanned before merge</Text></View>
        <View style={S.metricCard}><Text style={[S.metricValue, s.with_exceptions ? S.high : {}]}>{s.with_exceptions}</Text><Text style={S.metricLabel}>With exceptions</Text></View>
      </View>

      {register.complete ? (
        <View style={S.infoBox}>
          <Text style={S.infoText}>Population complete: all {register.coverage.length} connected repositories were read from GitHub in full.</Text>
        </View>
      ) : (
        <View style={S.scopeBox}>
          <Text style={S.scopeLabel}>POPULATION INCOMPLETE</Text>
          {notRead.map(c => <Text key={c.repo} style={S.scopeText}>• {c.repo}: {c.reason ?? "not read in full"}</Text>)}
          <Text style={S.scopeText}>Changes in these repositories may be missing from the register and the sample.</Text>
        </View>
      )}

      <View style={S.section}>
        <Text style={S.sectionTitle}>Exceptions ({withExceptions.length})</Text>
        {withExceptions.length === 0 ? (
          <View style={S.gapOkBox}><Text style={S.gapOkText}>✓ Every merged pull request has the evidence above</Text></View>
        ) : (
          <>
            <RegisterTable rows={withExceptions.slice(0, MAX_EXCEPTION_ROWS)} />
            {withExceptions.length > MAX_EXCEPTION_ROWS && (
              <Text style={S.ctrlEvidenceRow}>+ {withExceptions.length - MAX_EXCEPTION_ROWS} more in the evidence record.</Text>
            )}
            <Text style={S.ctrlEvidenceRow}>&quot;Approved on an earlier commit&quot; is an observation (later commits were not re-approved); the others are exceptions.</Text>
          </>
        )}
      </View>

      {(register.branch_protection ?? []).length > 0 && (
        <View style={S.section}>
          <Text style={S.sectionTitle}>How merging is protected (default branch, as of report generation)</Text>
          <Text style={[S.ctrlEvidenceRow, { marginBottom:6 }]}>
            The control&apos;s design, read from GitHub when this report was generated -- a snapshot, not a history of the settings.
          </Text>
          <View style={S.table}>
            <View style={S.tableHead}>
              <Text style={[S.th, { flex:1.8 }]}>Repository</Text><Text style={S.th}>PR required</Text><Text style={[S.th, { flex:0.8 }]}>Approvals</Text>
              <Text style={S.th}>Stale approvals dismissed</Text><Text style={[S.th, { flex:1.4 }]}>Required checks</Text><Text style={S.th}>Force push blocked</Text>
            </View>
            {register.branch_protection!.map((p, i) => (
              <View key={p.repo} style={[S.tableRow, i % 2 ? S.tableRowAlt : {}]} wrap={false}>
                <Text style={[S.td, { flex:1.8 }]}>{p.repo}{p.branch ? ` (${p.branch})` : ""}</Text>
                <Text style={S.td}>{protectionValue(p.pull_request_required)}</Text>
                <Text style={[S.td, { flex:0.8 }]}>{protectionValue(p.approvals_required)}</Text>
                <Text style={S.td}>{protectionValue(p.dismiss_stale_approvals)}</Text>
                <Text style={[S.td, { flex:1.4 }]}>{p.required_status_checks.join(", ") || "—"}</Text>
                <Text style={S.td}>{protectionValue(p.force_push_blocked)}</Text>
              </View>
            ))}
          </View>
          {register.branch_protection!.flatMap(p => p.limits.map(l => (
            <Text key={`${p.repo}${l}`} style={[S.ctrlEvidenceRow, S.statusPartial]}>{p.repo}: {l}</Text>
          )))}
        </View>
      )}

      <View style={S.section}>
        <Text style={S.sectionTitle}>Auditor sample ({sampled.length} of {s.merged})</Text>
        <Text style={[S.ctrlEvidenceRow, { marginBottom:6 }]}>
          Drawn at random with seed {register.sample.seed} (this report&apos;s id). Anyone with the evidence record draws
          the same {sampled.length} pull requests; the auditor may draw another sample with a seed of their own.
        </Text>
        {sampled.length > 0 ? <RegisterTable rows={sampled} /> : <Text style={S.ctrlEvidenceRow}>No pull requests were merged in the period.</Text>}
      </View>
      {footer}
    </Page>
  );
}

// ── Document component ─────────────────────────────────────────────────────────

export function buildReportDocument({ data, signature }: { data: ReportData; signature: ReportSignature }) {
  const fw = FRAMEWORKS.find(f => f.id === (data.framework_id ?? normalizeFrameworkId(data.framework)));
  const meta = {
    full: data.evidence_scope?.name ?? fw?.name ?? data.framework,
    standard: data.evidence_scope?.standard ?? fw?.standard ?? "—",
    certBody: ASSESSOR[fw?.id ?? ""] ?? "—",
    scopeNote: data.evidence_scope?.scope ?? fw?.scope ?? "This report shows evidence recorded by TrustLedger for the period below. It is not a substitute for a formal audit.",
  };
  const topScans = data.scans
    .filter(s => s.overall_risk === "CRITICAL" || s.overall_risk === "HIGH")
    .slice(0, 15);
  const recentAttests = data.attestations.slice(0, 20);
  const rb = data.risk_breakdown;
  const rbTotal = Math.max(1, rb.critical + rb.high + rb.medium + rb.low);
  const riskRows: Array<{ label: string; count: number; color: string }> = [
    { label:"CRITICAL", count:rb.critical, color:"#7c3aed" },
    { label:"HIGH",     count:rb.high,     color:"#ea580c" },
    { label:"MEDIUM",   count:rb.medium,   color:"#d97706" },
    { label:"LOW",      count:rb.low,      color:"#15803d" },
  ];
  // the register page is section 5 when present; the sections after it move down one
  const cr = data.change_register;
  const n = cr ? 1 : 0;

  return (
    <Document>
      {/* ── Page 1: Cover, Scope, Report Reference, Executive Summary ──────── */}
      <Page size="A4" style={S.page}>
        <View style={S.coverBg} fixed />

        <View style={S.logo}>
          {/* eslint-disable-next-line jsx-a11y/alt-text -- react-pdf Image has no alt */}
          <Image src={WORDMARK_PNG_DATA_URI} style={{ width: 170, height: 170 / WORDMARK_ASPECT, marginBottom: 10 }} />
          <Text style={S.coverTitle}>{meta.full} Evidence Assessment</Text>
          <Text style={S.coverOrg}>{data.org.name}  ·  {data.org.github_org ?? data.org.slug}</Text>
        </View>

        <View style={S.infoBox}>
          <Text style={S.infoText}>
            Audit period: {fmtDate(data.period_start)} — {fmtDate(data.period_end)}{"\n"}
            Standard: {meta.standard}{"\n"}
            Certifying body: {meta.certBody}{"\n"}
            Generated: {fmtDate(data.generated_at)} by TrustLedger AI Provenance Platform
          </Text>
        </View>

        <View style={S.scopeBox}>
          <Text style={S.scopeLabel}>SCOPE &amp; LIMITATIONS</Text>
          <Text style={S.scopeText}>{meta.scopeNote}</Text>
          {(data.not_covered ?? fw?.not_covered ?? []).length > 0 && (
            <>
              <Text style={[S.scopeLabel, { marginTop: 5 }]}>NOT COVERED BY THIS EVIDENCE</Text>
              {(data.not_covered ?? fw?.not_covered ?? []).map((n, i) => <Text key={i} style={S.scopeText}>• {n}</Text>)}
            </>
          )}
        </View>

        {/* Report Reference */}
        <View style={S.section}>
          <Text style={S.sectionTitle}>1. Report Reference</Text>
          <View style={S.refBox}>
            <View style={S.refItem}><Text style={S.refLabel}>REPORT ID</Text><Text style={S.refValue}>{data.report_id}</Text></View>
            <View style={S.refItem}><Text style={S.refLabel}>FRAMEWORK</Text><Text style={S.refValue}>{meta.full}</Text></View>
            <View style={S.refItem}><Text style={S.refLabel}>ORGANISATION</Text><Text style={S.refValue}>{data.org.name}</Text></View>
            <View style={S.refItem}><Text style={S.refLabel}>PERIOD START</Text><Text style={S.refValue}>{fmtDate(data.period_start)}</Text></View>
            <View style={S.refItem}><Text style={S.refLabel}>PERIOD END</Text><Text style={S.refValue}>{fmtDate(data.period_end)}</Text></View>
            <View style={S.refItem}><Text style={S.refLabel}>GENERATED BY</Text><Text style={S.refValue}>{data.generated_by}</Text></View>
          </View>
        </View>

        {/* Executive Summary */}
        <View style={S.section}>
          <Text style={S.sectionTitle}>2. Executive Summary</Text>
          <View style={S.metricsRow}>
            <View style={S.metricCard}><Text style={S.metricValue}>{data.metrics.total_scans}</Text><Text style={S.metricLabel}>Total Scans</Text></View>
            <View style={S.metricCard}><Text style={S.metricValue}>{data.metrics.total_files}</Text><Text style={S.metricLabel}>Files Scanned</Text></View>
            <View style={S.metricCard}><Text style={S.metricValue}>{data.metrics.total_attestations}</Text><Text style={S.metricLabel}>Attestations</Text></View>
            <View style={S.metricCard}><Text style={S.metricValue}>{fmtPct(data.metrics.avg_ai_percentage)}</Text><Text style={S.metricLabel}>Avg AI Content</Text></View>
          </View>
          <View style={S.metricsRow}>
            <View style={S.metricCard}><Text style={[S.metricValue, S.critical]}>{data.metrics.critical_findings}</Text><Text style={S.metricLabel}>Critical Findings</Text></View>
            <View style={S.metricCard}><Text style={[S.metricValue, S.high]}>{data.metrics.secrets_detected}</Text><Text style={S.metricLabel}>Secrets Detected</Text></View>
            <View style={S.metricCard}>
              <Text style={S.metricValue}>{data.metrics.high_risk_files > 0 ? `${data.metrics.high_risk_reviewed}/${data.metrics.high_risk_files}` : "N/A"}</Text>
              <Text style={S.metricLabel}>High-risk files reviewed</Text>
            </View>
            <View style={S.metricCard}>
              <Text style={[S.metricValue, data.metrics.self_approvals > 0 ? S.high : {}]}>{data.metrics.self_approvals}</Text>
              <Text style={S.metricLabel}>Self-approvals</Text>
            </View>
          </View>
        </View>

        <PageFooter label={data.report_id.slice(0, 8)} />
      </Page>

      {/* ── Page 2: Risk Overview + High-Risk Scan Results ─────────────────── */}
      <Page size="A4" style={S.page}>
        <Text style={S.pageHeading}>3. Risk Overview</Text>
        <Text style={S.pageSubheading}>Per-file risk classification across every scan in the audit period.</Text>

        <View style={[S.section, { marginTop:0 }]}>
          {riskRows.map(r => (
            <View key={r.label} style={S.riskBarRow}>
              <Text style={S.riskBarLabel}>{r.label}</Text>
              <View style={S.riskBarTrack}>
                <View style={[S.riskBarFill, { width:`${(r.count / rbTotal) * 100}%`, backgroundColor:r.color }]} />
              </View>
              <Text style={S.riskBarCount}>{r.count}</Text>
            </View>
          ))}
        </View>

        {topScans.length > 0 && (
          <View style={S.section}>
            <Text style={S.sectionTitle}>High-Risk Scan Results</Text>
            <View style={S.table}>
              <View style={S.tableHead}>
                <Text style={[S.th, { flex:2 }]}>Repository</Text>
                <Text style={S.th}>Risk</Text>
                <Text style={S.th}>AI Content</Text>
                <Text style={S.th}>Date</Text>
              </View>
              {topScans.map((s, i) => (
                <View key={i} style={[S.tableRow, i % 2 ? S.tableRowAlt : {}]}>
                  <Text style={[S.td, { flex:2 }]}>{s.repo_full_name}</Text>
                  <Text style={[S.td, riskStyle(s.overall_risk)]}>{s.overall_risk}</Text>
                  <Text style={S.td}>{fmtPct(s.total_ai_percentage)}</Text>
                  <Text style={S.td}>{fmtDate(s.created_at)}</Text>
                </View>
              ))}
            </View>
          </View>
        )}

        <PageFooter label={data.report_id.slice(0, 8)} />
      </Page>

      {/* ── Page 3: Compliance Mapping ──────────────────────────────────────── */}
      <Page size="A4" style={S.page} wrap>
        <Text style={S.pageHeading}>4. Control Evidence</Text>
        <Text style={S.pageSubheading}>
          What TrustLedger&apos;s own records show for each {meta.full} control in scope, measured from the
          period&apos;s scans, reviews, findings and audit log. A status describes the evidence; it is not an
          auditor&apos;s conclusion that the control is effective.
        </Text>

        {data.compliance.map(c => (
          <View key={c.control_id} style={S.ctrlCard} wrap={false}>
            <View style={S.ctrlHeadRow}>
              <View style={{ flexDirection:"row", alignItems:"center", flex:1 }}>
                <Text style={S.ctrlId}>{c.control_id}</Text>
                <Text style={S.ctrlName}>{c.control_name}</Text>
              </View>
              <Text style={[S.ctrlEvidenceRow, statusStyle(c.status), { marginLeft:8, marginTop:0 }]}>{statusLabel(c.status)}</Text>
            </View>
            {c.statement && (
              <>
                <Text style={S.ctrlEvidenceRow}>Control: {c.statement}</Text>
                <Text style={S.ctrlEvidenceRow}>Owner: {c.owner}  ·  Frequency: {c.frequency}</Text>
                <Text style={S.ctrlEvidenceRow}>Test: {c.test}</Text>
              </>
            )}
            {c.partial && <Text style={[S.ctrlEvidenceRow, S.statusPartial]}>Partial coverage: {c.partial}</Text>}
            {c.checks.map((k, i) => (
              <View key={i}>
                <Text style={S.ctrlEvidenceRow}>• {k.label}{k.basis === "current" ? ` (as of ${fmtDate(data.generated_at)}, not across the period)` : ""}: {k.summary}</Text>
                {k.gaps.map((g, j) => (
                  <Text key={j} style={[S.ctrlEvidenceRow, S.statusPartial, { marginLeft:8 }]}>Gap: {g}</Text>
                ))}
              </View>
            ))}
          </View>
        ))}

        {data.framework_view && <FrameworkViewPdf view={data.framework_view} />}

        <PageFooter label={data.report_id.slice(0, 8)} />
      </Page>

      {cr &&<ChangeRegisterPage register={cr} control={REGISTER_CONTROL[fw?.id ?? ""] ?? "change control"} reportId={data.report_id} />}

      {/* ── Page 4: Attestation Records + Gap Analysis ──────────────────────── */}
      <Page size="A4" style={S.page}>
        <Text style={S.sectionTitle}>{5 + n}. Attestation Evidence ({recentAttests.length} records)</Text>
        <View style={S.table}>
          <View style={S.tableHead}>
            <Text style={[S.th, { flex:2 }]}>File</Text>
            <Text style={S.th}>Risk</Text>
            <Text style={[S.th, { flex:1.5 }]}>Reviewer</Text>
            <Text style={S.th}>Date</Text>
          </View>
          {recentAttests.map((a, i) => (
            <View key={i} style={[S.tableRow, i % 2 ? S.tableRowAlt : {}]}>
              <Text style={[S.td, { flex:2 }]}>{shortPath(a.file_path)}</Text>
              <Text style={[S.td, riskStyle(a.risk_score)]}>{a.risk_score}</Text>
              <Text style={[S.td, { flex:1.5 }]}>{a.reviewer_email}</Text>
              <Text style={S.td}>{fmtDate(a.created_at)}</Text>
            </View>
          ))}
        </View>

        <View style={S.section}>
          <Text style={S.sectionTitle}>{6 + n}. Gap Analysis &amp; Remediation</Text>
          {data.gaps.length === 0 ? (
            <View style={S.gapOkBox}>
              <Text style={S.gapOkText}>✓ No open gaps identified for this audit period</Text>
              <Text style={[S.ctrlEvidenceRow, { marginTop:3 }]}>All HIGH and CRITICAL risk files were attested within the audit period.</Text>
            </View>
          ) : (
            <View style={S.table}>
              <View style={S.tableHead}>
                <Text style={[S.th, { flex:2 }]}>File</Text>
                <Text style={[S.th, { flex:1.3 }]}>Repository</Text>
                <Text style={S.th}>PR</Text>
                <Text style={S.th}>Risk</Text>
                <Text style={S.th}>AI %</Text>
              </View>
              {data.gaps.map((g, i) => (
                <View key={i} style={[S.tableRow, i % 2 ? S.tableRowAlt : {}]}>
                  <Text style={[S.td, { flex:2 }]}>{shortPath(g.file_path)}</Text>
                  <Text style={[S.td, { flex:1.3 }]}>{g.repo}</Text>
                  <Text style={S.td}>{g.pr_number > 0 ? `#${g.pr_number}` : "—"}</Text>
                  <Text style={[S.td, riskStyle(g.risk_score)]}>{g.risk_score}</Text>
                  <Text style={S.td}>{fmtPct(g.ai_percentage)}</Text>
                </View>
              ))}
            </View>
          )}
        </View>

        <PageFooter label={data.report_id.slice(0, 8)} />
      </Page>

      {/* ── Page 5: Secret Findings + Management Assertion + Signature ──────── */}
      <Page size="A4" style={S.page}>
        {data.secrets.length > 0 && (
          <View style={{ marginBottom:8 }}>
            <Text style={S.sectionTitle}>{7 + n}. Secret Findings</Text>
            <View style={S.table}>
              <View style={S.tableHead}>
                <Text style={[S.th, { flex:2 }]}>File</Text>
                <Text style={S.th}>Type</Text>
                <Text style={S.th}>Severity</Text>
                <Text style={S.th}>Status</Text>
              </View>
              {data.secrets.slice(0,20).map((s, i) => (
                <View key={i} style={[S.tableRow, i % 2 ? S.tableRowAlt : {}]}>
                  <Text style={[S.td, { flex:2 }]}>{shortPath(s.file_path)}</Text>
                  <Text style={S.td}>{s.label}</Text>
                  <Text style={[S.td, riskStyle(s.severity)]}>{s.severity}</Text>
                  <Text style={S.td}>{s.status}</Text>
                </View>
              ))}
            </View>
          </View>
        )}

        <View style={S.section}>
          <Text style={S.sectionTitle}>{(data.secrets.length > 0 ? 8 : 7) + n}. Evidence Summary for Management</Text>
          <View style={S.assertionBox}>
            <View style={S.assertionHead}>
              <Text style={{ fontSize:8, fontFamily:"Helvetica-Bold", color:"#1e293b" }}>Management review of this evidence</Text>
              <Text style={{ fontSize:7.5, color:"#64748b", marginTop:2 }}>
                For the period {fmtDate(data.period_start)} to {fmtDate(data.period_end)} · {meta.standard}
              </Text>
            </View>
            <View style={S.assertionBody}>
              <Text style={S.assertionP}>
                Management of {data.org.name} has reviewed the evidence in this report for the {meta.full} controls
                listed under Control Evidence, for the period {fmtDate(data.period_start)} to {fmtDate(data.period_end)},
                including the gaps and exceptions recorded there. This is a review of evidence for those controls only;
                it is not a management assertion over the whole {meta.full} scope and does not replace the independent
                audit or certification described under Scope &amp; Limitations on page 1.
              </Text>
              <Text style={S.assertionP}>
                Pull requests in connected repositories were scanned automatically, and reviewer sign-offs on
                high-risk files were recorded with the reviewer&apos;s identity. The evidence record this report is
                rendered from is signed (see Document Signature below) and supplied with it.
              </Text>
              <View style={{ flexDirection:"row", gap:24, marginTop:4 }}>
                <View style={{ flex:1 }}>
                  <View style={S.sigLine} />
                  <Text style={S.sigCaption}>Security Lead, {data.org.name}</Text>
                </View>
                <View style={{ flex:1 }}>
                  <View style={S.sigLine} />
                  <Text style={S.sigCaption}>Chief Information Security Officer</Text>
                </View>
              </View>
            </View>
          </View>
        </View>

        <View style={S.infoBox}>
          <Text style={S.infoText}>
            This report was automatically generated by TrustLedger and contains cryptographically
            signed attestation records. Each attestation payload hash is stored immutably in the
            TrustLedger database with a tamper-evident audit log chain. This document may be
            submitted to {meta.certBody} as supporting evidence for the narrow control scope
            described above — it is not a complete {meta.full} audit package on its own.
          </Text>
        </View>

        <View style={S.sigBox}>
          <Text style={S.sigLabel}>DOCUMENT SIGNATURE — {signature.algorithm}</Text>
          <Text style={S.sigNote}>Evidence record SHA-256</Text>
          <Text style={S.sigValue}>{signature.record_sha256}</Text>
          {signature.algorithm === "Ed25519" && <Text style={S.sigNote}>Signing key id: {signature.key_id}</Text>}
          <Text style={S.sigNote}>Signature</Text>
          <Text style={S.sigValue}>{signature.value}</Text>
          <Text style={S.sigNote}>
            {signature.algorithm === "Ed25519"
              ? "This PDF is rendered from the evidence record supplied with it (trustledger-…-evidence.json). To verify, " +
                "open /verify on the TrustLedger site and choose that file (it is checked in the browser, not uploaded); or " +
                "(1) check that the SHA-256 of the record's canonical JSON matches the value above; (2) verify the signature " +
                "with scripts/verify-trust-record.mjs and the public key published at " +
                "/.well-known/trustledger-export-signing-key, whose key id must equal the one above. A changed record, or " +
                "one signed with any other key, fails."
              : "Signed with TrustLedger's shared HMAC key over the canonical JSON of the evidence record supplied with " +
                "this PDF (its SHA-256 is above). An HMAC can only be checked by the issuing server; configure an Ed25519 " +
                "signing key for reports anyone can verify."}
          </Text>
        </View>

        <PageFooter label={data.report_id.slice(0, 8)} />
      </Page>
    </Document>
  );
}
