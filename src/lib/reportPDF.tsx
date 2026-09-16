/**
 * PDF Report Document — React PDF
 * Generates signed AI code review evidence assessments scoped to a single
 * framework's narrow control set (SOC 2, EU AI Act, PCI-DSS, ISO 27001) --
 * not a full compliance report. See each framework's scopeNote.
 */

import React from "react";
import {
  Document, Page, Text, View, StyleSheet,
} from "@react-pdf/renderer";

// ── Styles ─────────────────────────────────────────────────────────────────────

const S = StyleSheet.create({
  page: { fontFamily:"Helvetica", fontSize:9, padding:40, color:"#1e293b" },

  // Cover
  coverBg:    { position:"absolute", top:0, left:0, right:0, height:200, backgroundColor:"#0f172a" },
  logo:       { marginTop:60, marginBottom:8 },
  logoText:   { fontSize:22, fontFamily:"Helvetica-Bold", color:"#ffffff", letterSpacing:1 },
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
  ctrlScore:   { fontSize:9, fontFamily:"Helvetica-Bold" },
  ctrlBarTrack:{ height:5, backgroundColor:"#f1f5f9", borderRadius:3, overflow:"hidden", marginBottom:6 },
  ctrlBarFill: { height:5, borderRadius:3 },
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

function statusLabel(status: string) {
  if (status === "pass")    return "SATISFIED";
  if (status === "partial") return "PARTIAL";
  if (status === "fail")    return "NOT MET";
  return "NOT TESTED";
}

function scoreColor(score: number) {
  if (score >= 80) return "#15803d";
  if (score >= 50) return "#d97706";
  return "#dc2626";
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
  evidence:     Array<{ description: string; count: number; source: string }>;
}

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
  period_start:  string;
  period_end:    string;
  generated_at:  string;
  generated_by:  string;
  metrics: {
    total_scans:        number;
    total_files:        number;
    total_attestations: number;
    critical_findings:  number;
    secrets_detected:   number;
    avg_ai_percentage:  number;
  };
  risk_breakdown: { critical: number; high: number; medium: number; low: number };
  gaps:           GapFile[];
  compliance:     ComplianceControl[];
  scans:        Array<{ repo_full_name: string; overall_risk: string; total_ai_percentage: number; created_at: string }>;
  attestations: Array<{ file_path: string; risk_score: string; reviewer_email: string; created_at: string }>;
  secrets:      Array<{ file_path: string; severity: string; label: string; status: string; created_at: string }>;
}

// ── Framework metadata ─────────────────────────────────────────────────────────

const FRAMEWORK_META: Record<string, { full: string; certBody: string; standard: string; scopeNote: string }> = {
  SOC2: {
    full: "SOC 2 Type II", certBody: "AICPA-accredited CPA firm", standard: "Trust Services Criteria 2017",
    scopeNote: "This report evidences AI-generated code review controls only (Trust Services Criteria CC6.1, CC6.2, CC7.2, CC8.1, A1.2). It does not cover the full Trust Services Criteria and is not a substitute for a SOC 2 Type II audit performed by a licensed CPA firm.",
  },
  EUAI: {
    full: "EU AI Act", certBody: "EU Notified Body", standard: "Regulation (EU) 2024/1689",
    scopeNote: "This report evidences AI system provenance and human oversight for AI-generated source code only (Articles 9, 10, 13, 14, 17). It does not perform risk-tier classification or conformity assessment, and is not a substitute for a full EU AI Act compliance assessment.",
  },
  PCIDSS: {
    full: "PCI DSS v4.0", certBody: "QSA Assessor", standard: "PCI Security Standards Council Req 6",
    scopeNote: "This report evidences secure software development practices only (Requirement 6.2–6.4) as they relate to AI-generated code. It does not cover network segmentation, cardholder data encryption, physical security, ASV scanning, or PCI-DSS's other requirements, and is not a substitute for a Report on Compliance (ROC) or SAQ performed by a Qualified Security Assessor. Relevant only to organisations with a cardholder data environment.",
  },
  ISO27001: {
    full: "ISO/IEC 27001:2022", certBody: "Accredited Certification Body", standard: "ISO/IEC 27001:2022 Annex A",
    scopeNote: "This report evidences AI-generated code review against a subset of Annex A controls only (A.8.25, A.8.26, A.8.28, A.8.30, A.5.33). It does not cover the full ISMS scope and is not a substitute for a certification audit performed by an accredited certification body.",
  },
};

// ── Document component ─────────────────────────────────────────────────────────

export function buildReportDocument({ data, signature }: { data: ReportData; signature: string }) {
  const meta = FRAMEWORK_META[data.framework] ?? {
    full: data.framework, certBody:"—", standard:"—",
    scopeNote: "This report evidences AI-generated code review activity for the period below. It is not a substitute for a formal audit.",
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

  return (
    <Document>
      {/* ── Page 1: Cover, Scope, Report Reference, Executive Summary ──────── */}
      <Page size="A4" style={S.page}>
        <View style={S.coverBg} fixed />

        <View style={S.logo}>
          <Text style={S.logoText}>TrustLedger</Text>
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
              <Text style={S.metricValue}>{data.metrics.total_scans > 0 ? fmtPct(data.metrics.total_attestations / Math.max(data.metrics.total_files, 1)) : "N/A"}</Text>
              <Text style={S.metricLabel}>Attestation Coverage</Text>
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
        <Text style={S.pageHeading}>4. Compliance Mapping</Text>
        <Text style={S.pageSubheading}>
          Real, live-computed evidence per {meta.full} control in scope for this report — the same engine
          driving the Compliance and Evidence pages, not a separate estimate.
        </Text>

        {data.compliance.map(c => (
          <View key={c.control_id} style={S.ctrlCard} wrap={false}>
            <View style={S.ctrlHeadRow}>
              <View style={{ flexDirection:"row", alignItems:"center", flex:1 }}>
                <Text style={S.ctrlId}>{c.control_id}</Text>
                <Text style={S.ctrlName}>{c.control_name}</Text>
              </View>
              <Text style={[S.ctrlScore, { color:scoreColor(c.score) }]}>{Math.round(c.score)}%</Text>
              <Text style={[S.ctrlEvidenceRow, statusStyle(c.status), { marginLeft:8, marginTop:0 }]}>{statusLabel(c.status)}</Text>
            </View>
            <View style={S.ctrlBarTrack}>
              <View style={[S.ctrlBarFill, { width:`${Math.round(c.score)}%`, backgroundColor:scoreColor(c.score) }]} />
            </View>
            {c.evidence.map((e, i) => (
              <Text key={i} style={S.ctrlEvidenceRow}>
                • {e.description} — {e.count} record{e.count === 1 ? "" : "s"} ({e.source})
              </Text>
            ))}
          </View>
        ))}

        <PageFooter label={data.report_id.slice(0, 8)} />
      </Page>

      {/* ── Page 4: Attestation Records + Gap Analysis ──────────────────────── */}
      <Page size="A4" style={S.page}>
        <Text style={S.sectionTitle}>5. Attestation Evidence ({recentAttests.length} records)</Text>
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
          <Text style={S.sectionTitle}>6. Gap Analysis &amp; Remediation</Text>
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
            <Text style={S.sectionTitle}>7. Secret Findings</Text>
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
          <Text style={S.sectionTitle}>{data.secrets.length > 0 ? "8." : "7."} Management Assertion</Text>
          <View style={S.assertionBox}>
            <View style={S.assertionHead}>
              <Text style={{ fontSize:8, fontFamily:"Helvetica-Bold", color:"#1e293b" }}>Management Representation Letter</Text>
              <Text style={{ fontSize:7.5, color:"#64748b", marginTop:2 }}>
                For the period {fmtDate(data.period_start)} to {fmtDate(data.period_end)} · {meta.standard}
              </Text>
            </View>
            <View style={S.assertionBody}>
              <Text style={S.assertionP}>
                Management of {data.org.name} asserts that, to the best of its knowledge and belief, the
                controls described in this report were suitably designed and operating effectively throughout
                the period {fmtDate(data.period_start)} to {fmtDate(data.period_end)} with respect to the specific
                {" "}{meta.full} criteria listed in Compliance Mapping above. This assertion does not extend to
                any {meta.full} requirement outside that scope — see Scope &amp; Limitations on page 1.
              </Text>
              <Text style={S.assertionP}>
                All AI-generated code changes were subjected to automated risk scanning, and HIGH/CRITICAL-risk
                files required named reviewer attestation prior to deployment. The attestation records and scan
                logs included in this report constitute the evidence base for this assertion; this document
                additionally carries the cryptographic signature below over its exact contents.
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
          <Text style={S.sigLabel}>DOCUMENT SIGNATURE — HMAC-SHA256</Text>
          <Text style={S.sigValue}>{signature}</Text>
          <Text style={S.sigNote}>
            Computed over this report&apos;s exact contents (org, framework, period, metrics, risk
            breakdown, compliance mapping, scans, attestations, secrets) using TrustLedger&apos;s export
            signing key. Recomputing this HMAC over an altered copy of this data will not match —
            verify by requesting the same report regeneration from TrustLedger and comparing signatures.
          </Text>
        </View>

        <PageFooter label={data.report_id.slice(0, 8)} />
      </Page>
    </Document>
  );
}
