/**
 * PDF Report Document — React PDF
 * Generates signed AI code review evidence assessments scoped to a single
 * framework's narrow control set (SOC 2, EU AI Act, PCI-DSS, ISO 27001) --
 * not a full compliance report. See each framework's scopeNote.
 */

import React from "react";
import {
  Document, Page, Text, View, StyleSheet, Font,
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
  section:        { marginTop:20 },
  sectionTitle:   { fontSize:11, fontFamily:"Helvetica-Bold", color:"#0f172a",
                    borderBottomWidth:1, borderBottomColor:"#e2e8f0",
                    paddingBottom:4, marginBottom:10 },

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

  // Risk badges
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

function fmtDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-GB", { day:"numeric", month:"short", year:"numeric" });
}

function fmtPct(n: number) { return `${(n * 100).toFixed(1)}%`; }

// ── Report data type ───────────────────────────────────────────────────────────

interface ReportData {
  org:           { name: string; slug: string; github_org: string | null };
  framework:     string;
  period_start:  string;
  period_end:    string;
  generated_at:  string;
  metrics: {
    total_scans:        number;
    total_files:        number;
    total_attestations: number;
    critical_findings:  number;
    secrets_detected:   number;
    avg_ai_percentage:  number;
  };
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
  const meta = FRAMEWORK_META[data.framework] ?? { full: data.framework, certBody:"—", standard:"—" };
  const topScans = data.scans
    .filter(s => s.overall_risk === "CRITICAL" || s.overall_risk === "HIGH")
    .slice(0, 15);
  const recentAttests = data.attestations.slice(0, 20);

  return (
    <Document>
      {/* ── Cover page ────────────────────────────────────────────────────── */}
      <Page size="A4" style={S.page}>
        <View style={S.coverBg} />

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

        {/* Metrics */}
        <View style={S.section}>
          <Text style={S.sectionTitle}>Executive Summary</Text>
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

        {/* High-risk scans */}
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

        <View style={S.footer}>
          <Text style={S.footerText}>TrustLedger AI Governance Platform  ·  Confidential</Text>
          <Text style={S.footerText}>Generated {fmtDate(data.generated_at)}</Text>
        </View>
      </Page>

      {/* ── Attestation evidence page ──────────────────────────────────────── */}
      <Page size="A4" style={S.page}>
        <Text style={S.sectionTitle}>Attestation Evidence ({recentAttests.length} records)</Text>
        <View style={S.table}>
          <View style={S.tableHead}>
            <Text style={[S.th, { flex:2 }]}>File</Text>
            <Text style={S.th}>Risk</Text>
            <Text style={[S.th, { flex:1.5 }]}>Reviewer</Text>
            <Text style={S.th}>Date</Text>
          </View>
          {recentAttests.map((a, i) => (
            <View key={i} style={[S.tableRow, i % 2 ? S.tableRowAlt : {}]}>
              <Text style={[S.td, { flex:2 }]}>{a.file_path.split("/").slice(-2).join("/")}</Text>
              <Text style={[S.td, riskStyle(a.risk_score)]}>{a.risk_score}</Text>
              <Text style={[S.td, { flex:1.5 }]}>{a.reviewer_email}</Text>
              <Text style={S.td}>{fmtDate(a.created_at)}</Text>
            </View>
          ))}
        </View>

        {data.secrets.length > 0 && (
          <View style={[S.section, { marginTop:20 }]}>
            <Text style={S.sectionTitle}>Secret Findings</Text>
            <View style={S.table}>
              <View style={S.tableHead}>
                <Text style={[S.th, { flex:2 }]}>File</Text>
                <Text style={S.th}>Type</Text>
                <Text style={S.th}>Severity</Text>
                <Text style={S.th}>Status</Text>
              </View>
              {data.secrets.slice(0,20).map((s, i) => (
                <View key={i} style={[S.tableRow, i % 2 ? S.tableRowAlt : {}]}>
                  <Text style={[S.td, { flex:2 }]}>{s.file_path.split("/").slice(-2).join("/")}</Text>
                  <Text style={S.td}>{s.label}</Text>
                  <Text style={[S.td, riskStyle(s.severity)]}>{s.severity}</Text>
                  <Text style={S.td}>{s.status}</Text>
                </View>
              ))}
            </View>
          </View>
        )}

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
            Computed over this report&apos;s exact contents (org, framework, period, metrics, scans,
            attestations, secrets) using TrustLedger&apos;s export signing key. Recomputing this HMAC
            over an altered copy of this data will not match — verify by requesting the same report
            regeneration from TrustLedger and comparing signatures.
          </Text>
        </View>

        <View style={S.footer}>
          <Text style={S.footerText}>TrustLedger AI Governance Platform  ·  Confidential</Text>
          <Text style={S.footerText}>Page 2 of 2</Text>
        </View>
      </Page>
    </Document>
  );
}
