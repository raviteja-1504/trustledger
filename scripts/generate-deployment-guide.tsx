/**
 * TrustLedger Deployment Guide — PDF generator
 * Run: npx tsx scripts/generate-deployment-guide.tsx
 * Output: deployment-guide.pdf (project root)
 */

import React from "react";
import {
  Document,
  Page,
  Text,
  View,
  StyleSheet,
  renderToFile,
  Font,
  Link,
} from "@react-pdf/renderer";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, "..", "deployment-guide.pdf");

// ── Palette ───────────────────────────────────────────────────────────────────

const C = {
  indigo:      "#6366f1",
  indigoDark:  "#4338ca",
  violet:      "#7c3aed",
  gray900:     "#111827",
  gray700:     "#374151",
  gray500:     "#6b7280",
  gray400:     "#9ca3af",
  gray200:     "#e5e7eb",
  gray100:     "#f3f4f6",
  gray50:      "#f9fafb",
  white:       "#ffffff",
  green:       "#15803d",
  greenBg:     "#f0fdf4",
  greenBorder: "#bbf7d0",
  amber:       "#b45309",
  amberBg:     "#fffbeb",
  amberBorder: "#fde68a",
  red:         "#be123c",
  redBg:       "#fff1f2",
  blue:        "#1d4ed8",
  blueBg:      "#eff6ff",
  code:        "#1e293b",
  codeBg:      "#0f172a",
};

// ── Styles ────────────────────────────────────────────────────────────────────

const s = StyleSheet.create({
  page: {
    fontFamily:      "Helvetica",
    fontSize:         10,
    color:            C.gray700,
    backgroundColor:  C.white,
    paddingTop:       48,
    paddingBottom:    52,
    paddingHorizontal: 48,
  },

  // Cover
  coverPage: {
    fontFamily:       "Helvetica",
    backgroundColor:  C.codeBg,
    paddingTop:       80,
    paddingBottom:    60,
    paddingHorizontal: 60,
    justifyContent:   "space-between",
  },
  coverTop: { flex: 1, justifyContent: "center" },
  coverBadge: {
    backgroundColor: C.indigo,
    borderRadius:    6,
    paddingHorizontal: 10,
    paddingVertical:   4,
    alignSelf:       "flex-start",
    marginBottom:    24,
  },
  coverBadgeText: { color: C.white, fontSize: 9, fontFamily: "Helvetica-Bold", letterSpacing: 1.5 },
  coverTitle: { fontSize: 32, fontFamily: "Helvetica-Bold", color: C.white, lineHeight: 1.2, marginBottom: 12 },
  coverSub:   { fontSize: 13, color: "rgba(165,180,252,0.8)", lineHeight: 1.5, maxWidth: 400 },
  coverMeta:  { flexDirection: "row", gap: 24, marginTop: 40 },
  coverMetaItem: { flexDirection: "column", gap: 2 },
  coverMetaLabel: { fontSize: 8, color: "rgba(165,180,252,0.5)", fontFamily: "Helvetica-Bold", letterSpacing: 0.8 },
  coverMetaValue: { fontSize: 11, color: "rgba(165,180,252,0.9)" },
  coverBottom: { borderTopColor: "rgba(99,102,241,0.3)", borderTopWidth: 1, paddingTop: 20 },
  coverBottomText: { fontSize: 9, color: "rgba(165,180,252,0.4)" },

  // Header / Footer
  pageHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 28, paddingBottom: 12, borderBottomColor: C.gray200, borderBottomWidth: 1 },
  pageHeaderTitle: { fontSize: 8, color: C.gray400, fontFamily: "Helvetica-Bold", letterSpacing: 0.6 },
  pageHeaderSection: { fontSize: 8, color: C.indigo, fontFamily: "Helvetica-Bold" },
  footer: { position: "absolute", bottom: 20, left: 48, right: 48, flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  footerText: { fontSize: 8, color: C.gray400 },

  // TOC
  tocTitle: { fontSize: 22, fontFamily: "Helvetica-Bold", color: C.gray900, marginBottom: 6 },
  tocSub: { fontSize: 11, color: C.gray500, marginBottom: 32 },
  tocRow: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", paddingVertical: 7, borderBottomColor: C.gray100, borderBottomWidth: 1 },
  tocNum:  { fontSize: 10, color: C.indigo, fontFamily: "Helvetica-Bold", width: 24 },
  tocLabel: { fontSize: 10, color: C.gray700, flex: 1 },
  tocPage: { fontSize: 9, color: C.gray400 },

  // Section headings
  sectionBadge: {
    flexDirection: "row", alignItems: "center", gap: 8, marginBottom: 18,
  },
  stepCircle: {
    width: 26, height: 26, borderRadius: 13,
    backgroundColor: C.indigo, justifyContent: "center", alignItems: "center",
  },
  stepNum: { fontSize: 11, fontFamily: "Helvetica-Bold", color: C.white },
  sectionTitle: { fontSize: 18, fontFamily: "Helvetica-Bold", color: C.gray900 },
  sectionSub: { fontSize: 10, color: C.gray500, marginTop: 4, marginBottom: 20, lineHeight: 1.5 },

  h2: { fontSize: 13, fontFamily: "Helvetica-Bold", color: C.gray900, marginTop: 18, marginBottom: 8 },
  h3: { fontSize: 11, fontFamily: "Helvetica-Bold", color: C.gray700, marginTop: 14, marginBottom: 6 },

  p: { fontSize: 10, color: C.gray700, lineHeight: 1.6, marginBottom: 8 },

  // Code blocks
  codeBlock: {
    backgroundColor: C.codeBg, borderRadius: 6, padding: 12,
    marginVertical: 10,
  },
  codeLine: { fontFamily: "Courier", fontSize: 9, color: "#94a3b8", lineHeight: 1.7 },
  codeComment: { fontFamily: "Courier", fontSize: 9, color: "#475569", lineHeight: 1.7 },
  codeCmd:  { fontFamily: "Courier", fontSize: 9, color: "#a5b4fc", lineHeight: 1.7 },

  // Callout boxes
  calloutInfo: { backgroundColor: C.blueBg, borderLeftColor: C.blue, borderLeftWidth: 3, borderRadius: 4, padding: 10, marginVertical: 8 },
  calloutWarn: { backgroundColor: C.amberBg, borderLeftColor: C.amber, borderLeftWidth: 3, borderRadius: 4, padding: 10, marginVertical: 8 },
  calloutOk:   { backgroundColor: C.greenBg, borderLeftColor: C.green, borderLeftWidth: 3, borderRadius: 4, padding: 10, marginVertical: 8 },
  calloutText: { fontSize: 9.5, lineHeight: 1.5 },
  calloutLabel: { fontFamily: "Helvetica-Bold", fontSize: 9, marginBottom: 3 },

  // Table
  table: { marginVertical: 10, borderColor: C.gray200, borderWidth: 1, borderRadius: 6, overflow: "hidden" },
  tableHeaderRow: { flexDirection: "row", backgroundColor: C.gray50, borderBottomColor: C.gray200, borderBottomWidth: 1 },
  tableRow: { flexDirection: "row", borderBottomColor: C.gray100, borderBottomWidth: 1 },
  tableRowLast: { flexDirection: "row" },
  tableCell: { padding: 7, fontSize: 9, color: C.gray700, flex: 1 },
  tableCellHeader: { padding: 7, fontSize: 9, fontFamily: "Helvetica-Bold", color: C.gray900, flex: 1 },
  tableCellMono: { padding: 7, fontSize: 8.5, fontFamily: "Courier", color: C.code, flex: 1 },
  tableCellRequired: { padding: 7, fontSize: 9, fontFamily: "Helvetica-Bold", color: C.green, flex: 0.5 },
  tableCellOptional: { padding: 7, fontSize: 9, color: C.gray500, flex: 0.5 },

  // Bullet list
  li: { flexDirection: "row", marginBottom: 5 },
  liDot: { width: 14, fontSize: 10, color: C.indigo, fontFamily: "Helvetica-Bold" },
  liText: { flex: 1, fontSize: 10, color: C.gray700, lineHeight: 1.5 },

  // Check items
  checkRow: { flexDirection: "row", alignItems: "flex-start", marginBottom: 7, paddingLeft: 4 },
  checkBox: { width: 16, height: 16, borderRadius: 3, borderColor: C.gray200, borderWidth: 1, marginRight: 10, marginTop: 1, justifyContent: "center", alignItems: "center" },
  checkText: { flex: 1, fontSize: 10, color: C.gray700, lineHeight: 1.4 },

  // Divider
  divider: { borderBottomColor: C.gray200, borderBottomWidth: 1, marginVertical: 16 },

  // Chip / badge inline
  chip: { backgroundColor: C.gray100, borderRadius: 4, paddingHorizontal: 6, paddingVertical: 2 },
  chipText: { fontSize: 8, fontFamily: "Courier", color: C.code },
  chipGreen: { backgroundColor: C.greenBg, borderRadius: 4, paddingHorizontal: 6, paddingVertical: 2 },
  chipGreenText: { fontSize: 8, fontFamily: "Helvetica-Bold", color: C.green },
});

// ── Reusable components ───────────────────────────────────────────────────────

function PageHeader({ section }: { section: string }) {
  return (
    <View style={s.pageHeader} fixed>
      <Text style={s.pageHeaderTitle}>TRUSTLEDGER — DEPLOYMENT GUIDE</Text>
      <Text style={s.pageHeaderSection}>{section}</Text>
    </View>
  );
}

function Footer() {
  return (
    <View style={s.footer} fixed>
      <Text style={s.footerText}>TrustLedger · AI Code Governance Platform · Confidential</Text>
      <Text style={s.footerText} render={({ pageNumber, totalPages }) => `${pageNumber} / ${totalPages}`} />
    </View>
  );
}

function SectionHeading({ num, title }: { num: string; title: string }) {
  return (
    <View style={s.sectionBadge}>
      <View style={s.stepCircle}><Text style={s.stepNum}>{num}</Text></View>
      <Text style={s.sectionTitle}>{title}</Text>
    </View>
  );
}

function Code({ children }: { children: React.ReactNode }) {
  return <View style={s.codeBlock}>{children}</View>;
}

function CL({ children, cmd }: { children: string; cmd?: boolean }) {
  return <Text style={cmd ? s.codeCmd : s.codeLine}>{children}</Text>;
}

function Callout({ type, label, children }: { type: "info" | "warn" | "ok"; label: string; children: string }) {
  const boxStyle = type === "warn" ? s.calloutWarn : type === "ok" ? s.calloutOk : s.calloutInfo;
  const labelColor = type === "warn" ? C.amber : type === "ok" ? C.green : C.blue;
  return (
    <View style={boxStyle}>
      <Text style={[s.calloutLabel, { color: labelColor }]}>{label}</Text>
      <Text style={s.calloutText}>{children}</Text>
    </View>
  );
}

function Bullet({ children }: { children: string }) {
  return (
    <View style={s.li}>
      <Text style={s.liDot}>•</Text>
      <Text style={s.liText}>{children}</Text>
    </View>
  );
}

function CheckItem({ children }: { children: string }) {
  return (
    <View style={s.checkRow}>
      <View style={s.checkBox} />
      <Text style={s.checkText}>{children}</Text>
    </View>
  );
}

function Divider() { return <View style={s.divider} />; }

// ── ENV var table row ─────────────────────────────────────────────────────────

function EnvRow({ varName, required, note, last }: { varName: string; required: boolean; note: string; last?: boolean }) {
  const RowStyle = last ? s.tableRowLast : s.tableRow;
  return (
    <View style={RowStyle}>
      <Text style={[s.tableCellMono, { flex: 1.4 }]}>{varName}</Text>
      <Text style={required ? s.tableCellRequired : s.tableCellOptional}>{required ? "Required" : "Optional"}</Text>
      <Text style={[s.tableCell, { flex: 1.6 }]}>{note}</Text>
    </View>
  );
}

// ── Cron table row ────────────────────────────────────────────────────────────

function CronRow({ path, schedule, desc, last }: { path: string; schedule: string; desc: string; last?: boolean }) {
  const RowStyle = last ? s.tableRowLast : s.tableRow;
  return (
    <View style={RowStyle}>
      <Text style={[s.tableCellMono, { flex: 1.3 }]}>{path}</Text>
      <Text style={[s.tableCellMono, { flex: 0.9 }]}>{schedule}</Text>
      <Text style={[s.tableCell, { flex: 1.8 }]}>{desc}</Text>
    </View>
  );
}

// ── Document ──────────────────────────────────────────────────────────────────

function DeploymentGuide() {
  return (
    <Document
      title="TrustLedger Deployment Guide"
      author="TrustLedger"
      subject="Production Deployment Guide"
      keywords="TrustLedger deployment Vercel Supabase Next.js"
      creator="TrustLedger PDF Generator"
    >

      {/* ── COVER ── */}
      <Page size="A4" style={s.coverPage}>
        <View style={s.coverTop}>
          <View style={s.coverBadge}>
            <Text style={s.coverBadgeText}>DEPLOYMENT GUIDE</Text>
          </View>
          <Text style={s.coverTitle}>TrustLedger{"\n"}Production Deployment</Text>
          <Text style={s.coverSub}>
            Step-by-step guide to deploying the TrustLedger AI Code Governance
            Platform to Vercel with Supabase, Upstash Redis, Stripe, and Sentry.
          </Text>
          <View style={s.coverMeta}>
            <View style={s.coverMetaItem}>
              <Text style={s.coverMetaLabel}>VERSION</Text>
              <Text style={s.coverMetaValue}>1.0.0</Text>
            </View>
            <View style={s.coverMetaItem}>
              <Text style={s.coverMetaLabel}>DATE</Text>
              <Text style={s.coverMetaValue}>{new Date().toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" })}</Text>
            </View>
            <View style={s.coverMetaItem}>
              <Text style={s.coverMetaLabel}>PLATFORM</Text>
              <Text style={s.coverMetaValue}>Vercel + Supabase</Text>
            </View>
            <View style={s.coverMetaItem}>
              <Text style={s.coverMetaLabel}>RUNTIME</Text>
              <Text style={s.coverMetaValue}>Node.js 20 · Next.js 13.5</Text>
            </View>
          </View>
        </View>
        <View style={s.coverBottom}>
          <Text style={s.coverBottomText}>
            TrustLedger · AI Code Governance Platform · Internal Documentation · Confidential
          </Text>
        </View>
      </Page>

      {/* ── TABLE OF CONTENTS ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="TABLE OF CONTENTS" />
        <Text style={s.tocTitle}>Contents</Text>
        <Text style={s.tocSub}>This guide covers every step from zero to a live production deployment.</Text>

        {[
          ["1", "Prerequisites & Architecture Overview",  "3"],
          ["2", "Supabase — Database, Auth & Realtime",   "4"],
          ["3", "Upstash Redis — Rate Limiting",          "6"],
          ["4", "GitHub App — Webhook Integration",       "7"],
          ["5", "Vercel — Deploy the Application",        "8"],
          ["6", "Environment Variables Reference",        "10"],
          ["7", "Vercel Cron Jobs",                       "12"],
          ["8", "Optional Services (Stripe, SendGrid…)",  "13"],
          ["9", "Post-Deploy Verification",               "15"],
          ["10","Docker / Self-Hosted Alternative",        "16"],
          ["11","Troubleshooting",                         "17"],
          ["12","Go-Live Checklist",                       "18"],
        ].map(([num, label, pg]) => (
          <View style={s.tocRow} key={num}>
            <Text style={s.tocNum}>{num}</Text>
            <Text style={s.tocLabel}>{label}</Text>
            <Text style={s.tocPage}>{pg}</Text>
          </View>
        ))}
        <Footer />
      </Page>

      {/* ── PAGE 1: PREREQUISITES ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="PREREQUISITES & ARCHITECTURE" />
        <SectionHeading num="1" title="Prerequisites & Architecture Overview" />
        <Text style={s.sectionSub}>
          Review what you need before starting and understand how the pieces fit together.
        </Text>

        <Text style={s.h2}>1.1 What you need</Text>
        <Bullet>A GitHub account with access to the TrustLedger repository</Bullet>
        <Bullet>A Vercel account (free tier works; Pro required for cron jobs on custom domains)</Bullet>
        <Bullet>A Supabase account (free tier works for staging; Pro recommended for production)</Bullet>
        <Bullet>An Upstash account (free tier Redis is sufficient)</Bullet>
        <Bullet>Node.js 20+ installed locally (for running migrations)</Bullet>
        <Bullet>npm 9+ installed locally</Bullet>

        <Text style={s.h2}>1.2 Architecture at a glance</Text>
        <Text style={s.p}>
          TrustLedger is a Next.js 13.5 application that uses the App Router with both
          server components and client components. All API routes live under /api and run
          as Vercel Serverless Functions. Background work runs via five Vercel Cron Jobs.
        </Text>

        <Code>
          <CL>Browser / GitHub Webhook</CL>
          <CL>        │</CL>
          <CL>        ▼</CL>
          <CL cmd>  Vercel (Next.js 13.5)  ←─── Vercel Crons (5 schedules)</CL>
          <CL>        │         │</CL>
          <CL>        ▼         ▼</CL>
          <CL cmd>  Supabase   Upstash Redis</CL>
          <CL>  (Postgres     (Rate limiting,</CL>
          <CL>   Auth, RT)     idempotency)</CL>
          <CL>        │</CL>
          <CL>        ├── Stripe   (billing webhooks)</CL>
          <CL>        ├── SendGrid (alert emails)</CL>
          <CL>        ├── Sentry   (error tracking)</CL>
          <CL>        └── PostHog  (product analytics)</CL>
        </Code>

        <Text style={s.h2}>1.3 Clone the repository</Text>
        <Code>
          <CL cmd>git clone https://github.com/your-org/trustledger.git</CL>
          <CL cmd>cd trustledger/dashboard</CL>
          <CL cmd>npm install</CL>
        </Code>

        <Callout type="warn" label="Important">
          All commands in this guide assume you are inside the dashboard/ directory unless stated otherwise.
        </Callout>
        <Footer />
      </Page>

      {/* ── PAGE 2: SUPABASE ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="SUPABASE SETUP" />
        <SectionHeading num="2" title="Supabase — Database, Auth & Realtime" />
        <Text style={s.sectionSub}>
          Supabase provides the PostgreSQL database, authentication, row-level security,
          and real-time subscriptions used by the live dashboard.
        </Text>

        <Text style={s.h2}>2.1 Create a Supabase project</Text>
        <Bullet>Go to supabase.com and sign in</Bullet>
        <Bullet>Click New Project, choose your organisation, set a name (e.g. trustledger-prod) and a strong database password</Bullet>
        <Bullet>Select the AWS region closest to your users (the app defaults to us-east-1 / iad1)</Bullet>
        <Bullet>Wait ~2 minutes for provisioning to complete</Bullet>

        <Text style={s.h2}>2.2 Collect your API credentials</Text>
        <Text style={s.p}>Navigate to Project Settings → API and copy the following values — you will need them later:</Text>
        <View style={s.table}>
          <View style={s.tableHeaderRow}>
            <Text style={[s.tableCellHeader, { flex: 1.3 }]}>Value</Text>
            <Text style={[s.tableCellHeader, { flex: 1.7 }]}>Where to find it</Text>
          </View>
          <View style={s.tableRow}>
            <Text style={[s.tableCellMono, { flex: 1.3 }]}>SUPABASE_URL</Text>
            <Text style={[s.tableCell,     { flex: 1.7 }]}>Settings → API → Project URL</Text>
          </View>
          <View style={s.tableRow}>
            <Text style={[s.tableCellMono, { flex: 1.3 }]}>SUPABASE_ANON_KEY</Text>
            <Text style={[s.tableCell,     { flex: 1.7 }]}>Settings → API → Project API Keys → anon public</Text>
          </View>
          <View style={s.tableRowLast}>
            <Text style={[s.tableCellMono, { flex: 1.3 }]}>SUPABASE_SERVICE_ROLE_KEY</Text>
            <Text style={[s.tableCell,     { flex: 1.7 }]}>Settings → API → Project API Keys → service_role (keep secret)</Text>
          </View>
        </View>

        <Text style={s.h2}>2.3 Run database migrations</Text>
        <Text style={s.p}>
          The migration script creates all tables, indexes, RLS policies, and seed data.
          Set the environment variable first, then run:
        </Text>
        <Code>
          <CL comment>{"# Set the connection string (find it in Settings → Database → Connection string)"}</CL>
          <CL cmd>export DATABASE_URL="postgresql://postgres:[password]@db.[ref].supabase.co:5432/postgres"</CL>
          <CL>{" "}</CL>
          <CL cmd>npm run migrate</CL>
          <CL comment>{"# Verify all migrations applied:"}</CL>
          <CL cmd>npm run migrate:status</CL>
        </Code>

        <Callout type="info" label="Migration dry-run">
          Run npm run migrate:dry first to preview SQL without applying it. Inspect the output before running against production.
        </Callout>

        <Text style={s.h2}>2.4 Configure authentication</Text>
        <Bullet>Go to Authentication → Providers in the Supabase dashboard</Bullet>
        <Bullet>Enable GitHub OAuth: create a GitHub OAuth App at github.com/settings/developers, set the callback URL to https://your-domain.com/auth/callback and paste the Client ID and Secret into Supabase</Bullet>
        <Bullet>Optionally enable Email/Password auth for non-GitHub users</Bullet>
        <Bullet>Under Authentication → URL Configuration, set Site URL to https://your-domain.com and add https://your-domain.com/auth/callback to Redirect URLs</Bullet>

        <Text style={s.h2}>2.5 Enable Realtime</Text>
        <Text style={s.p}>
          The live dashboard uses Supabase Realtime to push updates without polling.
          Enable it for each of these tables in Database → Replication:
        </Text>
        <Bullet>scans</Bullet>
        <Bullet>attestations</Bullet>
        <Bullet>violations</Bullet>
        <Bullet>alerts</Bullet>
        <Bullet>incidents</Bullet>
        <Footer />
      </Page>

      {/* ── PAGE 3: UPSTASH ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="UPSTASH REDIS" />
        <SectionHeading num="3" title="Upstash Redis — Rate Limiting" />
        <Text style={s.sectionSub}>
          Upstash provides a serverless Redis instance used for API rate limiting and
          webhook idempotency. Without it the app falls back to in-memory rate limiting,
          which is not safe across multiple Vercel function instances.
        </Text>

        <Text style={s.h2}>3.1 Create a Redis database</Text>
        <Bullet>Go to console.upstash.com and sign in</Bullet>
        <Bullet>Click Create Database, choose a name (e.g. trustledger-ratelimit) and select the AWS region that matches your Vercel deployment (us-east-1 recommended)</Bullet>
        <Bullet>Leave the type as Regional (not Global) unless you have multi-region Vercel deployments</Bullet>
        <Bullet>Click Create</Bullet>

        <Text style={s.h2}>3.2 Collect credentials</Text>
        <Text style={s.p}>From the database detail page, copy:</Text>
        <Bullet>UPSTASH_REDIS_REST_URL — the HTTPS REST URL</Bullet>
        <Bullet>UPSTASH_REDIS_REST_TOKEN — the REST token</Bullet>

        <Text style={s.h2}>3.3 Rate limit configuration</Text>
        <Text style={s.p}>
          The built-in rate limits are defined in src/lib/rateLimit.ts. Default values:
        </Text>
        <View style={s.table}>
          <View style={s.tableHeaderRow}>
            <Text style={[s.tableCellHeader, { flex: 1 }]}>Endpoint type</Text>
            <Text style={[s.tableCellHeader, { flex: 1 }]}>Limit</Text>
            <Text style={[s.tableCellHeader, { flex: 1 }]}>Window</Text>
          </View>
          <View style={s.tableRow}>
            <Text style={s.tableCell}>Scan submissions</Text>
            <Text style={s.tableCell}>60 requests</Text>
            <Text style={s.tableCell}>60 seconds</Text>
          </View>
          <View style={s.tableRow}>
            <Text style={s.tableCell}>API key auth</Text>
            <Text style={s.tableCell}>300 requests</Text>
            <Text style={s.tableCell}>60 seconds</Text>
          </View>
          <View style={s.tableRowLast}>
            <Text style={s.tableCell}>Webhook ingest</Text>
            <Text style={s.tableCell}>100 requests</Text>
            <Text style={s.tableCell}>60 seconds</Text>
          </View>
        </View>

        <Callout type="ok" label="Free tier is sufficient">
          Upstash free tier supports 10,000 commands/day and 256 MB storage. This comfortably handles hundreds of scans per day. Upgrade when you exceed ~1,000 API calls per hour.
        </Callout>
        <Footer />
      </Page>

      {/* ── PAGE 4: GITHUB APP ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="GITHUB APP SETUP" />
        <SectionHeading num="4" title="GitHub App — Webhook Integration" />
        <Text style={s.sectionSub}>
          The GitHub App receives pull request webhook events, triggers scans, and posts
          Check Run results back to GitHub. This is required for the core PR-gate workflow.
        </Text>

        <Text style={s.h2}>4.1 Create the GitHub App</Text>
        <Bullet>Go to github.com/settings/apps (personal) or github.com/organizations/YOUR_ORG/settings/apps (org)</Bullet>
        <Bullet>Click New GitHub App</Bullet>
        <Bullet>Set Homepage URL to https://your-domain.com</Bullet>
        <Bullet>Set Webhook URL to https://your-domain.com/api/github-app</Bullet>
        <Bullet>Generate a random Webhook secret (e.g. openssl rand -hex 32) and save it</Bullet>

        <Text style={s.h2}>4.2 Set permissions</Text>
        <Text style={s.p}>Under Permissions & Events, grant the following:</Text>
        <View style={s.table}>
          <View style={s.tableHeaderRow}>
            <Text style={[s.tableCellHeader, { flex: 1 }]}>Permission</Text>
            <Text style={[s.tableCellHeader, { flex: 1 }]}>Level</Text>
          </View>
          <View style={s.tableRow}><Text style={s.tableCell}>Repository: Pull requests</Text><Text style={s.tableCell}>Read & write</Text></View>
          <View style={s.tableRow}><Text style={s.tableCell}>Repository: Checks</Text><Text style={s.tableCell}>Read & write</Text></View>
          <View style={s.tableRow}><Text style={s.tableCell}>Repository: Contents</Text><Text style={s.tableCell}>Read only</Text></View>
          <View style={s.tableRowLast}><Text style={s.tableCell}>Repository: Statuses</Text><Text style={s.tableCell}>Read & write</Text></View>
        </View>

        <Text style={s.p} style={{ marginTop: 8 }}>Under Subscribe to events, check: Pull request, Push</Text>

        <Text style={s.h2}>4.3 Generate a private key</Text>
        <Bullet>After creating the app, scroll to Private keys and click Generate a private key</Bullet>
        <Bullet>Download the .pem file</Bullet>
        <Bullet>Convert it for use as an env var: cat private-key.pem | base64 | tr -d "\n"</Bullet>
        <Bullet>The base64 output becomes GITHUB_APP_PRIVATE_KEY</Bullet>

        <Text style={s.h2}>4.4 Install the app</Text>
        <Bullet>Click Install App in the left sidebar and install it on the repositories you want TrustLedger to scan</Bullet>
        <Bullet>Copy the App ID from the General settings page — this becomes GITHUB_APP_ID</Bullet>

        <Callout type="info" label="GitLab / Bitbucket">
          TrustLedger also supports GitLab MR scanning (via /api/gitlab-webhook) and Bitbucket PR scanning (/api/bitbucket-webhook). Configure those webhooks similarly using the GITLAB_WEBHOOK_SECRET and BITBUCKET_WEBHOOK_SECRET env vars.
        </Callout>
        <Footer />
      </Page>

      {/* ── PAGE 5: VERCEL ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="VERCEL DEPLOYMENT" />
        <SectionHeading num="5" title="Vercel — Deploy the Application" />
        <Text style={s.sectionSub}>
          The project ships with a vercel.json that configures the build, security headers,
          deployment region, and cron jobs. Deployment is a single command.
        </Text>

        <Text style={s.h2}>5.1 Install the Vercel CLI</Text>
        <Code>
          <CL cmd>npm install -g vercel</CL>
          <CL cmd>vercel login</CL>
        </Code>

        <Text style={s.h2}>5.2 Link your project</Text>
        <Code>
          <CL comment>{"# From the dashboard/ directory:"}</CL>
          <CL cmd>vercel link</CL>
          <CL comment>{"# Answer the prompts: select your team/scope and project name"}</CL>
        </Code>

        <Text style={s.h2}>5.3 Add environment variables</Text>
        <Text style={s.p}>
          Add each variable via the Vercel CLI or the dashboard (Project → Settings → Environment Variables).
          Use the CLI for batch entry:
        </Text>
        <Code>
          <CL comment>{"# Repeat for each variable — CLI prompts for the value:"}</CL>
          <CL cmd>vercel env add NEXT_PUBLIC_SUPABASE_URL production</CL>
          <CL cmd>vercel env add NEXT_PUBLIC_SUPABASE_ANON_KEY production</CL>
          <CL cmd>vercel env add SUPABASE_SERVICE_ROLE_KEY production</CL>
          <CL cmd>vercel env add NEXT_PUBLIC_APP_URL production</CL>
          <CL cmd>vercel env add NEXT_PUBLIC_SKIP_AUTH production</CL>
          <CL comment>{"# ... (see full reference on page 10)"}</CL>
        </Code>

        <Callout type="warn" label="Critical: disable demo mode">
          Set NEXT_PUBLIC_SKIP_AUTH=false in production. The app will refuse to start if this is true in a production NODE_ENV environment.
        </Callout>

        <Text style={s.h2}>5.4 Deploy</Text>
        <Code>
          <CL comment>{"# Preview deployment (staging):"}</CL>
          <CL cmd>vercel</CL>
          <CL>{" "}</CL>
          <CL comment>{"# Production deployment:"}</CL>
          <CL cmd>vercel --prod</CL>
        </Code>

        <Text style={s.h2}>5.5 Connect a custom domain</Text>
        <Bullet>In Vercel dashboard: Project → Settings → Domains → Add</Bullet>
        <Bullet>Enter your domain (e.g. app.trustledger.dev)</Bullet>
        <Bullet>Add the CNAME or A record shown to your DNS provider</Bullet>
        <Bullet>Wait for SSL provisioning (~2 minutes for Let's Encrypt)</Bullet>
        <Bullet>Update NEXT_PUBLIC_APP_URL to match the new domain and redeploy</Bullet>

        <Text style={s.h2}>5.6 Configure the Supabase Auth callback</Text>
        <Text style={s.p}>
          After setting your custom domain, go back to Supabase → Authentication → URL Configuration
          and update Site URL and Redirect URLs to your production domain. GitHub OAuth also needs
          the callback URL updated in the GitHub OAuth App settings.
        </Text>

        <Text style={s.h2}>5.7 Verify the build</Text>
        <Code>
          <CL cmd>vercel logs --follow</CL>
          <CL comment>{"# Look for: ✓ Ready in Xs"}</CL>
          <CL comment>{"# Then visit /healthz to confirm DB connectivity"}</CL>
        </Code>
        <Footer />
      </Page>

      {/* ── PAGE 6: ENV VARS ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="ENVIRONMENT VARIABLES" />
        <SectionHeading num="6" title="Environment Variables Reference" />
        <Text style={s.sectionSub}>
          Complete list of all environment variables. Required variables must be set before deployment.
          Optional variables enable additional features but the app runs without them.
        </Text>

        <Text style={s.h2}>Core (required)</Text>
        <View style={s.table}>
          <View style={s.tableHeaderRow}>
            <Text style={[s.tableCellHeader, { flex: 1.4 }]}>Variable</Text>
            <Text style={[s.tableCellHeader, { flex: 0.5 }]}>Status</Text>
            <Text style={[s.tableCellHeader, { flex: 1.6 }]}>Notes</Text>
          </View>
          <EnvRow varName="NEXT_PUBLIC_SUPABASE_URL"      required note="Your Supabase project URL" />
          <EnvRow varName="NEXT_PUBLIC_SUPABASE_ANON_KEY" required note="Supabase anon/public key" />
          <EnvRow varName="SUPABASE_SERVICE_ROLE_KEY"     required note="Supabase service role key — server only, never expose to browser" />
          <EnvRow varName="NEXT_PUBLIC_APP_URL"           required note="Full URL of your deployment e.g. https://app.example.com" />
          <EnvRow varName="NEXT_PUBLIC_SKIP_AUTH"         required note="Must be false in production. true only for local demo mode." />
          <EnvRow varName="NEXT_PUBLIC_ORG"               required note="Your organisation slug e.g. acmecorp — used in mock data and API scoping" />
          <EnvRow varName="UPSTASH_REDIS_REST_URL"        required note="Upstash Redis REST endpoint URL" />
          <EnvRow varName="UPSTASH_REDIS_REST_TOKEN"      required note="Upstash Redis REST token" />
          <EnvRow varName="CRON_SECRET"                   required note="Random 32-char string. Cron requests must pass Bearer {CRON_SECRET}" last />
        </View>

        <Text style={s.h2}>GitHub integration</Text>
        <View style={s.table}>
          <View style={s.tableHeaderRow}>
            <Text style={[s.tableCellHeader, { flex: 1.4 }]}>Variable</Text>
            <Text style={[s.tableCellHeader, { flex: 0.5 }]}>Status</Text>
            <Text style={[s.tableCellHeader, { flex: 1.6 }]}>Notes</Text>
          </View>
          <EnvRow varName="GITHUB_WEBHOOK_SECRET"   required note="HMAC-SHA256 secret set when creating the GitHub App webhook" />
          <EnvRow varName="GITHUB_APP_ID"           required note="Numeric App ID from the GitHub App general settings page" />
          <EnvRow varName="GITHUB_APP_PRIVATE_KEY"  required note="Base64-encoded PEM private key downloaded from GitHub App" last />
        </View>
        <Footer />
      </Page>

      {/* ── PAGE 7: ENV VARS continued ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="ENVIRONMENT VARIABLES (continued)" />

        <Text style={s.h2}>Billing (optional)</Text>
        <View style={s.table}>
          <View style={s.tableHeaderRow}>
            <Text style={[s.tableCellHeader, { flex: 1.4 }]}>Variable</Text>
            <Text style={[s.tableCellHeader, { flex: 0.5 }]}>Status</Text>
            <Text style={[s.tableCellHeader, { flex: 1.6 }]}>Notes</Text>
          </View>
          <EnvRow varName="STRIPE_SECRET_KEY"              required={false} note="Stripe secret key (sk_live_...)" />
          <EnvRow varName="STRIPE_WEBHOOK_SECRET"          required={false} note="Stripe webhook signing secret (whsec_...)" />
          <EnvRow varName="STRIPE_PRICE_STARTER_MONTHLY"   required={false} note="Stripe Price ID for Starter plan monthly" />
          <EnvRow varName="STRIPE_PRICE_STARTER_ANNUAL"    required={false} note="Stripe Price ID for Starter plan annual" />
          <EnvRow varName="STRIPE_PRICE_GROWTH_MONTHLY"    required={false} note="Stripe Price ID for Growth plan monthly" />
          <EnvRow varName="STRIPE_PRICE_GROWTH_ANNUAL"     required={false} note="Stripe Price ID for Growth plan annual" last />
        </View>

        <Text style={s.h2}>Notifications & email (optional)</Text>
        <View style={s.table}>
          <View style={s.tableHeaderRow}>
            <Text style={[s.tableCellHeader, { flex: 1.4 }]}>Variable</Text>
            <Text style={[s.tableCellHeader, { flex: 0.5 }]}>Status</Text>
            <Text style={[s.tableCellHeader, { flex: 1.6 }]}>Notes</Text>
          </View>
          <EnvRow varName="SENDGRID_API_KEY"      required={false} note="SendGrid API key for alert and digest emails" />
          <EnvRow varName="SENDGRID_FROM_EMAIL"   required={false} note="Verified sender address e.g. alerts@trustledger.dev" last />
        </View>

        <Text style={s.h2}>Observability (optional)</Text>
        <View style={s.table}>
          <View style={s.tableHeaderRow}>
            <Text style={[s.tableCellHeader, { flex: 1.4 }]}>Variable</Text>
            <Text style={[s.tableCellHeader, { flex: 0.5 }]}>Status</Text>
            <Text style={[s.tableCellHeader, { flex: 1.6 }]}>Notes</Text>
          </View>
          <EnvRow varName="NEXT_PUBLIC_SENTRY_DSN"   required={false} note="Sentry DSN for client-side error tracking" />
          <EnvRow varName="SENTRY_AUTH_TOKEN"        required={false} note="Sentry auth token for source map upload during build" />
          <EnvRow varName="SENTRY_ORG"               required={false} note="Your Sentry organisation slug" />
          <EnvRow varName="SENTRY_PROJECT"           required={false} note="Your Sentry project slug" />
          <EnvRow varName="NEXT_PUBLIC_POSTHOG_KEY"  required={false} note="PostHog project API key" />
          <EnvRow varName="NEXT_PUBLIC_POSTHOG_HOST" required={false} note="PostHog host, default https://app.posthog.com" last />
        </View>

        <Text style={s.h2}>Security headers note</Text>
        <Text style={s.p}>
          Security headers (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
          are set in both vercel.json and next.config.mjs and apply automatically. No
          additional configuration is needed.
        </Text>

        <Callout type="warn" label="Secret management">
          Never commit .env.local or any file containing real keys to git. Use vercel env add to inject secrets at deploy time. Rotate the SUPABASE_SERVICE_ROLE_KEY and CRON_SECRET before your first production deployment if they were ever shared.
        </Callout>
        <Footer />
      </Page>

      {/* ── PAGE 8: CRONS ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="VERCEL CRON JOBS" />
        <SectionHeading num="7" title="Vercel Cron Jobs" />
        <Text style={s.sectionSub}>
          Five cron jobs are pre-configured in vercel.json. They activate automatically
          on deployment. Each calls an API route that verifies the CRON_SECRET bearer token.
        </Text>

        <View style={s.table}>
          <View style={s.tableHeaderRow}>
            <Text style={[s.tableCellHeader, { flex: 1.3 }]}>Path</Text>
            <Text style={[s.tableCellHeader, { flex: 0.9 }]}>Schedule</Text>
            <Text style={[s.tableCellHeader, { flex: 1.8 }]}>Purpose</Text>
          </View>
          <CronRow path="/api/cron/sla"                  schedule="Every 15 min" desc="Scans open violations for SLA deadline breaches. Fires alerts for overdue items and updates violation statuses." />
          <CronRow path="/api/cron/webhook-retry"        schedule="Every 5 min"  desc="Retries failed outbound webhooks (GitHub Check Run updates, Slack notifications) with exponential back-off." />
          <CronRow path="/api/cron/scheduled-scans"     schedule="Hourly"        desc="Runs scheduled repository scans configured via the integrations settings page." />
          <CronRow path="/api/cron/weekly-report"        schedule="Mon 8am UTC"  desc="Generates and emails the weekly compliance digest report to configured recipients." />
          <CronRow path="/api/cron/compliance-reminders" schedule="Daily 9am UTC" desc="Sends reminders for upcoming compliance calendar deadlines (audits, cert expiry, reviews)." last />
        </View>

        <Text style={s.h2}>How crons are authenticated</Text>
        <Text style={s.p}>
          Vercel sends an Authorization: Bearer header containing your CRON_SECRET value.
          Each cron handler in the API verifies this before executing. If CRON_SECRET is not
          set or is set to the default dev-cron-secret value the go-live checker will warn you.
        </Text>

        <Text style={s.h2}>Monitoring crons</Text>
        <Bullet>Vercel dashboard → Project → Cron Jobs shows execution history and errors</Bullet>
        <Bullet>Failed cron runs trigger Sentry errors if NEXT_PUBLIC_SENTRY_DSN is configured</Bullet>
        <Bullet>Crons only run on Vercel Pro or above for custom domains. They work on all plans for the *.vercel.app domain.</Bullet>

        <Callout type="info" label="Local cron testing">
          To test a cron handler locally, call it directly with curl:  curl -H "Authorization: Bearer dev-cron-secret" http://localhost:3000/api/cron/sla
        </Callout>
        <Footer />
      </Page>

      {/* ── PAGE 9: OPTIONAL SERVICES ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="OPTIONAL SERVICES" />
        <SectionHeading num="8" title="Optional Services" />
        <Text style={s.sectionSub}>
          These services enhance the platform but are not required to get started.
          Configure them when you are ready to move beyond basic functionality.
        </Text>

        <Text style={s.h2}>8.1 Stripe — Billing</Text>
        <Bullet>Create a Stripe account and go to the Developers → API Keys page</Bullet>
        <Bullet>Copy your live secret key (sk_live_...) as STRIPE_SECRET_KEY</Bullet>
        <Bullet>Create three products (Starter, Growth, Enterprise) in Stripe → Products, each with monthly and annual prices</Bullet>
        <Bullet>Copy each Price ID (price_...) into the STRIPE_PRICE_* env vars</Bullet>
        <Bullet>Set up a webhook in Stripe → Developers → Webhooks pointing to https://your-domain.com/api/stripe</Bullet>
        <Bullet>Subscribe to: checkout.session.completed, customer.subscription.updated, customer.subscription.deleted, invoice.payment_failed</Bullet>
        <Bullet>Copy the webhook signing secret (whsec_...) as STRIPE_WEBHOOK_SECRET</Bullet>

        <Text style={s.h2}>8.2 SendGrid — Alert emails</Text>
        <Bullet>Create a SendGrid account and go to Settings → API Keys → Create API Key (Full Access)</Bullet>
        <Bullet>Set SENDGRID_API_KEY to the generated key</Bullet>
        <Bullet>Verify a sender email address in Settings → Sender Authentication and set it as SENDGRID_FROM_EMAIL</Bullet>
        <Bullet>Alert emails are sent for P1 incidents, SLA breaches, and weekly compliance digests</Bullet>

        <Text style={s.h2}>8.3 Sentry — Error tracking</Text>
        <Bullet>Create a Sentry project (platform: Next.js)</Bullet>
        <Bullet>Copy the DSN from Project → Settings → Client Keys as NEXT_PUBLIC_SENTRY_DSN</Bullet>
        <Bullet>For source map upload: create an Auth Token in User Settings → Auth Tokens with project:releases and org:read scopes. Set SENTRY_AUTH_TOKEN, SENTRY_ORG, SENTRY_PROJECT</Bullet>
        <Bullet>The app uses @sentry/nextjs and captures both client errors (via the global error boundary) and server errors (in API routes)</Bullet>

        <Text style={s.h2}>8.4 PostHog — Product analytics</Text>
        <Bullet>Create a PostHog Cloud project at app.posthog.com</Bullet>
        <Bullet>Copy the Project API Key as NEXT_PUBLIC_POSTHOG_KEY</Bullet>
        <Bullet>Leave NEXT_PUBLIC_POSTHOG_HOST unset to use the default EU cloud endpoint, or set it for self-hosted PostHog</Bullet>
        <Bullet>Page views, feature interactions, and scan events are tracked automatically</Bullet>

        <Callout type="ok" label="Ship without these">
          The core scan, attest, audit, and compliance features work without Stripe, SendGrid, Sentry, or PostHog. Add them progressively as you onboard real users.
        </Callout>
        <Footer />
      </Page>

      {/* ── PAGE 10: POST-DEPLOY ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="POST-DEPLOY VERIFICATION" />
        <SectionHeading num="9" title="Post-Deploy Verification" />
        <Text style={s.sectionSub}>
          After the first successful deployment, run these checks to confirm everything is wired up correctly.
        </Text>

        <Text style={s.h2}>9.1 Health endpoint</Text>
        <Code>
          <CL cmd>curl https://your-domain.com/healthz</CL>
          <CL comment>{"# Expected response:"}</CL>
          <CL>{"{ \"status\": \"ok\", \"db\": \"connected\", \"latency_ms\": 12 }"}</CL>
        </Code>
        <Text style={s.p}>
          If db is not "connected", check that SUPABASE_SERVICE_ROLE_KEY is set correctly
          and that the Supabase project is not paused.
        </Text>

        <Text style={s.h2}>9.2 Run the go-live checklist</Text>
        <Text style={s.p}>
          Visit https://your-domain.com/admin/go-live while logged in as an admin.
          The page runs automated checks across five categories:
        </Text>
        <Bullet>Infrastructure — env vars set, skip-auth disabled</Bullet>
        <Bullet>API Health — /healthz responds, database connected</Bullet>
        <Bullet>Security — HTTPS, cron secret, webhook secret</Bullet>
        <Bullet>Features — Stripe, SendGrid, Redis configured</Bullet>
        <Bullet>Observability — Sentry, PostHog active</Bullet>
        <Text style={s.p}>
          All required items must show PASS before taking production traffic. WARN items
          are optional services — resolve them before onboarding paying customers.
        </Text>

        <Text style={s.h2}>9.3 Seed demo data (optional)</Text>
        <Text style={s.p}>
          Visit /seed to apply mock scan data for a demo walkthrough. This writes to
          localStorage and does not affect the database. Clear it by visiting /seed again
          and clicking Clear.
        </Text>

        <Text style={s.h2}>9.4 Submit a test scan</Text>
        <Code>
          <CL cmd>curl -X POST https://your-domain.com/api/scans \</CL>
          <CL cmd>  -H "Authorization: Bearer YOUR_API_KEY" \</CL>
          <CL cmd>  -H "Content-Type: application/json" \</CL>
          <CL cmd>  -d '{"{\"repo\":\"org/test\",\"commit_sha\":\"abc123\",\"files\":[]}"}'</CL>
          <CL comment>{"# Should return: { scan_id: \"...\", overall_risk: \"LOW\", ... }"}</CL>
        </Code>

        <Callout type="info" label="API keys">
          Generate API keys in Settings → Integrations → API Keys. Each key is scoped to an organisation and rate-limited. The key format is tl_live_... for production.
        </Callout>
        <Footer />
      </Page>

      {/* ── PAGE 11: DOCKER ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="DOCKER / SELF-HOSTED" />
        <SectionHeading num="10" title="Docker / Self-Hosted Alternative" />
        <Text style={s.sectionSub}>
          The Next.js config sets output: "standalone" which produces a minimal, self-contained
          Node.js server. Use this path for AWS ECS, GCP Cloud Run, Kubernetes, or any VPS.
        </Text>

        <Text style={s.h2}>10.1 Build the standalone output</Text>
        <Code>
          <CL cmd>npm run build</CL>
          <CL comment>{"# Output: .next/standalone/ — a minimal server with no node_modules/"}</CL>
        </Code>

        <Text style={s.h2}>10.2 Dockerfile</Text>
        <Code>
          <CL>FROM node:20-alpine AS base</CL>
          <CL>WORKDIR /app</CL>
          <CL>{" "}</CL>
          <CL comment>{"# Copy standalone build output"}</CL>
          <CL>COPY .next/standalone ./</CL>
          <CL>COPY .next/static ./.next/static</CL>
          <CL>COPY public ./public</CL>
          <CL>{" "}</CL>
          <CL>ENV NODE_ENV=production</CL>
          <CL>ENV PORT=3000</CL>
          <CL>EXPOSE 3000</CL>
          <CL>{" "}</CL>
          <CL>CMD ["node", "server.js"]</CL>
        </Code>

        <Code>
          <CL cmd>docker build -t trustledger:latest .</CL>
          <CL cmd>docker run -p 3000:3000 \</CL>
          <CL cmd>  -e NEXT_PUBLIC_SUPABASE_URL=... \</CL>
          <CL cmd>  -e SUPABASE_SERVICE_ROLE_KEY=... \</CL>
          <CL comment>{"  # (pass all env vars via -e or --env-file .env.production)"}</CL>
          <CL cmd>  trustledger:latest</CL>
        </Code>

        <Text style={s.h2}>10.3 Cron jobs on self-hosted</Text>
        <Text style={s.p}>
          Vercel crons do not run in a Docker deployment. Use one of these alternatives:
        </Text>
        <Bullet>Kubernetes CronJob resource — one job per endpoint, each calling curl with the CRON_SECRET header</Bullet>
        <Bullet>AWS EventBridge Scheduler — trigger an HTTP call to each cron path on the same schedule as vercel.json</Bullet>
        <Bullet>GCP Cloud Scheduler — same approach, one job per path</Bullet>
        <Bullet>A sidecar cron container running crontab that calls the API endpoints</Bullet>

        <Callout type="info" label="Reverse proxy">
          Place an nginx or Caddy reverse proxy in front of the Docker container to handle SSL termination and the HSTS headers. The Next.js server itself serves on plain HTTP and expects the proxy to terminate TLS.
        </Callout>
        <Footer />
      </Page>

      {/* ── PAGE 12: TROUBLESHOOTING ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="TROUBLESHOOTING" />
        <SectionHeading num="11" title="Troubleshooting" />
        <Text style={s.sectionSub}>
          Common issues encountered during deployment and how to resolve them.
        </Text>

        <Text style={s.h2}>Build fails: "Cannot find module"</Text>
        <Text style={s.p}>
          Usually caused by a missing or mismatched Node.js version. The project requires Node 20+.
          Check with node --version. On Vercel set Node.js Version to 20.x in Project → Settings → General.
        </Text>

        <Text style={s.h2}>500 errors after deploy</Text>
        <Text style={s.p}>
          Check Vercel Functions logs (Project → Functions → select function → Logs).
          The most common cause is a missing environment variable. Look for "Cannot read properties of undefined"
          or "missing required env" in the logs.
        </Text>

        <Text style={s.h2}>Supabase "JWT expired" or auth errors</Text>
        <Text style={s.p}>
          Ensure NEXT_PUBLIC_SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY are set to the
          correct project. If you regenerated keys in Supabase, redeploy Vercel to pick up the new values.
        </Text>

        <Text style={s.h2}>Realtime not updating</Text>
        <Bullet>Check that Realtime is enabled for the relevant tables in Supabase → Database → Replication</Bullet>
        <Bullet>Ensure the Supabase project is on a plan that supports Realtime (free tier is limited to 2 concurrent connections)</Bullet>
        <Bullet>Check browser console for WebSocket connection errors</Bullet>

        <Text style={s.h2}>GitHub webhooks returning 401</Text>
        <Text style={s.p}>
          The HMAC-SHA256 signature validation failed. Verify that GITHUB_WEBHOOK_SECRET
          exactly matches the secret set in the GitHub App webhook settings. No trailing spaces or newlines.
        </Text>

        <Text style={s.h2}>Cron jobs not running</Text>
        <Bullet>Crons require Vercel Pro for custom domains — they run for free on *.vercel.app</Bullet>
        <Bullet>Verify CRON_SECRET is set and matches what the cron handlers expect</Bullet>
        <Bullet>Check Vercel dashboard → Project → Cron Jobs for execution history and error details</Bullet>

        <Text style={s.h2}>Rate limit errors (429)</Text>
        <Text style={s.p}>
          If UPSTASH_REDIS_REST_URL is not set the app uses in-memory rate limiting.
          Under load this can cause false 429s because each serverless function instance
          has its own counter. Set the Upstash env vars to use shared Redis counters.
        </Text>

        <Callout type="info" label="Getting help">
          Check the go-live checklist at /admin/go-live first — it surfaces most configuration problems automatically. For persistent issues check the Vercel function logs and Supabase logs (Database → Logs) side by side.
        </Callout>
        <Footer />
      </Page>

      {/* ── PAGE 13: CHECKLIST ── */}
      <Page size="A4" style={s.page}>
        <PageHeader section="GO-LIVE CHECKLIST" />
        <SectionHeading num="12" title="Go-Live Checklist" />
        <Text style={s.sectionSub}>
          Print this page and work through it before directing production traffic to your deployment.
          Every item must be checked before going live.
        </Text>

        <Text style={s.h2}>Infrastructure</Text>
        <CheckItem>Supabase project created and database migrations applied (npm run migrate:status shows all green)</CheckItem>
        <CheckItem>NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY set in Vercel</CheckItem>
        <CheckItem>SUPABASE_SERVICE_ROLE_KEY set in Vercel (server-only, not prefixed NEXT_PUBLIC_)</CheckItem>
        <CheckItem>NEXT_PUBLIC_APP_URL set to the production HTTPS domain</CheckItem>
        <CheckItem>NEXT_PUBLIC_SKIP_AUTH set to false</CheckItem>
        <CheckItem>Custom domain added to Vercel and SSL certificate issued</CheckItem>
        <CheckItem>Supabase Auth callback URL updated to production domain</CheckItem>

        <Text style={s.h2}>Rate limiting & security</Text>
        <CheckItem>UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN set</CheckItem>
        <CheckItem>CRON_SECRET set to a unique random string (not the default dev-cron-secret)</CheckItem>
        <CheckItem>GITHUB_WEBHOOK_SECRET set and matches the GitHub App webhook configuration</CheckItem>
        <CheckItem>GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY set</CheckItem>

        <Text style={s.h2}>Verification</Text>
        <CheckItem>/healthz returns {"{ status: \"ok\", db: \"connected\" }"}</CheckItem>
        <CheckItem>/admin/go-live shows all required checks as PASS</CheckItem>
        <CheckItem>A test scan submitted via the API returns a valid scan_id</CheckItem>
        <CheckItem>GitHub webhook delivery test (GitHub App → Advanced → Recent Deliveries) shows 200</CheckItem>
        <CheckItem>Realtime: open two browser tabs and confirm scan status updates propagate live</CheckItem>

        <Text style={s.h2}>Optional (before onboarding customers)</Text>
        <CheckItem>Stripe billing configured and a test checkout completed</CheckItem>
        <CheckItem>SendGrid sender verified and a test alert email received</CheckItem>
        <CheckItem>Sentry DSN set and a test error captured</CheckItem>
        <CheckItem>PostHog key set and page views appearing in the dashboard</CheckItem>
        <CheckItem>Cron jobs visible in Vercel dashboard with at least one successful execution</CheckItem>
        <CheckItem>Seed data cleared from any test accounts (/seed → Clear)</CheckItem>

        <Divider />
        <Text style={{ fontSize: 9, color: C.gray400, textAlign: "center", marginTop: 8 }}>
          Once all boxes above are checked, TrustLedger is production-ready.{"\n"}
          Visit /dashboard and onboard your first repository.
        </Text>
        <Footer />
      </Page>

    </Document>
  );
}

// ── Render ────────────────────────────────────────────────────────────────────

(async () => {
  console.log("Generating deployment-guide.pdf …");
  await renderToFile(<DeploymentGuide />, OUT);
  console.log(`Done → ${OUT}`);
})();
