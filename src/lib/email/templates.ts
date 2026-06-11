/**
 * TrustLedger Email Templates
 * Beautiful, responsive HTML email templates for all notification types.
 * Compatible with major email clients (Gmail, Outlook, Apple Mail).
 */

export interface EmailTemplate {
  subject: string;
  html:    string;
  text:    string;
}

// ── Base layout ────────────────────────────────────────────────────────────────

function layout(opts: {
  title:    string;
  preview?: string;
  header:   { gradient: string; badge?: string; title: string; subtitle?: string };
  body:     string;
  footer?:  string;
  appUrl:   string;
  orgName:  string;
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${opts.title}</title>
${opts.preview ? `<meta name="x-apple-mail-preview" content="${opts.preview}">` : ""}
<style>
  body{margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;-webkit-font-smoothing:antialiased}
  .wrapper{max-width:600px;margin:0 auto;padding:32px 16px}
  .card{background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.06)}
  .header{padding:32px;background:${opts.header.gradient}}
  .badge{display:inline-block;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.8px;color:rgba(255,255,255,.7);background:rgba(255,255,255,.12);border-radius:20px;padding:4px 10px;margin-bottom:12px}
  .header h1{margin:0;font-size:22px;font-weight:900;color:#fff;line-height:1.3}
  .header p{margin:6px 0 0;font-size:13px;color:rgba(255,255,255,.6)}
  .body{padding:28px 32px}
  .metric-row{display:flex;gap:12px;margin:16px 0}
  .metric{flex:1;background:#f8fafc;border-radius:10px;padding:14px;text-align:center;border:1px solid #e2e8f0}
  .metric-val{font-size:22px;font-weight:900;color:#1e293b}
  .metric-label{font-size:10px;color:#94a3b8;margin-top:2px}
  .table{width:100%;border-collapse:collapse;margin:16px 0}
  .table th{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#94a3b8;padding:8px 12px;text-align:left;border-bottom:2px solid #f1f5f9}
  .table td{font-size:12px;color:#334155;padding:8px 12px;border-bottom:1px solid #f8fafc}
  .badge-risk{display:inline-block;font-size:9px;font-weight:800;padding:2px 8px;border-radius:20px}
  .crit{background:#ede9fe;color:#6d28d9}.high{background:#fff7ed;color:#c2410c}.med{background:#fffbeb;color:#b45309}.low{background:#f0fdf4;color:#15803d}
  .cta{display:block;margin:20px 0;padding:14px 28px;background:linear-gradient(135deg,#6366f1,#7c3aed);color:#fff;text-decoration:none;border-radius:10px;font-size:14px;font-weight:800;text-align:center}
  .footer{padding:20px 32px 28px;text-align:center}
  .footer p{font-size:11px;color:#94a3b8;margin:0}
  .footer a{color:#6366f1;text-decoration:none}
  .divider{height:1px;background:#f1f5f9;margin:20px 0}
  @media(prefers-color-scheme:dark){body{background:#0f172a}.card{background:#1e293b;box-shadow:none}.metric{background:#0f172a;border-color:#334155}.metric-val{color:#f1f5f9}.table td{color:#cbd5e1}.table th{color:#64748b;border-color:#334155}.table td{border-color:#1e293b}.body p{color:#94a3b8}}
</style>
</head>
<body>
<div class="wrapper">
  <div style="text-align:center;margin-bottom:20px">
    <span style="font-size:13px;font-weight:900;color:#6366f1;letter-spacing:-0.3px">🛡️ TrustLedger</span>
  </div>
  <div class="card">
    <div class="header">
      ${opts.header.badge ? `<div class="badge">${opts.header.badge}</div><br>` : ""}
      <h1>${opts.header.title}</h1>
      ${opts.header.subtitle ? `<p>${opts.header.subtitle}</p>` : ""}
    </div>
    <div class="body">${opts.body}</div>
    <div class="footer">
      ${opts.footer ?? ""}
      <div class="divider"></div>
      <p>Sent by <a href="${opts.appUrl}">TrustLedger</a> · ${opts.orgName}<br>
      <a href="${opts.appUrl}/settings">Manage notifications</a> · <a href="${opts.appUrl}/settings">Unsubscribe</a></p>
    </div>
  </div>
  <p style="text-align:center;font-size:10px;color:#94a3b8;margin-top:16px">TrustLedger AI Governance Platform · Confidential</p>
</div>
</body>
</html>`;
}

// ── Alert email ───────────────────────────────────────────────────────────────

export function alertEmail(opts: {
  severity:   "P1" | "P2" | "P3" | "P4";
  title:      string;
  body:       string;
  repo?:      string;
  reviewUrl?: string;
  runbook?:   string;
  orgName:    string;
  appUrl:     string;
}): EmailTemplate {
  const gradients: Record<string, string> = {
    P1:"linear-gradient(135deg,#dc2626,#b91c1c)",
    P2:"linear-gradient(135deg,#ea580c,#c2410c)",
    P3:"linear-gradient(135deg,#2563eb,#1d4ed8)",
    P4:"linear-gradient(135deg,#15803d,#166534)",
  };
  const body = `
    <p style="font-size:14px;color:#334155;line-height:1.6">${opts.body}</p>
    ${opts.repo ? `<p style="font-size:12px;color:#64748b;font-family:monospace;background:#f8fafc;padding:8px 12px;border-radius:6px;border:1px solid #e2e8f0">${opts.repo}</p>` : ""}
    ${opts.reviewUrl ? `<a href="${opts.reviewUrl}" class="cta">Review in TrustLedger →</a>` : ""}
    ${opts.runbook   ? `<p style="font-size:12px;text-align:center"><a href="${opts.runbook}" style="color:#6366f1">View Runbook →</a></p>` : ""}
  `;
  const html = layout({
    title:   opts.title,
    preview: opts.title,
    header:  { gradient: gradients[opts.severity] ?? gradients.P3, badge: `${opts.severity} Alert`, title: opts.title, subtitle: `${opts.orgName} · TrustLedger` },
    body,
    appUrl:  opts.appUrl,
    orgName: opts.orgName,
  });
  return {
    subject: `[${opts.severity}] ${opts.title} — ${opts.orgName}`,
    html,
    text: `${opts.severity} Alert: ${opts.title}\n\n${opts.body}\n\n${opts.reviewUrl ?? opts.appUrl}`,
  };
}

// ── Scan complete email ───────────────────────────────────────────────────────

export function scanCompleteEmail(opts: {
  repo:          string;
  prNumber:      number;
  overallRisk:   string;
  aiPct:         number;
  fileCount:     number;
  critCount:     number;
  highCount:     number;
  reviewUrl:     string;
  orgName:       string;
  appUrl:        string;
}): EmailTemplate {
  const blocked = opts.overallRisk === "CRITICAL" || opts.overallRisk === "HIGH";
  const riskColors: Record<string,string> = { CRITICAL:"#dc2626",HIGH:"#ea580c",MEDIUM:"#d97706",LOW:"#15803d" };
  const riskColor = riskColors[opts.overallRisk] ?? "#6366f1";

  const body = `
    <div class="metric-row">
      <div class="metric"><div class="metric-val" style="color:${riskColor}">${opts.overallRisk}</div><div class="metric-label">Overall Risk</div></div>
      <div class="metric"><div class="metric-val">${(opts.aiPct*100).toFixed(0)}%</div><div class="metric-label">Avg AI Content</div></div>
      <div class="metric"><div class="metric-val">${opts.fileCount}</div><div class="metric-label">Files Scanned</div></div>
    </div>
    ${(opts.critCount + opts.highCount) > 0 ? `
    <div class="metric-row">
      ${opts.critCount > 0 ? `<div class="metric"><div class="metric-val" style="color:#6d28d9">${opts.critCount}</div><div class="metric-label">CRITICAL</div></div>` : ""}
      ${opts.highCount > 0 ? `<div class="metric"><div class="metric-val" style="color:#c2410c">${opts.highCount}</div><div class="metric-label">HIGH</div></div>` : ""}
    </div>` : ""}
    ${blocked
      ? `<p style="font-size:13px;color:#b91c1c;background:#fff1f2;padding:12px;border-radius:8px;border:1px solid #fecdd3"><strong>⛔ Merge blocked</strong> — ${opts.critCount + opts.highCount} file(s) require attestation before this PR can be merged.</p>`
      : `<p style="font-size:13px;color:#15803d;background:#f0fdf4;padding:12px;border-radius:8px;border:1px solid #bbf7d0">✅ Policy gate passed — all requirements met.</p>`
    }
    <a href="${opts.reviewUrl}" class="cta">${blocked ? "Attest Files to Unblock →" : "View Scan Results →"}</a>
  `;

  const subject = blocked
    ? `⛔ ${opts.overallRisk} risk — ${opts.repo} PR #${opts.prNumber} blocked`
    : `✅ Scan complete — ${opts.repo} PR #${opts.prNumber} (${opts.overallRisk})`;

  return {
    subject,
    html: layout({
      title:   subject,
      preview: `${opts.repo} PR #${opts.prNumber} — ${opts.overallRisk} risk`,
      header:  { gradient: blocked ? "linear-gradient(135deg,#0f172a,#4c1d95)" : "linear-gradient(135deg,#0f172a,#052e16)", badge: "Scan Complete", title: `${opts.repo.split("/")[1]} · PR #${opts.prNumber}`, subtitle: `${opts.overallRisk} risk · ${(opts.aiPct*100).toFixed(0)}% AI content` },
      body,
      appUrl:  opts.appUrl,
      orgName: opts.orgName,
    }),
    text: `Scan: ${opts.repo} PR #${opts.prNumber}\nRisk: ${opts.overallRisk}\nAI: ${(opts.aiPct*100).toFixed(0)}%\n${opts.reviewUrl}`,
  };
}

// ── Weekly digest email ───────────────────────────────────────────────────────

export function weeklyDigestEmail(opts: {
  orgName:        string;
  periodStart:    string;
  periodEnd:      string;
  totalScans:     number;
  totalAttest:    number;
  openViolations: number;
  critCaught:     number;
  topRepos:       Array<{ name: string; risk: string; ai_pct: number }>;
  appUrl:         string;
}): EmailTemplate {
  const period = `${new Date(opts.periodStart).toLocaleDateString("en-GB",{day:"numeric",month:"short"})} – ${new Date(opts.periodEnd).toLocaleDateString("en-GB",{day:"numeric",month:"short",year:"numeric"})}`;

  const body = `
    <p style="font-size:13px;color:#64748b">Weekly security digest for <strong>${opts.orgName}</strong> · ${period}</p>
    <div class="metric-row">
      <div class="metric"><div class="metric-val" style="color:#6366f1">${opts.totalScans}</div><div class="metric-label">Scans Run</div></div>
      <div class="metric"><div class="metric-val" style="color:#10b981">${opts.totalAttest}</div><div class="metric-label">Attestations</div></div>
      <div class="metric"><div class="metric-val" style="color:${opts.openViolations>0?"#ef4444":"#22c55e"}">${opts.openViolations}</div><div class="metric-label">Open Violations</div></div>
    </div>
    ${opts.critCaught > 0 ? `<p style="font-size:13px;color:#b91c1c;background:#fff1f2;padding:10px;border-radius:8px;border:1px solid #fecdd3"><strong>🔴 ${opts.critCaught} CRITICAL finding${opts.critCaught>1?"s":""}</strong> caught and logged this week.</p>` : `<p style="font-size:13px;color:#15803d;background:#f0fdf4;padding:10px;border-radius:8px;border:1px solid #bbf7d0">✅ No CRITICAL findings this week. Keep it up!</p>`}
    ${opts.topRepos.length > 0 ? `
    <p style="font-size:12px;font-weight:700;color:#475569;margin:20px 0 8px">Top repositories by activity:</p>
    <table class="table">
      <thead><tr><th>Repository</th><th>Risk</th><th>AI Content</th></tr></thead>
      <tbody>${opts.topRepos.slice(0,5).map(r => `<tr><td>${r.name}</td><td><span class="badge-risk ${r.risk.toLowerCase()}">${r.risk}</span></td><td>${(r.ai_pct*100).toFixed(0)}%</td></tr>`).join("")}</tbody>
    </table>` : ""}
    <a href="${opts.appUrl}/reports" class="cta">Download Full Report →</a>
  `;

  return {
    subject: `Weekly TrustLedger Digest — ${opts.orgName} · ${period}`,
    html: layout({
      title:   "Weekly Security Digest",
      preview: `${opts.totalScans} scans · ${opts.openViolations} open violations · ${opts.critCaught} CRITICAL`,
      header:  { gradient:"linear-gradient(135deg,#0f172a,#1e1040)", badge:"Weekly Digest", title:`Security Summary · ${opts.orgName}`, subtitle:period },
      body,
      appUrl:  opts.appUrl,
      orgName: opts.orgName,
    }),
    text: `Weekly digest for ${opts.orgName}\nScans: ${opts.totalScans}\nAttestations: ${opts.totalAttest}\nOpen violations: ${opts.openViolations}\n${opts.appUrl}/reports`,
  };
}

// ── Invite email ──────────────────────────────────────────────────────────────

export function inviteEmail(opts: {
  inviteeName:  string;
  inviterName:  string;
  orgName:      string;
  role:         string;
  acceptUrl:    string;
  appUrl:       string;
}): EmailTemplate {
  const body = `
    <p style="font-size:14px;color:#334155;line-height:1.6"><strong>${opts.inviterName}</strong> has invited you to join the <strong>${opts.orgName}</strong> organisation on TrustLedger as a <strong>${opts.role.replace(/_/g," ")}</strong>.</p>
    <p style="font-size:13px;color:#64748b;line-height:1.6">TrustLedger is an AI code governance platform that scans pull requests for AI-generated code, enforces reviewer attestation, and generates compliance reports.</p>
    <a href="${opts.acceptUrl}" class="cta">Accept Invitation →</a>
    <p style="font-size:11px;text-align:center;color:#94a3b8">This invitation expires in 7 days. If you didn't expect this, you can ignore this email.</p>
  `;
  return {
    subject: `${opts.inviterName} invited you to ${opts.orgName} on TrustLedger`,
    html: layout({
      title:   "You're invited to TrustLedger",
      preview: `${opts.inviterName} invited you to join ${opts.orgName}`,
      header:  { gradient:"linear-gradient(135deg,#6366f1,#7c3aed)", title:`You're invited to ${opts.orgName}`, subtitle:`Invited by ${opts.inviterName}` },
      body,
      appUrl:  opts.appUrl,
      orgName: opts.orgName,
    }),
    text: `${opts.inviterName} invited you to ${opts.orgName} on TrustLedger.\nAccept: ${opts.acceptUrl}`,
  };
}
