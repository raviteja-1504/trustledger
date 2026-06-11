/**
 * GitHub PR Comment Bot
 * Posts a detailed TrustLedger risk summary as a PR comment.
 * Called after scan completion — provides rich feedback directly in the PR.
 *
 * POST /api/github-app/comment
 * Body: { scan_id, repo, pr_number, installation_id }
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { getInstallationToken } from "@/lib/github";

const RISK_EMOJI: Record<string, string> = {
  CRITICAL:"🔴", HIGH:"🟠", MEDIUM:"🟡", LOW:"🟢", UNKNOWN:"⚪",
};

const INDICATOR_LABEL: Record<string, string> = {
  "hardcoded-secret":    "Hardcoded credential",
  "sql-injection":       "SQL injection pattern",
  "eval-exec":           "Arbitrary code execution (eval/exec)",
  "jwt-none-alg":        "JWT none-algorithm bypass",
  "command-injection":   "Command injection",
  "comment-density":     "High comment density (AI indicator)",
  "structural-uniformity":"Structural uniformity (AI indicator)",
  "identifier-entropy":  "Low-entropy identifiers (AI indicator)",
  "ai-comment-pattern":  "AI comment patterns",
  "ai-model-attribution":"AI model attribution",
};

function buildPRComment(scan: {
  scan_id:            string;
  repo:               string;
  pr_number:          number;
  overall_risk:       string;
  total_ai_percentage:number;
  files: Array<{ file_path: string; risk_score: string; ai_percentage: number; risk_indicators: string[]; attested: boolean }>;
  appUrl:             string;
}): string {
  const { CRITICAL:crit=0, HIGH:high=0, MEDIUM:med=0, LOW:low=0 } = scan.files.reduce(
    (acc, f) => { acc[f.risk_score] = (acc[f.risk_score] ?? 0) + 1; return acc; },
    {} as Record<string, number>,
  );

  const blocked  = scan.overall_risk === "CRITICAL" || scan.overall_risk === "HIGH";
  const aiPct    = (scan.total_ai_percentage * 100).toFixed(0);
  const riskEmoji= RISK_EMOJI[scan.overall_risk] ?? "⚪";
  const reviewUrl= `${scan.appUrl}/pr/${scan.scan_id}`;

  const lines: string[] = [
    `## ${riskEmoji} TrustLedger AI Governance — ${scan.overall_risk} Risk`,
    "",
    blocked
      ? `> ⛔ **Merge blocked** — ${crit + high} file(s) with CRITICAL/HIGH AI risk require attestation before this PR can be merged.`
      : `> ✅ **Policy gate passed** — all AI governance requirements are met.`,
    "",
    "### Summary",
    "",
    `| Metric | Value |`,
    `|--------|-------|`,
    `| Overall Risk | ${riskEmoji} **${scan.overall_risk}** |`,
    `| Average AI Content | ${aiPct}% |`,
    `| Files Scanned | ${scan.files.length} |`,
    `| CRITICAL | ${RISK_EMOJI.CRITICAL} ${crit} |`,
    `| HIGH | ${RISK_EMOJI.HIGH} ${high} |`,
    `| MEDIUM | ${RISK_EMOJI.MEDIUM} ${med} |`,
    `| LOW | ${RISK_EMOJI.LOW} ${low} |`,
  ];

  // High-risk files table
  const highRisk = scan.files.filter(f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH");
  if (highRisk.length > 0) {
    lines.push("", "### Files Requiring Attestation", "");
    lines.push("| File | Risk | AI% | Indicators | Status |");
    lines.push("|------|------|-----|------------|--------|");
    highRisk.slice(0, 10).forEach(f => {
      const indicators = f.risk_indicators
        .filter(i => !i.startsWith("comment") && !i.startsWith("structural") && !i.startsWith("identifier"))
        .slice(0, 2)
        .map(i => INDICATOR_LABEL[i] ?? i)
        .join(", ") || "AI content";
      const status = f.attested ? "✅ Attested" : "⏳ Pending";
      lines.push(`| \`${f.file_path.split("/").slice(-2).join("/")}\` | ${RISK_EMOJI[f.risk_score]} ${f.risk_score} | ${(f.ai_percentage*100).toFixed(0)}% | ${indicators} | ${status} |`);
    });
    if (highRisk.length > 10) {
      lines.push(`| _...and ${highRisk.length - 10} more_ | | | | |`);
    }
  }

  // Security findings summary
  const securityFiles = scan.files.filter(f =>
    f.risk_indicators.some(i => ["hardcoded-secret","sql-injection","eval-exec","jwt-none-alg","command-injection"].includes(i))
  );
  if (securityFiles.length > 0) {
    lines.push("", "### ⚠️ Security Findings", "");
    securityFiles.slice(0, 5).forEach(f => {
      const secIndicators = f.risk_indicators.filter(i =>
        ["hardcoded-secret","sql-injection","eval-exec","jwt-none-alg","command-injection"].includes(i)
      );
      secIndicators.forEach(ind => {
        lines.push(`- **${INDICATOR_LABEL[ind] ?? ind}** in \`${f.file_path}\``);
      });
    });
  }

  lines.push(
    "",
    "---",
    "",
    `**[📋 Full review in TrustLedger](${reviewUrl})** · Scan ID: \`${scan.scan_id.slice(0,8)}\``,
    "",
    blocked
      ? `To unblock: attest all CRITICAL and HIGH files in TrustLedger, then re-run this check.`
      : `_Powered by [TrustLedger](${scan.appUrl}) AI Code Governance_`,
  );

  return lines.join("\n");
}

async function findExistingComment(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<number | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/issues/${prNumber}/comments?per_page=50`,
    { headers: { Authorization: `token ${token}`, Accept: "application/vnd.github+json" } },
  );
  if (!res.ok) return null;
  const comments = await res.json() as Array<{ id: number; body: string; user: { login: string } }>;
  const existing  = comments.find(c => c.body.includes("TrustLedger AI Governance") && c.user.login.endsWith("[bot]"));
  return existing?.id ?? null;
}

async function upsertComment(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
  body: string,
  existingId?: number | null,
): Promise<void> {
  const GITHUB_API = "https://api.github.com";
  const headers    = { Authorization: `token ${token}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" };

  if (existingId) {
    await fetch(`${GITHUB_API}/repos/${owner}/${repo}/issues/comments/${existingId}`, {
      method: "PATCH", headers, body: JSON.stringify({ body }),
    });
  } else {
    await fetch(`${GITHUB_API}/repos/${owner}/${repo}/issues/${prNumber}/comments`, {
      method: "POST", headers, body: JSON.stringify({ body }),
    });
  }
}

export async function POST(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as {
    scan_id:          string;
    repo:             string;
    pr_number:        number;
    installation_id?: number;
  };

  if (!body.scan_id || !body.repo || !body.pr_number) {
    return NextResponse.json({ error: "missing_fields" }, { status: 400 });
  }

  const db = createServiceClient();

  // Fetch scan + files
  const { data: scan } = await db
    .from("scans")
    .select("id, repo_full_name, pr_number, overall_risk, total_ai_percentage")
    .eq("id", body.scan_id).eq("org_id", org_id)
    .single() as { data: Record<string, unknown> | null };

  if (!scan) return NextResponse.json({ error: "scan_not_found" }, { status: 404 });

  const { data: files } = await db
    .from("scan_files")
    .select("file_path, risk_score, ai_percentage, risk_indicators")
    .eq("scan_id", body.scan_id) as { data: Array<{ file_path: string; risk_score: string; ai_percentage: number; risk_indicators: string[] }> | null };

  const { data: attests } = await db
    .from("attestations")
    .select("file_path")
    .eq("scan_id", body.scan_id) as { data: Array<{ file_path: string }> | null };

  const attestedPaths = new Set((attests ?? []).map(a => a.file_path));

  const filesWithAttest = (files ?? []).map(f => ({
    ...f, attested: attestedPaths.has(f.file_path),
  }));

  // Get GitHub token
  let token: string | null = null;
  if (body.installation_id) {
    try { const t = await getInstallationToken(body.installation_id); token = t.token; } catch {}
  } else {
    const { data: install } = await db
      .from("github_installations")
      .select("installation_id")
      .eq("org_id", org_id)
      .single() as { data: { installation_id: number } | null };
    if (install) {
      try { const t = await getInstallationToken(install.installation_id); token = t.token; } catch {}
    }
  }

  if (!token) return NextResponse.json({ error: "no_github_token" }, { status: 422 });

  const [owner, repoName] = body.repo.split("/");
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

  const comment = buildPRComment({
    scan_id:            body.scan_id,
    repo:               body.repo,
    pr_number:          body.pr_number,
    overall_risk:       scan.overall_risk as string,
    total_ai_percentage:scan.total_ai_percentage as number,
    files:              filesWithAttest,
    appUrl,
  });

  // Find existing TrustLedger comment to update (avoid spam)
  const existingId = await findExistingComment(token, owner, repoName, body.pr_number);
  await upsertComment(token, owner, repoName, body.pr_number, comment, existingId);

  return NextResponse.json({ ok: true, updated: !!existingId });
}
