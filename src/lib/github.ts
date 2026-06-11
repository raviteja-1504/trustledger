/**
 * GitHub App integration helpers
 * - Webhook signature verification (HMAC-SHA256)
 * - Installation access token fetch
 * - PR check run creation / update
 * - File content fetching from GitHub API
 */

import crypto from "crypto";

const GITHUB_API = "https://api.github.com";

// ── Webhook verification ───────────────────────────────────────────────────────

/** Verify GitHub webhook HMAC-SHA256 signature. */
export function verifyWebhookSignature(
  payload: string,
  signature: string | null,
  secret: string,
): boolean {
  if (!signature) return false;
  const expected = `sha256=${crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("hex")}`;
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected),
    );
  } catch {
    return false;
  }
}

// ── Installation token ─────────────────────────────────────────────────────────

interface InstallationToken { token: string; expires_at: string }

export async function getInstallationToken(
  installationId: number,
): Promise<InstallationToken> {
  const jwt = buildAppJWT();
  const res = await fetch(
    `${GITHUB_API}/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept:        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    },
  );
  if (!res.ok) throw new Error(`GitHub token fetch failed: ${res.status}`);
  return res.json() as Promise<InstallationToken>;
}

/** Build a short-lived JWT for the GitHub App. */
function buildAppJWT(): string {
  const appId      = process.env.GITHUB_APP_ID!;
  const privateKey = process.env.GITHUB_APP_PRIVATE_KEY!.replace(/\\n/g, "\n");

  const now  = Math.floor(Date.now() / 1000);
  const exp  = now + 540;           // 9 minutes
  const header  = b64({ alg:"RS256", typ:"JWT" });
  const payload = b64({ iat: now - 60, exp, iss: appId });
  const unsigned = `${header}.${payload}`;
  const sig = crypto.createSign("RSA-SHA256").update(unsigned).sign(privateKey, "base64url");
  return `${unsigned}.${sig}`;
}

function b64(obj: object): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

// ── File content ───────────────────────────────────────────────────────────────

export interface GitHubFile { path: string; content: string }

/** Fetch file contents for a list of paths at a given commit. */
export async function fetchFileContents(
  token: string,
  owner: string,
  repo: string,
  ref: string,
  paths: string[],
): Promise<GitHubFile[]> {
  const results: GitHubFile[] = [];

  await Promise.all(
    paths.map(async path => {
      try {
        const res = await fetch(
          `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}?ref=${ref}`,
          {
            headers: {
              Authorization: `token ${token}`,
              Accept:        "application/vnd.github+json",
              "X-GitHub-Api-Version": "2022-11-28",
            },
          },
        );
        if (!res.ok) return;
        const data = await res.json() as { content?: string; encoding?: string };
        if (data.content && data.encoding === "base64") {
          results.push({ path, content: Buffer.from(data.content, "base64").toString("utf8") });
        }
      } catch { /* skip unreadable files */ }
    }),
  );

  return results;
}

// ── Changed files in a PR ──────────────────────────────────────────────────────

export interface PRFile { filename: string; status: string; additions: number; deletions: number }

export async function getPRFiles(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<PRFile[]> {
  const files: PRFile[] = [];
  let page = 1;

  while (true) {
    const res = await fetch(
      `${GITHUB_API}/repos/${owner}/${repo}/pulls/${prNumber}/files?per_page=100&page=${page}`,
      {
        headers: {
          Authorization: `token ${token}`,
          Accept:        "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      },
    );
    if (!res.ok) break;
    const data = await res.json() as PRFile[];
    if (data.length === 0) break;
    files.push(...data);
    if (data.length < 100) break;
    page++;
  }

  return files;
}

// ── Check runs ────────────────────────────────────────────────────────────────

export type CheckConclusion = "success" | "failure" | "neutral" | "cancelled" | "action_required";

interface CheckRunPayload {
  name:       string;
  head_sha:   string;
  status:     "queued" | "in_progress" | "completed";
  conclusion?: CheckConclusion;
  output?: {
    title:   string;
    summary: string;
    text?:   string;
  };
}

export async function createCheckRun(
  token: string,
  owner: string,
  repo: string,
  payload: CheckRunPayload,
): Promise<{ id: number }> {
  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/check-runs`, {
    method: "POST",
    headers: {
      Authorization: `token ${token}`,
      Accept:        "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`GitHub check-run failed: ${res.status}`);
  return res.json() as Promise<{ id: number }>;
}

export async function updateCheckRun(
  token: string,
  owner: string,
  repo: string,
  checkRunId: number,
  payload: Omit<CheckRunPayload, "head_sha">,
): Promise<void> {
  await fetch(`${GITHUB_API}/repos/${owner}/${repo}/check-runs/${checkRunId}`, {
    method: "PATCH",
    headers: {
      Authorization: `token ${token}`,
      Accept:        "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify(payload),
  });
}

/** Build a human-readable check-run summary from scan results. */
export function buildCheckSummary(scan: {
  overall_risk: string;
  total_ai_percentage: number;
  files: Array<{ file_path: string; risk_score: string; risk_indicators: string[] }>;
}): { title: string; summary: string; conclusion: CheckConclusion } {
  const blocked = scan.overall_risk === "CRITICAL" || scan.overall_risk === "HIGH";
  const critFiles = scan.files.filter(f => f.risk_score === "CRITICAL");
  const highFiles = scan.files.filter(f => f.risk_score === "HIGH");
  const aiPct     = (scan.total_ai_percentage * 100).toFixed(0);

  const title = blocked
    ? `TrustLedger: ${scan.overall_risk} risk — ${critFiles.length + highFiles.length} file(s) require attestation`
    : `TrustLedger: ${scan.overall_risk} — ${aiPct}% AI content`;

  const lines = [
    `**Overall Risk:** ${scan.overall_risk}`,
    `**Average AI Content:** ${aiPct}%`,
    `**Files Scanned:** ${scan.files.length}`,
    "",
  ];

  if (critFiles.length > 0) {
    lines.push("### 🔴 CRITICAL Files");
    critFiles.forEach(f => lines.push(`- \`${f.file_path}\` — ${f.risk_indicators.join(", ")}`));
    lines.push("");
  }
  if (highFiles.length > 0) {
    lines.push("### 🟠 HIGH Risk Files");
    highFiles.forEach(f => lines.push(`- \`${f.file_path}\` — ${f.risk_indicators.join(", ")}`));
    lines.push("");
  }

  if (blocked) {
    lines.push("**Action required:** Attest all CRITICAL and HIGH files in TrustLedger before this PR can merge.");
    lines.push(`Review at: ${process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev"}`);
  }

  return {
    title,
    summary:    lines.join("\n"),
    conclusion: blocked ? "action_required" : "success",
  };
}
