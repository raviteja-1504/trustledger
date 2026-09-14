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

/** Fetch the GitHub org/user login an installation belongs to. */
export async function getInstallationAccount(installationId: number): Promise<string> {
  const jwt = buildAppJWT();
  const res = await fetch(`${GITHUB_API}/app/installations/${installationId}`, {
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept:        "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  if (!res.ok) throw new Error(`GitHub installation lookup failed: ${res.status}`);
  const data = await res.json() as { account: { login: string } };
  return data.account.login;
}

/** Build a short-lived JWT for the GitHub App. */
function buildAppJWT(): string {
  // Trim \r from App ID (Windows CLI piping adds carriage returns to env vars)
  const appId      = (process.env.GITHUB_APP_ID ?? "").replace(/\r/g, "").trim();
  // Strip \r and convert escaped \n back to real newlines for the RSA key
  const privateKey = (process.env.GITHUB_APP_PRIVATE_KEY ?? "")
    .replace(/\r/g, "")
    .replace(/\\n/g, "\n");

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

// ── Bounded concurrency ───────────────────────────────────────────────────────
// A worker-pool mapper: at most `limit` calls to `fn` are ever in flight at
// once, regardless of how many `items` there are. Plain `Promise.all` has no
// such bound -- for a 1,700-file PR that means 1,700 simultaneous requests
// fired at once, which risks tripping GitHub's secondary rate limit / abuse
// detection (and gets worse now that multiple scans can run concurrently
// against the same shared installation token -- see queue.ts flowControl).
export async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

// ── File content ───────────────────────────────────────────────────────────────

export interface GitHubFile { path: string; content: string }

const FILE_FETCH_CONCURRENCY = 15;

/**
 * Fetch file contents for a list of paths at a given commit.
 * `token` is optional so whole-repo scans of a public repo with no
 * connected GitHub App installation can still fetch content (unauthenticated
 * GitHub API access works for public repos, just at a lower rate limit).
 */
export async function fetchFileContents(
  token: string | undefined,
  owner: string,
  repo: string,
  ref: string,
  paths: string[],
): Promise<GitHubFile[]> {
  const results: GitHubFile[] = [];

  await mapWithConcurrency(paths, FILE_FETCH_CONCURRENCY, async path => {
    try {
      const res = await fetch(
        `${GITHUB_API}/repos/${owner}/${repo}/contents/${path}?ref=${ref}`,
        {
          headers: {
            ...(token ? { Authorization: `token ${token}` } : {}),
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
  });

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

/**
 * Returns the PR's CURRENT head commit SHA, straight from GitHub.
 *
 * Used for scan supersession: a scan-worker invocation queued for commit X
 * can take tens of seconds, during which a developer may push commit Y. If
 * this returns something other than the SHA the caller was processing, a
 * newer scan for this PR is either already running or about to be queued,
 * so the caller should bail out rather than finish and present commit X's
 * (now stale) results as current. Returns null on any API failure so
 * callers fail open (proceed with the scan) rather than silently dropping
 * work over a transient GitHub API blip.
 */
export async function getPRHeadSha(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<string | null> {
  try {
    const res = await fetch(
      `${GITHUB_API}/repos/${owner}/${repo}/pulls/${prNumber}`,
      {
        headers: {
          Authorization: `token ${token}`,
          Accept:        "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      },
    );
    if (!res.ok) return null;
    const data = await res.json() as { head?: { sha?: string } };
    return data.head?.sha ?? null;
  } catch {
    return null;
  }
}

/**
 * Returns the set of file paths that changed between two commits.
 * Used for delta scanning: on a `synchronize` event we only need to re-scan
 * files that appeared in the new push, not the entire PR.
 */
export async function getCommitDiff(
  token: string,
  owner: string,
  repo: string,
  before: string,
  after: string,
): Promise<Set<string>> {
  try {
    const res = await fetch(
      `${GITHUB_API}/repos/${owner}/${repo}/compare/${before}...${after}`,
      {
        headers: {
          Authorization: `token ${token}`,
          Accept:        "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      },
    );
    if (!res.ok) return new Set();
    const data = await res.json() as { files?: PRFile[] };
    return new Set((data.files ?? []).map(f => f.filename));
  } catch {
    return new Set();
  }
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
  checkRunId: number | string,
  payload: Omit<CheckRunPayload, "head_sha">,
): Promise<void> {
  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/check-runs/${checkRunId}`, {
    method: "PATCH",
    headers: {
      Authorization: `token ${token}`,
      Accept:        "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new Error(`GitHub updateCheckRun failed: ${res.status} — ${detail.slice(0, 200)}`);
  }
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
