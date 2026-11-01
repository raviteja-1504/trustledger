/**
 * Loads the change-management register (lib/changeRegister.ts) for an organisation and period: merged pull requests
 * and their reviews from GitHub (through the organisation's GitHub App installations), and TrustLedger's scans,
 * HIGH/CRITICAL files and sign-offs from the database. A repository GitHub won't list is recorded in `coverage` with
 * the reason, so the register states that its population is incomplete instead of silently missing changes.
 *
 * Server-only (service-role client, installation tokens).
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { allRows } from "@/lib/allRows";
import { getInstallationToken, listMergedPullRequests, listPullReviews, mapWithConcurrency, readBranchProtection } from "@/lib/github";
import { normalizeProtection } from "@/lib/branchProtection";
import {
  buildRegister, pullKey, type ChangeRegister, type MergedPull, type PullReview, type RegisterRiskyFile, type RegisterScan,
  type RegisterSignoff, type RepoCoverage,
} from "@/lib/changeRegister";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

const REVIEW_CONCURRENCY = 6;
const MAX_PULLS_PER_REPO = 1000;
// A pull request merged in the period may have been scanned before it started: look back this far for its scans.
const SCAN_LOOKBACK_DAYS = 90;
const IN_CHUNK = 200;

// A failed read would show up as missing evidence (every pull request "not scanned"), so it fails the register instead.
async function rowsOrThrow<T>(what: string, page: (from: number, to: number) => PromiseLike<{ data: T[] | null; error?: unknown }>): Promise<T[]> {
  const { data, error } = await allRows<T>(page);
  if (error) throw new Error(`change register: reading ${what} failed`);
  return data;
}

async function inChunks<T>(what: string, ids: string[], fetch: (chunk: string[], from: number, to: number) => PromiseLike<{ data: T[] | null; error?: unknown }>): Promise<T[]> {
  const out: T[] = [];
  for (let i = 0; i < ids.length; i += IN_CHUNK) out.push(...await rowsOrThrow<T>(what, (from, to) => fetch(ids.slice(i, i + IN_CHUNK), from, to)));
  return out;
}

export async function loadChangeRegister(db: Db, orgId: string, periodStart: string, periodEnd: string): Promise<ChangeRegister> {
  const [{ data: repoRows, error: repoErr }, { data: installs, error: installErr }] = await Promise.all([
    db.from("repositories").select("repo_full_name").eq("org_id", orgId).eq("is_active", true) as unknown as Promise<{ data: Array<{ repo_full_name: string }> | null; error: unknown }>,
    db.from("github_installations").select("installation_id, github_org").eq("org_id", orgId).limit(20) as unknown as Promise<{ data: Array<{ installation_id: number; github_org: string | null }> | null; error: unknown }>,
  ]);
  if (repoErr || installErr) throw new Error("change register: reading repositories failed");
  const repos = (repoRows ?? []).map(r => r.repo_full_name);

  // One installation token per installation, fetched once (an org can have the App on several GitHub accounts).
  const tokens = new Map<number, Promise<string>>();
  const tokenFor = (id: number) => {
    if (!tokens.has(id)) tokens.set(id, getInstallationToken(id).then(t => t.token));
    return tokens.get(id)!;
  };

  const pulls: MergedPull[] = [];
  const coverage: RepoCoverage[] = [];
  const tokenByRepo = new Map<string, string>();
  for (const repo of repos) {
    const [owner, name] = repo.split("/");
    // same choice as lib/connectedRepo.ts: the installation that owns this repository, else the first one
    const install = (installs ?? []).find(i => (i.github_org ?? "").toLowerCase() === owner.toLowerCase()) ?? (installs ?? [])[0];
    if (!install) { coverage.push({ repo, read: false, pulls: 0, reason: "The TrustLedger GitHub App is not installed" }); continue; }
    try {
      const token = await tokenFor(install.installation_id);
      const { pulls: merged, truncated } = await listMergedPullRequests(token, owner, name, periodStart, periodEnd, MAX_PULLS_PER_REPO);
      tokenByRepo.set(repo, token);
      pulls.push(...merged.map(p => ({ ...p, repo })));
      coverage.push({ repo, read: true, pulls: merged.length, ...(truncated ? { truncated: true, reason: `Only the first ${MAX_PULLS_PER_REPO} merged pull requests were read` } : {}) });
    } catch (err) {
      coverage.push({ repo, read: false, pulls: 0, reason: `GitHub didn't return this repository's pull requests (${err instanceof Error ? err.message : "error"})` });
    }
  }

  // Reviews per pull request. A pull request whose reviews couldn't be read is left with none (it then shows as
  // unapproved) and the repository's coverage notes it -- never reported as approved without evidence.
  const reviews = new Map<string, PullReview[]>();
  const reviewFailures = new Map<string, number>();
  await mapWithConcurrency(pulls, REVIEW_CONCURRENCY, async p => {
    const [owner, name] = p.repo.split("/");
    try {
      reviews.set(pullKey(p.repo, p.number), await listPullReviews(tokenByRepo.get(p.repo)!, owner, name, p.number));
    } catch {
      reviewFailures.set(p.repo, (reviewFailures.get(p.repo) ?? 0) + 1);
    }
  });
  for (const c of coverage) {
    const failed = reviewFailures.get(c.repo);
    if (failed) Object.assign(c, { truncated: true, reason: `${failed} pull request${failed === 1 ? "'s" : "s'"} reviews couldn't be read from GitHub` });
  }

  // TrustLedger's scans of those pull requests, their HIGH/CRITICAL files and sign-offs.
  const wanted = new Set(pulls.map(p => pullKey(p.repo, p.number)));
  const lookback = new Date(new Date(periodStart).getTime() - SCAN_LOOKBACK_DAYS * 86400_000).toISOString();
  const scanRows = repos.length === 0 ? [] : await rowsOrThrow<{ id: string; repo_full_name: string; pr_number: number | null; commit_sha: string | null; created_at: string; overall_risk: string }>("scans", (from, to) =>
    db.from("scans").select("id, repo_full_name, pr_number, commit_sha, created_at, overall_risk").eq("org_id", orgId)
      .in("repo_full_name", repos).gte("created_at", lookback).lte("created_at", periodEnd)
      .order("created_at", { ascending: true }).order("id", { ascending: true }).range(from, to) as unknown as PromiseLike<{ data: never[] | null; error: unknown }>);
  const scans: RegisterScan[] = scanRows
    .filter(s => s.pr_number != null && wanted.has(pullKey(s.repo_full_name, s.pr_number)))
    .map(s => ({ scan_id: s.id, repo: s.repo_full_name, pr_number: s.pr_number!, commit_sha: s.commit_sha, created_at: s.created_at, overall_risk: s.overall_risk }));
  const ids = scans.map(s => s.scan_id);
  const [riskyFiles, signoffs] = await Promise.all([
    inChunks<RegisterRiskyFile>("scan files", ids, (c, f, t) => db.from("scan_files").select("scan_id, file_path, risk_score").eq("org_id", orgId).in("scan_id", c)
      .in("risk_score", ["CRITICAL", "HIGH"]).order("scan_id", { ascending: true }).order("file_path", { ascending: true }).order("id", { ascending: true }).range(f, t) as unknown as PromiseLike<{ data: RegisterRiskyFile[] | null; error: unknown }>),
    inChunks<RegisterSignoff>("sign-offs", ids, (c, f, t) => db.from("attestations").select("scan_id, file_path, reviewer_github, created_at").eq("org_id", orgId).in("scan_id", c)
      .order("scan_id", { ascending: true }).order("file_path", { ascending: true }).order("id", { ascending: true }).range(f, t) as unknown as PromiseLike<{ data: RegisterSignoff[] | null; error: unknown }>),
  ]);

  // How each default branch is protected right now: the design of the control whose operation the register shows.
  const branch_protection = await mapWithConcurrency(repos, REVIEW_CONCURRENCY, async repo => {
    const token = tokenByRepo.get(repo);
    if (!token) return normalizeProtection({ repo, branch: null, protected: null, rules: null, classic: "unreadable", error: coverage.find(c => c.repo === repo)?.reason ?? "not read" });
    const [owner, name] = repo.split("/");
    return normalizeProtection(await readBranchProtection(token, owner, name));
  });

  return { ...buildRegister({ period_start: periodStart, period_end: periodEnd, pulls, reviews, scans, riskyFiles, signoffs, coverage }), branch_protection };
}
