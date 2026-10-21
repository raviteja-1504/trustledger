import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, permissionsFor } from "../_middleware";
import { validateBody, AttestSchema } from "@/lib/validation";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import { safeError } from "@/lib/errors";
import { performAttestation } from "@/lib/attestation";
import {
  buildAttestationRecords,
  type RecordAttestationRow, type RecordFileRow, type RecordScanRow,
} from "@/lib/attestationRecords";

const PAGE = 1000;
const MAX_ROWS = 10_000;
const IN_CHUNK = 200;
const ISO = /^\d{4}-\d{2}-\d{2}(T[\d:.]+Z)?$/;
type Page<T> = PromiseLike<{ data: T[] | null; error: unknown }>;

async function all<T>(page: (from: number, to: number) => Page<T>): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; from < MAX_ROWS; from += PAGE) {
    const { data, error } = await page(from, from + PAGE - 1);
    if (error) throw error;
    out.push(...(data ?? []));
    if (!data || data.length < PAGE) break;
  }
  return out;
}

/**
 * GET /api/attest?since=YYYY-MM-DD&until=YYYY-MM-DD[&repo=owner/name] → every attestation record signed in the
 * period (inclusive, UTC days), explained: repository / PR / commit / file, the findings that required it, who signed
 * off, whether they were independent of the PR author, time from scan to sign-off, and the record hash
 * (lib/attestationRecords.ts). Developers see records for their own pull requests only.
 */
export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const { org_id, role, user_id } = auth;
  const p = req.nextUrl.searchParams;
  const since = p.get("since"), until = p.get("until"), repo = p.get("repo");
  if (!since || !until || !ISO.test(since) || !ISO.test(until)) {
    return NextResponse.json({ error: "invalid_period", message: "Pass since and until as YYYY-MM-DD." }, { status: 400 });
  }
  const start = since.length === 10 ? `${since}T00:00:00.000Z` : since;
  const end = until.length === 10 ? `${until}T23:59:59.999Z` : until;
  const db = createServiceClient();

  try {
    let ownLogin: string | null = null;
    if (role === "developer") {
      const { data: me } = user_id
        ? await db.from("org_members").select("github_login").eq("org_id", org_id).eq("user_id", user_id).maybeSingle() as { data: { github_login?: string | null } | null }
        : { data: null };
      ownLogin = me?.github_login ?? null;
      if (!ownLogin) return NextResponse.json({ ...buildAttestationRecords({ attestations: [], scans: [], files: [] }), period: { start, end }, scope: "own" });
    }

    const attestations = await all<RecordAttestationRow>((f, t) => db.from("attestations")
      .select("id, scan_id, file_path, risk_score, reviewer_email, reviewer_github, payload_hash, created_at")
      .eq("org_id", org_id).gte("created_at", start).lte("created_at", end)
      .order("created_at", { ascending: false }).order("id", { ascending: true }).range(f, t) as unknown as Page<RecordAttestationRow>);

    const scanIds = [...new Set(attestations.map(a => a.scan_id))];
    const chunks = Array.from({ length: Math.ceil(scanIds.length / IN_CHUNK) }, (_, i) => scanIds.slice(i * IN_CHUNK, (i + 1) * IN_CHUNK));
    const [scans, files] = await Promise.all([
      Promise.all(chunks.map(ids => all<RecordScanRow>((f, t) => db.from("scans")
        .select("id, repo_full_name, pr_number, commit_sha, branch, pr_author, created_at")
        .eq("org_id", org_id).in("id", ids).order("id", { ascending: true }).range(f, t) as unknown as Page<RecordScanRow>))).then(x => x.flat()),
      Promise.all(chunks.map(ids => all<RecordFileRow>((f, t) => db.from("scan_files")
        .select("scan_id, file_path, risk_indicators, ai_percentage")
        // Attested files are MEDIUM and above; skipping LOW files skips most of each scan.
        .eq("org_id", org_id).in("scan_id", ids).in("risk_score", ["CRITICAL", "HIGH", "MEDIUM"]).order("file_path", { ascending: true }).range(f, t) as unknown as Page<RecordFileRow>))).then(x => x.flat()),
    ]);

    // Scope: one repository, and/or a developer's own pull requests.
    const keep = new Set(scans.filter(s => (!repo || s.repo_full_name === repo) && (!ownLogin || s.pr_author === ownLogin)).map(s => s.id));
    const result = buildAttestationRecords({ attestations: attestations.filter(a => keep.has(a.scan_id)), scans, files });
    return NextResponse.json({ ...result, period: { start, end }, scope: ownLogin ? "own" : "org" }, { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    return safeError(err, { code: "attestation_records_failed", message: "We couldn't load attestation records right now. Please try again." });
  }
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, user_id, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });

  const rl = await checkRateLimit(org_id, RATE_LIMITS.attest);
  if (!rl.success) {
    return NextResponse.json({ error: "rate_limited" }, { status: 429, headers: rl.headers });
  }

  const validation = await validateBody(req, AttestSchema);
  if (!validation.ok) return validation.response;
  const body = validation.data;

  const db = createServiceClient();
  // A signed-in reviewer attests as themselves, whatever the body says -- their GitHub login included: attestation
  // records judge a sign-off independent when that login isn't the PR author's, so a typed-in handle could fake it.
  // An API-key caller (CI, the CLI) has no member identity and names the reviewer in the body.
  const reviewerEmail = auth.actor_email ?? body.reviewer_email;
  let reviewerGithub = body.reviewer_github;
  if (user_id) {
    const { data: member } = await db.from("org_members").select("github_login")
      .eq("org_id", org_id).eq("user_id", user_id).maybeSingle() as { data: { github_login?: string | null } | null };
    reviewerGithub = member?.github_login ?? undefined;
  }
  const result = await performAttestation(db, {
    org_id,
    user_id,
    scan_id:         body.scan_id,
    file_path:       body.file_path,
    reviewer_email:  reviewerEmail,
    reviewer_github: reviewerGithub,
    permissions:     await permissionsFor(auth),
  });

  if (!result.ok) {
    if (result.reason === "forbidden") {
      return NextResponse.json({ error: "insufficient_permissions", risk_score: result.risk_score }, { status: 403 });
    }
    if (result.reason === "scan_not_found") {
      return NextResponse.json({ error: "scan_not_found" }, { status: 404 });
    }
    return safeError(result.detail, { code: "attestation_failed", message: "We couldn't record this attestation. Please try again." });
  }

  return NextResponse.json({
    attestation_id: result.attestation_id,
    payload_hash:   result.payload_hash,
    attested_at:    result.attested_at,
    file_path:      body.file_path,
    // who the attestation was recorded for, not who the page asked for
    reviewer_email:  reviewerEmail,
    reviewer_github: reviewerGithub ?? null,
  });
}
