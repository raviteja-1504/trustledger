import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { runScan } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import { validateBody, CreateScanSchema } from "@/lib/validation";
import { logger } from "@/lib/logger";
import { cacheDel, cacheKeys } from "@/lib/cache";

// Day windows the dashboard UI requests (src/app/dashboard/page.tsx DAYS_OPTIONS)
const DASHBOARD_CACHE_DAYS = [7, 30, 90];

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url   = new URL(req.url);
  const repo  = url.searchParams.get("repo") ?? undefined;
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "100"), 200);

  const db = createServiceClient();

  let query = db
    .from("scans")
    .select("id, repo_full_name, pr_number, commit_sha, branch, overall_risk, total_ai_percentage, file_count, created_at, triggered_by")
    .eq("org_id", org_id)
    .order("created_at", { ascending: false })
    .limit(limit);

  if (repo) query = query.eq("repo_full_name", repo);

  const { data: scans, error: dbErr } = await query;
  if (dbErr) return NextResponse.json({ error: "db_error" }, { status: 500 });

  // Count attestations per scan in one query
  const scanIds = (scans ?? []).map(s => s.id);
  const attestCounts = new Map<string, number>();
  if (scanIds.length > 0) {
    const { data: attests } = await db
      .from("attestations")
      .select("scan_id")
      .in("scan_id", scanIds);
    (attests ?? []).forEach(a => {
      attestCounts.set(a.scan_id, (attestCounts.get(a.scan_id) ?? 0) + 1);
    });
  }

  return NextResponse.json({
    scans: (scans ?? []).map(s => ({
      scan_id:             s.id,
      repo:                s.repo_full_name,
      pr_number:           s.pr_number ?? 0,
      commit_sha:          s.commit_sha,
      branch:              s.branch ?? "main",
      overall_risk:        s.overall_risk,
      total_ai_percentage: s.total_ai_percentage,
      file_count:          s.file_count,
      attested_count:      attestCounts.get(s.id) ?? 0,
      created_at:          s.created_at,
      triggered_by:        s.triggered_by ?? "api",
    })),
  });
}

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  // Rate limit: 60 scans/minute per org
  const rl = await checkRateLimit(org_id, RATE_LIMITS.scan);
  if (!rl.success) {
    return NextResponse.json({ error: "rate_limit_exceeded", retry_after: rl.reset }, {
      status: 429,
      headers: rl.headers,
    });
  }

  // Validate request body with Zod
  const validation = await validateBody(req, CreateScanSchema);
  if (!validation.ok) return validation.response;
  const body = validation.data;

  type LocalResult = { ai_percentage: number; risk_score: string; risk_indicators: string[]; content_hash: string; line_count: number; language: string };

  // If files have pre-computed local results, skip re-scanning
  const isLocalScan = body.local_scan === true && body.files.every(f => f._local_result);
  let result: import("@/lib/scanner").ScanOutput;

  if (isLocalScan) {
    // Build ScanOutput from pre-computed local results
    const crypto = await import("crypto");
    const scanId = crypto.randomUUID();
    const emptySupplyChain  = () => ({ score: 0, risky_imports: [] as string[], typosquats: [] as string[], suspicious: [] as string[] });
    const emptyBehavioral   = () => ({ score: 0, logic_bombs: 0, exfiltration_patterns: 0, timing_channels: 0, hidden_channels: 0 });
    const emptyProvenance   = () => ({ drift_score: 0, temporal_risk: 0, agentic_artifacts: [] as string[] });
    const files  = body.files.map(f => {
      const lr = f._local_result!;
      return {
        file_path:         f.path,
        language:          lr.language,
        ai_percentage:     lr.ai_percentage,
        risk_score:        lr.risk_score as import("@/lib/scanner").RiskLevel,
        risk_indicators:   lr.risk_indicators,
        indicators:        [],
        content_hash:      lr.content_hash,
        line_count:        lr.line_count,
        attribution:       { model:"unknown" as const, confidence:0, signals:[], breakdown:{ "github-copilot":0,chatgpt:0,gemini:0,claude:0,codewhisperer:0,cursor:0,tabnine:0,human:0,unknown:0 }, humanEvidence:0 },
        scan_quality:      0,
        fix_suggestions:   [],
        watermarks:        [],
        supply_chain:      emptySupplyChain(),
        behavioral_risk:   emptyBehavioral(),
        provenance:        emptyProvenance(),
        line_attribution:  [] as number[],
        explained_signals: [],
        exploitability:    null,
        compliance:        null,
        ast_metrics:       null,
        ast_risks:         [],
        ssa_taint_paths:   [],
        ml_score:          null,
      };
    });
    const riskOrder: Record<string, number> = { LOW:0, MEDIUM:1, HIGH:2, CRITICAL:3, UNKNOWN:-1 };
    const overallRisk = files.reduce<string>((m, f) => riskOrder[f.risk_score] > riskOrder[m] ? f.risk_score : m, "LOW");
    const avgAI = files.length === 0 ? 0 : files.reduce((s, f) => s + f.ai_percentage, 0) / files.length;
    result = {
      scan_id:             scanId,
      repo:                body.repo,
      pr_number:           body.pr_number ?? 0,
      commit_sha:          body.commit_sha,
      overall_risk:        overallRisk as import("@/lib/scanner").RiskLevel,
      total_ai_percentage: avgAI,
      cross_file_ai_boost: false,
      mixed_authorship:    false,
      scan_quality:        0,
      ai_distribution:     { p10:0, p25:0, p50:avgAI, p75:avgAI, p90:avgAI },
      files,
      duration_ms:         0,
      scan_summary: {
        total_security_findings:  0,
        critical_count:           0,
        high_count:               0,
        medium_count:             0,
        low_count:                0,
        top_vuln_types:           [],
        ai_high_confidence_files: 0,
        requires_immediate_action: false,
      },
      cicd_trust:  null,
      trust_chain: { genesis_hash:"", file_hashes:[], chain_hash:"", scan_seal:"", timestamp: new Date().toISOString() },
      cross_file_consistency: { dominant_model:"unknown", style_agreement:1, outlier_files:[], mixed_languages:false },
      repository_trust: { score:1, factors:{ ai_percentage:0, security_density:0, cicd_trust:1, dep_risk:0, compliance_score:1, watermark_count:0, backdoor_risk:0 }, label:"TRUSTED" as const },
      dep_report:  null,
      compliance:  { frameworks:[], overall_score:1, top_findings:[] },
      skipped_unchanged: 0,
      semantic_graph: null,
      git_provenance: null,
      ai_tooling: [],
    };
  } else {
    // Run the real scanner on provided content
    result = runScan({
      repo:       body.repo,
      pr_number:  body.pr_number ?? 0,
      commit_sha: body.commit_sha,
      branch:     body.branch,
      files:      body.files,
    });
  }

  // ── Demo mode: skip all DB writes, return result immediately ─────────────
  if (process.env.NEXT_PUBLIC_SKIP_AUTH === "true") {
    return NextResponse.json({
      scan_id:             result.scan_id,
      repo:                body.repo,
      pr_number:           body.pr_number,
      commit_sha:          body.commit_sha,
      overall_risk:        result.overall_risk,
      total_ai_percentage: result.total_ai_percentage,
      file_count:          result.files.length,
      duration_ms:         result.duration_ms,
      files: result.files.map(f => ({
        file_path:       f.file_path,
        language:        f.language,
        ai_percentage:   f.ai_percentage,
        risk_score:      f.risk_score,
        risk_indicators: f.risk_indicators,
        attested:        false,
      })),
    });
  }

  const db = createServiceClient();

  // Ensure repo record exists
  const { data: repo } = await db
    .from("repositories")
    .upsert({ org_id, repo_full_name: body.repo, default_branch: body.branch ?? "main" },
      { onConflict: "org_id,repo_full_name" })
    .select("id")
    .single();

  // Insert scan record
  const { data: scan, error: scanErr } = await db
    .from("scans")
    .insert({
      id:                  result.scan_id,
      org_id,
      repo_id:             repo?.id ?? null,
      repo_full_name:      body.repo,
      pr_number:           body.pr_number ?? null,
      commit_sha:          body.commit_sha,
      branch:              body.branch ?? null,
      overall_risk:        result.overall_risk,
      total_ai_percentage: result.total_ai_percentage,
      file_count:          result.files.length,
      triggered_by:        user_id ? "api" : "webhook",
      duration_ms:         result.duration_ms,
    })
    .select("id")
    .single();

  if (scanErr || !scan) {
    return NextResponse.json({ error: "scan_insert_failed" }, { status: 500 });
  }

  // Invalidate cached dashboard stats so this scan shows up immediately
  await Promise.all(DASHBOARD_CACHE_DAYS.map(days => cacheDel(cacheKeys.dashboard(org_id, days))));

  // Insert scan files
  if (result.files.length > 0) {
    const { error: filesErr } = await db.from("scan_files").insert(
      result.files.map(f => ({
        scan_id:         scan.id,
        org_id,
        file_path:       f.file_path,
        language:        f.language,
        ai_percentage:   f.ai_percentage,
        risk_score:      f.risk_score,
        risk_indicators: f.risk_indicators,
        content_hash:    f.content_hash,
        line_count:      f.line_count,
      })),
    );
    if (filesErr) logger.warn("scan_files insert failed", { scan_id: scan.id, error: filesErr.message });
  }

  // Create violations for CRITICAL/HIGH/MEDIUM files
  const violationFiles = result.files.filter(
    f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH" || f.risk_score === "MEDIUM"
  );
  if (violationFiles.length > 0) {
    const slaHours = result.overall_risk === "CRITICAL" ? 24 : 48;
    const { error: violErr } = await db.from("violations").insert(
      violationFiles.map(f => ({
        org_id,
        scan_id:      scan.id,
        file_path:    f.file_path,
        risk_score:   f.risk_score,
        sla_deadline: new Date(Date.now() + slaHours * 3600_000).toISOString(),
      })),
    );
    if (violErr) logger.warn("violations insert failed", { scan_id: scan.id, error: violErr.message });
  }

  // Create secret finding records
  const secretFiles = result.files.filter(f => f.risk_indicators.includes("hardcoded-secret"));
  if (secretFiles.length > 0) {
    const { error: secretErr } = await db.from("secret_findings").insert(
      secretFiles.flatMap(f =>
        f.indicators
          .filter(i => i.id === "hardcoded-secret")
          .map(i => ({
            org_id,
            scan_id:      scan.id,
            file_path:    f.file_path,
            secret_type:  "detected",
            severity:     (i.severity === "critical" ? "CRITICAL" : i.severity === "high" ? "HIGH" : "MEDIUM") as "CRITICAL"|"HIGH"|"MEDIUM",
            label:        i.label,
            masked_value: "detected",
            line_number:  i.line ?? null,
          }))
      ),
    );
    if (secretErr) logger.warn("secret_findings insert failed", { scan_id: scan.id, error: secretErr.message });
  }

  // Write audit log entry
  await writeAuditLog(db, {
    org_id,
    event_type:    "scan_complete",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? "webhook",
    resource_type: "scan",
    resource_id:   scan.id,
    payload: {
      repo:         body.repo,
      pr_number:    body.pr_number,
      commit_sha:   body.commit_sha,
      overall_risk: result.overall_risk,
      file_count:   result.files.length,
    },
  });

  // Structured log for observability
  logger.scan(scan.id, body.repo, result.overall_risk, result.duration_ms, org_id);

  return NextResponse.json({
    scan_id:             scan.id,
    repo:                body.repo,
    pr_number:           body.pr_number,
    commit_sha:          body.commit_sha,
    overall_risk:        result.overall_risk,
    total_ai_percentage: result.total_ai_percentage,
    file_count:          result.files.length,
    duration_ms:         result.duration_ms,
    files: result.files.map(f => ({
      file_path:       f.file_path,
      language:        f.language,
      ai_percentage:   f.ai_percentage,
      risk_score:      f.risk_score,
      risk_indicators: f.risk_indicators,
      attested:        false,
    })),
  });
}
