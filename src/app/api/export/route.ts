/**
 * Data Export API
 * Exports org data in CSV or JSON format for compliance, SIEM, and analysis.
 *
 * GET /api/export?type=violations&format=csv
 * GET /api/export?type=audit&format=json&limit=1000
 * GET /api/export?type=scans&format=csv&days=90
 * GET /api/export?type=attestations&format=csv
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../_middleware";

type ExportType = "violations" | "audit" | "scans" | "attestations" | "secrets" | "aibom";
type ExportFormat = "csv" | "json";

function toCSV(rows: Record<string, unknown>[], columns: string[]): string {
  const header = columns.join(",");
  const lines  = rows.map(row =>
    columns.map(col => {
      const val = row[col] ?? "";
      const str = String(val).replace(/"/g, '""');
      return str.includes(",") || str.includes("\n") || str.includes('"') ? `"${str}"` : str;
    }).join(",")
  );
  return [header, ...lines].join("\n");
}

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "security_reviewer");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });
  const { org_id } = auth;

  const url    = new URL(req.url);
  const type   = (url.searchParams.get("type") ?? "violations") as ExportType;
  const format = (url.searchParams.get("format") ?? "csv") as ExportFormat;
  const limit  = Math.min(parseInt(url.searchParams.get("limit") ?? "5000"), 10_000);
  const days   = parseInt(url.searchParams.get("days") ?? "90");
  const since  = new Date(Date.now() - days * 86400_000).toISOString();

  const db = createServiceClient();
  const filename = `trustledger-${type}-${new Date().toISOString().split("T")[0]}`;

  let data: Record<string, unknown>[] = [];
  let columns: string[] = [];

  switch (type) {

    case "violations": {
      const { data: rows } = await db
        .from("violations")
        .select("id, scan_id, file_path, risk_score, status, assigned_email, sla_deadline, resolved_at, created_at")
        .eq("org_id", org_id)
        .order("created_at", { ascending: false })
        .limit(limit) as { data: Record<string, unknown>[] | null };
      data    = rows ?? [];
      columns = ["id","scan_id","file_path","risk_score","status","assigned_email","sla_deadline","resolved_at","created_at"];
      break;
    }

    case "audit": {
      const { data: rows } = await db
        .from("audit_log")
        .select("id, event_type, actor_email, resource_type, resource_id, entry_hash, prev_hash, created_at")
        .eq("org_id", org_id)
        .order("id", { ascending: false })
        .limit(limit) as { data: Record<string, unknown>[] | null };
      data    = rows ?? [];
      columns = ["id","event_type","actor_email","resource_type","resource_id","entry_hash","prev_hash","created_at"];
      break;
    }

    case "scans": {
      const { data: rows } = await db
        .from("scans")
        .select("id, repo_full_name, pr_number, commit_sha, branch, overall_risk, total_ai_percentage, file_count, triggered_by, duration_ms, created_at")
        .eq("org_id", org_id)
        .gte("created_at", since)
        .order("created_at", { ascending: false })
        .limit(limit) as { data: Record<string, unknown>[] | null };
      data    = rows ?? [];
      columns = ["id","repo_full_name","pr_number","commit_sha","branch","overall_risk","total_ai_percentage","file_count","triggered_by","duration_ms","created_at"];
      break;
    }

    case "attestations": {
      const { data: rows } = await db
        .from("attestations")
        .select("id, scan_id, file_path, risk_score, reviewer_email, reviewer_github, payload_hash, created_at")
        .eq("org_id", org_id)
        .gte("created_at", since)
        .order("created_at", { ascending: false })
        .limit(limit) as { data: Record<string, unknown>[] | null };
      data    = rows ?? [];
      columns = ["id","scan_id","file_path","risk_score","reviewer_email","reviewer_github","payload_hash","created_at"];
      break;
    }

    case "aibom": {
      const { data: rows } = await db
        .from("scan_files")
        .select("scan_id, file_path, language, ai_percentage, risk_score, risk_indicators, created_at, scans(repo_full_name)")
        .eq("org_id", org_id)
        .gte("created_at", since)
        .order("ai_percentage", { ascending: false })
        .limit(limit) as { data: Array<{ scan_id: string; file_path: string; language: string | null; ai_percentage: number; risk_score: string; risk_indicators: string[]; created_at: string; scans: { repo_full_name: string } | null }> | null };

      const { data: attests } = await db
        .from("attestations")
        .select("scan_id, file_path")
        .eq("org_id", org_id)
        .gte("created_at", since) as { data: Array<{ scan_id: string; file_path: string }> | null };
      const attestedSet = new Set((attests ?? []).map(a => `${a.scan_id}::${a.file_path}`));

      data = (rows ?? []).map(f => ({
        file_path:       f.file_path,
        language:        f.language ?? "unknown",
        ai_percentage:   f.ai_percentage,
        risk_score:      f.risk_score,
        risk_indicators: f.risk_indicators ?? [],
        scan_id:         f.scan_id,
        repo:            f.scans?.repo_full_name ?? "",
        scanned_at:      f.created_at,
        attested:        attestedSet.has(`${f.scan_id}::${f.file_path}`),
      }));
      columns = ["repo","file_path","language","ai_percentage","risk_score","risk_indicators","scan_id","scanned_at","attested"];
      break;
    }

    case "secrets": {
      const { data: rows } = await db
        .from("secret_findings")
        .select("id, scan_id, file_path, secret_type, severity, label, masked_value, status, resolved_email, resolved_at, created_at")
        .eq("org_id", org_id)
        .order("created_at", { ascending: false })
        .limit(limit) as { data: Record<string, unknown>[] | null };
      data    = rows ?? [];
      columns = ["id","scan_id","file_path","secret_type","severity","label","masked_value","status","resolved_email","resolved_at","created_at"];
      break;
    }

    default:
      return NextResponse.json({ error: "invalid_type" }, { status: 400 });
  }

  if (format === "json") {
    return new NextResponse(JSON.stringify({ exported_at: new Date().toISOString(), count: data.length, data }, null, 2), {
      headers: {
        "Content-Type":        "application/json",
        "Content-Disposition": `attachment; filename="${filename}.json"`,
      },
    });
  }

  // CSV
  const csv = toCSV(data, columns);
  return new NextResponse(csv, {
    headers: {
      "Content-Type":        "text/csv",
      "Content-Disposition": `attachment; filename="${filename}.csv"`,
    },
  });
}
