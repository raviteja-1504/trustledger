/**
 * Full-Text Search API
 * Searches across scans, violations, secrets, incidents, and audit log.
 *
 * GET /api/search?q=stripe&types=violations,secrets&limit=20
 *
 * Returns ranked results from multiple tables.
 * Uses Postgres ILIKE for now; in production upgrade to full-text search (pg_trgm + GIN index).
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";

type SearchType = "scans" | "violations" | "secrets" | "incidents" | "audit";

interface SearchResult {
  type:       SearchType;
  id:         string;
  title:      string;
  subtitle:   string;
  risk?:      string;
  href:       string;
  created_at: string;
  score:      number;
}

function rankResult(query: string, title: string, subtitle: string): number {
  const q = query.toLowerCase();
  let score = 0;
  if (title.toLowerCase().startsWith(q))          score += 100;
  if (title.toLowerCase().includes(q))             score += 50;
  if (subtitle.toLowerCase().includes(q))          score += 20;
  // Exact word match bonus
  if (new RegExp(`\\b${q}\\b`, "i").test(title))   score += 30;
  return score;
}

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url   = new URL(req.url);
  const query = url.searchParams.get("q")?.trim() ?? "";
  const typesParam = url.searchParams.get("types");
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "20"), 100);

  if (query.length < 2) {
    return NextResponse.json({ results: [], total: 0, query });
  }

  const types: SearchType[] = typesParam
    ? (typesParam.split(",").filter(t => ["scans","violations","secrets","incidents","audit"].includes(t)) as SearchType[])
    : ["scans","violations","secrets","incidents","audit"];

  const db      = createServiceClient();
  const pattern = `%${query}%`;
  const results: SearchResult[] = [];

  await Promise.all([

    // ── Scans ──────────────────────────────────────────────────────────────
    types.includes("scans") && (async () => {
      const { data } = await db
        .from("scans")
        .select("id, repo_full_name, commit_sha, overall_risk, created_at")
        .eq("org_id", org_id)
        .or(`repo_full_name.ilike.${pattern},commit_sha.ilike.${pattern}`)
        .order("created_at", { ascending: false })
        .limit(limit / types.length | 0) as { data: Array<{ id: string; repo_full_name: string; commit_sha: string; overall_risk: string; created_at: string }> | null };

      (data ?? []).forEach(s => results.push({
        type:       "scans",
        id:         s.id,
        title:      s.repo_full_name,
        subtitle:   `Scan · ${s.commit_sha.slice(0, 8)} · ${s.overall_risk}`,
        risk:       s.overall_risk,
        href:       `/pr/${s.id}`,
        created_at: s.created_at,
        score:      rankResult(query, s.repo_full_name, s.commit_sha),
      }));
    })(),

    // ── Violations ─────────────────────────────────────────────────────────
    types.includes("violations") && (async () => {
      const { data } = await db
        .from("violations")
        .select("id, file_path, risk_score, status, scan_id, created_at")
        .eq("org_id", org_id)
        .ilike("file_path", pattern)
        .order("created_at", { ascending: false })
        .limit(limit / types.length | 0) as { data: Array<{ id: string; file_path: string; risk_score: string; status: string; scan_id: string; created_at: string }> | null };

      (data ?? []).forEach(v => results.push({
        type:       "violations",
        id:         v.id,
        title:      v.file_path.split("/").pop() ?? v.file_path,
        subtitle:   `${v.risk_score} violation · ${v.status} · ${v.file_path}`,
        risk:       v.risk_score,
        href:       `/violations`,
        created_at: v.created_at,
        score:      rankResult(query, v.file_path, v.status),
      }));
    })(),

    // ── Secrets ────────────────────────────────────────────────────────────
    types.includes("secrets") && (async () => {
      const { data } = await db
        .from("secret_findings")
        .select("id, file_path, label, secret_type, severity, status, created_at")
        .eq("org_id", org_id)
        .or(`file_path.ilike.${pattern},label.ilike.${pattern},secret_type.ilike.${pattern}`)
        .order("created_at", { ascending: false })
        .limit(limit / types.length | 0) as { data: Array<{ id: string; file_path: string; label: string; secret_type: string; severity: string; status: string; created_at: string }> | null };

      (data ?? []).forEach(s => results.push({
        type:       "secrets",
        id:         s.id,
        title:      s.label,
        subtitle:   `${s.severity} · ${s.file_path} · ${s.status}`,
        risk:       s.severity,
        href:       `/secrets`,
        created_at: s.created_at,
        score:      rankResult(query, s.label, s.file_path),
      }));
    })(),

    // ── Incidents ──────────────────────────────────────────────────────────
    types.includes("incidents") && (async () => {
      const { data } = await db
        .from("incidents")
        .select("id, title, severity, status, affected_repo, detected_at")
        .eq("org_id", org_id)
        .or(`title.ilike.${pattern},affected_repo.ilike.${pattern}`)
        .order("detected_at", { ascending: false })
        .limit(limit / types.length | 0) as { data: Array<{ id: string; title: string; severity: string; status: string; affected_repo: string | null; detected_at: string }> | null };

      (data ?? []).forEach(i => results.push({
        type:       "incidents",
        id:         i.id,
        title:      i.title,
        subtitle:   `${i.severity} incident · ${i.status}${i.affected_repo ? ` · ${i.affected_repo}` : ""}`,
        risk:       i.severity,
        href:       `/incidents`,
        created_at: i.detected_at,
        score:      rankResult(query, i.title, i.affected_repo ?? ""),
      }));
    })(),

    // ── Audit log ──────────────────────────────────────────────────────────
    types.includes("audit") && (async () => {
      const { data } = await db
        .from("audit_log")
        .select("id, event_type, actor_email, resource_type, resource_id, created_at")
        .eq("org_id", org_id)
        .or(`event_type.ilike.${pattern},actor_email.ilike.${pattern},resource_id.ilike.${pattern}`)
        .order("created_at", { ascending: false })
        .limit(limit / types.length | 0) as { data: Array<{ id: number; event_type: string; actor_email: string | null; resource_type: string | null; resource_id: string | null; created_at: string }> | null };

      (data ?? []).forEach(e => results.push({
        type:       "audit",
        id:         String(e.id),
        title:      e.event_type.replace(/_/g, " "),
        subtitle:   `${e.actor_email ?? "system"} · ${e.resource_type ?? ""}`,
        href:       `/audit`,
        created_at: e.created_at,
        score:      rankResult(query, e.event_type, e.actor_email ?? ""),
      }));
    })(),
  ].filter(Boolean));

  // Sort by score desc, then by date
  results.sort((a, b) => b.score - a.score || new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  return NextResponse.json({
    results:  results.slice(0, limit),
    total:    results.length,
    query,
    types,
  });
}
