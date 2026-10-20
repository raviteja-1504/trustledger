import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../_middleware";
import { verifyAuditChain } from "@/lib/audit";
import { safeError } from "@/lib/errors";

const ISO = /^\d{4}-\d{2}-\d{2}(T[\d:.]+Z)?$/;
const TYPE_RE = /^[a-z_]{1,60}$/;
const MAX_LIMIT = 500;

/**
 * GET /api/audit → the org's audit log, newest first: ?limit (≤500) &page, optional ?since / ?until (YYYY-MM-DD,
 * inclusive UTC days, or ISO), ?type=<event_type>[,<event_type>…], ?actor=<email>. Each entry includes its
 * entry_hash / prev_hash, so the chain shown is the stored one. `total` counts entries matching the filters;
 * `counts` gives entries per event type for the same period (all types), for the page's summary.
 */
export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_view_audit_log");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const p = req.nextUrl.searchParams;
  const limit = Math.min(Math.max(parseInt(p.get("limit") ?? "100") || 100, 1), MAX_LIMIT);
  const page = Math.max(parseInt(p.get("page") ?? "0") || 0, 0);
  const since = p.get("since"), until = p.get("until"), actor = p.get("actor");
  const types = (p.get("type") ?? "").split(",").map(t => t.trim()).filter(Boolean);
  if ((since && !ISO.test(since)) || (until && !ISO.test(until)) || types.some(t => !TYPE_RE.test(t))) {
    return NextResponse.json({ error: "invalid_filter", message: "since/until must be YYYY-MM-DD; type must be event type names." }, { status: 400 });
  }
  const start = since ? (since.length === 10 ? `${since}T00:00:00.000Z` : since) : null;
  const end = until ? (until.length === 10 ? `${until}T23:59:59.999Z` : until) : null;

  const db = createServiceClient();
  try {
    const period = <Q extends { gte: (c: string, v: string) => Q; lte: (c: string, v: string) => Q }>(q: Q) => {
      let out = q;
      if (start) out = out.gte("created_at", start);
      if (end) out = out.lte("created_at", end);
      return out;
    };
    let q = db.from("audit_log")
      .select("id, event_type, actor_email, resource_type, resource_id, payload, prev_hash, entry_hash, created_at", { count: "exact" })
      .eq("org_id", org_id);
    q = period(q);
    if (types.length) q = q.in("event_type", types);
    if (actor) q = q.eq("actor_email", actor);
    const { data, count, error: qErr } = await q.order("id", { ascending: false }).range(page * limit, page * limit + limit - 1);
    if (qErr) throw qErr;

    // Per-type counts for the period (paged: one small column).
    const counts: Record<string, number> = {};
    let periodTotal = 0;
    for (let from = 0; from < 100_000; from += 1000) {
      let cq = db.from("audit_log").select("event_type").eq("org_id", org_id);
      cq = period(cq);
      const { data: rows, error: cErr } = await cq.order("id", { ascending: false }).range(from, from + 999) as { data: { event_type: string }[] | null; error: unknown };
      if (cErr) throw cErr;
      for (const r of rows ?? []) { counts[r.event_type] = (counts[r.event_type] ?? 0) + 1; periodTotal++; }
      if (!rows || rows.length < 1000) break;
    }

    return NextResponse.json(
      { events: data ?? [], total: count ?? 0, counts, period_total: periodTotal, page, limit, period: { start, end } },
      { headers: { "Cache-Control": "private, no-store" } },
    );
  } catch (err) {
    return safeError(err, { code: "audit_fetch_failed", message: "We couldn't load the audit log right now. Please try again." });
  }
}

/** Verify the audit log hash chain integrity (every entry; see lib/audit.ts checkAuditChain). */
export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_view_audit_log");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const db = createServiceClient();
  try {
    return NextResponse.json(await verifyAuditChain(db, org_id), { headers: { "Cache-Control": "private, no-store" } });
  } catch (err) {
    return safeError(err, { code: "audit_verify_failed", message: "We couldn't verify the audit log right now. Please try again." });
  }
}
