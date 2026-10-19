/**
 * Violation statuses as every page should see them: the server's (violation_overrides, via /api/violation-status --
 * the same on every device) with this tab's just-made changes on top (localStatuses.ts, minutes-long bridge).
 *
 * Several components ask at once on page load (sidebar + page), so concurrent callers share one request for
 * SHARE_MS; a status change on this tab calls invalidateServerStatuses() so the next read is fresh.
 */
import { authedFetch, isSeedMode } from "./useRealData";
import { readLocalStatuses } from "./localStatuses";

export interface ServerOverride { status: string; assigned_email?: string | null; note?: string | null; escalated?: boolean; updated_at?: string }

const SHARE_MS = 3_000;
let shared: { at: number; p: Promise<Record<string, ServerOverride>> } | null = null;

export function invalidateServerStatuses(): void { shared = null; }

/** Full server overrides. Rejects when the server can't be reached (callers decide what to keep showing). */
export function fetchServerOverrides(now = Date.now()): Promise<Record<string, ServerOverride>> {
  if (isSeedMode()) return Promise.resolve({});
  if (shared && now - shared.at < SHARE_MS) return shared.p;
  const p = authedFetch<{ overrides?: Record<string, ServerOverride> }>("/api/violation-status").then(r => r.overrides ?? {});
  shared = { at: now, p };
  p.catch(() => { if (shared?.p === p) shared = null; });
  return p;
}

export const statusesOf = (o: Record<string, ServerOverride>): Record<string, string> =>
  Object.fromEntries(Object.entries(o).map(([k, v]) => [k, v.status]));

export interface ViolationDetails { assignees: Record<string, string>; notes: Record<string, string>; escalated: Set<string> }

/** Assignee / note / escalation per violation, from the server overrides. */
export function detailsFromOverrides(o: Record<string, ServerOverride>): ViolationDetails {
  const d: ViolationDetails = { assignees: {}, notes: {}, escalated: new Set() };
  for (const [id, v] of Object.entries(o)) {
    if (v.assigned_email) d.assignees[id] = v.assigned_email;
    if (v.note) d.notes[id] = v.note;
    if (v.escalated) d.escalated.add(id);
  }
  return d;
}

export interface OverridePatch { violation_id: string; status: string; assigned_email?: string; note?: string; escalated?: boolean }

/** The PATCHes that carry details a browser held before they were stored server-side up to the server: one per
 *  violation with a local value the server doesn't have yet (the server's value wins). Each keeps the server's
 *  current status, so uploading never changes one. */
export function localDetailUploads(
  server: Record<string, ServerOverride>,
  local: { assignees: Record<string, string>; notes: Record<string, string>; escalated: unknown[] },
): OverridePatch[] {
  const out = new Map<string, OverridePatch>();
  const get = (id: string) => out.get(id) ?? { violation_id: id, status: server[id]?.status ?? "open" };
  // An address the server would reject (400) would otherwise be retried on every visit; it's dropped instead.
  const isEmail = (s: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 255;
  for (const [id, email] of Object.entries(local.assignees)) if (typeof email === "string" && isEmail(email) && !server[id]?.assigned_email) out.set(id, { ...get(id), assigned_email: email });
  for (const [id, note] of Object.entries(local.notes)) if (typeof note === "string" && note && !server[id]?.note) out.set(id, { ...get(id), note: note.slice(0, 2000) });
  for (const id of local.escalated) if (typeof id === "string" && id && !server[id]?.escalated) out.set(id, { ...get(id), escalated: true });
  return Array.from(out.values());
}

/** Server statuses merged with this tab's fresh local ones (local wins: it is newer by construction). If the server
 *  can't be reached, local ones alone. */
export async function loadStatuses(): Promise<Record<string, string>> {
  const server = await fetchServerOverrides().then(statusesOf, () => ({} as Record<string, string>));
  return { ...server, ...readLocalStatuses() };
}
