/**
 * The browser's copy of violation statuses (tl_violation_statuses): what this tab marked resolved the moment a file
 * was attested, before the next server fetch shows it. It is a short-lived bridge, not a source of truth -- the
 * server (violation_overrides + attestations) is. Kept forever, it made one browser disagree with every other
 * device (a reopened or revoked file stayed "resolved" here), so outside demo mode an entry only counts for
 * LOCAL_STATUS_TTL_MS after it was written; older entries (and ones written before timestamps existed) are dropped.
 *
 * Pure browser module, no app imports: trustScore.ts uses it and is also bundled server-side.
 */

export const LOCAL_STATUS_KEY = "tl_violation_statuses";
export const LOCAL_STATUS_AT_KEY = "tl_violation_statuses_at";
export const LOCAL_STATUS_TTL_MS = 10 * 60_000;

type Map_ = Record<string, string>;

const read = (k: string): Record<string, unknown> => {
  try {
    const v = JSON.parse(localStorage.getItem(k) ?? "{}");
    return v && typeof v === "object" && !Array.isArray(v) ? v : {};
  } catch { return {}; }
};
const write = (k: string, v: unknown) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* quota / private mode */ } };
// Same flag as useRealData.isSeedMode, read directly to keep this module dependency-free.
const seedMode = () => { try { return localStorage.getItem("tl_force_seed") === "1"; } catch { return false; } };

/** Record statuses this tab just set (e.g. an attestation), stamped so they expire. */
export function recordLocalStatuses(updates: Map_, now = Date.now()): void {
  if (typeof window === "undefined" || Object.keys(updates).length === 0) return;
  write(LOCAL_STATUS_KEY, { ...read(LOCAL_STATUS_KEY), ...updates });
  const at = read(LOCAL_STATUS_AT_KEY);
  for (const k of Object.keys(updates)) at[k] = now;
  write(LOCAL_STATUS_AT_KEY, at);
}

/**
 * The statuses that still count: every entry in demo mode (seed data lives here), otherwise only entries written in
 * the last LOCAL_STATUS_TTL_MS. Expired entries are removed from storage.
 */
export function readLocalStatuses(now = Date.now()): Map_ {
  if (typeof window === "undefined") return {};
  const all = read(LOCAL_STATUS_KEY);
  const str = (o: Record<string, unknown>) => Object.fromEntries(Object.entries(o).filter(([, v]) => typeof v === "string")) as Map_;
  if (seedMode()) return str(all);
  const at = read(LOCAL_STATUS_AT_KEY);
  const fresh: Record<string, unknown> = {}, freshAt: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(all)) {
    const t = at[k];
    if (typeof t === "number" && now - t < LOCAL_STATUS_TTL_MS && t <= now) { fresh[k] = v; freshAt[k] = t; }
  }
  if (Object.keys(fresh).length !== Object.keys(all).length) { write(LOCAL_STATUS_KEY, fresh); write(LOCAL_STATUS_AT_KEY, freshAt); }
  return str(fresh);
}
