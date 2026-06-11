import type { DashboardData } from "@/types";

const SEED_KEY  = "tl_notif_snapshot";
const FORCE_KEY = "tl_force_seed";

/** Returns seeded DashboardData if /dev-seed forced it, otherwise null. Synchronous. */
export function readSeed(): DashboardData | null {
  if (typeof window === "undefined") return null;
  if (localStorage.getItem(FORCE_KEY) !== "1") return null;
  try {
    const raw = localStorage.getItem(SEED_KEY);
    if (!raw) return null;
    const d = JSON.parse(raw) as DashboardData;
    if (Array.isArray(d?.repos) && d.repos.length > 0) return d;
  } catch {}
  return null;
}

function getOfflineDashboard(fallback: DashboardData): DashboardData {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = localStorage.getItem(SEED_KEY);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw) as DashboardData;
    if (Array.isArray(parsed?.repos) && parsed.repos.length > 0) return parsed;
  } catch {}
  return fallback;
}

/** Kept for compatibility — prefer inline readSeed() check for new code. */
export async function dashboardWithSeed(
  apiCall: () => Promise<DashboardData>,
  fallback: DashboardData,
): Promise<DashboardData> {
  const seed = readSeed();
  if (seed) return seed;
  try { return await apiCall(); } catch { return getOfflineDashboard(fallback); }
}
