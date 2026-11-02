/**
 * The status bar's API check (components/StatusBar.tsx). One slow answer used to mark the API "offline" for five
 * minutes: a 3-second limit was shorter than a serverless cold start, and nothing re-checked sooner. Now a check
 * allows for a cold start, retries once before calling the API offline, and the caller re-checks often while it
 * is offline. The viewer's own connection being down is told apart: that is not the API being offline.
 */
export type ApiStatus = "online" | "offline" | "no-network";

export const HEALTH_TIMEOUT_MS = 8000;      // a cold start (function boot + database round trip) fits in this
export const HEALTH_RETRY_DELAY_MS = 2000;
export const RECHECK_ONLINE_MS = 300_000;   // healthy: every 5 minutes is plenty for an indicator
export const RECHECK_OFFLINE_MS = 30_000;   // unhealthy: find out soon when it is back

type Fetch = (url: string, init: { signal: AbortSignal; cache: RequestCache }) => Promise<{ ok: boolean }>;

export async function probeApi(opts: { fetch?: Fetch; isOnline?: () => boolean; wait?: (ms: number) => Promise<void> } = {}): Promise<ApiStatus> {
  const doFetch = opts.fetch ?? ((url, init) => fetch(url, init));
  const isOnline = opts.isOnline ?? (() => (typeof navigator === "undefined" ? true : navigator.onLine));
  const wait = opts.wait ?? (ms => new Promise(r => setTimeout(r, ms)));
  if (!isOnline()) return "no-network";
  const once = async () => {
    try {
      return (await doFetch("/healthz", { signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS), cache: "no-store" })).ok;
    } catch {
      return false;
    }
  };
  if (await once()) return "online";
  await wait(HEALTH_RETRY_DELAY_MS);
  if (!isOnline()) return "no-network";
  return (await once()) ? "online" : "offline";
}

export const recheckAfter = (s: ApiStatus) => (s === "online" ? RECHECK_ONLINE_MS : RECHECK_OFFLINE_MS);
