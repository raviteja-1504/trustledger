"use client";

/**
 * Loading states that say they're loading -- so a page that's still fetching is never read as "nothing here".
 *
 *   <Spinner />                      a small spinning ring
 *   <LoadingBlock label="scans" />   spinner + "Loading scans…" over a skeleton, for a section or a whole page
 *   <NetworkActivity />              top-bar pill: "Loading…" / "Refreshing…" whenever any data request is in
 *                                    flight for more than a moment (lib/netActivity.ts), background refreshes included
 */
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { getInFlight, subscribe } from "@/lib/netActivity";

export function Spinner({ size = 14, className = "" }: { size?: number; className?: string }) {
  return (
    <svg className={`animate-spin shrink-0 ${className}`} width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.2" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

/** A section or page that's loading: a spinner with what's loading, over a skeleton of its rough shape. */
export function LoadingBlock({ label, rows = 4, cards = 0, className = "" }: { label: string; rows?: number; cards?: number; className?: string }) {
  return (
    <div role="status" aria-live="polite" aria-label={`Loading ${label}`} className={`space-y-4 ${className}`}>
      <div className="flex items-center gap-2 text-sm font-semibold text-indigo-600">
        <Spinner size={16} />
        <span>Loading {label}…</span>
      </div>
      {cards > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {Array.from({ length: cards }).map((_, i) => <div key={i} className="rounded-2xl h-20 animate-pulse bg-gray-100" />)}
        </div>
      )}
      {rows > 0 && (
        <div className="section-card overflow-hidden divide-y divide-gray-50">
          {Array.from({ length: rows }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 px-5 py-4">
              <div className="w-8 h-8 rounded-lg animate-pulse bg-gray-100 shrink-0" />
              <div className="flex-1 space-y-2">
                <div className="h-3 w-3/4 rounded animate-pulse bg-gray-100" />
                <div className="h-2.5 w-1/2 rounded animate-pulse bg-gray-100" />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Shown only if requests last longer than this, so quick refreshes don't flicker. */
export const ACTIVITY_DELAY_MS = 300;

/** `page` identifies the current page (e.g. its pathname): its first requests read "Loading…", later ones
 *  (polling, focus, after an action) "Refreshing…". */
export function NetworkActivity({ page }: { page: string }) {
  const inFlight = useSyncExternalStore(subscribe, getInFlight, () => 0);
  const [visible, setVisible] = useState(false);
  const [loadedPage, setLoadedPage] = useState<string | null>(null);
  const busyOn = useRef<string | null>(null);   // the page that had requests in flight
  useEffect(() => {
    if (inFlight === 0) {
      setVisible(false);
      // This page's requests have finished at least once: later ones are refreshes.
      if (busyOn.current === page) setLoadedPage(page);
      busyOn.current = null;
      return;
    }
    busyOn.current = page;
    const t = setTimeout(() => setVisible(true), ACTIVITY_DELAY_MS);
    return () => clearTimeout(t);
  }, [inFlight, page]);
  if (!visible) return null;
  return (
    <span role="status" aria-live="polite"
      className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-indigo-700 bg-indigo-50 border border-indigo-100 px-2.5 py-1 rounded-full whitespace-nowrap">
      <Spinner size={12} />
      {loadedPage === page ? "Refreshing…" : "Loading…"}
    </span>
  );
}
