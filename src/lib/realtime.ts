"use client";
/**
 * Supabase Realtime hooks
 * Replaces localStorage polling with live database subscriptions.
 * Pages subscribe to their relevant tables; Supabase pushes changes instantly.
 */

import { useEffect, useRef, useCallback } from "react";
import { supabase } from "./supabase";
import { useAuth } from "./auth";

type ChangeHandler<T = Record<string, unknown>> = (payload: {
  eventType: "INSERT" | "UPDATE" | "DELETE";
  new: T;
  old: Partial<T>;
}) => void;

// ── Generic table subscription ─────────────────────────────────────────────────

export function useRealtimeTable<T = Record<string, unknown>>(
  table: string,
  orgId: string | undefined,
  onchange: ChangeHandler<T>,
  filter?: string,       // e.g. "status=eq.open"
) {
  const handlerRef = useRef(onchange);
  handlerRef.current = onchange;

  useEffect(() => {
    // Skip realtime when Supabase is not configured (demo/seed mode)
    if (!orgId) return;
    if (!process.env.NEXT_PUBLIC_SUPABASE_URL) return;

    let channel: ReturnType<typeof supabase.channel> | null = null;
    try {
      channel = supabase
        .channel(`${table}:${orgId}`)
        .on(
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          "postgres_changes" as any,
          {
            event:  "*",
            schema: "public",
            table,
            filter: filter ?? `org_id=eq.${orgId}`,
          },
          (payload: unknown) => {
            handlerRef.current(payload as Parameters<ChangeHandler<T>>[0]);
          },
        )
        .subscribe();
    } catch {
      return; // Supabase stub — ignore
    }

    return () => {
      try { if (channel) supabase.removeChannel(channel); } catch { /* ignore */ }
    };
  }, [table, orgId, filter]);
}

// ── Violations realtime hook ───────────────────────────────────────────────────

export function useViolationsRealtime(
  orgId: string | undefined,
  onRefresh: () => void,
) {
  const refresh = useCallback(onRefresh, [onRefresh]);
  useRealtimeTable("violations", orgId, refresh);
}

// ── Scans realtime hook ────────────────────────────────────────────────────────

export function useScansRealtime(
  orgId: string | undefined,
  onNewScan: (scan: Record<string, unknown>) => void,
) {
  useRealtimeTable("scans", orgId, ({ new: scan }) => {
    onNewScan(scan);
  });
}

// ── Alerts realtime hook ───────────────────────────────────────────────────────

export function useAlertsRealtime(
  orgId: string | undefined,
  onRefresh: () => void,
) {
  useRealtimeTable("alerts", orgId, onRefresh);
}

// ── Attestations realtime hook ─────────────────────────────────────────────────

export function useAttestationsRealtime(
  scanId: string | undefined,
  onAttestation: (att: Record<string, unknown>) => void,
) {
  useRealtimeTable(
    "attestations",
    scanId, // use scanId as channel key
    ({ new: att }) => onAttestation(att),
    scanId ? `scan_id=eq.${scanId}` : undefined,
  );
}

// ── Incidents realtime hook ────────────────────────────────────────────────────

export function useIncidentsRealtime(
  orgId: string | undefined,
  onRefresh: () => void,
) {
  useRealtimeTable("incidents", orgId, onRefresh);
}

// ── Live notification hook (replaces polling in notifications.ts) ─────────────

export interface LiveNotification {
  id:     string;
  level:  "critical" | "high" | "warning" | "info" | "success";
  title:  string;
  body:   string;
  time:   number;
  read:   boolean;
  href?:  string;
}

function alertToNotification(alert: Record<string, unknown>): LiveNotification {
  const sevMap: Record<string, LiveNotification["level"]> = {
    P1: "critical", P2: "high", P3: "warning", P4: "info",
  };
  return {
    id:    alert.id as string,
    level: sevMap[alert.severity as string] ?? "info",
    title: alert.title as string,
    body:  alert.body  as string ?? "",
    time:  new Date(alert.fired_at as string).getTime(),
    read:  false,
    href:  alert.scan_id ? `/pr/${alert.scan_id as string}` : "/alerts",
  };
}

/**
 * Live notification stream from the database.
 * Returns only firing P1/P2 alerts from the current session (last 24h).
 */
export function useLiveAlertNotifications(
  onNew: (n: LiveNotification) => void,
) {
  const { profile } = useAuth();
  const onNewRef = useRef(onNew);
  onNewRef.current = onNew;

  useEffect(() => {
    if (!profile?.org_id) return;

    const channel = supabase
      .channel(`live-alerts:${profile.org_id}`)
      .on(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        "postgres_changes" as any,
        {
          event:  "INSERT",
          schema: "public",
          table:  "alerts",
          filter: `org_id=eq.${profile.org_id}`,
        },
        (payload: { new: Record<string, unknown> }) => {
          const alert = payload.new;
          if (alert.severity === "P1" || alert.severity === "P2") {
            onNewRef.current(alertToNotification(alert));
          }
        },
      )
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [profile?.org_id]);
}
