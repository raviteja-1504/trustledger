"use client";
/**
 * useRealData — transparent data upgrade hook.
 *
 * Priority order (each page applies this pattern):
 *   1. Seed mode (tl_force_seed=1)  → localStorage / seed data  [dev/demo]
 *   2. Supabase session exists       → internal /api/* routes    [production]
 *   3. No session / network fail     → local fallback data        [offline]
 *
 * Usage:
 *   const { data, loading, error, isRealData } = useRealData(loader, fallback)
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { supabase } from "./supabase";

const SKIP_AUTH = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";

export function isSeedMode(): boolean {
  if (typeof window === "undefined") return false;
  return localStorage.getItem("tl_force_seed") === "1";
}

export async function getAuthHeader(): Promise<Record<string, string>> {
  if (SKIP_AUTH) return {};
  try {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session?.access_token) return {};
    return { Authorization: `Bearer ${session.access_token}` };
  } catch {
    return {};
  }
}

export async function authedFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const headers = await getAuthHeader();
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...headers, ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as { error?: string };
    throw new Error(body.error ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

interface UseRealDataResult<T> {
  data:       T | null;
  loading:    boolean;
  error:      string | null;
  isRealData: boolean;   // true = served from real API (not seed/mock)
  refetch:    () => void;
}

export function useRealData<T>(
  loader: () => Promise<T>,       // real API call
  seedLoader?: () => T | null,    // seed/local fallback
  deps: unknown[] = [],
): UseRealDataResult<T> {
  const [data,       setData]       = useState<T | null>(null);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState<string | null>(null);
  const [isRealData, setIsRealData] = useState(false);
  const loaderRef = useRef(loader);
  const seedRef   = useRef(seedLoader);
  loaderRef.current = loader;
  seedRef.current   = seedLoader;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);

    // 1. Seed mode
    if (isSeedMode() && seedRef.current) {
      const seedData = seedRef.current();
      if (seedData !== null && seedData !== undefined) {
        setData(seedData);
        setIsRealData(false);
        setLoading(false);
        return;
      }
    }

    // 2. Real API
    try {
      const result = await loaderRef.current();
      setData(result);
      setIsRealData(true);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      // 3. Fallback to seed/local even if not in seed mode
      if (seedRef.current) {
        const fallback = seedRef.current();
        if (fallback !== null && fallback !== undefined) setData(fallback);
      }
      setIsRealData(false);
    } finally {
      setLoading(false);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => { load(); }, [load]);

  return { data, loading, error, isRealData, refetch: load };
}
