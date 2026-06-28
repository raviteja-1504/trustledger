"use client";

import { useEffect, useState } from "react";

const TZ_STORAGE_KEY = "tl_user_timezone";

/** Returns the user's saved timezone (e.g. "Asia/Kolkata"), falling back to the browser default. */
export function getSavedTimezone(): string {
  if (typeof window === "undefined") return "UTC";
  return localStorage.getItem(TZ_STORAGE_KEY) || Intl.DateTimeFormat().resolvedOptions().timeZone;
}

/** Persists the chosen timezone to localStorage so all pages pick it up. */
export function saveTimezone(tz: string): void {
  if (typeof window !== "undefined") localStorage.setItem(TZ_STORAGE_KEY, tz);
}

/** React hook — returns the current timezone string, reactive to changes. */
export function useTimezone(): string {
  const [tz, setTz] = useState<string>("UTC");

  useEffect(() => {
    setTz(getSavedTimezone());
    // Listen for changes made on the profile page
    const onStorage = (e: StorageEvent) => {
      if (e.key === TZ_STORAGE_KEY && e.newValue) setTz(e.newValue);
    };
    window.addEventListener("storage", onStorage);
    // Also listen for same-tab updates via a custom event
    const onTzChange = (e: Event) => { setTz((e as CustomEvent<string>).detail); };
    window.addEventListener("tl:timezone", onTzChange);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("tl:timezone", onTzChange);
    };
  }, []);

  return tz;
}

/** Format a date string/object with the given timezone. */
export function formatDate(
  date: string | Date | null | undefined,
  options: Intl.DateTimeFormatOptions = {},
  timezone?: string,
): string {
  if (!date) return "—";
  const tz = timezone ?? getSavedTimezone();
  try {
    return new Intl.DateTimeFormat("en-GB", {
      timeZone: tz,
      ...options,
    }).format(new Date(date));
  } catch {
    return new Date(date).toLocaleString();
  }
}

/** Short relative time ("2h ago", "3d ago") — timezone-aware. */
export function relativeTime(date: string | Date | null | undefined, timezone?: string): string {
  if (!date) return "—";
  const tz = timezone ?? getSavedTimezone();
  const now = Date.now();
  const then = new Date(date).getTime();
  const diff = now - then;
  const mins  = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days  = Math.floor(diff / 86400000);
  if (mins  < 1)  return "just now";
  if (mins  < 60) return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days  < 7)  return `${days}d ago`;
  // Fall back to localised date in the user's timezone
  return formatDate(date, { day: "numeric", month: "short" }, tz);
}

/** Full datetime string: "18 Jun 2026, 14:30" */
export function formatDateTime(date: string | Date | null | undefined, timezone?: string): string {
  return formatDate(date, {
    day: "numeric", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  }, timezone);
}

/** Date only: "18 Jun 2026" */
export function formatDateOnly(date: string | Date | null | undefined, timezone?: string): string {
  return formatDate(date, { day: "numeric", month: "short", year: "numeric" }, timezone);
}
