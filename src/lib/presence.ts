"use client";
/**
 * Realtime Presence — shows who is currently reviewing a PR scan.
 * Uses Supabase Realtime Presence to broadcast reviewer activity.
 * Shows avatars of other reviewers in the PR review header.
 */

import { useEffect, useState, useRef } from "react";
import { supabase } from "./supabase";
import { useAuth } from "./auth";

export interface Reviewer {
  user_id:   string;
  email:     string;
  name?:     string;
  avatar?:   string;
  online_at: string;
  viewing?:  string;  // current file_path being reviewed
}

// Supabase is only configured when NEXT_PUBLIC_SUPABASE_URL is set
const SUPABASE_CONFIGURED = !!(
  process.env.NEXT_PUBLIC_SUPABASE_URL && process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
);

export function usePresence(scanId: string | null) {
  const { profile, user } = useAuth();
  const [reviewers, setReviewers] = useState<Reviewer[]>([]);
  const channelRef = useRef<ReturnType<typeof supabase.channel> | null>(null);

  useEffect(() => {
    // Only run presence when Supabase is configured and user is authenticated
    if (!scanId || !user || !profile || !SUPABASE_CONFIGURED) return;

    const channelName = `presence:scan:${scanId}`;
    let channel: ReturnType<typeof supabase.channel>;

    try {
      channel = supabase.channel(channelName, { config: { presence: { key: user.id } } });
    } catch {
      return; // Supabase stub doesn't support presence
    }

    channel
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .on("presence" as any, { event: "sync" }, () => {
        try {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const state = (channel as any).presenceState?.() ?? {};
          const others: Reviewer[] = [];
          Object.entries(state).forEach(([, presences]) => {
            (presences as Reviewer[]).forEach((p: Reviewer) => {
              if (p.user_id !== user.id) others.push(p);
            });
          });
          setReviewers(others);
        } catch { /* presence state not available in stub */ }
      })
      .subscribe(async (status: string) => {
        if (status === "SUBSCRIBED") {
          try {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            await (channel as any).track?.({
              user_id:   user.id,
              email:     profile.email,
              name:      profile.name ?? undefined,
              avatar:    profile.avatar_url ?? undefined,
              online_at: new Date().toISOString(),
            } as Reviewer);
          } catch { /* track not available in stub */ }
        }
      });

    channelRef.current = channel;

    return () => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (channel as any).untrack?.();
        supabase.removeChannel(channel);
      } catch { /* ignore cleanup errors */ }
    };
  }, [scanId, user?.id, profile?.org_id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function updateViewing(filePath: string) {
    if (!channelRef.current || !user || !profile || !SUPABASE_CONFIGURED) return;
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (channelRef.current as any).track?.({
        user_id:   user.id,
        email:     profile.email,
        name:      profile.name ?? undefined,
        online_at: new Date().toISOString(),
        viewing:   filePath,
      } as Reviewer);
    } catch { /* ignore */ }
  }

  return { reviewers, updateViewing };
}

/** Small avatar stack for displaying other reviewers. */
export function initials(email: string, name?: string | null): string {
  if (name) return name.split(/\s+/).map(w => w[0]).join("").slice(0, 2).toUpperCase();
  return email.slice(0, 2).toUpperCase();
}
