"use client";

import { useEffect } from "react";

export default function ErrorPage({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log to Sentry if configured
    import("@/lib/observability").then(({ captureError }) => {
      captureError(error, { digest: error.digest });
    }).catch(() => {});

    // Stale JS chunks (e.g. mid-navigation after a deploy, or a transient
    // network blip) surface as ChunkLoadError. A hard reload re-fetches the
    // current manifest and usually resolves it — guard against loop with a
    // one-shot sessionStorage flag.
    const isChunkError = error.name === "ChunkLoadError" || /Loading chunk [\d]+ failed/.test(error.message);
    if (isChunkError && typeof window !== "undefined") {
      const key = "tl_chunk_reload";
      if (!sessionStorage.getItem(key)) {
        sessionStorage.setItem(key, "1");
        window.location.reload();
      }
    }
  }, [error]);

  return (
    <div className="min-h-screen flex items-center justify-center px-4"
      style={{ background:"linear-gradient(135deg,#0f172a 0%,#1e1b4b 50%,#0f172a 100%)" }}>
      <div className="text-center space-y-6 max-w-md">
        <div className="text-5xl">⚠️</div>
        <div>
          <h1 className="text-2xl font-black text-white">Something went wrong</h1>
          <p className="text-white/50 mt-2 text-sm leading-relaxed">
            An unexpected error occurred. Our team has been notified.
          </p>
          {error.digest && (
            <p className="text-white/20 font-mono text-[10px] mt-2">Error ID: {error.digest}</p>
          )}
        </div>
        <div className="flex items-center justify-center gap-3">
          <button onClick={reset}
            className="px-5 py-2.5 rounded-xl font-bold text-sm text-white transition-all"
            style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
            Try again
          </button>
          <a href="/dashboard"
            className="px-5 py-2.5 rounded-xl font-semibold text-sm text-white/60 hover:text-white border border-white/10 hover:border-white/20 transition-all">
            Go to dashboard
          </a>
        </div>
      </div>
    </div>
  );
}
