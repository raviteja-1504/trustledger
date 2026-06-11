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
