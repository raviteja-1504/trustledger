"use client";

import { useToast, type ToastVariant } from "@/lib/toast";

const VARIANT: Record<ToastVariant, { bg:string; border:string; icon:JSX.Element; title:string; progress:string }> = {
  success: {
    bg:"#f0fdf4", border:"#bbf7d0", progress:"#10b981", title:"#15803d",
    icon:(
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
      </svg>
    ),
  },
  error: {
    bg:"#fef2f2", border:"#fecdd3", progress:"#ef4444", title:"#be123c",
    icon:(
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    ),
  },
  warning: {
    bg:"#fffbeb", border:"#fde68a", progress:"#f59e0b", title:"#b45309",
    icon:(
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
    ),
  },
  info: {
    bg:"#eff6ff", border:"#bfdbfe", progress:"#3b82f6", title:"#1d4ed8",
    icon:(
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
    ),
  },
};

export default function Toaster() {
  const { toasts, dismiss } = useToast();

  if (toasts.length === 0) return null;

  return (
    <div
      className="fixed bottom-4 right-4 z-[500] flex flex-col gap-2 pointer-events-none"
      role="region" aria-label="Notifications" aria-live="polite"
    >
      {toasts.map((t, i) => {
        const v = VARIANT[t.variant];
        return (
          <div
            key={t.id}
            role="alert"
            className="pointer-events-auto w-[340px] rounded-2xl border overflow-hidden animate-slide-down"
            style={{
              background: v.bg,
              borderColor: v.border,
              boxShadow: "0 8px 32px rgba(0,0,0,0.12), 0 2px 8px rgba(0,0,0,0.06)",
              opacity: i > 2 ? 0.6 : 1,
              transform: `translateY(${i * -4}px) scale(${1 - i * 0.02})`,
              transition: "all 0.2s ease",
            }}
          >
            {/* Progress bar at the very top */}
            {(t.duration ?? 4000) > 0 && (
              <div className="h-0.5 w-full" style={{ background:v.progress+"25" }}>
                <div
                  className="h-full rounded-full"
                  style={{
                    background: v.progress,
                    width: "100%",
                    animation: `toast-progress ${(t.duration ?? 4000)}ms linear forwards`,
                  }}
                />
              </div>
            )}

            <div className="flex items-start gap-3 px-4 py-3">
              <span className="shrink-0 mt-0.5">{v.icon}</span>

              <div className="flex-1 min-w-0">
                <p className="text-sm font-bold leading-snug" style={{ color:v.title }}>{t.title}</p>
                {t.body && <p className="text-xs mt-0.5 leading-snug" style={{ color:v.title, opacity:0.7 }}>{t.body}</p>}
                {t.action && (
                  <button
                    onClick={() => { t.action!.onClick(); dismiss(t.id); }}
                    className="mt-1.5 text-[11px] font-bold underline underline-offset-2"
                    style={{ color:v.title }}>
                    {t.action.label}
                  </button>
                )}
              </div>

              <button
                onClick={() => dismiss(t.id)}
                className="shrink-0 mt-0.5 opacity-50 hover:opacity-100 transition-opacity"
                aria-label="Dismiss">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ color:v.title }}>
                  <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
              </button>
            </div>
          </div>
        );
      })}

      <style>{`
        @keyframes toast-progress {
          from { width: 100%; }
          to   { width: 0%; }
        }
      `}</style>
    </div>
  );
}
