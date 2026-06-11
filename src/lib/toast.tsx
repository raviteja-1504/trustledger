"use client";

import { createContext, useContext, useState, useCallback, ReactNode } from "react";

// ── Types ──────────────────────────────────────────────────────────────────────

export type ToastVariant = "success" | "error" | "warning" | "info";

export interface Toast {
  id: string;
  variant: ToastVariant;
  title: string;
  body?: string;
  duration?: number;   // ms — 0 = sticky
  action?: { label: string; onClick: () => void };
}

interface ToastContextValue {
  toasts: Toast[];
  toast: (t: Omit<Toast, "id">) => string;
  dismiss: (id: string) => void;
}

// ── Context ────────────────────────────────────────────────────────────────────

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const toast = useCallback((t: Omit<Toast, "id">) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2,7)}`;
    const dur = t.duration ?? 4000;
    setToasts(prev => [{ ...t, id }, ...prev].slice(0, 6)); // max 6 stacked
    if (dur > 0) setTimeout(() => dismiss(id), dur);
    return id;
  }, [dismiss]);

  return (
    <ToastContext.Provider value={{ toasts, toast, dismiss }}>
      {children}
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used inside ToastProvider");
  return ctx;
}

// ── Helper shortcuts ───────────────────────────────────────────────────────────

export function useToastHelpers() {
  const { toast } = useToast();
  return {
    success: (title: string, body?: string) => toast({ variant:"success", title, body }),
    error:   (title: string, body?: string) => toast({ variant:"error",   title, body, duration:6000 }),
    warning: (title: string, body?: string) => toast({ variant:"warning", title, body, duration:5000 }),
    info:    (title: string, body?: string) => toast({ variant:"info",    title, body }),
  };
}
