"use client";
/**
 * Accessibility components for WCAG 2.1 AA compliance.
 * - Skip navigation link
 * - Live announcement region
 * - Focus trap utility
 * - Screen reader announcements
 */

import { useEffect, useRef, useState } from "react";

// ── Skip navigation ────────────────────────────────────────────────────────────

export function SkipNav() {
  return (
    <a
      href="#main-content"
      className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-indigo-600 focus:text-white focus:rounded-xl focus:font-bold focus:text-sm focus:shadow-lg"
      style={{ transition:"none" }}
    >
      Skip to main content
    </a>
  );
}

// ── Live region for screen reader announcements ────────────────────────────────

let _announce: ((msg: string, politeness?: "polite" | "assertive") => void) | null = null;

export function announce(msg: string, politeness: "polite" | "assertive" = "polite") {
  _announce?.(msg, politeness);
}

export function LiveRegion() {
  const [politeMsg,    setPoliteMsg]    = useState("");
  const [assertiveMsg, setAssertiveMsg] = useState("");

  useEffect(() => {
    _announce = (msg, politeness = "polite") => {
      if (politeness === "assertive") {
        setAssertiveMsg(""); setTimeout(() => setAssertiveMsg(msg), 50);
      } else {
        setPoliteMsg(""); setTimeout(() => setPoliteMsg(msg), 50);
      }
    };
    return () => { _announce = null; };
  }, []);

  return (
    <>
      <div aria-live="polite" aria-atomic="true" className="sr-only">
        {politeMsg}
      </div>
      <div aria-live="assertive" aria-atomic="true" className="sr-only">
        {assertiveMsg}
      </div>
    </>
  );
}

// ── Focus trap (for modals) ────────────────────────────────────────────────────

export function useFocusTrap(active: boolean) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!active) return;
    const container = containerRef.current;
    if (!container) return;

    const FOCUSABLE = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
    const focusable = Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE));
    const first     = focusable[0];
    const last      = focusable[focusable.length - 1];

    first?.focus();

    function trap(e: KeyboardEvent) {
      if (e.key !== "Tab") return;
      if (e.shiftKey) {
        if (document.activeElement === first) { e.preventDefault(); last?.focus(); }
      } else {
        if (document.activeElement === last)  { e.preventDefault(); first?.focus(); }
      }
    }

    container.addEventListener("keydown", trap);
    return () => container.removeEventListener("keydown", trap);
  }, [active]);

  return containerRef;
}

// ── Visually hidden (sr-only) ──────────────────────────────────────────────────

export function VisuallyHidden({ children }: { children: React.ReactNode }) {
  return (
    <span className="sr-only">{children}</span>
  );
}

// ── Accessible icon button ─────────────────────────────────────────────────────

interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  label:    string;
  children: React.ReactNode;
}

export function IconButton({ label, children, ...props }: IconButtonProps) {
  return (
    <button
      {...props}
      aria-label={label}
      title={label}
    >
      {children}
      <VisuallyHidden>{label}</VisuallyHidden>
    </button>
  );
}

// ── Status indicator with accessible label ─────────────────────────────────────

interface StatusBadgeProps {
  status:  "success" | "warning" | "error" | "info";
  label:   string;
  children:React.ReactNode;
}

const STATUS_ICONS = {
  success: "✓",
  warning: "⚠",
  error:   "✗",
  info:    "ℹ",
};

export function StatusBadge({ status, label, children }: StatusBadgeProps) {
  return (
    <span role="status" aria-label={`${status}: ${label}`}>
      <span aria-hidden="true">{STATUS_ICONS[status]}</span>
      {children}
    </span>
  );
}
