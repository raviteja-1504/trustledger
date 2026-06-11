"use client";
/**
 * Global keyboard shortcuts for TrustLedger dashboard.
 * Inspired by GitHub's keyboard shortcut system.
 *
 * Shortcuts:
 *   g d     → Dashboard
 *   g v     → Violations
 *   g a     → Alerts
 *   g i     → Incidents
 *   g r     → Reports
 *   g s     → Settings
 *   /       → Focus global search
 *   ?       → Show shortcut help
 *   Esc     → Close any modal/panel
 *   j / k   → Navigate list items (down/up)
 *   Enter   → Open selected item
 */

import { useEffect, useState, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";

interface Shortcut {
  keys:    string;
  label:   string;
  group:   string;
  action?: () => void;
}

export function useKeyboardShortcuts() {
  const router   = useRouter();
  const gBuf     = useRef<string>("");
  const gTimer   = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleKey = useCallback((e: KeyboardEvent) => {
    const tag = (e.target as HTMLElement).tagName;
    const isInput = ["INPUT","TEXTAREA","SELECT"].includes(tag) ||
                    (e.target as HTMLElement).isContentEditable;

    // Allow Escape even in inputs
    if (e.key === "Escape") {
      document.dispatchEvent(new CustomEvent("tl:close-modal"));
      return;
    }

    if (isInput) return;

    // "/" → focus search
    if (e.key === "/" && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      const searchInput = document.querySelector<HTMLInputElement>("[data-search-input]");
      searchInput?.focus();
      return;
    }

    // "?" → show help modal
    if (e.key === "?" && e.shiftKey) {
      document.dispatchEvent(new CustomEvent("tl:show-shortcuts"));
      return;
    }

    // "g" prefix navigation
    if (e.key === "g" && !e.ctrlKey && !e.metaKey) {
      gBuf.current = "g";
      if (gTimer.current) clearTimeout(gTimer.current);
      gTimer.current = setTimeout(() => { gBuf.current = ""; }, 1500);
      return;
    }

    if (gBuf.current === "g") {
      gBuf.current = "";
      if (gTimer.current) clearTimeout(gTimer.current);
      const nav: Record<string, string> = {
        d: "/dashboard", v: "/violations", a: "/alerts",
        i: "/incidents", r: "/reports",    s: "/settings",
        c: "/compliance",p: "/posture",    l: "/audit",
        e: "/evidence",  k: "/risks",      b: "/billing",
      };
      if (e.key in nav) {
        e.preventDefault();
        router.push(nav[e.key]);
        return;
      }
    }

    // j/k navigation in lists
    if (e.key === "j" || e.key === "k") {
      document.dispatchEvent(new CustomEvent("tl:list-nav", { detail: { dir: e.key === "j" ? 1 : -1 } }));
      return;
    }

    // Enter → activate selected item
    if (e.key === "Enter" && !e.shiftKey) {
      const focused = document.querySelector<HTMLElement>("[data-focused='true']");
      if (focused) { focused.click(); }
      return;
    }

    // Ctrl/Cmd+K → search (same as /)
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault();
      document.dispatchEvent(new CustomEvent("tl:open-search"));
    }
  }, [router]);

  useEffect(() => {
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [handleKey]);
}

const SHORTCUTS: Shortcut[] = [
  { keys:"g → d", label:"Dashboard",         group:"Navigation" },
  { keys:"g → v", label:"Violations",         group:"Navigation" },
  { keys:"g → a", label:"Alerts",             group:"Navigation" },
  { keys:"g → i", label:"Incidents",          group:"Navigation" },
  { keys:"g → r", label:"Reports",            group:"Navigation" },
  { keys:"g → s", label:"Settings",           group:"Navigation" },
  { keys:"g → c", label:"Compliance",         group:"Navigation" },
  { keys:"g → l", label:"Audit Trail",        group:"Navigation" },
  { keys:"/ or ⌘K", label:"Open search",      group:"Search"     },
  { keys:"j / k",   label:"Navigate list",    group:"Lists"      },
  { keys:"Enter",   label:"Open selected",    group:"Lists"      },
  { keys:"Esc",     label:"Close panel",      group:"Actions"    },
  { keys:"?",       label:"Show this help",   group:"Actions"    },
];

export function KeyboardShortcutsModal() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const show  = () => setOpen(true);
    const close = () => setOpen(false);
    document.addEventListener("tl:show-shortcuts", show);
    document.addEventListener("tl:close-modal",   close);
    return () => {
      document.removeEventListener("tl:show-shortcuts", show);
      document.removeEventListener("tl:close-modal",   close);
    };
  }, []);

  if (!open) return null;

  const groups = Array.from(new Set(SHORTCUTS.map(s => s.group)));

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background:"rgba(0,0,0,0.5)", backdropFilter:"blur(4px)" }}
      onClick={() => setOpen(false)}
    >
      <div
        className="bg-white rounded-2xl shadow-2xl max-w-lg w-full p-6 space-y-5"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-base font-black text-gray-900">Keyboard Shortcuts</h2>
          <button onClick={() => setOpen(false)}
            className="text-gray-400 hover:text-gray-600 text-xs px-2 py-1 rounded-lg border border-gray-200">
            Esc
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-5">
          {groups.map(group => (
            <div key={group}>
              <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">{group}</p>
              <div className="space-y-1.5">
                {SHORTCUTS.filter(s => s.group === group).map(s => (
                  <div key={s.keys} className="flex items-center justify-between gap-3">
                    <span className="text-xs text-gray-600">{s.label}</span>
                    <div className="flex items-center gap-1">
                      {s.keys.split(" / ").map(k => (
                        <kbd key={k} className="text-[10px] font-mono font-bold bg-gray-100 border border-gray-200 text-gray-700 px-1.5 py-0.5 rounded">
                          {k}
                        </kbd>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        <p className="text-[10px] text-gray-400 text-center">
          Press <kbd className="text-[9px] font-mono bg-gray-100 border border-gray-200 px-1 rounded">?</kbd> anytime to show this
        </p>
      </div>
    </div>
  );
}

/** Drop this into AppShell to enable global keyboard shortcuts. */
export function KeyboardShortcutsProvider() {
  useKeyboardShortcuts();
  return <KeyboardShortcutsModal />;
}
