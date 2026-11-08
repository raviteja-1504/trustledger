"use client";

/**
 * A tooltip around any element -- a button, a table header, a badge -- not only an "i" icon (InfoTooltip).
 *
 *  - shows on hover AND on keyboard focus (a tap focuses the element on touch screens), hides on leave / blur / Escape
 *  - the element is described by it (aria-describedby), so screen readers read it
 *  - rendered in a portal in viewport coordinates, so no clipped overflow or stacking context hides it, and it sits
 *    above full-screen overlays
 *  - opens above the element, or below when there is no room above
 *
 * Wrap the element: <Tip tip="What this does"><button>…</button></Tip>. With no `tip`, children render untouched.
 */
import { cloneElement, isValidElement, useCallback, useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";

interface Props {
  tip?: React.ReactNode;
  /** A short bold heading above the text. */
  title?: string;
  /** Preferred side; flips when it doesn't fit. */
  side?: "top" | "bottom";
  /** Width of the bubble in px. */
  width?: number;
  children: React.ReactElement;
  /** Class for the wrapper (default: shrink-to-fit inline-flex, so the wrapped element's layout is unchanged). */
  className?: string;
}

const GAP = 8;
const EDGE = 8;

export default function Tip({ tip, title, side = "top", width = 260, children, className = "inline-flex" }: Props) {
  const id = useId();
  const wrapRef = useRef<HTMLSpanElement>(null);
  const bubbleRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number; below: boolean }>({ top: 0, left: 0, below: false });

  const place = useCallback(() => {
    const el = wrapRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const h = bubbleRef.current?.offsetHeight ?? 0;
    const below = side === "bottom" ? true : r.top - h - GAP < EDGE && window.innerHeight - r.bottom > h + GAP;
    const left = Math.max(EDGE, Math.min(r.left + r.width / 2 - width / 2, window.innerWidth - width - EDGE));
    setPos({ top: below ? r.bottom + GAP : r.top - GAP, left, below });
  }, [side, width]);

  const show = useCallback(() => { setOpen(true); }, []);
  const hide = useCallback(() => { setOpen(false); }, []);

  // Measure once the bubble exists, then again on scroll / resize (it follows its element, or leaves with Escape).
  useEffect(() => {
    if (!open) return;
    place();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") hide(); };
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("scroll", place, true);
      window.removeEventListener("resize", place);
      window.removeEventListener("keydown", onKey);
    };
  }, [open, place, hide]);

  if (!tip || !isValidElement(children)) return children;

  const describedBy = open ? id : undefined;
  const child = cloneElement(children as React.ReactElement<Record<string, unknown>>, {
    "aria-describedby": [children.props && (children.props as Record<string, unknown>)["aria-describedby"], describedBy].filter(Boolean).join(" ") || undefined,
  });

  return (
    <span ref={wrapRef} className={className} onMouseEnter={show} onMouseLeave={hide} onFocus={show} onBlur={hide}>
      {child}
      {open && typeof document !== "undefined" && createPortal(
        <div
          ref={bubbleRef}
          id={id}
          role="tooltip"
          style={{
            position: "fixed", top: pos.top, left: pos.left, width, zIndex: 99999,
            transform: pos.below ? "none" : "translateY(-100%)",
            background: "#1e293b", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 10,
            boxShadow: "0 12px 40px rgba(0,0,0,0.55), 0 4px 12px rgba(0,0,0,0.3)",
            padding: "10px 12px", pointerEvents: "none",
          }}
        >
          {title && <p style={{ margin: 0, marginBottom: 4, fontSize: 10, fontWeight: 900, letterSpacing: "0.08em", textTransform: "uppercase", color: "#fff" }}>{title}</p>}
          <div style={{ fontSize: 11, lineHeight: 1.55, color: "#cbd5e1" }}>{tip}</div>
        </div>,
        document.body,
      )}
    </span>
  );
}
