"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { createPortal } from "react-dom";

interface Props {
  title: string;
  description: string;
  formula?: string;
  position?: "top" | "bottom" | "left" | "right";
  size?: "sm" | "md";
}

const TIP_W = 260;

export default function InfoTooltip({
  title,
  description,
  formula,
  position = "top",
  size = "sm",
}: Props) {
  const [open,   setOpen]   = useState(false);
  const [coords, setCoords] = useState({ top: 0, left: 0 });
  const btnRef = useRef<HTMLButtonElement>(null);

  const recalc = useCallback(() => {
    if (!btnRef.current) return;
    const r   = btnRef.current.getBoundingClientRect();
    const gap = 10;

    let top  = 0;
    let left = 0;

    if (position === "top") {
      top  = r.top + window.scrollY - gap;   // will be offset by translateY(-100%)
      left = r.left + window.scrollX + r.width / 2 - TIP_W / 2;
    } else if (position === "bottom") {
      top  = r.bottom + window.scrollY + gap;
      left = r.left + window.scrollX + r.width / 2 - TIP_W / 2;
    } else if (position === "left") {
      top  = r.top + window.scrollY + r.height / 2;
      left = r.left + window.scrollX - TIP_W - gap;
    } else {
      top  = r.top + window.scrollY + r.height / 2;
      left = r.right + window.scrollX + gap;
    }

    // Clamp so tooltip never goes off-screen horizontally
    const maxLeft = window.innerWidth - TIP_W - 8;
    left = Math.max(8, Math.min(left, maxLeft));

    setCoords({ top, left });
  }, [position]);

  const show = useCallback(() => { recalc(); setOpen(true);  }, [recalc]);
  const hide = useCallback(() => { setOpen(false); }, []);

  // Close on outside click or scroll
  useEffect(() => {
    if (!open) return;
    const fn = (e: MouseEvent) => {
      if (btnRef.current && !btnRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", fn);
    window.addEventListener("scroll", hide, true);
    window.addEventListener("resize", hide);
    return () => {
      document.removeEventListener("mousedown", fn);
      window.removeEventListener("scroll", hide, true);
      window.removeEventListener("resize", hide);
    };
  }, [open, hide]);

  const btnSize = size === "sm" ? "w-3.5 h-3.5 text-[8px]" : "w-4 h-4 text-[9px]";

  const transformStyle = position === "top"   ? "translateY(-100%)"
                       : position === "bottom" ? "none"
                       : position === "left"   ? "translateY(-50%)"
                       :                         "translateY(-50%)";

  // Arrow position within the popup
  const arrowStyle = (): React.CSSProperties => {
    const base: React.CSSProperties = {
      position:"absolute", width:10, height:10, transform:"rotate(45deg)",
      background:"#1e293b", zIndex:1,
    };
    if (position === "top")    return { ...base, bottom:-5, left: coords.left + TIP_W/2 - 5 - coords.left, borderRight:"1px solid rgba(255,255,255,0.12)", borderBottom:"1px solid rgba(255,255,255,0.12)" };
    if (position === "bottom") return { ...base, top:-5,    left: "calc(50% - 5px)", borderLeft:"1px solid rgba(255,255,255,0.12)", borderTop:"1px solid rgba(255,255,255,0.12)" };
    if (position === "left")   return { ...base, right:-5,  top:"calc(50% - 5px)",   borderRight:"1px solid rgba(255,255,255,0.12)", borderTop:"1px solid rgba(255,255,255,0.12)" };
    return                              { ...base, left:-5,   top:"calc(50% - 5px)",   borderLeft:"1px solid rgba(255,255,255,0.12)", borderBottom:"1px solid rgba(255,255,255,0.12)" };
  };

  const popup = open ? (
    <div
      role="tooltip"
      style={{
        position:  "fixed",
        top:       coords.top,
        left:      coords.left,
        width:     TIP_W,
        transform: transformStyle,
        zIndex:    99999,           // above everything — portalled to body
        background:   "#1e293b",
        border:       "1px solid rgba(255,255,255,0.12)",
        borderRadius: 12,
        boxShadow:    "0 12px 40px rgba(0,0,0,0.55), 0 4px 12px rgba(0,0,0,0.3)",
        pointerEvents:"none",
      }}
    >
      {/* Arrow */}
      {position === "top" && (
        <span style={{ position:"absolute", bottom:-5, left:"calc(50% - 5px)", width:10, height:10,
          transform:"rotate(45deg)", background:"#1e293b",
          borderRight:"1px solid rgba(255,255,255,0.12)", borderBottom:"1px solid rgba(255,255,255,0.12)" }} />
      )}
      {position === "bottom" && (
        <span style={{ position:"absolute", top:-5, left:"calc(50% - 5px)", width:10, height:10,
          transform:"rotate(45deg)", background:"#1e293b",
          borderLeft:"1px solid rgba(255,255,255,0.12)", borderTop:"1px solid rgba(255,255,255,0.12)" }} />
      )}
      {position === "left" && (
        <span style={{ position:"absolute", right:-5, top:"calc(50% - 5px)", width:10, height:10,
          transform:"rotate(45deg)", background:"#1e293b",
          borderRight:"1px solid rgba(255,255,255,0.12)", borderTop:"1px solid rgba(255,255,255,0.12)" }} />
      )}
      {position === "right" && (
        <span style={{ position:"absolute", left:-5, top:"calc(50% - 5px)", width:10, height:10,
          transform:"rotate(45deg)", background:"#1e293b",
          borderLeft:"1px solid rgba(255,255,255,0.12)", borderBottom:"1px solid rgba(255,255,255,0.12)" }} />
      )}

      <div style={{ padding:"14px 16px", display:"flex", flexDirection:"column", gap:8 }}>
        {/* Title */}
        <p style={{ fontSize:10, fontWeight:900, color:"#ffffff", textTransform:"uppercase",
          letterSpacing:"0.08em", lineHeight:1, margin:0 }}>
          {title}
        </p>
        {/* Description */}
        <p style={{ fontSize:11, color:"#cbd5e1", lineHeight:1.6, margin:0 }}>
          {description}
        </p>
        {/* Formula */}
        {formula && (
          <div style={{ borderTop:"1px solid rgba(255,255,255,0.1)", paddingTop:8 }}>
            <p style={{ fontSize:9, fontWeight:800, textTransform:"uppercase",
              letterSpacing:"0.08em", color:"#475569", marginBottom:4, margin:0 }}>
              Formula
            </p>
            <code style={{ fontSize:10, fontFamily:"monospace", color:"#7dd3fc",
              lineHeight:1.6, whiteSpace:"pre-wrap", display:"block", marginTop:4 }}>
              {formula}
            </code>
          </div>
        )}
      </div>
    </div>
  ) : null;

  return (
    <div className="relative inline-flex items-center shrink-0">
      <button
        ref={btnRef}
        type="button"
        onClick={() => (open ? hide() : show())}
        onMouseEnter={show}
        onMouseLeave={hide}
        className={`${btnSize} rounded-full flex items-center justify-center font-black transition-all`}
        style={{
          background: open ? "rgba(99,102,241,0.18)" : "rgba(100,116,139,0.15)",
          color:      open ? "#6366f1" : "#64748b",
          border:     `1.5px solid ${open ? "rgba(99,102,241,0.4)" : "rgba(100,116,139,0.25)"}`,
        }}
        aria-label={`Info: ${title}`}
        aria-expanded={open}
      >
        i
      </button>

      {/* Portalled to body — escapes every stacking context */}
      {typeof document !== "undefined" && popup
        ? createPortal(popup, document.body)
        : null}
    </div>
  );
}
