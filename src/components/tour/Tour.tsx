"use client";

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useAuth } from "@/lib/auth";
import { tourTarget, type TourDef } from "@/lib/tour";

interface Rect { top: number; left: number; width: number; height: number }

const PAD = 6;          // space around the highlighted element
const CARD_W = 340;
const GAP = 12;

/**
 * Starts a tour once for a signed-in person who has not seen it (`ready` = the page has the things to point at),
 * and lets them replay it. `active` drives <Tour>.
 */
export function useTour(def: TourDef, ready: boolean) {
  const { tourEnabled, tourSeen, markTourSeen } = useAuth();
  const [active, setActive] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (started.current || !ready || !tourEnabled || tourSeen.includes(def.id)) return;
    started.current = true;
    setActive(true);
  }, [ready, tourEnabled, tourSeen, def.id]);

  const close = useCallback(() => { setActive(false); void markTourSeen(def.id); }, [markTourSeen, def.id]);
  const start = useCallback(() => setActive(true), []);
  return { active, start, close, available: tourEnabled };
}

/** The "Take the tour" button, shown on the page the tour belongs to. */
export function TourButton({ onClick }: { onClick: () => void }) {
  return (
    <button type="button" onClick={onClick}
      className="inline-flex items-center gap-1.5 text-xs font-medium text-indigo-700 hover:text-indigo-800 px-2.5 py-1.5 rounded-lg border border-indigo-200 bg-indigo-50 hover:bg-indigo-100 transition-colors">
      <span aria-hidden>?</span> Take the tour
    </button>
  );
}

/**
 * Bring `el` to the middle of the screen by scrolling VERTICALLY only. Element.scrollIntoView scrolls every ancestor on both axes,
 * including the app shell's `overflow: hidden` containers: when the target (a wide table, an Attest button at its far right) sat
 * beyond the right edge, it shifted the whole page sideways and left it "not fitting the window". The page scrolls inside <main>,
 * so find the nearest scrollable ancestor and change only its scrollTop.
 */
export function scrollVerticallyTo(el: HTMLElement) {
  let box: HTMLElement | null = el.parentElement;
  while (box && !(box.scrollHeight > box.clientHeight && /(auto|scroll)/.test(getComputedStyle(box).overflowY))) box = box.parentElement;
  const scroller = box ?? (document.scrollingElement as HTMLElement | null);
  if (!scroller) return;
  const er = el.getBoundingClientRect();
  const top = box ? box.getBoundingClientRect().top : 0;
  const height = box ? box.clientHeight : window.innerHeight;
  // centred, or its top edge a little below the container's top when it is taller than the container
  const delta = er.height >= height - 48 ? er.top - top - 24 : er.top - top - (height - er.height) / 2;
  scroller.scrollTop += delta;
}

const find = (name: string) => (typeof document === "undefined" ? null : document.querySelector<HTMLElement>(tourTarget(name)));

/** A spotlight on one element of the page with a short explanation, stepping through `def.steps`. */
export default function Tour({ def, onClose, onFinish }: { def: TourDef; onClose: () => void; onFinish?: () => void }) {
  // Steps whose target is not on the page are skipped, unless they carry a fallback text.
  const [steps] = useState(() => def.steps.filter(s => !!find(s.target) || !!s.fallback));
  const [i, setI] = useState(0);
  const [rect, setRect] = useState<Rect | null>(null);
  const cardRef = useRef<HTMLDivElement>(null);
  const step = steps[i];
  const last = i === steps.length - 1;
  const el = step ? find(step.target) : null;

  const measure = useCallback(() => {
    const t = step ? find(step.target) : null;
    if (!t) { setRect(null); return; }
    const r = t.getBoundingClientRect();
    // beyond the left or right edge of the window (a far-right table column): nothing to point at, so say it in the middle
    if (r.right <= 0 || r.left >= window.innerWidth) { setRect(null); return; }
    setRect({ top: r.top, left: r.left, width: r.width, height: r.height });
  }, [step]);

  // bring the target into view, then follow it while the page scrolls or resizes
  useLayoutEffect(() => {
    if (el) scrollVerticallyTo(el);
    measure();
  }, [el, measure]);
  useEffect(() => {
    window.addEventListener("resize", measure);
    window.addEventListener("scroll", measure, true);
    return () => { window.removeEventListener("resize", measure); window.removeEventListener("scroll", measure, true); };
  }, [measure]);

  const next = useCallback(() => {
    if (last) { onClose(); onFinish?.(); } else setI(n => n + 1);
  }, [last, onClose, onFinish]);
  const back = useCallback(() => setI(n => Math.max(0, n - 1)), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); onClose(); }
      else if (e.key === "ArrowRight") { e.preventDefault(); next(); }
      else if (e.key === "ArrowLeft") { e.preventDefault(); back(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [next, back, onClose]);

  useEffect(() => { cardRef.current?.focus(); }, [i]);

  if (!step) return null;

  // Place the card under the target, above it when there is no room, centred when there is no target.
  const vw = typeof window === "undefined" ? 1024 : window.innerWidth;
  const vh = typeof window === "undefined" ? 768 : window.innerHeight;
  const w = Math.min(CARD_W, vw - 24);
  let style: React.CSSProperties;
  if (rect) {
    const left = Math.min(Math.max(12, rect.left), vw - w - 12);
    const below = rect.top + rect.height + PAD + GAP;
    const fitsBelow = below + 190 < vh;
    style = { left, width: w, ...(fitsBelow ? { top: below } : { bottom: Math.max(12, vh - rect.top + PAD + GAP) }) };
  } else {
    style = { left: Math.max(12, (vw - w) / 2), top: Math.max(12, vh / 3), width: w };
  }

  // Rendered into <body>, not where the page put it: <main> has `contain: layout`, which makes it the containing block of `position: fixed`
  // descendants. The overlay and the card were then placed against <main> (not the window) using window coordinates, and the card, offset
  // by the sidebar's width, stretched <main>'s scrollable area: the whole page scrolled sideways while the tour was open.
  if (typeof document === "undefined") return null;
  return createPortal(
    <div className="fixed inset-0 z-[100] overflow-hidden" role="dialog" aria-modal="true" aria-label="Guided tour">
      {/* dims the page, leaving the target lit; a click on the dimmed area does nothing */}
      {rect ? (
        <div aria-hidden className="absolute rounded-lg pointer-events-none transition-all duration-150"
          style={{ top: rect.top - PAD, left: rect.left - PAD, width: rect.width + PAD * 2, height: rect.height + PAD * 2, boxShadow: "0 0 0 9999px rgba(15,23,42,0.55)", outline: "2px solid rgb(99 102 241)" }} />
      ) : (
        <div aria-hidden className="absolute inset-0 bg-slate-900/55" />
      )}
      <div ref={cardRef} tabIndex={-1} style={style}
        className="absolute bg-white rounded-xl shadow-2xl border border-gray-200 p-4 outline-none">
        <div className="flex items-start justify-between gap-3">
          <h2 className="text-sm font-semibold text-gray-900">{step.title}</h2>
          <button type="button" onClick={onClose} aria-label="Skip the tour" className="text-gray-400 hover:text-gray-600 text-lg leading-none -mt-1">×</button>
        </div>
        <p className="text-xs text-gray-600 leading-relaxed mt-1.5">{rect || el || !step.fallback ? step.body : step.fallback}</p>
        <div className="flex items-center justify-between mt-3.5">
          <span className="text-[11px] text-gray-400 tabular-nums">{i + 1} of {steps.length}</span>
          <div className="flex items-center gap-2">
            {i === 0
              ? <button type="button" onClick={onClose} className="text-xs text-gray-500 hover:text-gray-700 px-2 py-1">Skip</button>
              : <button type="button" onClick={back} className="text-xs text-gray-500 hover:text-gray-700 px-2 py-1">Back</button>}
            <button type="button" onClick={next} className="text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg px-3 py-1.5">
              {last ? (def.finishLabel ?? "Done") : "Next"}
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}
