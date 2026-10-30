/**
 * The three product walkthroughs, recorded from the live demo (/demo) running the real engine -- see
 * scripts/record-demo-videos.mjs, which drives the page with Playwright and writes the WebM files and their
 * captions into public/videos. Each video says what it shows and what it is recorded from.
 */
import { BORDER, CYAN, EMERALD, VIOLET } from "@/components/marketing/Site";

export const DEMO_VIDEOS = [
  {
    id: "tour",
    title: "TrustLedger in under a minute",
    color: CYAN,
    desc: "A pull request with a SQL injection: the scan, the cross-file trace from the query string to the database call, and the merge held by the default policy.",
  },
  {
    id: "engine",
    title: "How the engine detects a real vulnerability",
    color: VIOLET,
    desc: "A multi-file flow and the step-by-step trace, then the parameterised fix side by side, the rescan, and a sanitised sample that stays clean.",
  },
  {
    id: "provenance",
    title: "AI provenance and reviewer attestation",
    color: EMERALD,
    desc: "The AI-generated estimate and what it means, a sign-off bound to the file's content hash, and what happens to that sign-off when the code changes.",
  },
] as const;

export function DemoVideos() {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
      {DEMO_VIDEOS.map(v => (
        <figure key={v.id} className="rounded-2xl border overflow-hidden" style={{ borderColor: BORDER, background: "rgba(255,255,255,0.03)" }}>
          <video controls preload="metadata" playsInline className="w-full aspect-video bg-black" aria-label={v.title}>
            <source src={`/videos/${v.id}.webm`} type="video/webm" />
            <track kind="captions" src={`/videos/${v.id}.vtt`} srcLang="en" label="English" default />
          </video>
          <figcaption className="p-4">
            <p className="font-bold text-white" style={{ color: v.color }}>{v.title}</p>
            <p className="text-sm text-white/65 mt-1">{v.desc}</p>
            <p className="text-[11px] text-white/40 mt-2 font-mono">Recorded from the live demo · real engine · sample code, not a customer repository</p>
          </figcaption>
        </figure>
      ))}
    </div>
  );
}
