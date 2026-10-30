import type { Metadata } from "next";
import Link from "next/link";
import { SitePage, Section, Card, Pill, CYAN, EMERALD, AMBER, VIOLET } from "@/components/marketing/Site";

export const metadata: Metadata = {
  title: "Roadmap — TrustLedger",
  description: "What has shipped (with the commit that shipped it), what we are working on next, and what is planned — kept separate so nothing planned reads as available.",
};

/** Shipped work, each with the commit it landed in (git history of this repository). */
const SHIPPED: { date: string; commit: string; title: string }[] = [
  { date: "2026-10-30", commit: "e2f90ea", title: "C# proofs from the batch's own call sites; Java request wrappers across files; Rust integer-overflow and unsafe-memory checks; C/C++ allocation sizes and loop bounds; Go, PHP, Ruby, Kotlin, Express and Android rules" },
  { date: "2026-10-29", commit: "bbe15dd", title: "C# proof pass and network sources; PHP, Android, DOM and Juice Shop coverage" },
  { date: "2026-10-29", commit: "043a098", title: "Java proof pass; Rust shape and log sinks; relative-URL guards" },
  { date: "2026-10-29", commit: "a21ecb3", title: "C/C++ data-flow and memory-safety engine" },
  { date: "2026-10-29", commit: "c71997f", title: "Constant folding and log injection in every engine" },
  { date: "2026-10-27", commit: "b53029e", title: "Precision and recall work from NodeGoat, Juliet (Java/C#) and OWASP BenchmarkJava" },
  { date: "2026-10-27", commit: "5fff17f", title: "Go, Rust, PHP, Ruby, C# and Kotlin precision and recall from the sast-benchmark corpus" },
  { date: "2026-10-24", commit: "b73e12f", title: "Python engine on OWASP BenchmarkPython (score 12 → 95)" },
  { date: "2026-10-24", commit: "c018d07", title: "Large pull requests fetched as one archive; scans fail closed on unread files" },
  { date: "2026-10-23", commit: "358eba2", title: "Merge gate follows the organisation's Block CRITICAL / Block HIGH settings" },
  { date: "2026-10-21", commit: "b3ea10c", title: "Sign-offs follow file content across scans" },
];

const NEXT: { title: string; why: string }[] = [
  { title: "Follow return values across files in the C# proof pass", why: "The largest remaining source of C# SQL false positives (Juliet flow variant 61)." },
  { title: "Resolve settings read from .properties files in Java", why: "Hash and cipher algorithms chosen in configuration are currently missed (BenchmarkJava hash category)." },
  { title: "A labelled corpus for trace accuracy", why: "So the report can measure whether each trace names the right source and sink, not only whether a finding exists." },
  { title: "CodeQL and Semgrep run under identical conditions", why: "To publish a fair comparison — wins and losses — on the same corpora." },
];

const PLANNED: { title: string; why: string }[] = [
  { title: "Kotlin scored on a public labelled corpus", why: "Kotlin is tested by unit tests and deliberately vulnerable apps today, but no public labelled corpus exists to score it on." },
  { title: "Ruby and Rust authorization and CSRF categories", why: "Not detected yet on the sast-benchmark corpus." },
  { title: "Independent penetration test of TrustLedger itself", why: "We will publish a summary on the Trust Center when it is done." },
  { title: "SOC 2 audit of TrustLedger", why: "Not started; the Trust Center will say when it is." },
];

export default function RoadmapPage() {
  return (
    <SitePage active="/roadmap" eyebrow="Roadmap" eyebrowColor={VIOLET} title="Shipped, next, and planned — kept apart"
      lede={<>Everything under <strong className="text-white">Shipped</strong> is in the product today, with the commit that shipped it. Everything else is not available yet. Dates for planned work are not promises.</>}>
      <Section title="Shipped">
        <div className="space-y-2.5">
          {SHIPPED.map(s => (
            <Card key={s.commit} className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 !py-3.5">
              <span className="text-[12px] font-mono text-white/45 shrink-0 w-24">{s.date}</span>
              <Pill color={EMERALD}>{s.commit}</Pill>
              <span className="text-sm text-white/80">{s.title}</span>
            </Card>
          ))}
        </div>
        <p className="text-[12.5px] text-white/50 mt-4">Release notes: <Link href="/changelog" className="underline underline-offset-2">changelog</Link>. Measured effect: <Link href="/benchmarks#history" className="underline underline-offset-2">benchmark history</Link>.</p>
      </Section>
      <Section title="Working on next" tone="surface">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {NEXT.map(n => <Card key={n.title} accent={CYAN}><p className="font-bold text-white">{n.title}</p><p className="text-sm text-white/60 mt-1">{n.why}</p></Card>)}
        </div>
      </Section>
      <Section title="Planned">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {PLANNED.map(n => <Card key={n.title} accent={AMBER}><p className="font-bold text-white">{n.title}</p><p className="text-sm text-white/60 mt-1">{n.why}</p></Card>)}
        </div>
      </Section>
    </SitePage>
  );
}
