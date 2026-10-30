import type { Metadata } from "next";
import Link from "next/link";
import { SitePage, Section, Card, Pill, TableWrap, BORDER, CYAN, EMERALD, ROSE, AMBER, VIOLET } from "@/components/marketing/Site";
import { BENCHMARK_REPORT as R, rates, categoryAverage, throughput, pct, type CorpusResult } from "@/lib/benchmarkReport";

export const metadata: Metadata = {
  title: "Benchmark report — TrustLedger",
  description: "Precision and recall of the TrustLedger engines on public, labelled SAST benchmarks — per language and per vulnerability category, with methodology, failures and known limitations.",
};

const fmtDate = (iso: string) => new Date(iso).toISOString().slice(0, 10);

function Stat({ label, value, sub, color = CYAN }: { label: string; value: string; sub?: string; color?: string }) {
  return (
    <Card>
      <p className="text-[11px] font-bold uppercase tracking-[0.12em] text-white/45 font-mono">{label}</p>
      <p className="text-3xl font-black mt-1 font-mono" style={{ color }}>{value}</p>
      {sub && <p className="text-[12px] text-white/50 mt-1">{sub}</p>}
    </Card>
  );
}

function CorpusTable({ c }: { c: CorpusResult }) {
  const t = rates(c.categories);
  return (
    <details className="rounded-2xl border group" style={{ borderColor: BORDER, background: "rgba(255,255,255,0.025)" }}>
      <summary className="cursor-pointer list-none p-5 flex flex-wrap items-center gap-x-6 gap-y-2">
        <span className="min-w-0 flex-1">
          <span className="block font-bold text-white">{c.name} <span className="text-white/40 font-mono text-[12px]">v{c.version}</span></span>
          <span className="block text-[12px] text-white/50">{c.languages.join(", ")} · {t.cases.toLocaleString()} labelled samples · run {fmtDate(c.runAt)}</span>
        </span>
        <span className="font-mono text-sm"><span className="text-white/45">score </span><strong className="text-white">{t.score}</strong></span>
        <span className="font-mono text-sm"><span className="text-white/45">TPR </span><strong style={{ color: EMERALD }}>{pct(t.tpr)}</strong></span>
        <span className="font-mono text-sm"><span className="text-white/45">FPR </span><strong style={{ color: t.fpr > 0.1 ? ROSE : AMBER }}>{pct(t.fpr)}</strong></span>
        <span className="text-[12px] text-white/40 group-open:hidden">show categories ▾</span>
      </summary>
      <div className="px-5 pb-5 space-y-3">
        <p className="text-[12.5px] text-white/55">{c.scoring} Source: {/^https?:/.test(c.url)
          ? <a href={c.url} className="underline underline-offset-2 text-white/75" target="_blank" rel="noopener noreferrer">{c.url}</a>
          : <code className="font-mono text-white/75">{c.url}</code>}. Category-averaged score: {categoryAverage(c.categories)}.</p>
        <TableWrap>
          <table className="w-full text-[12.5px] font-mono">
            <thead><tr className="text-left text-white/45">{["Category", "TP", "FN", "FP", "TN", "TPR", "FPR", "Score"].map(h => <th key={h} className="px-3 py-2 font-semibold">{h}</th>)}</tr></thead>
            <tbody>
              {c.categories.map(cat => {
                const r = rates([cat]);
                return (
                  <tr key={cat.name} className="border-t" style={{ borderColor: BORDER }}>
                    <td className="px-3 py-1.5 text-white/85">{cat.name}</td>
                    <td className="px-3 py-1.5">{cat.tp}</td><td className="px-3 py-1.5">{cat.fn}</td>
                    <td className="px-3 py-1.5">{cat.fp}</td><td className="px-3 py-1.5">{cat.tn}</td>
                    <td className="px-3 py-1.5" style={{ color: EMERALD }}>{pct(r.tpr)}</td>
                    <td className="px-3 py-1.5" style={{ color: r.fpr > 0.1 ? ROSE : "rgba(255,255,255,0.7)" }}>{pct(r.fpr)}</td>
                    <td className="px-3 py-1.5 font-bold text-white">{r.score}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      </div>
    </details>
  );
}

export default function BenchmarksPage() {
  const all = rates(R.corpora.flatMap(c => c.categories));
  const juiceHits = R.juice.challenges.filter(c => c.detected).length;
  const timed = R.corpora.filter(c => throughput(c) !== null);
  const totalFiles = timed.reduce((s, c) => s + (c.files ?? 0), 0);
  const totalMs = timed.reduce((s, c) => s + (c.wallMs ?? 0), 0);
  return (
    <SitePage active="/benchmarks" eyebrow={`Measured ${fmtDate(R.generatedAt)} · engine ${R.engineCommit}`} title="Benchmark report"
      lede={<>How often the engines find real vulnerabilities, and how often they flag safe code, on public labelled benchmarks that anyone can download. Every number below comes from one run of the scorers against engine commit <code className="font-mono text-white/85">{R.engineCommit}</code>. Failures and limitations are listed alongside the wins. <a href="/benchmarks/report.json" className="underline underline-offset-2 text-white/85">Download the machine-readable report</a>.</>}>
      <Section>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <Stat label="Recall (TPR)" value={pct(all.tpr)} sub={`${all.tp.toLocaleString()} of ${(all.tp + all.fn).toLocaleString()} labelled vulnerabilities, all corpora`} color={EMERALD} />
          <Stat label="False-positive rate" value={pct(all.fpr)} sub={`${all.fp.toLocaleString()} of ${(all.fp + all.tn).toLocaleString()} safe samples flagged`} color={AMBER} />
          <Stat label="Trace accuracy" value="Not measured" sub="No public corpus labels the expected source-to-sink path yet; we will publish this once we have a labelled set." color="rgba(255,255,255,0.7)" />
          <Stat label="Scan throughput" value={totalMs ? `${Math.round(totalFiles / (totalMs / 1000))} files/s` : "—"} sub={`${totalFiles.toLocaleString()} files across the timed runs. ${R.environment}`} color={VIOLET} />
        </div>
        <p className="text-[12px] text-white/45 mt-3">Pooled numbers weight large corpora more heavily; per-corpus and per-category results are below. Precision is not a single meaningful number across corpora with different positive/negative ratios, so each table lists TP, FN, FP and TN for you to compute it.</p>
      </Section>

      <Section id="corpora" title="Results by corpus, language and category" tone="surface"
        intro="Open a corpus to see every vulnerability category. A category with a low score is a real gap — the roadmap lists which ones we are working on.">
        <div className="space-y-3">{R.corpora.map(c => <CorpusTable key={c.id} c={c} />)}</div>
      </Section>

      <Section id="juice-shop" title={`OWASP Juice Shop: ${juiceHits} of ${R.juice.challenges.length} code-level challenges`}
        intro={<>Juice Shop v{R.juice.version} marks the vulnerable line of each coding challenge in its own source (vuln-code-snippet). A challenge counts as detected when a security finding lands within two lines of one of its marked lines. Several challenges live in YAML data, Solidity or Angular routing that no code scanner is expected to judge; they stay in the denominator.</>}>
        <TableWrap>
          <table className="w-full text-[12.5px] font-mono">
            <thead><tr className="text-left text-white/45"><th className="px-3 py-2">Challenge</th><th className="px-3 py-2">Marked line</th><th className="px-3 py-2">Result</th></tr></thead>
            <tbody>
              {R.juice.challenges.map(ch => (
                <tr key={ch.id} className="border-t" style={{ borderColor: BORDER }}>
                  <td className="px-3 py-1.5 text-white/85">{ch.id}</td>
                  <td className="px-3 py-1.5 text-white/55">{ch.location}</td>
                  <td className="px-3 py-1.5">{ch.detected ? <span style={{ color: EMERALD }}>detected · {ch.via}</span> : <span className="text-white/40">missed</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Section>

      <Section id="ai-attribution" title="AI-attribution validation" tone="surface"
        intro={<>The AI-generated estimate is checked against a small labelled corpus in the repository ({R.aiAttribution.samples} files, TypeScript/JavaScript only). It is a regression check, not a statistically strong evaluation — treat these numbers as indicative, and the estimate itself as a probability, not proof of authorship.</>}>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Stat label="Precision" value={pct(R.aiAttribution.precision)} />
          <Stat label="Recall" value={pct(R.aiAttribution.recall)} />
          <Stat label="Accuracy" value={pct(R.aiAttribution.accuracy)} sub={`threshold ${R.aiAttribution.threshold}`} />
          <Stat label="ROC-AUC" value={R.aiAttribution.rocAuc.toFixed(2)} />
          <Stat label="Tool attribution" value={pct(R.aiAttribution.toolAccuracy)} sub={`${R.aiAttribution.toolSamples} labelled samples`} />
        </div>
        <p className="text-[12.5px] text-white/55 mt-3">Read the method and its limits in the <Link href="/docs/ai-attribution" className="underline underline-offset-2 text-white/80">AI attribution documentation</Link>.</p>
      </Section>

      <Section id="failures" title="False positives and false negatives we know about"
        intro="Representative cases from the corpora above, with the reason. Some are engine gaps we are fixing; some are deliberate choices where we think the corpus label is wrong for real-world code — we say which.">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {([["False positives — flagged, but safe", R.falsePositives, ROSE], ["False negatives — missed", R.falseNegatives, AMBER]] as const).map(([title, list, color]) => (
            <div key={title} className="space-y-3">
              <p className="font-bold" style={{ color }}>{title}</p>
              {list.map(e => (
                <Card key={`${e.corpus}:${e.caseId}`}>
                  <div className="flex flex-wrap items-center gap-2 mb-1.5"><Pill color={color}>{e.rule}</Pill><span className="text-[11.5px] font-mono text-white/45">{e.corpus} · {e.caseId}</span></div>
                  <p className="text-sm font-semibold text-white">{e.title}</p>
                  <p className="text-[13px] text-white/60 mt-1">{e.explanation}</p>
                </Card>
              ))}
            </div>
          ))}
        </div>
      </Section>

      <Section id="limitations" title="Known limitations" tone="surface">
        <ul className="list-disc pl-5 space-y-2 text-white/70 max-w-4xl">{R.limitations.map(l => <li key={l}>{l}</li>)}</ul>
      </Section>

      <Section id="comparison" title="Comparison with other scanners">
        <Card accent={CYAN}>
          <p className="text-white/80 max-w-4xl">{R.comparison.note}</p>
          <p className="text-[12.5px] text-white/50 mt-3">Planned method: CodeQL and Semgrep run on the same corpus versions with their default security query packs, scored by the same scripts and matching rules; we will publish categories where they beat us as prominently as those where we lead.</p>
        </Card>
      </Section>

      <Section id="methodology" title="Methodology" tone="surface">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5 text-[13.5px] text-white/65 leading-relaxed">
          <Card><p className="font-bold text-white mb-1.5">What runs</p><p>The production scanner (<code className="font-mono">runScan</code>) — every language engine, cross-file analysis and the line-level detectors — on each corpus in batches, exactly as a pull request is scanned. No benchmark-specific configuration. Helper files a corpus ships next to its test cases are scanned with them, as a whole-repository scan would.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">How it is scored</p><p>A labelled case is a true positive when a finding of that category&apos;s rules lands in the case (per file, per method for Juliet&apos;s bad/good regions); a safe case with such a finding is a false positive. Counts are of labelled samples, each either vulnerable or safe: a Juliet case has one of each, so it counts twice. The mapping from our rule ids to each corpus&apos;s categories is part of the published harness.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">Reproducing it</p><p>The scorers and the probe harness are in the repository under <code className="font-mono">benchmarks/</code>, with the corpus versions and download links listed in its README. Engine commit {R.engineCommit}; report generated {fmtDate(R.generatedAt)}.</p></Card>
          <Card><p className="font-bold text-white mb-1.5">What these numbers do not say</p><p>Benchmarks are small, synthetic programs. They measure whether known patterns are recognised, not how a scanner behaves on your codebase. Scores across different corpora are not comparable with each other.</p></Card>
        </div>
      </Section>

      <Section id="history" title="Engine changes over time" intro={<>Scores measured on the same harness at earlier engine commits. The <Link href="/changelog" className="underline underline-offset-2 text-white/80">changelog</Link> lists what changed in each release.</>}>
        <TableWrap>
          <table className="w-full text-[12.5px] font-mono">
            <thead><tr className="text-left text-white/45">{["Commit", "Date", "Corpus", "Score", "Note"].map(h => <th key={h} className="px-3 py-2">{h}</th>)}</tr></thead>
            <tbody>{R.history.map((h, i) => (
              <tr key={i} className="border-t" style={{ borderColor: BORDER }}>
                <td className="px-3 py-1.5 text-white/85">{h.commit}</td><td className="px-3 py-1.5">{h.date}</td><td className="px-3 py-1.5">{h.corpus}</td>
                <td className="px-3 py-1.5 font-bold text-white">{h.score}</td><td className="px-3 py-1.5 text-white/50">{h.note ?? ""}</td>
              </tr>
            ))}</tbody>
          </table>
        </TableWrap>
      </Section>
    </SitePage>
  );
}
