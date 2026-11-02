/**
 * @jest-environment node
 *
 * Golden findings snapshot -- step 0 of the Universal Taint Model migration (docs/taint/utm-gap-report.md §6.4):
 * every program kept in the repository for benchmarking (the hard fixtures, the cross-file cases, the
 * interprocedural fixtures) scanned through the production pipeline, each finding recorded as
 * `file:line rule <- source`. Moving a source, sink, sanitizer or propagator into the model registry must leave
 * this unchanged; a difference is either a regression or a reviewed improvement, recorded with UPDATE_GOLDEN=1.
 *
 * Detail text is left out on purpose: rewording a message is not a detection change.
 */
import fs from "fs";
import path from "path";
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
import { CROSS_FILE_CASES } from "../crossFile/cases";
import { INTERPROCEDURAL_CASES } from "../interprocedural/cases";
import { fixtureSource } from "../interprocedural/runInterprocedural";

jest.setTimeout(900_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

const GOLDEN = path.join(__dirname, "goldenFindings.json");
const HARD = path.join(__dirname, "..", "fixtures");

type Program = { name: string; files: Array<{ path: string; content: string }> };

function programs(): Program[] {
  const hard = fs.readdirSync(HARD).filter(f => f.endsWith(".fixture")).sort()
    .map(f => ({ name: `hard/${f}`, files: [{ path: f.replace(/\.fixture$/, ""), content: fs.readFileSync(path.join(HARD, f), "utf8").replace(/\r\n/g, "\n") }] }));
  const cross = CROSS_FILE_CASES.map(c => ({ name: `cross-file/${c.language}/${c.name}`, files: c.files }));
  const inter = INTERPROCEDURAL_CASES.map(c => ({ name: `interprocedural/${c.id}`, files: [{ path: c.path, content: fixtureSource(c) }] }));
  return [...hard, ...cross, ...inter];
}

function snapshot(p: Program): string[] {
  const r = runScan({ repo: "benchmark/golden", pr_number: 1, commit_sha: "0000000", branch: "main", files: p.files });
  return r.files.flatMap(f => f.indicators.filter(i => i.line != null)
    .map(i => `${f.file_path}:${i.line} ${i.id} <- ${(i.sourceExpr ?? "-").replace(/\s+/g, " ").slice(0, 80)}`))
    .sort();
}

it("every benchmark program's findings match the golden snapshot", () => {
  const current: Record<string, string[]> = Object.fromEntries(programs().map(p => [p.name, snapshot(p)]));
  if (process.env.UPDATE_GOLDEN) {
    fs.writeFileSync(GOLDEN, JSON.stringify(current, null, 1) + "\n");
    return;
  }
  const golden = JSON.parse(fs.readFileSync(GOLDEN, "utf8")) as Record<string, string[]>;
  const diffs: string[] = [];
  for (const name of new Set([...Object.keys(golden), ...Object.keys(current)])) {
    const was = new Set(golden[name] ?? []), now = new Set(current[name] ?? []);
    for (const f of now) if (!was.has(f)) diffs.push(`+ ${name}: ${f}`);
    for (const f of was) if (!now.has(f)) diffs.push(`- ${name}: ${f}`);
  }
  expect(diffs).toEqual([]);
});
