/**
 * @jest-environment node
 *
 * Advanced interprocedural taint suite (cases.ts, scored by runInterprocedural.ts) against its committed baseline
 * (interproceduralBaseline.json): no case may score worse than recorded, and no safe twin may start reporting a
 * flow. A case that scores better must be recorded -- run with UPDATE_BASELINE=1 -- so the baseline stays the
 * engine's real level.
 */
import fs from "fs";
import path from "path";
import { ensureTaintEngines } from "@/lib/engineWarmup";
import { runInterprocedural, type CaseResult, type Outcome } from "./runInterprocedural";

jest.setTimeout(600_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

const BASELINE = path.join(__dirname, "interproceduralBaseline.json");
const RANK: Record<Outcome, number> = { miss: 0, partial: 1, pass: 2 };

it("no case scores worse than its baseline, and safe twins stay quiet", () => {
  const results = runInterprocedural();
  const table = results.map(r => `${r.id.padEnd(8)} ${r.outcome.padEnd(7)} twin:${r.twin.padEnd(5)} ${r.missing.join("; ")}${process.env.SHOW_TRACES ? `\n           trace: ${r.detail}` : ""}`).join("\n");
  const summary = (["pass", "partial", "miss"] as Outcome[]).map(o => `${o} ${results.filter(r => r.outcome === o).length}`).join(" · ");
  console.log(`interprocedural suite: ${summary}\n${table}`);

  if (process.env.UPDATE_BASELINE) {
    const record = Object.fromEntries(results.map(r => [r.id, { outcome: r.outcome, twin: r.twin }]));
    fs.writeFileSync(BASELINE, JSON.stringify(record, null, 2) + "\n");
    return;
  }
  const baseline = JSON.parse(fs.readFileSync(BASELINE, "utf8")) as Record<string, Pick<CaseResult, "outcome" | "twin">>;
  const worse = results.filter(r => !baseline[r.id] || RANK[r.outcome] < RANK[baseline[r.id].outcome] || (r.twin === "fp" && baseline[r.id].twin === "clean"));
  const better = results.filter(r => baseline[r.id] && (RANK[r.outcome] > RANK[baseline[r.id].outcome] || (r.twin === "clean" && baseline[r.id].twin === "fp")));
  expect(worse.map(r => `${r.id}: ${r.outcome}/${r.twin} (baseline ${baseline[r.id]?.outcome}/${baseline[r.id]?.twin})`)).toEqual([]);
  expect(better.map(r => `${r.id} improved to ${r.outcome}/${r.twin}: record it with UPDATE_BASELINE=1`)).toEqual([]);
});
