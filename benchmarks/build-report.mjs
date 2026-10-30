#!/usr/bin/env node
/**
 * Builds the published benchmark report (src/data/benchmarks.json, served at /benchmarks/report.json and rendered
 * at /benchmarks) from one measured run.
 *
 *   node benchmarks/build-report.mjs <run.json>
 *
 * <run.json> describes the run (see benchmarks/README.md): the engine commit, and for every corpus its metadata,
 * the probe output (TSV) and the scorer to apply. Each scorer is executed with JSON_OUT so the report carries exact
 * per-category counts, never numbers retyped from a terminal. Curated content -- the false-positive / false-negative
 * examples, known limitations, comparison status and history -- comes from benchmarks/report-notes.json.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const run = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const notes = JSON.parse(fs.readFileSync(path.join(here, "report-notes.json"), "utf8"));

/** Runs a scorer with JSON_OUT and returns what it wrote. */
function score(scorer, args) {
  const out = path.join(os.tmpdir(), `tl-score-${process.pid}-${Math.random().toString(36).slice(2)}.json`);
  execFileSync(process.execPath, [path.join(here, "scorers", scorer), ...args], { env: { ...process.env, JSON_OUT: out }, stdio: ["ignore", "ignore", "inherit"], maxBuffer: 1 << 28 });
  const data = JSON.parse(fs.readFileSync(out, "utf8"));
  fs.unlinkSync(out);
  return data;
}

/** The internal cross-file suite's committed baseline (src/__tests__/.../crossFileBaseline.json): counts per language. */
function fromBaseline(file) {
  const b = JSON.parse(fs.readFileSync(file, "utf8"));
  return Object.entries(b.byLanguage).sort().map(([name, s]) => ({ name, tp: s.tp, fn: s.fn, fp: s.fp, tn: s.tn }));
}

const corpora = run.corpora.map(c => ({
  id: c.id, name: c.name, url: c.url, version: c.version, languages: c.languages, scoring: c.scoring,
  runAt: c.runAt, files: c.files ?? null, wallMs: c.wallMs ?? null,
  categories: c.baseline ? fromBaseline(c.baseline) : score(c.scorer, c.args),
}));

const j = run.juice;
const juice = {
  name: "OWASP Juice Shop", url: j.url, version: j.version, runAt: j.runAt, files: j.files ?? null, wallMs: j.wallMs ?? null,
  challenges: score("score_juice.js", j.args),
};

const report = {
  generatedAt: run.generatedAt,
  engineCommit: run.engineCommit,
  environment: run.environment,
  corpora,
  juice,
  aiAttribution: JSON.parse(fs.readFileSync(run.aiAttributionJson, "utf8")),
  falsePositives: notes.falsePositives,
  falseNegatives: notes.falseNegatives,
  limitations: notes.limitations,
  comparison: notes.comparison,
  history: notes.history,
};

const target = path.join(here, "..", "src", "data", "benchmarks.json");
fs.mkdirSync(path.dirname(target), { recursive: true });
fs.writeFileSync(target, JSON.stringify(report, null, 2) + "\n");
console.log(`wrote ${path.relative(process.cwd(), target)}: ${corpora.length} corpora, ${juice.challenges.length} Juice Shop challenges`);
