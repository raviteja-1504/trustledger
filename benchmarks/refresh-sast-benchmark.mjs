#!/usr/bin/env node
/**
 * Re-measures the 0llino/sast-benchmark corpora (Go, PHP, Ruby, Rust) in src/data/benchmarks.json and leaves every other
 * corpus, the Juice Shop result and the curated notes exactly as they are -- for the case where only this corpus was re-run
 * (the others need downloads from NIST SARD, OWASP and Snyk; see benchmarks/README.md).
 *
 *   node benchmarks/refresh-sast-benchmark.mjs <sast-benchmark checkout> <probe dir> <engine commit> [YYYY-MM-DD]
 *
 * <probe dir> holds, per language, the probe output and its console log: go.tsv / go.log, php.tsv / php.log, ... where the
 * .tsv is the harness's findings file and the .log carries its `files=N findings=M ms=T` line. Counts come from score_sb.js
 * run with JSON_OUT, never typed in. A commit name ending in "+" means that commit plus uncommitted changes of the same day.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const [checkout, probeDir, engineCommit, dayArg] = process.argv.slice(2);
if (!checkout || !probeDir || !engineCommit) { console.error("usage: refresh-sast-benchmark.mjs <checkout> <probe dir> <engine commit> [date]"); process.exit(2); }
if (!/^[0-9a-f]{7,40}\+?$/.test(engineCommit)) { console.error(`engine commit must look like b4505ab or b4505ab+, got ${engineCommit}`); process.exit(2); }

// Only these four languages are corpora of the report.
const LANGS = [
  { key: "go", label: "Go" }, { key: "php", label: "PHP" }, { key: "ruby", label: "Ruby" }, { key: "rust", label: "Rust" },
];
const SCORING = "Each test case is one file labelled vulnerable or safe for a category; a case is flagged when a finding of that category's rules is in its file.";
const target = path.join(here, "..", "src", "data", "benchmarks.json");
const report = JSON.parse(fs.readFileSync(target, "utf8"));
const runAt = new Date(dayArg ? `${dayArg}T12:00:00Z` : Date.now()).toISOString();

const scoreOf = (csv, tsv) => {
  const out = path.join(os.tmpdir(), `tl-sb-${process.pid}-${Math.random().toString(36).slice(2)}.json`);
  execFileSync(process.execPath, [path.join(here, "scorers", "score_sb.js"), csv, tsv], { env: { ...process.env, JSON_OUT: out }, stdio: ["ignore", "ignore", "inherit"], maxBuffer: 1 << 28 });
  const data = JSON.parse(fs.readFileSync(out, "utf8"));
  fs.unlinkSync(out);
  return data;
};

for (const { key, label } of LANGS) {
  const dir = path.join(checkout, key);
  const csvName = fs.readdirSync(dir).find(f => /^expectedresults-.*\.csv$/.test(f));
  const tsv = path.join(probeDir, `${key}.tsv`), log = path.join(probeDir, `${key}.log`);
  if (!csvName || !fs.existsSync(tsv)) { console.log(`skip ${key}: no expected results or probe output`); continue; }
  const version = /expectedresults-(.+)\.csv$/.exec(csvName)[1];
  const m = /files=(\d+)\s+findings=\d+\s+ms=(\d+)/.exec(fs.existsSync(log) ? fs.readFileSync(log, "utf8") : "");
  const entry = {
    id: `sast-benchmark-${key}`, name: `SAST Benchmark — ${label}`, url: "https://github.com/0llino/sast-benchmark", version, languages: [label],
    scoring: SCORING, runAt, files: m ? Number(m[1]) : null, wallMs: m ? Number(m[2]) : null,
    categories: scoreOf(path.join(dir, csvName), tsv), engineCommit,
  };
  const at = report.corpora.findIndex(c => c.id === entry.id);
  if (at >= 0) report.corpora[at] = { ...report.corpora[at], ...entry }; else report.corpora.splice(report.corpora.findLastIndex(c => /^sast-benchmark-/.test(c.id)) + 1, 0, entry);
  console.log(`${label.padEnd(5)} v${version}: ${entry.categories.length} categories, ${entry.files ?? "?"} files`);
}
report.generatedAt = new Date().toISOString();
fs.writeFileSync(target, JSON.stringify(report, null, 2) + "\n");
console.log(`updated ${path.relative(process.cwd(), target)}`);
