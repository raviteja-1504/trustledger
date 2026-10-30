// Score a probe TSV (path \t line \t id \t kind) against OWASP BenchmarkJava's expectedresults CSV.
// A test case counts as flagged for its category when any finding of that category's rules is in its file.
const fs = require("fs");
const [csvPath, tsvPath, mode] = process.argv.slice(2);
const RULES = {
  cmdi: ["command-injection", "argument-injection"],
  crypto: ["weak-crypto"],
  hash: ["weak-crypto", "weak-hash"],
  ldapi: ["ldap-injection"],
  pathtraver: ["path-traversal"],
  securecookie: ["cookie-no-httponly", "cookie-no-secure", "cookie-insecure", "insecure-cookie"],
  sqli: ["sql-injection"],
  trustbound: ["trust-boundary", "trust-boundary-violation"],
  weakrand: ["insecure-randomness", "weak-random"],
  xpathi: ["xpath-injection"],
  xss: ["xss"],
};
const byFile = new Map();
for (const line of fs.readFileSync(tsvPath, "utf8").split("\n")) {
  const [loc, , rule] = line.split("\t");
  if (!rule) continue;
  const m = /BenchmarkTest(\d{5})\.java/.exec(loc);
  if (!m) continue;
  const k = `BenchmarkTest${m[1]}`;
  if (!byFile.has(k)) byFile.set(k, new Set());
  byFile.get(k).add(rule);
}
const stats = {}, fps = {}, fns = {};
for (const line of fs.readFileSync(csvPath, "utf8").split(/\r?\n/)) {
  if (!line || line.startsWith("#")) continue;
  const [name, cat, real] = line.split(",");
  const rules = RULES[cat] ?? [];
  const hit = [...(byFile.get(name) ?? [])].some(r => rules.includes(r));
  const s = (stats[cat] ??= { tp: 0, fn: 0, fp: 0, tn: 0 });
  if (real === "true") { if (hit) s.tp++; else { s.fn++; (fns[cat] ??= []).push(name); } }
  else { if (hit) { s.fp++; (fps[cat] ??= []).push(name); } else s.tn++; }
}
const T = { tp: 0, fn: 0, fp: 0, tn: 0 };
let scoreSum = 0, cats = 0;
console.log("category        TP  FN  FP  TN   TPR   FPR  score");
for (const [cat, s] of Object.entries(stats).sort()) {
  for (const k of Object.keys(T)) T[k] += s[k];
  const tpr = s.tp / Math.max(1, s.tp + s.fn), fpr = s.fp / Math.max(1, s.fp + s.tn);
  scoreSum += tpr - fpr; cats++;
  console.log(`${cat.padEnd(15)} ${String(s.tp).padStart(3)} ${String(s.fn).padStart(3)} ${String(s.fp).padStart(3)} ${String(s.tn).padStart(3)}  ${(tpr * 100).toFixed(0).padStart(3)}%  ${(fpr * 100).toFixed(0).padStart(3)}%  ${((tpr - fpr) * 100).toFixed(0).padStart(4)}`);
}
const tpr = T.tp / (T.tp + T.fn), fpr = T.fp / (T.fp + T.tn);
console.log(`TOTAL           ${T.tp} ${T.fn} ${T.fp} ${T.tn}  ${(tpr * 100).toFixed(0)}%  ${(fpr * 100).toFixed(0)}%  ${((tpr - fpr) * 100).toFixed(0)}  (category-averaged ${(100 * scoreSum / cats).toFixed(1)})`);
if (mode === "detail") { console.log("FP:", JSON.stringify(fps)); console.log("FN:", JSON.stringify(fns)); }
// JSON_OUT=<file>: the per-category counts for the published report (benchmarks/build-report.mjs)
if (process.env.JSON_OUT) fs.writeFileSync(process.env.JSON_OUT, JSON.stringify(Object.entries(stats).sort().map(([name, s]) => ({ name, ...s }))));
