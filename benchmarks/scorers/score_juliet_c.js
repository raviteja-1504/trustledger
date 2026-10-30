// Score a Juliet C/C++ probe TSV (path \t line \t id). Usage: node score_juliet_c.js <testcasesRoot> <tsv> <CWES>
// A test case is TP when a finding of its CWE's rules lands in a bad function, FP when one lands in a good function.
// SHOW=<cwe dir> lists FN cases and FP locations for that directory.
const fs = require("fs");
const path = require("path");
const [root, tsv, cwes] = process.argv.slice(2);
const RULES = {
  CWE78: ["command-injection"], CWE134: ["format-string"], CWE121: ["buffer-overflow"], CWE122: ["buffer-overflow"],
  CWE242: ["buffer-overflow"], CWE789: ["integer-overflow"], CWE416: ["use-after-free"], CWE415: ["double-free"],
  CWE690: ["null-dereference"], CWE762: ["mismatched-deallocation"], CWE377: ["insecure-temp-file"],
  CWE23: ["path-traversal"], CWE36: ["path-traversal"], CWE90: ["ldap-injection"], CWE114: ["eval-exec"],
  CWE680: ["integer-overflow", "buffer-overflow"],
};
const walk = d => fs.readdirSync(d, { withFileTypes: true }).flatMap(e =>
  e.isDirectory() ? walk(path.join(d, e.name)) : /\.(?:c|cpp)$/.test(e.name) && !/^main/.test(e.name) ? [path.join(d, e.name)] : []);
// a definition starts at column 0: `static void goodG2B()`, `char * CWE..._badSource(char * data)`, `void bad()`
const SIG = /^(?:static\s+|inline\s+)*(?:[\w:<>]+[\s*&]+)+(\w+)\s*\(([^;]*)$/;
function regions(text) {
  const lines = text.split("\n");
  const kind = new Array(lines.length + 2).fill("other");
  for (let i = 0; i < lines.length; i++) {
    const m = SIG.exec(lines[i]);
    if (!m || /^(?:return|else|if|for|while|switch|namespace|class|struct)\b/.test(lines[i])) continue;
    const name = m[1];
    let k = /(?:^|_)bad/i.test(name) ? "bad" : /(?:^|_)good/i.test(name) ? "good" : "other";
    if (/(?:^|_)good$/i.test(name)) k = "other"; // dispatcher
    let depth = 0, started = false, j = i;
    for (; j < lines.length; j++) {
      for (const ch of lines[j]) { if (ch === "{") { depth++; started = true; } else if (ch === "}") depth--; }
      if (started && depth <= 0) break;
      if (!started && /;\s*$/.test(lines[j])) break;
    }
    if (!started) continue;
    for (let l = i; l <= j; l++) kind[l + 1] = k;
    i = j;
  }
  return kind;
}
const caseOf = f => path.basename(f).replace(/\.(?:c|cpp)$/, "").replace(/(_\d\d)[a-e]$/, "$1").replace(/_(?:bad|good\w*)$/, "");
const findings = new Map();
for (const line of fs.readFileSync(tsv, "utf8").split("\n")) {
  const [p, l, id] = line.trim().split("\t");
  if (!id) continue;
  if (!findings.has(p)) findings.set(p, []);
  findings.get(p).push({ line: +l, id });
}
let totN = 0, totTP = 0, totFP = 0;
const rows = [];
// every case has a bad (vulnerable) and a good (safe) function: n positives and n negatives
const cats = [];
for (const cwe of cwes.split(",")) {
  const rules = RULES[cwe.split("_")[0]] ?? [];
  const cases = new Map();
  for (const abs of walk(path.join(root, cwe))) {
    const rel = path.relative(root, abs).split(path.sep).join("/");
    const c = caseOf(abs);
    if (!cases.has(c)) cases.set(c, { tp: false, fp: false, fpIds: new Set() });
    const fs_ = findings.get(rel);
    if (!fs_) continue;
    const kind = regions(fs.readFileSync(abs, "utf8"));
    for (const f of fs_) {
      if (!rules.includes(f.id)) continue;
      const k = kind[f.line];
      if (k === "bad") cases.get(c).tp = true;
      else if (k === "good") { cases.get(c).fp = true; cases.get(c).fpIds.add(`${rel}:${f.line}`); }
    }
  }
  const n = cases.size, tp = [...cases.values()].filter(x => x.tp).length, fp = [...cases.values()].filter(x => x.fp).length;
  totN += n; totTP += tp; totFP += fp;
  cats.push({ name: cwe, tp, fn: n - tp, fp, tn: n - fp });
  const tpr = n ? tp / n : 0, fpr = n ? fp / n : 0;
  rows.push(`${cwe.padEnd(44)} cases=${String(n).padStart(5)} TPR=${(100 * tpr).toFixed(1).padStart(5)}% FPR=${(100 * fpr).toFixed(1).padStart(5)}% score=${(100 * (tpr - fpr)).toFixed(1)}`);
  if (process.env.SHOW === cwe) {
    const fn = [...cases].filter(([, x]) => !x.tp).map(([c]) => c);
    console.log(`  FN (${fn.length}): ` + fn.slice(0, Number(process.env.SHOWN || 40)).join(" "));
    for (const [c, x] of cases) if (x.fp) console.log("  FP " + c + " " + [...x.fpIds].join(" "));
  }
}
console.log(rows.join("\n"));
console.log(`TOTAL cases=${totN} TPR=${(100 * totTP / totN).toFixed(1)}% FPR=${(100 * totFP / totN).toFixed(1)}%`);
// JSON_OUT=<file>: the per-CWE counts for the published report (benchmarks/build-report.mjs)
if (process.env.JSON_OUT) fs.writeFileSync(process.env.JSON_OUT, JSON.stringify(cats));
