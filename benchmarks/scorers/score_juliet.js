// Score a Juliet probe TSV (path \t line \t id \t kind). Usage: node score_juliet.js <testcasesRoot> <tsv> <CWES> <SRCregex> <EXTregex>
// A test case is TP when a finding of its CWE's rules lands in a bad region, FP when one lands in a good region.
const fs = require("fs");
const path = require("path");
const [root, tsv, cwes, srcRe, extRe] = process.argv.slice(2);
const RULES = {
  CWE89: ["sql-injection"], CWE78: ["command-injection", "argument-injection"], CWE80: ["xss"], CWE81: ["xss"], CWE83: ["xss"],
  CWE23: ["path-traversal"], CWE36: ["path-traversal"], CWE22: ["path-traversal"], CWE601: ["open-redirect"],
  CWE113: ["header-injection"], CWE90: ["ldap-injection"], CWE643: ["xpath-injection"], CWE470: ["eval-exec"],
  CWE327: ["weak-crypto", "weak-hash"], CWE328: ["weak-crypto", "weak-hash"], CWE338: ["insecure-randomness"],
  CWE614: ["cookie-no-secure", "cookie-insecure"], CWE259: ["hardcoded-secret"], CWE321: ["hardcoded-secret"],
  CWE117: ["log-injection"], CWE502: ["insecure-deserialization"], CWE611: ["xxe"], CWE94: ["eval-exec"],
};
const src = new RegExp(srcRe || "."), ext = new RegExp(extRe || "\\.java$");
const walk = d => fs.readdirSync(d, { withFileTypes: true }).flatMap(e =>
  e.isDirectory() ? (e.name === "antbuild" ? [] : walk(path.join(d, e.name))) : ext.test(e.name) ? [path.join(d, e.name)] : []);
const SIG = /^\s*(?:(?:public|private|protected|internal|static|override|virtual|async|final|synchronized|unsafe)\s+)*[\w<>\[\],.?]+\s+(\w+)\s*\(/;
/** line (1-based) -> "bad" | "good" | "other" */
function regions(file, text) {
  const lines = text.split("\n");
  const kind = new Array(lines.length + 2).fill("other");
  const base = path.basename(file).replace(ext, "");
  const fileKind = /_bad$/.test(base) ? "bad" : /_good\w*$/.test(base) ? "good" : null;
  for (let i = 0; i < lines.length; i++) {
    const m = SIG.exec(lines[i]);
    if (!m || /^\s*(?:return|new|else|if|for|while|switch|catch)\b/.test(lines[i])) continue;
    const name = m[1];
    let k = /^bad/i.test(name) ? "bad" : /^good/i.test(name) ? "good" : (fileKind && name !== "main" ? fileKind : "other");
    if (/^good$/i.test(name)) k = "other";            // good() only dispatches to goodG2B()/goodB2G()
    // body: from the first "{" at/after the signature to its matching "}"
    let depth = 0, started = false, j = i;
    for (; j < lines.length; j++) {
      for (const ch of lines[j]) { if (ch === "{") { depth++; started = true; } else if (ch === "}") depth--; }
      if (started && depth <= 0) break;
      if (!started && /;\s*$/.test(lines[j])) break;   // abstract / interface declaration
    }
    if (!started) continue;
    for (let l = i; l <= j; l++) kind[l + 1] = k;
    i = j;
  }
  return kind;
}
const caseOf = f => path.basename(f).replace(ext, "").replace(/_(?:bad|good\w*|base|helper)$/, "").replace(/(_\d\d)[a-e]$/, "$1");
const findings = new Map();
for (const line of fs.readFileSync(tsv, "utf8").split("\n")) {
  const [p, l, id] = line.split("\t");
  if (!id) continue;
  if (!findings.has(p)) findings.set(p, []);
  findings.get(p).push({ line: +l, id });
}
let totN = 0, totTP = 0, totFP = 0;
const rows = [];
// every case has a bad (vulnerable) and a good (safe) region: n positives and n negatives
const cats = [];
for (const cwe of cwes.split(",")) {
  const rules = RULES[cwe.split("_")[0]] ?? [];
  const cases = new Map();   // case -> {tp, fp}
  for (const abs of walk(path.join(root, cwe)).filter(p => src.test(path.basename(p)))) {
    const rel = path.relative(root, abs).split(path.sep).join("/");
    const c = caseOf(abs);
    if (!cases.has(c)) cases.set(c, { tp: false, fp: false, fpIds: new Set() });
    const fs_ = findings.get(rel);
    if (!fs_) continue;
    const kind = regions(abs, fs.readFileSync(abs, "utf8"));
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
  rows.push(`${cwe.padEnd(34)} cases=${String(n).padStart(4)} TPR=${(100 * tpr).toFixed(1).padStart(5)}% FPR=${(100 * fpr).toFixed(1).padStart(5)}% score=${(100 * (tpr - fpr)).toFixed(1)}`);
  if (process.env.SHOW === cwe) {
    for (const [c, x] of cases) if (!x.tp) console.log("  FN " + c);
    for (const [c, x] of cases) if (x.fp) console.log("  FP " + c + " " + [...x.fpIds].join(" "));
  }
}
console.log(rows.join("\n"));
console.log(`TOTAL cases=${totN} TPR=${(100 * totTP / totN).toFixed(1)}% FPR=${(100 * totFP / totN).toFixed(1)}%`);
// JSON_OUT=<file>: the per-CWE counts for the published report (benchmarks/build-report.mjs)
if (process.env.JSON_OUT) fs.writeFileSync(process.env.JSON_OUT, JSON.stringify(cats));
