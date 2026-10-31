// Score a findings TSV (severity \t rule \t path:line \t detail) against a 0llino/sast-benchmark
// expectedresults CSV. A test case is flagged for its category when any finding of that category's
// rules lands in its file. Usage: node score_sb.js <csv> <tsv> [detail|rules]
const fs = require("fs");
const [csvPath, tsvPath, mode] = process.argv.slice(2);
const RULES = {
  sqli: ["sql-injection"],
  cmdi: ["command-injection", "argument-injection"],
  pathtraver: ["path-traversal", "zip-slip"],
  xss: ["xss"],
  ssrf: ["ssrf"],
  weakrand: ["insecure-randomness"],
  weakhash: ["weak-crypto", "weak-hash"],
  weakcipher: ["weak-crypto", "weak-cipher"],
  crypto: ["weak-crypto", "weak-hash", "weak-cipher", "weak-signing-secret"],
  securecookie: ["cookie-no-httponly", "cookie-no-secure"],
  redirect: ["open-redirect"],
  hardcodedcreds: ["hardcoded-secret", "high-entropy-secret", "weak-signing-secret", "hardcoded-credentials"],
  authnfailure: ["jwt-none-alg", "timing-attack", "weak-signing-secret", "plaintext-password-storage", "authn-failure", "api-endpoint-missing-auth"],
  authzfailure: ["idor", "bola-missing-ownership-check", "bola-identity-mismatch", "missing-authorization", "api-endpoint-missing-auth"],
  tlsverify: ["tls-verification-disabled"],
  loginjection: ["log-injection"],
  nosql: ["nosql-injection"],
  csrf: ["csrf-protection-disabled", "csrf"],
  // template injection is code injection (CWE-1336 is a child of CWE-94); the Go corpus files it under codeinj
  codeinj: ["eval-exec", "code-injection", "ssti"],
  ldapi: ["ldap-injection"],
  trustbound: ["trust-boundary"],
  deserial: ["insecure-deserialization"],
  race_condition: ["toctou", "race-condition"],
  fileupload: ["insecure-file-upload"],
  inputval: ["input-validation", "integer-overflow", "unvalidated-input"],
  infodisclosure: ["verbose-error", "pii-in-logs", "information-disclosure", "debug-mode-enabled"],
  xxe: ["xxe"],
  ssti: ["ssti"],
  headerinj: ["header-injection"],
  massassign: ["mass-assignment"],
  fileinclusion: ["file-inclusion"],
  extract: ["php-extract", "variable-overwrite", "mass-assignment"],
  variablevars: ["php-variable-variables", "variable-overwrite"],
  unsafereflect: ["unsafe-reflection", "eval-exec"],
  typejuggling: ["type-juggling"],
  dynmethod: ["unsafe-reflection", "dynamic-method"],
  regex: ["redos"],
  redos: ["redos"],
  memsafety: ["memory-safety", "unsafe-rust", "buffer-overflow"],
  intoverflow: ["integer-overflow", "arithmetic-overflow"],
};
const byFile = new Map();
for (const line of fs.readFileSync(tsvPath, "utf8").split("\n")) {
  const [, rule, loc] = line.split("\t");
  if (!loc) continue;
  const m = /benchmark_test_(\d{5})\./i.exec(loc) || /BenchmarkTest(\d{5})/.exec(loc);
  if (!m) continue;
  const k = `BenchmarkTest${m[1]}`;
  if (!byFile.has(k)) byFile.set(k, new Set());
  byFile.get(k).add(rule);
}
const stats = {}, fps = {}, fns = {}, rulesSeen = {};
for (const raw of fs.readFileSync(csvPath, "utf8").split(/\r?\n/)) {
  if (!raw || raw.startsWith("#")) continue;
  const [name, catRaw, real] = raw.split(",").map(s => s.trim());
  const cat = catRaw;
  if (!name || !cat) continue;
  const rules = RULES[cat] ?? [];
  const found = [...(byFile.get(name) ?? [])];
  for (const r of found) ((rulesSeen[cat] ??= {})[`${real === "true" ? "T" : "F"}:${r}`] ??= 0), rulesSeen[cat][`${real === "true" ? "T" : "F"}:${r}`]++;
  const hit = found.some(r => rules.includes(r));
  const s = (stats[cat] ??= { tp: 0, fn: 0, fp: 0, tn: 0 });
  if (real === "true") { if (hit) s.tp++; else { s.fn++; (fns[cat] ??= []).push(name); } }
  else { if (hit) { s.fp++; (fps[cat] ??= []).push(name); } else s.tn++; }
}
const T = { tp: 0, fn: 0, fp: 0, tn: 0 };
let sumScore = 0, n = 0;
console.log("category        TP  FN  FP  TN   TPR   FPR  score");
for (const [cat, s] of Object.entries(stats).sort()) {
  for (const k of Object.keys(T)) T[k] += s[k];
  const tpr = s.tp / Math.max(1, s.tp + s.fn), fpr = s.fp / Math.max(1, s.fp + s.tn);
  sumScore += tpr - fpr; n++;
  console.log(`${cat.padEnd(15)} ${String(s.tp).padStart(3)} ${String(s.fn).padStart(3)} ${String(s.fp).padStart(3)} ${String(s.tn).padStart(3)}  ${(tpr * 100).toFixed(0).padStart(3)}%  ${(fpr * 100).toFixed(0).padStart(3)}%  ${((tpr - fpr) * 100).toFixed(0).padStart(4)}`);
}
const tpr = T.tp / (T.tp + T.fn), fpr = T.fp / (T.fp + T.tn);
console.log(`TOTAL           ${T.tp} ${T.fn} ${T.fp} ${T.tn}  ${(tpr * 100).toFixed(0)}%  ${(fpr * 100).toFixed(0)}%  flat ${((tpr - fpr) * 100).toFixed(0)}  cat-avg ${((sumScore / n) * 100).toFixed(0)}`);
if (mode === "detail") { console.log("FP:", JSON.stringify(fps)); console.log("FN:", JSON.stringify(fns)); }
// JSON_OUT=<file>: the per-category counts for the published report (benchmarks/build-report.mjs)
if (process.env.JSON_OUT) fs.writeFileSync(process.env.JSON_OUT, JSON.stringify(Object.entries(stats).sort().map(([name, s]) => ({ name, ...s }))));
if (mode === "rules") for (const [c, m] of Object.entries(rulesSeen).sort()) console.log(c, JSON.stringify(m));
