// Score a probe TSV (severity \t rule \t path:line \t detail) against OWASP Juice Shop's own vuln-code-snippet markers.
// A challenge is detected when a security finding lands within +-2 lines of one of its `vuln-line` markers.
// Usage: node score_juice.js <juiceRoot> <tsv> [detail]
const fs = require("fs");
const path = require("path");
const [root, tsv, mode] = process.argv.slice(2);
const SKIP = /^(?:node_modules|codefixes|test|dist|\.git|\.ai|cypress)$/;
const EXT = /\.(?:ts|js|html|yml|yaml|sol|tf|json)$/;
const NON_SECURITY = /^(?:ai-|license|watermark|attribution|structural|magic-number|dead-code|nesting|line-length|blank-line|boilerplate|zero-debug|naming|comment|hallucinat|style|consistency)/;
const walk = d => fs.readdirSync(d, { withFileTypes: true }).flatMap(e =>
  e.isDirectory() ? (SKIP.test(e.name) ? [] : walk(path.join(d, e.name))) : EXT.test(e.name) ? [path.join(d, e.name)] : []);
const vuln = new Map(); // challenge -> [{file, line}]
for (const abs of walk(root)) {
  const rel = path.relative(root, abs).split(path.sep).join("/");
  const lines = fs.readFileSync(abs, "utf8").split("\n");
  lines.forEach((l, i) => {
    const m = /vuln-code-snippet vuln-line ([\w ]+)/.exec(l);
    if (!m) return;
    for (const ch of m[1].trim().split(/\s+/)) { if (!vuln.has(ch)) vuln.set(ch, []); vuln.get(ch).push({ file: rel, line: i + 1 }); }
  });
}
const findings = new Map(); // file -> [{line, id}]
for (const row of fs.readFileSync(tsv, "utf8").split("\n")) {
  const [, id, loc] = row.split("\t");
  if (!id || NON_SECURITY.test(id)) continue;
  const m = /^(.*):(\d+)$/.exec(loc ?? "");
  if (!m) continue;
  if (!findings.has(m[1])) findings.set(m[1], []);
  findings.get(m[1]).push({ line: +m[2], id });
}
let hit = 0;
const rows = [];
const challenges = [];
for (const [ch, locs] of [...vuln].sort()) {
  const ids = new Set();
  for (const { file, line } of locs) for (const f of findings.get(file) ?? []) if (Math.abs(f.line - line) <= 2) ids.add(f.id);
  if (ids.size) hit++;
  rows.push(`${ids.size ? "HIT " : "MISS"} ${ch.padEnd(36)} ${locs.map(l => `${l.file}:${l.line}`).slice(0, 2).join(" ")}${ids.size ? "  <- " + [...ids].join(",") : ""}`);
  challenges.push({ id: ch, detected: ids.size > 0, via: ids.size ? [...ids].join(", ") : null, location: `${locs[0].file}:${locs[0].line}` });
}
if (mode === "detail") console.log(rows.join("\n"));
console.log(`TOTAL challenges=${vuln.size} detected=${hit} (${(100 * hit / vuln.size).toFixed(1)}%)`);
// JSON_OUT=<file>: every challenge and whether it was detected, for the published report
if (process.env.JSON_OUT) fs.writeFileSync(process.env.JSON_OUT, JSON.stringify(challenges));
