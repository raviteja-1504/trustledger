/** @jest-environment node */
import * as fs from "fs";
import * as path from "path";
import { runScan } from "@/lib/scanner";

const ROOT = process.env.SCAN_ROOT!;
const OUT = process.env.SCAN_OUT!;
const EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]);
const SKIP = /(^|\/)(__tests__|__mocks__|node_modules|dist|build|lib|\.git|coverage|examples?|demo|docs|fixtures|e2e|stories|storybook)(\/|$)|\.(test|spec|min|d|stories)\.[a-z]+$|\.d\.ts$/;

function walk(d: string, out: string[]) {
  let ents: fs.Dirent[];
  try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    const p = path.join(d, e.name);
    const rel = path.relative(ROOT, p).replace(/\\/g, "/");
    if (SKIP.test(rel)) continue;
    if (e.isDirectory()) walk(p, out);
    else if (EXT.has(path.extname(e.name)) && fs.statSync(p).size < 400000) out.push(rel);
  }
}

it("scan", () => {
  const files: string[] = [];
  walk(ROOT, files);
  const hits: any[] = [];
  for (let i = 0; i < files.length; i += 40) {
    const batch = files.slice(i, i + 40).map(p => ({ path: p, content: fs.readFileSync(path.join(ROOT, p), "utf8") }));
    const res = runScan({ repo: process.env.SCAN_REPO || "x/y", pr_number: 1, commit_sha: "0", branch: "main", files: batch });
    for (const f of res.files as any[]) {
      for (const x of [...(f.ast_risks ?? []), ...(f.ssa_taint_paths ?? [])]) {
        hits.push({ file: f.file_path, id: x.id ?? x.rule ?? x.type, line: x.line ?? x.sinkLine, sev: x.severity, label: x.label ?? x.message, detail: String(x.detail ?? x.description ?? "").slice(0, 150), src: x.sourceExpr, sink: x.sinkExpr });
      }
    }
  }
  fs.writeFileSync(OUT, JSON.stringify({ nfiles: files.length, hits }, null, 1));
}, 1800000);
