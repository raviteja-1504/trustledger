/**
 * Large-repository stress test for the scanner: time, memory and correctness on a realistic, big code base.
 *
 * Opt-in (STRESS=1) -- it takes a minute or more. Two corpora:
 *  - synthetic (always, when enabled): ~1,500 files across the six data-flow languages, wired together the way
 *    real services are (routes importing services importing repositories, PHP includes, Go packages, injected
 *    Java/C# services), with a known number of real cross-file flows planted;
 *  - real (STRESS_DIRS=dir1,dir2,...): every scannable file under those directories, scanned as one batch.
 *
 * Budgets are deliberately generous (a laptop, not CI hardware) and exist to catch order-of-magnitude
 * regressions -- a super-linear pass, a leak -- not to benchmark precisely. Numbers are printed every run.
 */
import fs from "fs";
import path from "path";
import { runScan } from "@/lib/scanner";
import { isScannablePath } from "@/lib/scannableFiles";
import { ensureTaintEngines } from "@/lib/engineWarmup";

const enabled = !!process.env.STRESS;
const d = enabled ? describe : describe.skip;
jest.setTimeout(20 * 60_000);

type F = { path: string; content: string };

/** A synthetic multi-language service code base with `modules` feature modules per language. */
export function syntheticRepo(modules: number): { files: F[]; plantedFlows: number } {
  const files: F[] = [];
  let planted = 0;
  for (let m = 0; m < modules; m++) {
    const vuln = m % 5 === 0;                                  // every fifth module has a real cross-file SQLi
    if (vuln) planted += 6;
    const q = (v: string) => (vuln ? `"SELECT * FROM t${m} WHERE id = " + ${v}` : `"SELECT * FROM t${m} WHERE id = ?"`);
    // TypeScript: route -> service -> repository
    files.push({ path: `ts/m${m}/repo.ts`, content: `export class Repo${m} {\n  find(id: string) { return db.query(${q("id")}${vuln ? "" : ", [id]"}); }\n}\nexport const repo${m} = new Repo${m}();\n` });
    files.push({ path: `ts/m${m}/service.ts`, content: `import { repo${m} } from "./repo";\nexport function load${m}(id: string) {\n  const clean = id.trim();\n  return repo${m}.find(clean);\n}\n` });
    files.push({ path: `ts/m${m}/routes.ts`, content: `import { load${m} } from "./service";\napp.get("/m${m}/:id", async (req, res) => {\n  const row = await load${m}(req.query.id);\n  res.json(row);\n});\n` });
    // Python: view -> service module
    files.push({ path: `py/m${m}/db.py`, content: `def run_${m}(i):\n    cursor.execute(${vuln ? `"SELECT * FROM t WHERE id = " + i` : `"SELECT * FROM t WHERE id = %s", (i,)`})\n` });
    files.push({ path: `py/m${m}/views.py`, content: `from py.m${m}.db import run_${m}\ndef view_${m}(request):\n    return run_${m}(request.GET.get("id"))\n` });
    // Java: controller -> @Autowired service
    files.push({ path: `java/m${m}/Svc${m}.java`, content: `@Service public class Svc${m} {\n  public void find(String id) throws Exception { ${vuln ? `stmt.executeQuery("SELECT * FROM t WHERE id = " + id);` : `PreparedStatement p = conn.prepareStatement("SELECT * FROM t WHERE id = ?"); p.setString(1, id); p.executeQuery();`} }\n}\n` });
    files.push({ path: `java/m${m}/Ctl${m}.java`, content: `@RestController public class Ctl${m} {\n  @Autowired private Svc${m} svc;\n  @GetMapping("/m${m}") public void a(@RequestParam String id) throws Exception { svc.find(id); }\n}\n` });
    // C#: controller -> injected service
    files.push({ path: `cs/m${m}/Svc${m}.cs`, content: `public class Svc${m} {\n  public void Find(string id) { ${vuln ? `new SqlCommand("SELECT * FROM t WHERE id = " + id, conn).ExecuteReader();` : `db.Users.FromSqlInterpolated($"SELECT * FROM t WHERE id = {id}").ToList();`} }\n}\n` });
    files.push({ path: `cs/m${m}/Ctl${m}.cs`, content: `[ApiController] public class Ctl${m} : ControllerBase {\n  private readonly Svc${m} _svc;\n  public Ctl${m}(Svc${m} svc) { _svc = svc; }\n  [HttpGet] public IActionResult A([FromQuery] string id) { _svc.Find(id); return Ok(); }\n}\n` });
    // Go: handler -> models package
    files.push({ path: `go/m${m}/models/store.go`, content: `package models\nfunc Find${m}(db *sql.DB, id string) { ${vuln ? `db.Query("SELECT * FROM t WHERE id = " + id)` : `db.Query("SELECT * FROM t WHERE id = ?", id)`} }\n` });
    files.push({ path: `go/m${m}/api/h.go`, content: `package api\nimport "example.com/app/go/m${m}/models"\nfunc H${m}(w http.ResponseWriter, r *http.Request) { models.Find${m}(db, r.URL.Query().Get("id")) }\n` });
    // PHP: page -> included library
    files.push({ path: `php/m${m}/lib.php`, content: `<?php\nfunction find_${m}($c, $id) { mysqli_query($c, ${vuln ? `"SELECT * FROM t WHERE id = " . $id` : `"SELECT * FROM t WHERE id = " . intval($id)`}); }\n` });
    files.push({ path: `php/m${m}/index.php`, content: `<?php\nrequire_once __DIR__ . '/lib.php';\nfind_${m}($c, $_GET['id']);\n` });
    // Bulk: realistic filler with no findings (utilities, models, config) -- most of a real repo.
    files.push({ path: `ts/m${m}/util.ts`, content: Array.from({ length: 40 }, (_, k) => `export function helper${m}_${k}(a: number, b: number) {\n  const s = a + b * ${k};\n  return s > 100 ? s % 7 : s;\n}\n`).join("\n") });
  }
  return { files, plantedFlows: planted };
}

function loadDir(root: string): F[] {
  const out: F[] = [];
  const walk = (dir: string) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (/^(?:node_modules|vendor|\.git|dist|build)$/.test(e.name)) continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else {
        const rel = path.relative(root, p).split(path.sep).join("/");
        if (isScannablePath(rel) && fs.statSync(p).size < 300_000) out.push({ path: `${path.basename(root)}/${rel}`, content: fs.readFileSync(p, "utf8") });
      }
    }
  };
  walk(root);
  return out;
}

function measure(files: F[]) {
  global.gc?.();
  const heap0 = process.memoryUsage().heapUsed;
  let peak = heap0;
  const timer = setInterval(() => { peak = Math.max(peak, process.memoryUsage().heapUsed); }, 50);
  const t0 = Date.now();
  const result = runScan({ repo: "stress/repo", pr_number: 1, commit_sha: "0".repeat(40), files });
  const ms = Date.now() - t0;
  clearInterval(timer);
  peak = Math.max(peak, process.memoryUsage().heapUsed);
  const lines = files.reduce((n, f) => n + f.content.split("\n").length, 0);
  return { result, ms, lines, peakMb: Math.round((peak - heap0) / 1e6), rssMb: Math.round(process.memoryUsage().rss / 1e6) };
}

d("large-repository stress", () => {
  beforeAll(async () => { await ensureTaintEngines(60_000); });

  it("synthetic multi-language service repo: within budget, and every planted cross-file flow found", () => {
    const { files, plantedFlows } = syntheticRepo(Number(process.env.STRESS_MODULES ?? 100));
    const { result, ms, lines, peakMb, rssMb } = measure(files);
    const crossFileSqli = result.files.flatMap(f => f.indicators.filter(i => i.id === "sql-injection" && i.flow?.crossesFiles)).length;
    console.log(`[stress] synthetic: ${files.length} files, ${lines} lines -> ${ms} ms (${(ms / files.length).toFixed(1)} ms/file), heap +${peakMb} MB, rss ${rssMb} MB, health ${result.health?.status}, cross-file SQLi ${crossFileSqli}/${plantedFlows}`);
    console.log(`[stress] phases: ${JSON.stringify({ cross_file_ms: result.telemetry?.cross_file_ms, per_file_ms: result.telemetry?.per_file_ms, post_ms: result.telemetry?.post_ms, slowest: result.telemetry?.slowest.slice(0, 3) })}`);
    expect(result.files).toHaveLength(files.length);
    expect(result.health?.status).toBe("complete");
    expect(crossFileSqli).toBe(plantedFlows);                  // scale must not cost recall
    expect(ms / files.length).toBeLessThan(250);               // ~50x headroom over a typical laptop run
    expect(peakMb).toBeLessThan(3000);
  });

  it("real repositories (STRESS_DIRS), scanned as one batch", () => {
    const dirs = (process.env.STRESS_DIRS ?? "").split(",").map(s => s.trim()).filter(Boolean);
    if (!dirs.length) return;
    const files = dirs.flatMap(loadDir);
    const { result, ms, lines, peakMb, rssMb } = measure(files);
    console.log(`[stress] real (${dirs.map(x => path.basename(x)).join(", ")}): ${files.length} files, ${lines} lines -> ${ms} ms (${(ms / files.length).toFixed(1)} ms/file), heap +${peakMb} MB, rss ${rssMb} MB, health ${result.health?.status} ${JSON.stringify(result.health?.gap_counts)}`);
    console.log(`[stress] phases: ${JSON.stringify({ cross_file_ms: result.telemetry?.cross_file_ms, per_file_ms: result.telemetry?.per_file_ms, post_ms: result.telemetry?.post_ms, slowest: result.telemetry?.slowest })}`);
    expect(result.files).toHaveLength(files.length);
    expect(ms / Math.max(1, files.length)).toBeLessThan(500);
  });
});
