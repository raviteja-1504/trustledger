/**
 * @jest-environment node
 *
 * A very large Java class (java-tron's Wallet.java: 197 KB, ~5,000 lines) took over two minutes to scan, because the trace resolver and
 * several per-file lookups re-walked the whole syntax tree once per traced parameter / container write / call. The per-file indexes
 * (call nodes and their text, methods, collection variables, field types, per-body names) are now built once per tree.
 * The limit is generous (the fixed engine takes a fraction of it); the old one is several times over.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
jest.setTimeout(300_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

function bigController(methods: number): string {
  const body: string[] = [];
  for (let i = 0; i < methods; i++) {
    body.push(`
  public String handle${i}(HttpServletRequest request) throws Exception {
    String a${i} = request.getParameter("a${i}");
    String b${i} = helper${i}(a${i}, "k${i}");
    cache.put("k${i}", b${i});
    List<String> items${i} = new ArrayList<>();
    items${i}.add(b${i});
    for (String it : items${i}) { log.info(it); }
    return cache.get("k${i}") + String.valueOf(items${i}.size());
  }
  private String helper${i}(String s, String k) {
    String t = s + k;
    if (t.length() > ${i}) { t = t.substring(0, ${i}); }
    return t.trim();
  }`);
  }
  // one real finding the engine must still report, in the middle of everything
  body.push(`
  public java.sql.ResultSet find(HttpServletRequest request, java.sql.Statement stmt) throws Exception {
    String name = request.getParameter("name");
    return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
  }`);
  return `package app;\nimport java.util.*;\nimport javax.servlet.http.HttpServletRequest;\npublic class Big {\n  private final Map<String, String> cache = new HashMap<>();\n  private final java.util.logging.Logger log = java.util.logging.Logger.getLogger("big");\n${body.join("\n")}\n}\n`;
}

describe("a very large Java class", () => {
  it("is scanned in reasonable time and still reports its real finding", () => {
    const content = bigController(220);
    const t0 = Date.now();
    const res = runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/main/java/app/Big.java", content }] });
    const ms = Date.now() - t0;
    const found = res.files[0].indicators.filter(i => i.line != null);
    expect(found.map(i => i.id)).toContain("sql-injection");
    // eslint-disable-next-line no-console
    console.log(`Big.java: ${content.length} bytes, ${ms} ms`);
    expect(ms).toBeLessThan(60_000);
  });
});
