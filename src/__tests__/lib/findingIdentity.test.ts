import { runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { assignFingerprints } from "@/lib/findingIdentity";
import { toStoredIndicators } from "@/lib/indicatorStorage";

// Finding identity. The asymmetry that drives every case here: an UNSTABLE id (same finding, new id) costs a
// re-triage; a COLLIDING id (two findings, one id) lets acknowledging one silently acknowledge another. So
// ties must resolve toward "distinct", and losing an identity is the acceptable failure mode.

const ind = (over: Partial<ScanIndicator> & { id: string }): ScanIndicator =>
  ({ label: over.id, severity: "high", ...over });

describe("assignFingerprints (unit)", () => {
  it("gives two textually identical findings in the SAME function distinct, deterministic ids", () => {
    const mk = () => [
      ind({ id: "sql-injection", line: 10, sourceExpr: "id", sinkExpr: "db.execute" }),
      ind({ id: "sql-injection", line: 20, sourceExpr: "id", sinkExpr: "db.execute" }),
    ];
    const a = mk(); const b = mk();
    const ctx = { filePath: "f.ts", enclosingFunction: () => "handler" };
    assignFingerprints(a, ctx); assignFingerprints(b, ctx);
    expect(a[0].fingerprint).not.toBe(a[1].fingerprint);
    expect(a.map(x => x.fingerprint)).toEqual(b.map(x => x.fingerprint));
  });

  it("assigns ordinals in SOURCE order regardless of the array order it was given", () => {
    const first = [ind({ id: "x", line: 5, detail: "d" }), ind({ id: "x", line: 9, detail: "d" })];
    const swapped = [first[1], first[0]].map(i => ({ ...i }));
    const ctx = { filePath: "f.ts" };
    const a = first.map(i => ({ ...i })); assignFingerprints(a, ctx);
    assignFingerprints(swapped, ctx);
    const byLine = (xs: ScanIndicator[]) => Object.fromEntries(xs.map(x => [x.line, x.fingerprint]));
    expect(byLine(swapped)).toEqual(byLine(a));
  });

  it("the same flow in two DIFFERENT functions gets two ids (the old fingerprint collided here)", () => {
    const list = [
      ind({ id: "sql-injection", line: 3, sourceExpr: "req.query.id", sinkExpr: "db.execute" }),
      ind({ id: "sql-injection", line: 9, sourceExpr: "req.query.id", sinkExpr: "db.execute" }),
    ];
    assignFingerprints(list, { filePath: "f.ts", enclosingFunction: l => (l < 6 ? "handlerA" : "handlerB") });
    expect(list[0].fingerprint).not.toBe(list[1].fingerprint);
  });

  it("deleting one duplicate does NOT hand its identity to a duplicate in another function", () => {
    const both = [
      ind({ id: "sql-injection", line: 3, sourceExpr: "id", sinkExpr: "db.execute" }),
      ind({ id: "sql-injection", line: 9, sourceExpr: "id", sinkExpr: "db.execute" }),
    ];
    assignFingerprints(both, { filePath: "f.ts", enclosingFunction: l => (l < 6 ? "handlerA" : "handlerB") });
    const idOfB = both[1].fingerprint;
    // handlerA (line 3) is deleted; handlerB now sits at line 3 -- and must keep ITS identity.
    const afterDelete = [ind({ id: "sql-injection", line: 3, sourceExpr: "id", sinkExpr: "db.execute" })];
    assignFingerprints(afterDelete, { filePath: "f.ts", enclosingFunction: () => "handlerB" });
    expect(afterDelete[0].fingerprint).toBe(idOfB);
    expect(afterDelete[0].fingerprint).not.toBe(both[0].fingerprint);
  });

  it("is independent of the line number (a finding survives unrelated lines shifting it)", () => {
    const at = (line: number) => {
      const l = [ind({ id: "sql-injection", line, sourceExpr: "id", sinkExpr: "db.execute" })];
      assignFingerprints(l, { filePath: "f.ts", enclosingFunction: () => "h" });
      return l[0].fingerprint;
    };
    expect(at(4)).toBe(at(400));
  });

  it("differs by file, by rule id, and by flow", () => {
    const fp = (path: string, id: string, sink: string) => {
      const l = [ind({ id, line: 1, sourceExpr: "s", sinkExpr: sink })];
      assignFingerprints(l, { filePath: path });
      return l[0].fingerprint;
    };
    const base = fp("a.ts", "sql-injection", "db.execute");
    expect(fp("b.ts", "sql-injection", "db.execute")).not.toBe(base);
    expect(fp("a.ts", "xss", "db.execute")).not.toBe(base);
    expect(fp("a.ts", "sql-injection", "db.query")).not.toBe(base);
  });

  it("regex findings key on the whitespace-collapsed matched line text", () => {
    const fp = (text: string) => {
      const l = [ind({ id: "hardcoded-secret", line: 1 })];
      assignFingerprints(l, { filePath: "f.ts", lines: [text] });
      return l[0].fingerprint;
    };
    expect(fp("  const   key =  'abc123abc123';")).toBe(fp("const key = 'abc123abc123';"));
    expect(fp("const key = 'abc123abc123';")).not.toBe(fp("const key = 'zzz999zzz999';"));
  });

  it("file-level signals are identified by (rule, file) -- volatile numbers in `detail` must not change the id", () => {
    const fileLevelIds = new Set(["naming-consistency"]);
    const fp = (detail: string, file = "f.ts") => {
      const l = [ind({ id: "naming-consistency", severity: "info", detail })];
      assignFingerprints(l, { filePath: file, fileLevelIds });
      return l[0].fingerprint;
    };
    expect(fp("42% consistent naming")).toBe(fp("57% consistent naming"));
    expect(fp("42% consistent naming", "g.ts")).not.toBe(fp("42% consistent naming"));
  });

  it("a line-less NON-file-level indicator keys on its detail with digits masked", () => {
    const fp = (detail: string) => {
      const l = [ind({ id: "cross-file-taint-exposure", detail })];
      assignFingerprints(l, { filePath: "c.ts", fileLevelIds: new Set() });
      return l[0].fingerprint;
    };
    expect(fp("imports lookupUser from src/helper.ts (taint path at line 4)"))
      .toBe(fp("imports lookupUser from src/helper.ts (taint path at line 19)"));
    expect(fp("imports lookupUser from src/helper.ts (taint path at line 4)"))
      .not.toBe(fp("imports other from src/other.ts (taint path at line 4)"));
  });

  it("is fill-only and idempotent: an existing fingerprint is never overwritten", () => {
    const l = [ind({ id: "x", line: 1, fingerprint: "keepme" }), ind({ id: "y", line: 2 })];
    assignFingerprints(l, { filePath: "f.ts" });
    expect(l[0].fingerprint).toBe("keepme");
    const y1 = l[1].fingerprint;
    assignFingerprints(l, { filePath: "f.ts" });
    expect(l[1].fingerprint).toBe(y1);
  });

  it("treats an unresolvable enclosing function ('unknown') the same as no resolver, and survives a throwing resolver", () => {
    const fp = (enclosingFunction?: (l: number) => string) => {
      const l = [ind({ id: "x", line: 1, detail: "d" })];
      assignFingerprints(l, { filePath: "f.ts", enclosingFunction });
      return l[0].fingerprint;
    };
    expect(fp(() => "unknown")).toBe(fp(undefined));
    expect(fp(() => { throw new Error("parser gone"); })).toBe(fp(undefined));
  });
});

describe("through the real scanner", () => {
  const scanOne = (path: string, content: string) =>
    runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] }).files[0];
  const sqli = (f: ReturnType<typeof scanOne>) => f.indicators.filter(i => i.id === "sql-injection" && i.confidence === 95);

  const HANDLER_A = `function handlerA(req, res) {
  const id = req.query.id;
  db.execute(id);
}`;
  const HANDLER_B = `function handlerB(req, res) {
  const id = req.query.id;
  db.execute(id);
}`;

  it("the same source->sink flow in two handlers of one file is two findings with two ids", () => {
    const f = scanOne("src/routes.ts", `${HANDLER_A}\n\n${HANDLER_B}\n`);
    const found = sqli(f);
    expect(found).toHaveLength(2);
    expect(found[0].fingerprint).not.toBe(found[1].fingerprint);
  });

  it("removing handlerA leaves handlerB's finding with the SAME id it had before", () => {
    const both = sqli(scanOne("src/routes.ts", `${HANDLER_A}\n\n${HANDLER_B}\n`));
    const idOfB = both.find(i => i.line! > 4)!.fingerprint;     // handlerB is the later one
    const alone = sqli(scanOne("src/routes.ts", `${HANDLER_B}\n`));
    expect(alone).toHaveLength(1);
    expect(alone[0].fingerprint).toBe(idOfB);
  });

  it("two identical sink calls inside one function get distinct ids, stable across scans", () => {
    const src = `function handler(req, res) {
  const id = req.query.id;
  db.execute(id);
  db.execute(id);
}`;
    const a = sqli(scanOne("src/one.ts", src));
    const b = sqli(scanOne("src/one.ts", src));
    expect(a.length).toBeGreaterThanOrEqual(2);
    expect(new Set(a.map(i => i.fingerprint)).size).toBe(a.length);
    expect(a.map(i => i.fingerprint)).toEqual(b.map(i => i.fingerprint));
  });

  it("stays stable when unrelated lines are added above the function", () => {
    const a = sqli(scanOne("src/routes.ts", HANDLER_A));
    const b = sqli(scanOne("src/routes.ts", `// header\n// more\nconst unrelated = 1;\n\n${HANDLER_A}`));
    expect(a[0].fingerprint).toBeDefined();
    expect(a[0].fingerprint).toBe(b[0].fingerprint);
  });

  it("EVERY indicator on a scanned file carries a fingerprint, including the AI signals that had none before", () => {
    const src = `${HANDLER_A}\n\n${HANDLER_B}\n\n` + `// Generated by ChatGPT\n`.repeat(3) +
      `export function computeTotalPriceWithDiscount(items, discountRate) {\n  const total = items.reduce((sum, item) => sum + item.price, 0);\n  return total * (1 - discountRate);\n}\n`.repeat(6);
    const f = scanOne("src/big.ts", src);
    expect(f.indicators.length).toBeGreaterThan(2);
    for (const i of f.indicators) {
      expect(i.fingerprint).toBeDefined();
      expect(i.fingerprint).toMatch(/^[0-9a-f]{16}$/);
    }
  });

  it("no two indicators in a file share a fingerprint", () => {
    const src = `${HANDLER_A}\n\n${HANDLER_B}\n\n` + `export function computeTotalPriceWithDiscount(items, discountRate) {\n  const total = items.reduce((sum, item) => sum + item.price, 0);\n  return total * (1 - discountRate);\n}\n`.repeat(6);
    const f = scanOne("src/big.ts", src);
    const fps = f.indicators.map(i => i.fingerprint);
    expect(new Set(fps).size).toBe(fps.length);
  });

  it("PR-level post-pass indicators (cross-file-taint-exposure) get identities too", () => {
    const helper = `export function lookupUser(db, req) {\n  const id = req.params.id;\n  const result = db.query(\`SELECT * FROM users WHERE id=\${id}\`);\n  return result;\n}`;
    const consumer = `import { lookupUser } from "./helper";\n\nexport async function handler(db, req) {\n  const user = lookupUser(db, req);\n  return user;\n}`;
    const r = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main",
      files: [{ path: "src/helper.ts", content: helper }, { path: "src/consumer.ts", content: consumer }] });
    const x = r.files.find(f => f.file_path === "src/consumer.ts")!.indicators.find(i => i.id === "cross-file-taint-exposure");
    expect(x).toBeDefined();
    expect(x!.fingerprint).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe("persistence projection", () => {
  it("keeps fingerprint/confidence/sourceExpr/sinkExpr (all four routes used to drop them) and only line-bearing indicators", () => {
    const stored = toStoredIndicators([
      ind({ id: "sql-injection", line: 3, fingerprint: "abcd", confidence: 95, sourceExpr: "id", sinkExpr: "db.execute", trace: [] }),
      ind({ id: "naming-consistency", severity: "info", fingerprint: "ffff" }),   // line-less aggregate signal
    ]);
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ id: "sql-injection", fingerprint: "abcd", confidence: 95, sourceExpr: "id", sinkExpr: "db.execute" });
    // An empty trace carries nothing to show, so it isn't stored.
    expect(stored[0].trace).toBeUndefined();
  });

  it("keeps the data-flow trace, supporting detectors and enclosing function the PR page renders inline", () => {
    const trace = [
      { file: "a.ts", line: 2, kind: "source" as const, label: "req.query.id", snippet: "req.query.id" },
      { file: "a.ts", line: 3, kind: "sink" as const, label: "db.execute", snippet: "db.execute(id)" },
    ];
    const [stored] = toStoredIndicators([
      ind({ id: "sql-injection", line: 3, trace, supportingDetectors: ["Named-taint SQL"], functionName: "getUser" }),
    ]);
    expect(stored.trace).toEqual(trace);
    expect(stored.supportingDetectors).toEqual(["Named-taint SQL"]);
    expect(stored.functionName).toBe("getUser");
  });

  it("tolerates a missing indicator list", () => {
    expect(toStoredIndicators(undefined)).toEqual([]);
  });
});
