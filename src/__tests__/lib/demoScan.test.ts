/**
 * @jest-environment node
 *
 * The public live demo runs the real scanner (lib/demoScan.ts). Every sample's vulnerable version must produce its
 * advertised finding, with a source-to-sink trace, and block the merge; every fixed version must not. Also pins the
 * sandbox: only the sample's own files, a size cap, and an unknown sample refused.
 */
import { scanDemo, type DemoScanResponse } from "@/lib/demoScan";
import { DEMO_LIMITS, DEMO_SAMPLES } from "@/lib/demoSamples";

jest.setTimeout(120000);

const ok = (r: Awaited<ReturnType<typeof scanDemo>>): DemoScanResponse => {
  if ("error" in r) throw new Error(`demo scan failed: ${r.error}`);
  return r;
};
const findingsOf = (r: DemoScanResponse, rule: string) => r.files.flatMap(f => f.findings.filter(x => x.id === rule));

describe.each(DEMO_SAMPLES.map(s => [s.id, s] as const))("demo sample %s", (_id, sample) => {
  it(`vulnerable: reports ${sample.expectRule} with a trace and blocks the merge`, async () => {
    const r = ok(await scanDemo({ sampleId: sample.id, variant: "vulnerable" }));
    const hits = findingsOf(r, sample.expectRule);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.some(h => h.sourceExpr && h.trace.length > 0)).toBe(true);
    expect(r.mergeBlocked).toBe(true);
    for (const f of r.files) expect(f.contentHash).toMatch(/^[0-9a-f]{16,}$/);
  });

  it(`fixed: no ${sample.expectRule}`, async () => {
    const r = ok(await scanDemo({ sampleId: sample.id, variant: "fixed" }));
    expect(findingsOf(r, sample.expectRule)).toEqual([]);
  });
});

describe("the SQL injection sample crosses files", () => {
  it("its trace visits both the route and the repository", async () => {
    const r = ok(await scanDemo({ sampleId: "sqli-ts", variant: "vulnerable" }));
    const files = new Set(findingsOf(r, "sql-injection").flatMap(h => h.trace.map(t => t.file)));
    expect([...files].some(f => f.includes("routes/users.ts"))).toBe(true);
    expect([...files].some(f => f.includes("db/users.ts"))).toBe(true);
  });
});

describe("a visitor's edit", () => {
  const sample = DEMO_SAMPLES[0];
  it("is scanned when it only uses the sample's own paths; editing the code changes the content hash", async () => {
    const base = ok(await scanDemo({ sampleId: sample.id, variant: "vulnerable" }));
    const edited = ok(await scanDemo({ sampleId: sample.id, variant: "custom", files: sample.files.map(f => ({ path: f.path, content: f.vulnerable + "\n// reviewed\n" })) }));
    expect(edited.files.map(f => f.contentHash)).not.toEqual(base.files.map(f => f.contentHash));
  });
  it("is refused for another path, an oversized file, or an unknown sample", async () => {
    expect(await scanDemo({ sampleId: sample.id, variant: "custom", files: [{ path: "src/other.ts", content: "x" }] })).toEqual({ error: "files_must_be_the_samples_own", status: 400 });
    expect(await scanDemo({ sampleId: sample.id, variant: "custom", files: [{ path: sample.files[0].path, content: "a".repeat(DEMO_LIMITS.maxFileBytes + 1) }] })).toEqual({ error: "file_too_large", status: 413 });
    expect(await scanDemo({ sampleId: "nope", variant: "vulnerable" })).toEqual({ error: "unknown_sample", status: 404 });
  });
});
