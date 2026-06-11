/**
 * Sanity-checks that the larger, mixed human/AI-authored seed files
 * (src/lib/seedFileSamples.ts) produce realistic, partial scan results
 * when run through the real scanner engine — not 0% or 100% AI, with
 * security findings and AST/SSA output populated.
 */
import { runScan } from "@/lib/scanner";
import { attributeCode } from "@/lib/aiAttribution";
import { CUSTOMER_DATA_SYNC_PY, ORDER_EXPORT_CLIENT_TS } from "@/lib/seedFileSamples";

describe("seed file samples — mixed authorship", () => {
  const result = runScan({
    repo:       "acmecorp/data-platform",
    pr_number:  107,
    commit_sha: "d3e4f5a",
    branch:     "feat/customer-sync-v2",
    files: [
      { path: "src/pipelines/customer_data_sync.py",   content: CUSTOMER_DATA_SYNC_PY },
      { path: "src/connectors/order_export_client.ts", content: ORDER_EXPORT_CLIENT_TS },
    ],
  });

  it("produces a partial (mixed) AI percentage per file, not 0% or 100%", () => {
    for (const f of result.files) {
      expect(f.ai_percentage).toBeGreaterThan(0.10);
      expect(f.ai_percentage).toBeLessThan(0.90);
    }
  });

  it("attribution carries both AI and human evidence for each file", () => {
    const samples: Array<[string, string]> = [
      [CUSTOMER_DATA_SYNC_PY, "python"],
      [ORDER_EXPORT_CLIENT_TS, "typescript"],
    ];
    for (const [content, lang] of samples) {
      const attribution = attributeCode(content, lang);
      expect(attribution.breakdown.human).toBeGreaterThan(0);
      const aiMass = Object.entries(attribution.breakdown)
        .filter(([m]) => m !== "human" && m !== "unknown")
        .reduce((sum, [, p]) => sum + p, 0);
      expect(aiMass).toBeGreaterThan(0);
    }
  });

  it("flags the hardcoded credentials in both files", () => {
    const py = result.files.find(f => f.file_path.endsWith("customer_data_sync.py"))!;
    const ts = result.files.find(f => f.file_path.endsWith("order_export_client.ts"))!;
    expect(py.risk_indicators).toContain("hardcoded-secret");
    expect(ts.risk_indicators).toContain("hardcoded-secret");
  });

  it("flags the SQL injection in the Python sync pipeline", () => {
    const py = result.files.find(f => f.file_path.endsWith("customer_data_sync.py"))!;
    expect(py.risk_indicators.some(r => r.includes("sql-injection"))).toBe(true);
  });

  it("populates AST metrics and runs the SSA taint pass for both files", () => {
    for (const f of result.files) {
      expect(f.ast_metrics).not.toBeNull();
      expect(Array.isArray(f.ssa_taint_paths)).toBe(true);
    }
  });

  it("builds a semantic graph and ML score for the scan", () => {
    expect(result.semantic_graph).not.toBeNull();
    for (const f of result.files) {
      expect(f.ml_score).not.toBeNull();
    }
  });

  it("computes an overall scan AI percentage in the mixed range", () => {
    expect(result.total_ai_percentage).toBeGreaterThan(0.10);
    expect(result.total_ai_percentage).toBeLessThan(0.90);
  });
});
