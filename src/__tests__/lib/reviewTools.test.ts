import { runScan, analyzeFile } from "@/lib/scanner";
import { toStoredIndicators } from "@/lib/indicatorStorage";
import { buildTrustRecord, signTrustRecord, signingKeyId, checkTrustRecord, TRUST_RECORD_SCHEMA, type TrustRecordInput } from "@/lib/trustRecord";
import { buildPrSecuritySummary } from "@/lib/prSecuritySummary";
import { buildRuleCatalog } from "@/lib/ruleCatalog";
import { DATA_FLOW_LANGUAGES } from "@/lib/ruleLanguages";
import { FINDING_CATALOG } from "@/lib/findingCatalog";
import { securityRegression, regressionMarkdown } from "@/lib/securityRegression";
import { attachTriage, type TriageDecision } from "@/lib/findingLifecycle";
import { buildSarifReport } from "@/lib/sarif";
import { confidenceLevel } from "@/lib/confidence";
import { markIntroduced, addedLines } from "@/lib/prDiff";
import type { ScanResult, FileIndicator } from "@/types";

const NOW = new Date("2026-09-30T12:00:00Z");
const accepted = (over: Partial<TriageDecision> = {}): TriageDecision =>
  ({ status: "accepted", reason: "validated upstream", expires_at: null, set_by_email: "lead@acme.dev", set_at: "2026-09-29T00:00:00Z", ...over });

// A real scan: an introduced SQL injection and a pre-existing open redirect in one file.
const SRC = `export function register(app) {\n  app.get("/o", (req, res) => db.query("SELECT * FROM o WHERE id = " + req.query.id));\n  app.get("/go", (req, res) => res.redirect(req.query.next));\n}\n`;
function scanFiles() {
  const r = runScan({ repo: "acme/shop", pr_number: 7, commit_sha: "abcdef1234", files: [{ path: "src/routes.ts", content: SRC }] });
  const added = addedLines({ filename: "src/routes.ts", status: "modified", patch: "@@ -1,3 +1,4 @@\n export function register(app) {\n+  app.get(\"/o\", (req, res) => db.query(\"SELECT * FROM o WHERE id = \" + req.query.id));\n   app.get(\"/go\", (req, res) => res.redirect(req.query.next));\n }" });
  for (const f of r.files) markIntroduced(f.indicators, f.file_path, added);
  return { r, files: r.files.map(f => ({ ...f, indicators: toStoredIndicators(f.indicators) })) };
}

describe("Trust Record verification", () => {
  const input: TrustRecordInput = {
    org_name: "Acme", engine_version: "6.5", health: null, open_blocking_violations: 0, generated_at: NOW.toISOString(), triage: new Map(),
    scan: { id: "s1", repo: "acme/shop", pr_number: 7, commit_sha: "abcdef1234", created_at: NOW.toISOString(), overall_risk: "HIGH", total_ai_percentage: 10, triggered_by: "webhook", duration_ms: 10 },
    files: [{ file_path: "a.ts", risk_score: "HIGH", ai_percentage: 10, indicators: [] }], attestations: [],
  };
  const record = buildTrustRecord(input);
  const signed = (key: string, withKeyId = true) => ({ record, signature: { algorithm: "HMAC-SHA256", value: signTrustRecord(record, key), ...(withKeyId ? { key_id: signingKeyId(key) } : {}) } });

  it("valid / tampered / unknown key / unsigned / malformed / not configured", () => {
    expect(checkTrustRecord(signed("k1"), "k1")).toBe("valid");
    expect(checkTrustRecord({ ...signed("k1"), record: { ...record, verdict: { ...record.verdict, merge_gate: "blocked" } } }, "k1")).toBe("tampered");
    expect(checkTrustRecord(signed("k2"), "k1")).toBe("unknown_key");                  // key id tells them apart
    expect(checkTrustRecord(signed("k2", false), "k1")).toBe("tampered");              // pre-key-id record: can't tell, fails closed
    expect(checkTrustRecord({ record, signature: null }, "k1")).toBe("unsigned");
    expect(checkTrustRecord({ record: { schema: "something-else" } }, "k1")).toBe("malformed");
    expect(checkTrustRecord("not an object", "k1")).toBe("malformed");
    expect(checkTrustRecord(signed("k1"), undefined)).toBe("not_configured");
    expect(checkTrustRecord({ record, signature: { algorithm: "HMAC-SHA256", value: "zz", key_id: signingKeyId("k1") } }, "k1")).toBe("tampered");
  });
  it("the key id identifies a key without revealing it", () => {
    expect(signingKeyId("k1")).toMatch(/^[0-9a-f]{16}$/);
    expect(signingKeyId("k1")).not.toBe(signingKeyId("k2"));
    expect(signingKeyId("k1")).not.toContain("k1");
    expect(record.schema).toBe(TRUST_RECORD_SCHEMA);
  });
});

describe("export consistency: dashboard, SARIF, Trust Record and the PR summary agree", () => {
  it("same findings, severities, confidence, introduced flags and suppression state everywhere", () => {
    const { files } = scanFiles();
    const redirect = files[0].indicators.find(i => i.id === "open-redirect")!;
    const triage = new Map([[redirect.fingerprint!, accepted()]]);
    const withTriage = attachTriage(files, triage);

    // Dashboard: the security findings as the PR page shows them.
    const dash = withTriage.flatMap(f => f.indicators.filter(i => i.cwe).map(i => ({
      key: `${i.id}@${f.file_path}:${i.line}`, severity: i.severity, introduced: i.introduced ?? null,
      confidence: confidenceLevel({ confidence: i.confidence, sourceExpr: i.sourceExpr, sourceAssumed: i.flow?.source.assumed }),
      suppressed: !!i.triage,
    }))).sort((a, b) => a.key.localeCompare(b.key));
    expect(dash.map(d => d.key)).toEqual(["open-redirect@src/routes.ts:3", "sql-injection@src/routes.ts:2"]);

    // SARIF
    const sarif = buildSarifReport(withTriage) as { runs: Array<{ results: Array<{ ruleId: string; locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }>; properties: Record<string, unknown>; suppressions?: unknown[] }> }> };
    const sar = sarif.runs[0].results.filter(r => dash.some(d => d.key.startsWith(`${r.ruleId}@`))).map(r => ({
      key: `${r.ruleId}@${r.locations[0].physicalLocation.artifactLocation.uri}:${r.locations[0].physicalLocation.region.startLine}`,
      introduced: (r.properties["trustledger/introducedByPR"] as boolean | undefined) ?? null,
      confidence: r.properties["trustledger/confidenceLevel"] ?? null,
      suppressed: !!r.suppressions?.length,
      score: r.properties["security-severity"],
    })).sort((a, b) => a.key.localeCompare(b.key));

    // Trust Record
    const rec = buildTrustRecord({
      org_name: null, engine_version: "6.5", health: null, open_blocking_violations: 0, generated_at: NOW.toISOString(), triage,
      scan: { id: "s", repo: "acme/shop", pr_number: 7, commit_sha: "abcdef1234", created_at: NOW.toISOString(), overall_risk: "CRITICAL", total_ai_percentage: 0, triggered_by: null, duration_ms: null },
      files: files.map(f => ({ file_path: f.file_path, risk_score: f.risk_score, ai_percentage: f.ai_percentage, indicators: f.indicators })), attestations: [],
    });
    const tr = rec.findings.map(f => ({ key: `${f.rule}@${f.file}:${f.line}`, severity: f.severity, introduced: f.introduced_by_pr, confidence: f.confidence, suppressed: !!f.decision }))
      .sort((a, b) => a.key.localeCompare(b.key));

    expect(sar.map(s => ({ key: s.key, introduced: s.introduced, confidence: s.confidence, suppressed: s.suppressed })))
      .toEqual(dash.map(d => ({ key: d.key, introduced: d.introduced, confidence: d.confidence, suppressed: d.suppressed })));
    expect(tr).toEqual(dash);
    expect(sar.find(s => s.key.startsWith("sql-injection"))!.score).toBe("9.0");            // critical in every view

    // PR summary: the same rows, statuses and suppression reason.
    const summary = buildPrSecuritySummary({ scan_id: "s", repo: "acme/shop", pr_number: 7, commit_sha: "abcdef1234", overall_risk: "CRITICAL", total_ai_percentage: 0, timestamp: "", files: withTriage as unknown as ScanResult["files"] });
    expect(summary).toContain("`src/routes.ts:2` | Confirmed | introduced");
    expect(summary).toContain("`src/routes.ts:3` | Confirmed | pre-existing · “validated upstream”");
  });
});

describe("PR security summary", () => {
  it("delta, lifecycle, coverage, rows and link", () => {
    const { files } = scanFiles();
    const scan = {
      scan_id: "s", repo: "acme/shop", pr_number: 7, commit_sha: "abcdef1234", overall_risk: "CRITICAL", total_ai_percentage: 0, timestamp: "",
      files: files as unknown as ScanResult["files"],
      health: { status: "degraded", engine_version: "6.5", gap_counts: { "engine-unavailable": 1 }, engines_unavailable: ["python"], gaps: [] },
    } as ScanResult;
    const md = buildPrSecuritySummary(scan, { reviewUrl: "https://app/pr/s", lifecycle: { new: 1, existing: 1, reopened: 0, accepted: 0, false_positive: 0, fixed: 2 } });
    expect(md.split("\n")[0]).toBe("### TrustLedger security summary — PR #7 (`abcdef1`)");
    expect(md).toContain("**Introduced by this PR:** 1 (1 critical) · 1 already in the files it touches");
    expect(md).toContain("**Since the last push:** 1 new · 2 fixed");
    expect(md).toContain("**Coverage:** ⚠️ incomplete");
    expect(md).toContain("| Critical | SQL Injection (CWE-89) | `src/routes.ts:2` |");
    expect(md.trim().endsWith("Full review: https://app/pr/s")).toBe(true);
    expect(buildPrSecuritySummary({ ...scan, files: [], health: null })).toContain("No security findings.");
  });
});

describe("rule catalog", () => {
  const rules = buildRuleCatalog();
  const byId = new Map(rules.map(r => [r.id, r]));
  it("covers every catalogued rule and every data-flow engine rule, once", () => {
    for (const id of Object.keys(FINDING_CATALOG)) expect(byId.has(id)).toBe(true);
    for (const l of DATA_FLOW_LANGUAGES) for (const id of l.ids) expect(byId.has(id)).toBe(true);
    expect(new Set(rules.map(r => r.id)).size).toBe(rules.length);
  });
  it("languages, severity, detection and remediation come from the engines and rules themselves", () => {
    expect(byId.get("sql-injection")).toMatchObject({ detection: "data-flow", severity: "critical", cwe: "CWE-89" });
    expect(byId.get("sql-injection")!.appliesTo).toEqual(["JavaScript/TypeScript", "Python", "Java", "Go", "C#", "PHP"]);
    expect(byId.get("xxe")!.appliesTo).toEqual(["Python"]);
    expect(byId.get("prototype-pollution")!.appliesTo).toEqual(["JavaScript/TypeScript"]);
    expect(byId.get("cloud-open-admin-port")).toMatchObject({ detection: "configuration", severity: "high" });
    expect(byId.get("cloud-open-admin-port")!.appliesTo).toContain("Terraform");
    expect(byId.get("container-runs-as-root")!.appliesTo).toEqual(["Dockerfile"]);
    expect(byId.get("hardcoded-secret")!.detection).toBe("pattern");
    expect(byId.get("sql-injection")!.fix?.description.length).toBeGreaterThan(10);
  });
});

describe("security regression after every scan", () => {
  const f = (path: string, inds: Array<Partial<FileIndicator> & { id: string; fingerprint: string }>) =>
    ({ file_path: path, indicators: inds.map(i => ({ label: i.id, severity: "high", cwe: "CWE-89", line: 1, ...i })) });
  it("new (by severity) vs fixed vs already-decided; no previous scan means no section", () => {
    const previous = [f("a.ts", [{ id: "sql-injection", fingerprint: "old" }, { id: "xss", fingerprint: "gone", cwe: "CWE-79" }]), f("untouched.ts", [{ id: "xss", fingerprint: "u", cwe: "CWE-79" }])];
    const current = [f("a.ts", [
      { id: "sql-injection", fingerprint: "old" },
      { id: "sql-injection", fingerprint: "n1", severity: "critical", line: 9 },
      { id: "open-redirect", fingerprint: "n2", severity: "medium", cwe: "CWE-601" },
      { id: "xss", fingerprint: "n3", cwe: "CWE-79" },
      { id: "ai-style-uniformity", fingerprint: "ai", cwe: undefined },
    ])];
    const r = securityRegression(current, previous, new Map([["n3", accepted()]]), NOW);
    expect(r.added.map(a => a.id)).toEqual(["sql-injection", "open-redirect"]);           // most severe first; AI signal ignored
    expect(r.addedSuppressed).toBe(1);
    expect(r.fixed.map(x => x.id)).toEqual(["xss"]);                                     // "u" is in a file this scan didn't look at
    const md = regressionMarkdown(r);
    expect(md).toContain("⚠️ **2 new security findings** (1 critical, 1 medium):");
    expect(md).toContain("- CRITICAL · SQL Injection — `a.ts:9`");
    expect(md).toContain("1 more new finding is already accepted or marked false positive.");
    expect(md).toContain("✅ **1 fixed** since the last push.");
    expect(regressionMarkdown(securityRegression(current, null, new Map()))).toBe("");
    expect(regressionMarkdown(securityRegression(previous, previous, new Map()))).toContain("No change in security findings.");
  });
});

describe("SARIF suppressions from triage", () => {
  it("an active decision is a SARIF suppression with its reason; an expired one is not", () => {
    const { files } = scanFiles();
    const fp = files[0].indicators.find(i => i.id === "sql-injection")!.fingerprint!;
    const run = (d: TriageDecision) => (buildSarifReport(attachTriage(files, new Map([[fp, d]]))) as { runs: Array<{ results: Array<{ ruleId: string; suppressions?: Array<{ justification: string }> }> }> })
      .runs[0].results.find(r => r.ruleId === "sql-injection")!;
    expect(run(accepted({ status: "false_positive" })).suppressions![0].justification).toBe("False positive: validated upstream (lead@acme.dev)");
    expect(run(accepted({ expires_at: "2020-01-01T00:00:00Z" })).suppressions).toBeUndefined();
  });
});

describe("scanner performance on minified code", () => {
  it("a 60,000-character line analyzes quickly, and the anchored SQL checks still match what they did", () => {
    const longLine = `var a=${"x+".repeat(30_000)}1;`;
    const t0 = Date.now();
    analyzeFile("static/app.min.js", `${longLine}\n${longLine}\n`);
    expect(Date.now() - t0).toBeLessThan(5000);                     // was minutes before the anchoring fix
    const sql = (line: string) => analyzeFile("src/q.ts", `${line}\n`).indicators.some(i => i.id === "sql-injection");
    expect(sql(`const q = "SELECT * FROM users WHERE id = " + userId;`)).toBe(true);
    // Both halves anywhere on the line, in either order -- what the anchored lookahead pattern checks.
    expect(sql(`log("n=" + name); db.exec("DELETE FROM sessions");`)).toBe(true);
    expect(sql(`const q = "SELECT * FROM users";`)).toBe(false);
  });
});
