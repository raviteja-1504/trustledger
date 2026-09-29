import { confidenceLevel } from "@/lib/confidence";
import { addedLines, markIntroduced } from "@/lib/prDiff";
import { buildTrustRecord, canonicalJson, signTrustRecord, verifyTrustRecord, TRUST_RECORD_SCHEMA, type TrustRecordInput } from "@/lib/trustRecord";
import { REACHABILITY_DESC, REACHABILITY_RANK } from "@/lib/depReachability";
import type { FileIndicator } from "@/types";

describe("confidence vocabulary", () => {
  it("traced flows, assumed sources, and pattern strength", () => {
    expect(confidenceLevel({ confidence: 95, sourceExpr: "req.query.id" })).toBe("confirmed");
    expect(confidenceLevel({ confidence: 70, sourceExpr: "id", sourceAssumed: true })).toBe("likely");
    expect(confidenceLevel({ confidence: 96 })).toBe("confirmed");
    expect(confidenceLevel({ confidence: 80 })).toBe("likely");
    expect(confidenceLevel({ confidence: 60 })).toBe("possible");
    expect(confidenceLevel({ confidence: 30 })).toBe("weak");
    expect(confidenceLevel({})).toBeNull();                               // AI signals carry none
  });
});

describe("introduced by this PR", () => {
  const patch = [
    "@@ -1,4 +1,5 @@",
    " import db from './db';",   // new line 1
    "-const q = 1;",
    "+const q = req.query.id;",   // 2 (added)
    "+const extra = 2;",          // 3 (added)
    " function f() {}",           // 4
    "@@ -20,2 +21,3 @@",
    " a();",                      // 21
    "+db.query('x' + q);",        // 22 (added)
    " b();",                      // 23
    "\\ No newline at end of file",
  ].join("\n");

  it("parses added new-side line numbers across hunks; added files are 'all'; no patch is unknown", () => {
    expect([...(addedLines({ filename: "a.ts", status: "modified", patch }) as Set<number>)].sort((a, b) => a - b)).toEqual([2, 3, 22]);
    expect(addedLines({ filename: "b.ts", status: "added" })).toBe("all");
    expect(addedLines({ filename: "c.ts", status: "modified" })).toBeNull();
  });

  it("a finding is introduced when its line, or any same-file step of its flow, was added", () => {
    const added = addedLines({ filename: "a.ts", status: "modified", patch });
    const inds: Array<{ line?: number; introduced?: boolean; trace?: Array<{ line?: number; file?: string }> }> = [
      { line: 22 },                                                      // sink on an added line
      { line: 30, trace: [{ line: 2 }, { line: 30 }] },                  // old sink, but the PR added its source
      { line: 30, trace: [{ line: 2, file: "other.ts" }, { line: 30 }] }, // added line is in ANOTHER file
      { line: 4 },                                                       // untouched line
      {},                                                                // file-level signal: left alone
    ];
    markIntroduced(inds, "a.ts", added);
    expect(inds.map(i => i.introduced)).toEqual([true, true, false, false, undefined]);
    const unknown = [{ line: 1 } as { line?: number; introduced?: boolean }];
    markIntroduced(unknown, "c.ts", null);
    expect(unknown[0].introduced).toBeUndefined();
  });
});

describe("Trust Record", () => {
  const sqli: FileIndicator = { id: "sql-injection", label: "SQL Injection", severity: "critical", line: 3, cwe: "CWE-89", confidence: 95, sourceExpr: "req.query.id", fingerprint: "fp1", introduced: true };
  const redirect: FileIndicator = { id: "open-redirect", label: "Open Redirect", severity: "medium", line: 4, cwe: "CWE-601", confidence: 95, sourceExpr: "req.query.next", fingerprint: "fp2", introduced: false };
  const aiSignal: FileIndicator = { id: "ai-style-uniformity", label: "Uniform style", severity: "low" };
  const input: TrustRecordInput = {
    org_name: "Acme",
    scan: { id: "s1", repo: "acme/shop", pr_number: 7, commit_sha: "abc1234def", created_at: "2026-09-30T10:00:00Z", overall_risk: "CRITICAL", total_ai_percentage: 41.26, triggered_by: "webhook", duration_ms: 3200 },
    engine_version: "6.5",
    health: { status: "complete", engine_version: "6.5", gap_counts: {}, engines_unavailable: [], gaps: [] },
    files: [{ file_path: "src/r.ts", risk_score: "CRITICAL", ai_percentage: 41.26, indicators: [redirect, aiSignal, sqli] }],
    attestations: [{ file_path: "src/r.ts", reviewer_email: "lead@acme.dev", reviewer_github: "lead", payload_hash: "h", created_at: "2026-09-30T11:00:00Z" }],
    triage: new Map([["fp2", { status: "accepted", reason: "gateway allow-list", expires_at: null, set_by_email: "lead@acme.dev", set_at: "2026-09-30T09:00:00Z" }]]),
    open_blocking_violations: 1,
    generated_at: "2026-09-30T12:00:00Z",
  };

  it("security findings only, severity-ordered, with confidence, introduced and decision; verdict and summary", () => {
    const r = buildTrustRecord(input);
    expect(r.schema).toBe(TRUST_RECORD_SCHEMA);
    expect(r.findings.map(f => f.rule)).toEqual(["sql-injection", "open-redirect"]);   // AI signal excluded
    expect(r.findings[0]).toMatchObject({ confidence: "confirmed", analysis: "data-flow", introduced_by_pr: true, decision: null });
    expect(r.findings[1].decision).toMatchObject({ status: "accepted", reason: "gateway allow-list" });
    expect(r.verdict).toEqual({ overall_risk: "CRITICAL", ai_share_percent: 41.3, merge_gate: "blocked", open_blocking_violations: 1 });
    expect(r.summary).toMatchObject({ findings: 2, critical: 1, introduced_by_pr: 1, accepted_or_false_positive: 1, files_attested: 1 });
  });

  it("an expired decision is not reported as a decision", () => {
    const expired = { ...input, triage: new Map([["fp2", { ...input.triage.get("fp2")!, expires_at: "2026-09-01T00:00:00Z" }]]) };
    expect(buildTrustRecord(expired).findings[1].decision).toBeNull();
  });

  it("signature verifies, is independent of key order, and detects any change", () => {
    const record = buildTrustRecord(input);
    const doc = { record, signature: { algorithm: "HMAC-SHA256", value: signTrustRecord(record, "k") } };
    expect(verifyTrustRecord(doc, "k")).toBe(true);
    expect(verifyTrustRecord(doc, "other-key")).toBe(false);
    const reverseKeys = (v: unknown): unknown => Array.isArray(v) ? v.map(reverseKeys)
      : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).reverse().map(([k, x]) => [k, reverseKeys(x)])) : v;
    const reordered = reverseKeys(record);
    expect(JSON.stringify(reordered)).not.toBe(JSON.stringify(record));
    expect(canonicalJson(reordered)).toBe(canonicalJson(record));
    const tampered = { ...doc, record: { ...record, verdict: { ...record.verdict, merge_gate: "clear" as const } } };
    expect(verifyTrustRecord(tampered, "k")).toBe(false);
    expect(verifyTrustRecord({ ...doc, signature: { algorithm: "none", value: doc.signature.value } }, "k")).toBe(false);
  });
});

describe("dependency verdicts", () => {
  it("every verdict has an explanation", () => {
    for (const t of Object.keys(REACHABILITY_RANK)) expect((REACHABILITY_DESC as Record<string, string>)[t]?.length).toBeGreaterThan(20);
  });
});
