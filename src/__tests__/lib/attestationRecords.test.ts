/**
 * Attestation records explained (lib/attestationRecords.ts): what, why, how and when for each sign-off.
 */
import { buildAttestationRecords, independenceOf } from "@/lib/attestationRecords";

const att = (id: string, scan: string, path: string, at: string, o: Record<string, unknown> = {}) =>
  ({ id, scan_id: scan, file_path: path, risk_score: "HIGH", reviewer_email: "rev@x", reviewer_github: "rev", payload_hash: `hash-${id}`, created_at: at, ...o });
const scans = [
  { id: "s1", repo_full_name: "o/api", pr_number: 7, commit_sha: "abc1234567", branch: "feat", pr_author: "ada", created_at: "2026-10-01T00:00:00Z" },
  { id: "s2", repo_full_name: "o/web", pr_number: null, commit_sha: null, branch: null, pr_author: null, created_at: "2026-10-02T00:00:00Z" },
];
const files = [{ scan_id: "s1", file_path: "pay.ts", risk_indicators: ["sql-injection", 5, "eval-exec"], ai_percentage: 0.7 }];

describe("buildAttestationRecords", () => {
  const { records, summary } = buildAttestationRecords({
    attestations: [
      att("a1", "s1", "pay.ts", "2026-10-01T06:00:00Z", { risk_score: "CRITICAL" }),
      att("a2", "s1", "pay.ts", "2026-10-03T00:00:00Z", { reviewer_email: "two@x", reviewer_github: "ADA" }),   // the author, second sign-off
      att("a3", "s2", "web.ts", "2026-10-02T02:00:00Z", { reviewer_github: null }),
      att("a4", "gone", "x.ts", "2026-10-04T00:00:00Z"),
    ],
    scans, files,
  });

  it("newest first, each with what, why and how", () => {
    expect(records.map(r => r.id)).toEqual(["a4", "a2", "a3", "a1"]);
    const a1 = records.find(r => r.id === "a1")!;
    expect(a1).toMatchObject({
      repo: "o/api", pr_number: 7, commit_sha: "abc1234567", branch: "feat", scanned_at: "2026-10-01T00:00:00Z",
      file_path: "pay.ts", risk_score: "CRITICAL", findings: ["sql-injection", "eval-exec"], ai_percentage: 0.7,
      reviewer_email: "rev@x", pr_author: "ada", independence: "independent", hours_to_signoff: 6, payload_hash: "hash-a1", repeat: false,
    });
    expect(records.find(r => r.id === "a2")).toMatchObject({ independence: "self", repeat: true, hours_to_signoff: 48 });
    expect(records.find(r => r.id === "a3")).toMatchObject({ independence: "unknown", pr_number: 0, findings: [] });
    expect(records.find(r => r.id === "a4")).toMatchObject({ repo: "unknown", scanned_at: null, hours_to_signoff: null });
  });

  it("summary: period edges, files once, repos, reviewers, independence, median of first sign-offs", () => {
    expect(summary).toEqual({
      records: 4, files: 3, repos: ["o/api", "o/web", "unknown"], reviewers: ["rev@x", "two@x"],
      independent: 1, self: 1, unknown: 2,   // a3: no reviewer login; a4: its scan is gone, so no PR author
      first: "2026-10-01T06:00:00Z", last: "2026-10-04T00:00:00Z", median_hours: 4,
      by_risk: { CRITICAL: 1, HIGH: 3 },
    });
  });

  it("a sign-off timestamped before its scan (clock skew) counts as 0 hours, never negative", () => {
    const { records } = buildAttestationRecords({ attestations: [att("z", "s1", "pay.ts", "2026-09-30T23:00:00Z")], scans, files });
    expect(records[0].hours_to_signoff).toBe(0);
  });

  it("empty input → empty summary", () => {
    const e = buildAttestationRecords({ attestations: [], scans: [], files: [] }).summary;
    expect(e).toMatchObject({ records: 0, files: 0, first: null, last: null, median_hours: null });
  });
});

describe("independenceOf", () => {
  it("compares GitHub logins case-insensitively; missing either → unknown", () => {
    expect(independenceOf("Ada ", "ada")).toBe("self");
    expect(independenceOf("bob", "ada")).toBe("independent");
    expect(independenceOf(null, "ada")).toBe("unknown");
    expect(independenceOf("bob", "")).toBe("unknown");
  });
});
