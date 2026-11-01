/**
 * @jest-environment node
 *
 * The change-management register (lib/changeRegister.ts): every merged pull request with the evidence an auditor
 * checks -- an approval before the merge by someone other than the author, a TrustLedger scan, sign-offs on
 * HIGH/CRITICAL files before the merge -- and the exceptions where it is missing; a reproducible sample; a CSV whose
 * rows carry their own hash; an incomplete population stated.
 */
import crypto from "crypto";
import { buildRegister, drawSample, registerToCsv, pullKey, type MergedPull, type PullReview, type RegisterInput } from "@/lib/changeRegister";
import { canonicalJson } from "@/lib/trustRecord";

const P = (number: number, over: Partial<MergedPull> = {}): MergedPull => ({
  repo: "acme/api", number, title: `PR ${number}`, author: "alice", merged_at: `2026-10-${String(10 + number).padStart(2, "0")}T12:00:00Z`,
  merged_by: "carol", head_sha: `sha${number}`, url: `https://github.com/acme/api/pull/${number}`, ...over,
});
const approve = (reviewer: string, at: string, commit: string): PullReview => ({ reviewer, state: "APPROVED", submitted_at: at, commit_id: commit });

function input(over: Partial<RegisterInput> = {}): RegisterInput {
  return {
    period_start: "2026-10-01T00:00:00Z", period_end: "2026-10-31T23:59:59Z",
    pulls: [P(1)],
    reviews: new Map([[pullKey("acme/api", 1), [approve("bob", "2026-10-11T10:00:00Z", "sha1")]]]),
    scans: [{ scan_id: "s1", repo: "acme/api", pr_number: 1, commit_sha: "sha1", created_at: "2026-10-11T09:00:00Z", overall_risk: "LOW" }],
    riskyFiles: [], signoffs: [],
    coverage: [{ repo: "acme/api", read: true, pulls: 1 }],
    ...over,
  };
}
const row = (over: Partial<RegisterInput> = {}) => buildRegister(input(over)).rows[0];

describe("register rows", () => {
  it("a pull request approved by someone else on the merged commit and scanned before the merge has no exceptions", () => {
    const r = row();
    expect(r.exceptions).toEqual([]);
    expect(r.approvals).toEqual([{ reviewer: "bob", at: "2026-10-11T10:00:00Z", on_merged_commit: true }]);
    expect(r.scan).toEqual({ scan_id: "s1", at: "2026-10-11T09:00:00Z", overall_risk: "LOW" });
  });

  it("no approval at all", () => {
    expect(row({ reviews: new Map() }).exceptions).toContain("no_approval");
  });

  it("an approval given only after the merge is not an approval before it", () => {
    const r = row({ reviews: new Map([[pullKey("acme/api", 1), [approve("bob", "2026-10-12T10:00:00Z", "sha1")]]]) });
    expect(r.exceptions).toContain("approved_after_merge");
    expect(r.exceptions).not.toContain("no_approval");
  });

  it("the author's own approval doesn't count (any case of their login)", () => {
    expect(row({ reviews: new Map([[pullKey("acme/api", 1), [approve("Alice", "2026-10-11T10:00:00Z", "sha1")]]]) }).exceptions).toContain("no_approval");
  });

  it("comments and change requests are not approvals", () => {
    const reviews = new Map([[pullKey("acme/api", 1), [
      { reviewer: "bob", state: "COMMENTED", submitted_at: "2026-10-11T10:00:00Z", commit_id: "sha1" },
      { reviewer: "dan", state: "CHANGES_REQUESTED", submitted_at: "2026-10-11T10:30:00Z", commit_id: "sha1" },
    ]]]);
    expect(row({ reviews }).exceptions).toContain("no_approval");
  });

  it("an approval on an earlier commit is an observation (stale), not missing", () => {
    const r = row({ reviews: new Map([[pullKey("acme/api", 1), [approve("bob", "2026-10-11T10:00:00Z", "old-sha")]]]) });
    expect(r.exceptions).toEqual(["stale_approval"]);
  });

  it("no TrustLedger scan before the merge (a scan after it doesn't count)", () => {
    expect(row({ scans: [] }).exceptions).toContain("not_scanned");
    expect(row({ scans: [{ scan_id: "late", repo: "acme/api", pr_number: 1, commit_sha: "sha1", created_at: "2026-10-12T09:00:00Z", overall_risk: "LOW" }] }).exceptions).toContain("not_scanned");
  });

  it("uses the last scan before the merge, and its HIGH/CRITICAL files must be signed off before the merge by someone else", () => {
    const scans = [
      { scan_id: "s0", repo: "acme/api", pr_number: 1, commit_sha: "a", created_at: "2026-10-10T09:00:00Z", overall_risk: "CRITICAL" },
      { scan_id: "s1", repo: "acme/api", pr_number: 1, commit_sha: "sha1", created_at: "2026-10-11T09:00:00Z", overall_risk: "HIGH" },
    ];
    const riskyFiles = [
      { scan_id: "s0", file_path: "old.ts", risk_score: "CRITICAL" },   // superseded scan: not counted
      { scan_id: "s1", file_path: "pay.ts", risk_score: "HIGH" },
      { scan_id: "s1", file_path: "auth.ts", risk_score: "CRITICAL" },
      { scan_id: "s1", file_path: "util.ts", risk_score: "MEDIUM" },     // not high-risk
    ];
    const signoffs = [
      { scan_id: "s1", file_path: "pay.ts", reviewer_github: "bob", created_at: "2026-10-11T11:00:00Z" },
      { scan_id: "s1", file_path: "auth.ts", reviewer_github: "alice", created_at: "2026-10-11T11:00:00Z" },  // the author
    ];
    const r = row({ scans, riskyFiles, signoffs });
    expect(r.scan?.scan_id).toBe("s1");
    expect([r.high_risk_files, r.high_risk_signed_off]).toEqual([2, 1]);
    expect(r.exceptions).toContain("unsigned_high_risk");
    const allSigned = row({ scans, riskyFiles, signoffs: [...signoffs, { scan_id: "s1", file_path: "auth.ts", reviewer_github: "bob", created_at: "2026-10-11T11:30:00Z" }] });
    expect(allSigned.exceptions).not.toContain("unsigned_high_risk");
    const signedLate = row({ scans, riskyFiles, signoffs: [{ scan_id: "s1", file_path: "pay.ts", reviewer_github: "bob", created_at: "2026-10-13T00:00:00Z" }, signoffs[1]] });
    expect(signedLate.high_risk_signed_off).toBe(0);
  });

  it("each row carries the SHA-256 of its own canonical JSON", () => {
    const r = row();
    const { row_sha256, ...rest } = r;
    expect(row_sha256).toBe(crypto.createHash("sha256").update(canonicalJson(rest)).digest("hex"));
  });
});

describe("register", () => {
  it("lists only pull requests merged in the period, oldest first, with a summary", () => {
    const reg = buildRegister(input({
      pulls: [P(3), P(1), P(2, { merged_at: "2026-09-30T23:00:00Z" })],
      reviews: new Map([[pullKey("acme/api", 1), [approve("bob", "2026-10-11T10:00:00Z", "sha1")]]]),
    }));
    expect(reg.rows.map(r => r.number)).toEqual([1, 3]);
    expect(reg.summary).toMatchObject({ merged: 2, approved_before_merge: 1, scanned: 1, with_exceptions: 1 });
    expect(reg.summary.exceptions.no_approval).toBe(1);
  });

  it("a repository that couldn't be read makes the population incomplete, and says so", () => {
    const reg = buildRegister(input({ coverage: [{ repo: "acme/api", read: true, pulls: 1 }, { repo: "acme/web", read: false, pulls: 0, reason: "GitHub App has no access" }] }));
    expect(reg.complete).toBe(false);
    expect(buildRegister(input({ coverage: [{ repo: "acme/api", read: true, pulls: 500, truncated: true }] })).complete).toBe(false);
    expect(buildRegister(input()).complete).toBe(true);
  });
});

describe("auditor sample", () => {
  const rows = buildRegister(input({ pulls: Array.from({ length: 19 }, (_, i) => P(i + 1)) })).rows;

  it("is reproducible from its seed, and a different seed draws differently", () => {
    const a = drawSample(rows, 5, "seed-1").map(r => r.number);
    expect(drawSample(rows, 5, "seed-1").map(r => r.number)).toEqual(a);
    expect(drawSample(rows, 5, "seed-2").map(r => r.number)).not.toEqual(a);
  });

  it("draws distinct rows, in merge order, and the whole population when it is smaller than the sample", () => {
    const s = drawSample(rows, 7, "x").map(r => r.number);
    expect(new Set(s).size).toBe(7);
    expect([...s].sort((a, b) => a - b)).toEqual(s);
    expect(drawSample(rows, 100, "x")).toHaveLength(19);
    expect(drawSample(rows, 0, "x")).toEqual([]);
  });

  it("matches the documented algorithm (FNV-1a of the seed's UTF-8 bytes → mulberry32 → partial Fisher–Yates) for any seed", () => {
    // an independent implementation, with Node's own UTF-8 encoder: what an auditor would write to re-draw a sample
    function reference(n: number, size: number, seed: string): number[] {
      let a = [...Buffer.from(seed, "utf8")].reduce((h, b) => Math.imul(h ^ b, 0x01000193) >>> 0, 0x811c9dc5);
      const rand = () => {
        a = (a + 0x6d2b79f5) >>> 0;
        let t = a;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      };
      const idx = Array.from({ length: n }, (_, i) => i);
      for (let i = 0; i < size; i++) {
        const j = i + Math.floor(rand() * (n - i));
        [idx[i], idx[j]] = [idx[j], idx[i]];
      }
      return idx.slice(0, size).sort((x, y) => x - y);
    }
    for (const seed of ["ABC-123", "é", "審計", "🙂 audit"]) {   // 1-, 2-, 3- and 4-byte characters
      expect(drawSample(rows, 6, seed).map(r => rows.indexOf(r))).toEqual(reference(rows.length, 6, seed));
    }
  });

  it("over many seeds every row can be drawn (not stuck on the first ones)", () => {
    const seen = new Set<number>();
    for (let i = 0; i < 200; i++) for (const r of drawSample(rows, 3, `s${i}`)) seen.add(r.number);
    expect(seen.size).toBe(19);
  });
});

describe("CSV", () => {
  it("one line per pull request with its hash, and a formula-looking title is neutralised", () => {
    const reg = buildRegister(input({ pulls: [P(1, { title: '=HYPERLINK("x"), "quoted"' })] }));
    const lines = registerToCsv(reg.rows).trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatch(/^repo,pull_request,title,/);
    expect(lines[1]).toContain(`"'=HYPERLINK(""x""), ""quoted"""`);
    expect(lines[1].endsWith(reg.rows[0].row_sha256)).toBe(true);
  });
});
