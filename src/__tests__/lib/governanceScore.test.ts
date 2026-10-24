/**
 * @jest-environment node
 *
 * Trust Score as a governance score: real data in, every point explained, AI use itself never penalised.
 */
import { computeGovernanceScore, WEIGHTS, NO_POLICY_VALUE, band, grade, type ScoreInput } from "@/lib/governanceScore";

const NOW = "2026-10-20T12:00:00Z";
const daysAgo = (n: number) => new Date(Date.parse(NOW) - n * 86400_000).toISOString();

/** A clean org: two repos scanned today, nothing open, policy set and fully compliant. */
const base = (over: Partial<ScoreInput> = {}): ScoreInput => ({
  now: NOW,
  repos: ["acme/app", "acme/api"],
  scans: [
    { id: "a1", repo: "acme/app", pr_number: 1, created_at: daysAgo(1) },
    { id: "b1", repo: "acme/api", pr_number: 1, created_at: daysAgo(1) },
  ],
  riskyFiles: [], attested: [], violations: [], secrets: [],
  shadow: { policy_configured: true, compliance: 1, open_violations: 0 },
  ...over,
});
const dim = (s: ReturnType<typeof computeGovernanceScore>, key: string) => s.dimensions.find(d => d.key === key)!;

describe("a well-governed org", () => {
  it("scores 1000 with no actions", () => {
    const s = computeGovernanceScore(base());
    expect(s.total).toBe(1000);
    expect(s.band).toBe("Excellent");
    expect(s.dimensions.every(d => d.actions.length === 0 && d.gain === 0)).toBe(true);
  });

  it("weights sum to 1 and points add up to the total", () => {
    expect(Object.values(WEIGHTS).reduce((a, b) => a + b, 0)).toBeCloseTo(1);
    const s = computeGovernanceScore(base({ violations: [{ scan_id: "a1", file_path: "x.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null }] }));
    expect(s.total).toBe(s.dimensions.reduce((a, d) => a + d.points, 0));
  });
});

describe("AI use is not penalised; ungoverned AI is", () => {
  it("lots of reviewed AI-written risky code costs nothing", () => {
    const s = computeGovernanceScore(base({
      riskyFiles: [{ scan_id: "a1", file_path: "ai.ts", risk_score: "HIGH", ai_percentage: 0.99 }],
      attested: [{ scan_id: "a1", file_path: "ai.ts" }],
    }));
    expect(s.total).toBe(1000);
  });

  it("an unreviewed AI-heavy risky file counts double against review", () => {
    const s = computeGovernanceScore(base({
      riskyFiles: [
        { scan_id: "a1", file_path: "ai.ts", risk_score: "HIGH", ai_percentage: 0.9 },     // weight 2, unreviewed
        { scan_id: "a1", file_path: "human.ts", risk_score: "HIGH", ai_percentage: 0.1 },  // weight 1, reviewed
      ],
      attested: [{ scan_id: "a1", file_path: "human.ts" }],
    }));
    expect(dim(s, "review").value).toBeCloseTo(1 / 3);
    expect(dim(s, "review").facts[0]).toBe("1 high-risk file unreviewed, 1 of them mostly AI-written");
    expect(dim(s, "review").actions[0].label).toBe("Review 1 high-risk file in app (1 mostly AI-written)");
  });

  it("only each PR's latest scan counts for review", () => {
    const s = computeGovernanceScore(base({
      scans: [...base().scans, { id: "a0", repo: "acme/app", pr_number: 1, created_at: daysAgo(3) }],
      riskyFiles: [{ scan_id: "a0", file_path: "old.ts", risk_score: "CRITICAL", ai_percentage: 0 }],
    }));
    expect(dim(s, "review").value).toBe(1);
  });
});

describe("a repository's own score: how governed what was scanned is, not how recently", () => {
  it("every file signed off scores 1000 even when last scanned 40 days ago; the org's Scan coverage still counts it", () => {
    const s = computeGovernanceScore(base({
      scans: [{ id: "a1", repo: "acme/app", pr_number: 1, created_at: daysAgo(40) }, { id: "b1", repo: "acme/api", pr_number: 1, created_at: daysAgo(1) }],
      riskyFiles: [{ scan_id: "a1", file_path: "x.ts", risk_score: "CRITICAL", ai_percentage: 0 }],
      attested: [{ scan_id: "a1", file_path: "x.ts" }],
    }));
    expect(s.repos.find(r => r.repo === "acme/app")!.score).toBe(1000);
    expect(dim(s, "coverage").value).toBe(0.5);
  });

  it("age doesn't change a risky repo's score either; a repo never scanned keeps coverage in it (786)", () => {
    const risky = (age: number) => computeGovernanceScore(base({
      repos: ["acme/app", "acme/api", "acme/new"],
      scans: [{ id: "a1", repo: "acme/app", pr_number: 1, created_at: daysAgo(age) }, { id: "b1", repo: "acme/api", pr_number: 1, created_at: daysAgo(1) }],
      violations: [{ scan_id: "a1", file_path: "c.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null }],
    })).repos;
    expect(risky(1).find(r => r.repo === "acme/app")!.score).toBe(risky(40).find(r => r.repo === "acme/app")!.score);
    // exposure 1/(1+1) = 0.5: (0.5×0.25 + 0.2 + 0.1) / 0.55
    expect(risky(40).find(r => r.repo === "acme/app")!.score).toBe(Math.round((0.5 * 0.25 + 0.2 + 0.1) / 0.55 * 1000));
    expect(risky(40).find(r => r.repo === "acme/new")!.score).toBe(786);
  });
});

describe("open risk counts each PR's latest scan, like review and the dashboard", () => {
  it("a file a rescan no longer flags doesn't keep counting from the older scan's open row (63 vs 62)", () => {
    const s = computeGovernanceScore(base({
      scans: [...base().scans, { id: "a0", repo: "acme/app", pr_number: 1, created_at: daysAgo(3) }],
      violations: [
        // the original scan: two files flagged
        { scan_id: "a0", file_path: "nosql.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null },
        { scan_id: "a0", file_path: "sqli.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null },
        // the rescan (latest): only the real one is still flagged
        { scan_id: "a1", file_path: "sqli.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null },
      ],
    }));
    expect(s.repos.find(r => r.repo === "acme/app")).toMatchObject({ open_critical: 1, open_high: 0 });
    expect(dim(s, "exposure").facts[0]).toBe("1 open critical file, 0 open high-risk files across 1 repository");
  });

  it("another open PR's latest scan still counts; a file open in two PRs counts once", () => {
    const s = computeGovernanceScore(base({
      scans: [...base().scans, { id: "p2", repo: "acme/app", pr_number: 2, created_at: daysAgo(2) }],
      violations: [
        { scan_id: "a1", file_path: "a.ts", risk_score: "HIGH", status: "open", sla_deadline: null },
        { scan_id: "p2", file_path: "b.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null },
        { scan_id: "p2", file_path: "a.ts", risk_score: "HIGH", status: "open", sla_deadline: null },
      ],
    }));
    expect(s.repos.find(r => r.repo === "acme/app")).toMatchObject({ open_critical: 1, open_high: 1 });
  });
});

describe("open risk", () => {
  it("per repo 1/(1 + critical + 0.3 × high), averaged over scanned repos", () => {
    const s = computeGovernanceScore(base({
      violations: [
        { scan_id: "a1", file_path: "c.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null },
        { scan_id: "a1", file_path: "h.ts", risk_score: "HIGH", status: "in_review", sla_deadline: null },
        { scan_id: "a1", file_path: "done.ts", risk_score: "CRITICAL", status: "resolved", sla_deadline: null },
      ],
    }));
    expect(dim(s, "exposure").value).toBeCloseTo((1 / 2.3 + 1) / 2);
    expect(dim(s, "exposure").actions[0]).toMatchObject({ label: "Fix or review 1 critical file and 1 high-risk file in app", href: "/violations?repo=acme%2Fapp" });
  });

  it("a newer scan's row for the same file supersedes an older open one", () => {
    const s = computeGovernanceScore(base({
      scans: [...base().scans, { id: "a0", repo: "acme/app", pr_number: 2, created_at: daysAgo(5) }],
      violations: [
        { scan_id: "a0", file_path: "x.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null },
        { scan_id: "a1", file_path: "x.ts", risk_score: "CRITICAL", status: "resolved", sla_deadline: null },
      ],
    }));
    expect(dim(s, "exposure").value).toBe(1);
  });

  it("inactive repositories don't count", () => {
    const s = computeGovernanceScore(base({
      scans: [...base().scans, { id: "z1", repo: "acme/archived", pr_number: 1, created_at: daysAgo(1) }],
      violations: [{ scan_id: "z1", file_path: "x.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null }],
    }));
    expect(s.total).toBe(1000);
    // ...and are never suggested as something to fix
    expect(dim(s, "exposure").actions).toEqual([]);
    expect(dim(s, "exposure").facts[0]).toBe("0 open critical files, 0 open high-risk files across 0 repositories");
  });
});

describe("deadlines, secrets, coverage, Shadow AI", () => {
  it("SLA: share of open findings with a deadline still within it", () => {
    const s = computeGovernanceScore(base({
      violations: [
        { scan_id: "a1", file_path: "late.ts", risk_score: "HIGH", status: "open", sla_deadline: daysAgo(1) },
        { scan_id: "a1", file_path: "ok.ts", risk_score: "HIGH", status: "open", sla_deadline: daysAgo(-3) },
        { scan_id: "a1", file_path: "ok2.ts", risk_score: "HIGH", status: "open", sla_deadline: daysAgo(-1) },
      ],
    }));
    expect(dim(s, "sla").value).toBeCloseTo(2 / 3);
    expect(dim(s, "sla").actions[0].label).toBe("Resolve 1 overdue finding");
  });

  it("secrets: per repo 1/(1 + critical + 0.5 high + 0.2 medium)", () => {
    const s = computeGovernanceScore(base({ secrets: [{ scan_id: "b1", severity: "CRITICAL" }, { scan_id: "b1", severity: "HIGH" }] }));
    expect(dim(s, "secrets").value).toBeCloseTo((1 + 1 / 2.5) / 2);
    expect(dim(s, "secrets").actions[0].label).toBe("Rotate and resolve 2 secrets in api");
  });

  it("coverage: 7 days = 1, 30 days = 0.5, older or never = 0", () => {
    const s = computeGovernanceScore(base({
      repos: ["acme/app", "acme/api", "acme/old", "acme/new"],
      scans: [...base().scans, { id: "o1", repo: "acme/old", pr_number: 1, created_at: daysAgo(20) }],
    }));
    expect(dim(s, "coverage").value).toBeCloseTo((1 + 1 + 0.5 + 0) / 4);
    expect(dim(s, "coverage").actions.map(a => a.label).sort()).toEqual(["Rescan old", "Run a first scan of new"]);
  });

  it("no repositories at all: coverage 0, with a way forward", () => {
    const s = computeGovernanceScore(base({ repos: [], scans: [] }));
    expect(dim(s, "coverage").value).toBe(0);
    expect(dim(s, "coverage").actions[0].label).toBe("Connect a repository");
  });

  it("Shadow AI: no policy = partial credit and a prompt to set one; otherwise compliance", () => {
    const none = computeGovernanceScore(base({ shadow: { policy_configured: false, compliance: null, open_violations: 0 } }));
    expect(dim(none, "shadow_ai").value).toBe(NO_POLICY_VALUE);
    expect(dim(none, "shadow_ai").actions[0]).toMatchObject({ label: "Choose your approved AI tools", href: "/shadow-ai" });
    const half = computeGovernanceScore(base({ shadow: { policy_configured: true, compliance: 0.5, open_violations: 2 } }));
    expect(dim(half, "shadow_ai").value).toBe(0.5);
    expect(dim(half, "shadow_ai").actions[0].label).toBe("Resolve 2 unapproved AI tool detections");
  });
});

describe("explainability", () => {
  it("every dimension has a formula, facts, and gain = max - points", () => {
    const s = computeGovernanceScore(base({ secrets: [{ scan_id: "a1", severity: "HIGH" }] }));
    for (const d of s.dimensions) {
      expect(d.formula.length).toBeGreaterThan(20);
      expect(d.facts.length).toBeGreaterThan(0);
      expect(d.gain).toBe(d.max_points - d.points);
    }
  });

  it("per-repo scores rank the weakest repository first", () => {
    const s = computeGovernanceScore(base({ violations: [{ scan_id: "b1", file_path: "x.ts", risk_score: "CRITICAL", status: "open", sla_deadline: null }] }));
    expect(s.repos[0]).toMatchObject({ repo: "acme/api", open_critical: 1 });
    expect(s.repos[0].score).toBeLessThan(s.repos[1].score);
    expect(s.repos[1].score).toBe(1000);
  });

  it("bands and grades", () => {
    expect([band(900), band(700), band(550), band(400), band(399)]).toEqual(["Excellent", "Good", "Fair", "Poor", "Critical"]);
    expect([grade(0.9), grade(0.75), grade(0.6), grade(0.45), grade(0.44)]).toEqual(["A", "B", "C", "D", "F"]);
  });
});
