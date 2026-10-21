/**
 * A PR's policy alert, live (lib/alertProgress.ts): real progress instead of the count frozen at scan time, done
 * when its own scan is clear or a newer push of the PR replaced it.
 */
import { progressByScan, latestScanByPr, policyAlertVerdict, progressTitle } from "@/lib/alertProgress";

const scans = [
  { id: "s1", repo_full_name: "acme/sast", pr_number: 12, created_at: "2026-10-01T00:00:00Z" },
  { id: "s2", repo_full_name: "acme/sast", pr_number: 12, created_at: "2026-10-02T00:00:00Z" },
  { id: "s9", repo_full_name: "acme/web", pr_number: 12, created_at: "2026-10-05T00:00:00Z" },
  // a push straight to a branch: no PR, never "replaced" by anything
  { id: "d1", repo_full_name: "acme/sast", pr_number: null, created_at: "2026-10-09T00:00:00Z" },
];
const latest = latestScanByPr(scans);
const info = (id: string) => scans.find(s => s.id === id);

describe("alert progress", () => {
  it("counts open of all CRITICAL/HIGH violations per scan", () => {
    const p = progressByScan([
      { scan_id: "s2", status: "open" }, { scan_id: "s2", status: "resolved" }, { scan_id: "s2", status: "in_review" },
      { scan_id: "s1", status: "resolved" },
    ]);
    expect(p.get("s2")).toEqual({ open: 2, total: 3 });
    expect(p.get("s1")).toEqual({ open: 0, total: 1 });
  });

  it("the newest scan of each PR, per repository (the same PR number in two repos is two PRs)", () => {
    expect(latest.get("acme/sast#12")).toBe("s2");
    expect(latest.get("acme/web#12")).toBe("s9");
    expect([...latest.keys()].sort()).toEqual(["acme/sast#12", "acme/web#12"]);
  });

  it("active with progress while files remain; done when they're all signed off", () => {
    const p = progressByScan([{ scan_id: "s2", status: "open" }, { scan_id: "s2", status: "resolved" }]);
    expect(policyAlertVerdict("s2", p, info("s2"), latest)).toEqual({ state: "active", progress: { open: 1, total: 2 } });
    const done = progressByScan([{ scan_id: "s2", status: "resolved" }, { scan_id: "s2", status: "resolved" }]);
    expect(policyAlertVerdict("s2", done, info("s2"), latest)).toEqual({ state: "done", reason: "signed_off", progress: { open: 0, total: 2 } });
  });

  it("an older push's alert is replaced by the newer scan's, whatever its own count", () => {
    const p = progressByScan([{ scan_id: "s1", status: "open" }]);
    expect(policyAlertVerdict("s1", p, info("s1"), latest)).toMatchObject({ state: "done", reason: "superseded" });
  });

  it("no violation rows to judge by: left alone", () => {
    expect(policyAlertVerdict("s2", new Map(), info("s2"), latest)).toBeNull();
  });

  it("titles say how many still need a sign-off", () => {
    expect(progressTitle({ open: 1, total: 6 }, "sast", 12)).toBe("1 of 6 files still needs sign-off in sast PR #12");
    expect(progressTitle({ open: 3, total: 6 }, "sast", null)).toBe("3 of 6 files still need sign-off in sast");
    expect(progressTitle({ open: 0, total: 1 }, "sast", 12)).toBe("All 1 file signed off in sast PR #12");
  });
});
