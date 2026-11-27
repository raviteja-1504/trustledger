/**
 * @jest-environment node
 *
 * get_risk_trend must return every week of the selected period. It once ended in LIMIT 10, which cut a 90-day period
 * (13-14 weeks) down to its newest 10 and left the oldest weeks of the Risk trend chart empty.
 */
import fs from "fs";
import path from "path";
import { fillTrendWeeks } from "@/components/dashboard/RiskPanel";

const DIR = path.join(__dirname, "../../../supabase/migrations");

describe("get_risk_trend definition", () => {
  const latest = () => {
    const files = fs.readdirSync(DIR).filter(f => /get_risk_trend/.test(fs.readFileSync(path.join(DIR, f), "utf8")) && /CREATE OR REPLACE FUNCTION get_risk_trend/i.test(fs.readFileSync(path.join(DIR, f), "utf8"))).sort();
    return fs.readFileSync(path.join(DIR, files[files.length - 1]), "utf8");
  };
  it("the newest definition has no row limit", () => {
    const body = latest().split(/\$\$/)[1];
    expect(body).toMatch(/GROUP BY week_start/);
    expect(body).not.toMatch(/\bLIMIT\b/i);
  });
});

describe("the chart over a 90-day period", () => {
  it("shows every week of the period, with the oldest weeks' counts where the server returned them", () => {
    const now = Date.parse("2026-11-27T12:00:00Z");
    const period = { start: "2026-08-29", end: "2026-11-27" };
    const oldest = { date: "2026-08-24", critical_count: 4, high_count: 2, medium_count: 1 };
    const weeks = fillTrendWeeks([oldest], period, now);
    expect(weeks.length).toBeGreaterThanOrEqual(13);
    expect(weeks[0]).toMatchObject({ critical_count: 4, high_count: 2, medium_count: 1 });
  });
});

describe("get_risk_trend counts each file once", () => {
  const sql = () => {
    const files = fs.readdirSync(DIR).filter(f => /CREATE OR REPLACE FUNCTION get_risk_trend/i.test(fs.readFileSync(path.join(DIR, f), "utf8"))).sort();
    return fs.readFileSync(path.join(DIR, files[files.length - 1]), "utf8").split(/\$\$/)[1];
  };
  it("keeps one row per repository + PR + path (its latest scan), before filtering by risk", () => {
    const body = sql();
    expect(body).toMatch(/DISTINCT ON \(s\.repo_full_name, COALESCE\(s\.pr_number, 0\), f\.file_path\)/);
    expect(body).toMatch(/ORDER BY s\.repo_full_name, COALESCE\(s\.pr_number, 0\), f\.file_path, s\.created_at DESC/);
    // the risk filter is applied AFTER the latest row is chosen, so a file fixed in a later scan is not counted
    expect(body.indexOf("DISTINCT ON")).toBeLessThan(body.indexOf("risk_score IN"));
  });
});
