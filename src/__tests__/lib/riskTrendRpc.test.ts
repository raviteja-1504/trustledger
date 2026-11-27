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

describe("risk trend and totals count the CURRENT state of each PR", () => {
  const latestSql = () => {
    const files = fs.readdirSync(DIR).filter(f => /CREATE OR REPLACE FUNCTION get_risk_trend/i.test(fs.readFileSync(path.join(DIR, f), "utf8"))).sort();
    return fs.readFileSync(path.join(DIR, files[files.length - 1]), "utf8");
  };
  /** The text between the $$ pair of the named function. */
  const fn = (name: string) => {
    const sql = latestSql();
    const at = sql.indexOf("FUNCTION " + name + "(p_scan_ids uuid[])");
    const open = sql.indexOf("$$", at), close = sql.indexOf("$$", open + 2);
    return at < 0 ? "" : sql.slice(open + 2, close);
  };

  it("the weekly trend takes each PR's latest scan of the week, then each repo+path once", () => {
    const body = fn("get_risk_trend");
    expect(body).toContain("DISTINCT ON (s.repo_full_name, COALESCE(s.pr_number, 0), date_trunc('week', s.created_at))");
    expect(body).toContain("DISTINCT ON (wk.week_start, s.repo_full_name, f.file_path)");
    expect(body.lastIndexOf("DISTINCT ON")).toBeLessThan(body.indexOf("risk_score IN"));   // risk filter AFTER choosing the scan
    expect(body).not.toMatch(/LIMIT/i);
  });

  it("the totals take the latest scan of every PR in the period, each repo+path once", () => {
    const body = fn("get_risk_totals");
    expect(body).toContain("DISTINCT ON (s.repo_full_name, COALESCE(s.pr_number, 0)) s.id");
    expect(body).toContain("DISTINCT ON (s.repo_full_name, f.file_path)");
  });

  it("is callable by the service role only", () => {
    const sql = latestSql();
    expect(sql).toContain("GRANT EXECUTE ON FUNCTION get_risk_totals(uuid[]) TO service_role;");
    expect(sql).toContain("REVOKE ALL ON FUNCTION get_risk_totals(uuid[]) FROM PUBLIC;");
  });
});
