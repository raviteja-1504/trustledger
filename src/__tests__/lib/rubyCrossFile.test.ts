/**
 * @jest-environment node
 *
 * Ruby cross-file evidence through runScan: Rails autoloads classes by name, so a controller handing params to a
 * service object, a model class method or an instance method defined in ANOTHER file must report at the call
 * site -- and stay quiet when the callee sanitizes, or when the argument isn't attacker-controlled.
 */
import { runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";

beforeAll(async () => { await warmRubyTaintEngine(); }, 120000);

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const ast = (r: ReturnType<typeof scan>, path: string, id: string): ScanIndicator[] =>
  r.files.find(f => f.file_path === path)!.indicators.filter(i => i.confidence === 95 && i.id === id);

const CTL = "app/controllers/reports_controller.rb";
const controller = (call: string) => `class ReportsController < ApplicationController
  def show
    name = params[:name]
    ${call}
  end
end
`;

const SERVICE: F = { path: "app/services/report_search.rb", content: `class ReportSearch
  def initialize(term)
    @term = term
  end

  def call
    Report.where("title LIKE '%#{@term}%'")
  end

  def self.run(term)
    ActiveRecord::Base.connection.execute("SELECT * FROM reports WHERE title = '#{term}'")
  end

  def self.safe(term)
    Report.where(title: term)
  end

  def export(path)
    File.read(path)
  end
end
` };

describe("Ruby cross-file sink facts", () => {
  it("class method in another file sinks its parameter -> reported at the controller call", () => {
    const r = scan([SERVICE, { path: CTL, content: controller("ReportSearch.run(name)") }]);
    const f = ast(r, CTL, "sql-injection");
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(4);
    expect(f[0].sinkExpr).toContain("ReportSearch.run");
  });

  it("constructor -> ivar -> method flow (service object `.new(x).call`)", () => {
    const r = scan([SERVICE, { path: CTL, content: controller("ReportSearch.new(name).call") }]);
    expect(ast(r, CTL, "sql-injection")).toHaveLength(1);
  });

  it("instance method on a local of that class", () => {
    const r = scan([SERVICE, { path: CTL, content: controller("s = ReportSearch.new(\"x\")\n    s.export(name)") }]);
    expect(ast(r, CTL, "path-traversal")).toHaveLength(1);
  });

  it("no report when the callee uses the safe hash form, or the argument is a literal", () => {
    expect(ast(scan([SERVICE, { path: CTL, content: controller("ReportSearch.safe(name)") }]), CTL, "sql-injection")).toHaveLength(0);
    expect(ast(scan([SERVICE, { path: CTL, content: controller("ReportSearch.run(\"fixed\")") }]), CTL, "sql-injection")).toHaveLength(0);
  });

  it("the callee file alone reports nothing (it has no untrusted input of its own)", () => {
    const r = scan([SERVICE, { path: CTL, content: controller("ReportSearch.run(name)") }]);
    expect(ast(r, SERVICE.path, "sql-injection")).toHaveLength(0);
  });

  it("without the service file in the batch there is no evidence, so no report", () => {
    expect(ast(scan([{ path: CTL, content: controller("ReportSearch.run(name)") }]), CTL, "sql-injection")).toHaveLength(0);
  });

  it("multi-hop: controller -> service -> repository in a third file", () => {
    const repo: F = { path: "app/repositories/report_repo.rb", content: `class ReportRepo
  def self.raw(q)
    Report.find_by_sql("SELECT * FROM reports WHERE " + q)
  end
end
` };
    const svc: F = { path: "app/services/finder.rb", content: `class Finder
  def self.by(q)
    ReportRepo.raw(q)
  end
end
` };
    const r = scan([repo, svc, { path: CTL, content: controller("Finder.by(name)") }]);
    expect(ast(r, CTL, "sql-injection")).toHaveLength(1);
  });
});
