/**
 * @jest-environment node
 *
 * Ruby engine precision checks from an external review, each with a twin:
 *  - a call runs the method of ITS class (two classes' `process`, `QueryBuilder.new.build(x)`, a typed local);
 *  - per-method state: an unrestricted params hash forgotten on reassignment and not carried to another method,
 *    instance variables shared only within one class, a local's class forgotten when reassigned;
 *  - a resolved-path prefix check confines only when the base ends at a directory;
 *  - BOLA authorization evidence is about the record: a headless `authorize`, or an owner check on another record,
 *    doesn't clear it;
 *  - `**opts` and destructured `(a, b)` parameters carry what the caller passed.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";

beforeAll(async () => { await warmRubyTaintEngine(); }, 120000);

const engine = (code: string) => analyzeFile("app/controllers/x_controller.rb", code).indicators.filter(i => !!i.sourceExpr).map(i => i.id);
const ctl = (body: string, before = "") => `${before}class XController < ApplicationController\n${body}\nend\n`;
const SQL = "ActiveRecord::Base.connection.execute";

describe("a call runs the method of its own class", () => {
  const QB = `class QueryBuilder\n  def build(value)\n    "SELECT * FROM users WHERE id = #{value}"\n  end\nend\n`;
  it("an instance method's return: QueryBuilder.new.build(x), or through a local typed by .new", () => {
    expect(engine(ctl(`  def search\n    ${SQL}(QueryBuilder.new.build(params[:id]))\n  end`, QB))).toContain("sql-injection");
    expect(engine(ctl(`  def search\n    s = QueryBuilder.new\n    ${SQL}(s.build(params[:id]))\n  end`, QB))).toContain("sql-injection");
  });
  const SU = `class SafeService\n  def process(input)\n    "fixed"\n  end\n  def run(input)\n    input.to_s\n  end\nend\nclass UnsafeService\n  def process(input)\n    input\n  end\n  def run(input)\n    system(input)\n  end\nend\n`;
  it("two classes' same-named methods keep their own summaries and their own bodies", () => {
    expect(engine(ctl(`  def go\n    s = UnsafeService.new\n    system(s.process(params[:c]))\n  end`, SU))).toContain("command-injection");
    expect(engine(ctl(`  def go\n    s = SafeService.new\n    system(s.process(params[:c]))\n  end`, SU))).not.toContain("command-injection");
    expect(engine(ctl(`  def go\n    UnsafeService.new.run(params[:c])\n  end`, SU))).toContain("command-injection");
    expect(engine(ctl(`  def go\n    SafeService.new.run(params[:c])\n  end`, SU))).not.toContain("command-injection");
  });
  it("an implicit call runs the enclosing class's method, not another class's of that name", () => {
    const other = `class Helper\n  def clean(x)\n    x\n  end\nend\n`;
    expect(engine(ctl(`  def go\n    system(clean(params[:c]))\n  end\n  def clean(x)\n    "safe"\n  end`, other))).not.toContain("command-injection");
    expect(engine(ctl(`  def go\n    system(clean(params[:c]))\n  end\n  def clean(x)\n    x.strip\n  end`, other))).toContain("command-injection");
  });
  it("Klass.method(x) runs Klass's class method, not another class's", () => {
    const two = `class Fmt\n  def self.wrap(x)\n    x\n  end\nend\nclass Safe\n  def self.wrap(x)\n    "k"\n  end\nend\n`;
    expect(engine(ctl(`  def go\n    system(Fmt.wrap(params[:c]))\n  end`, two))).toContain("command-injection");
    expect(engine(ctl(`  def go\n    system(Safe.wrap(params[:c]))\n  end`, two))).not.toContain("command-injection");
  });
  it("a file re-opening a library namespace (a stub) doesn't replace the library's own model", () => {
    const stub = `module Net; module LDAP\n  def self.new(o = {}); self; end\n  def self.search(o = {}); []; end\n  module Filter\n    def self.eq(attr, val); "(#{attr}=#{val})"; end\n  end\nend; end\n`;
    expect(engine(ctl(`  def go\n    filter = Net::LDAP::Filter.eq('uid', params[:u])\n    Net::LDAP.new(host: 'x').search(filter: filter)\n  end`, stub))).not.toContain("ldap-injection");
    // the app's own namespace is user code: its summary applies
    const own = `module Ldapx\n  module Filter\n    def self.eq(attr, val); "(#{attr}=#{val})"; end\n  end\nend\n`;
    expect(engine(ctl(`  def go\n    system(Ldapx::Filter.eq('uid', params[:u]))\n  end`, own))).toContain("command-injection");
  });
  it("a local class's object still carries what its constructor was given", () => {
    const cls = `class Profile\n  def initialize(name)\n    @name = name\n  end\n  def label\n    "x"\n  end\nend\n`;
    expect(engine(ctl(`  def go\n    p = Profile.new(params[:n])\n    system(p.label)\n  end`, cls))).toContain("command-injection");
  });
});

describe("analysis state belongs to one method, one class, one binding", () => {
  it("a params hash made safe by reassignment, or another method's same-named local, is no mass assignment", () => {
    expect(engine(ctl(`  def create\n    attrs = params.to_unsafe_h\n    attrs = { name: "x", email: "y" }\n    User.create(attrs)\n  end`))).not.toContain("mass-assignment");
    expect(engine(ctl(`  def a\n    attrs = params.to_unsafe_h\n    User.create(attrs)\n  end\n  def b\n    attrs = { name: "x" }\n    User.create(attrs)\n  end`)).filter(i => i === "mass-assignment")).toHaveLength(1);
    expect(engine(ctl(`  def create\n    attrs = params.to_unsafe_h\n    User.create(attrs)\n  end`))).toContain("mass-assignment");
    // another method's PARAMETER of the same name is not that local
    expect(engine(ctl(`  def a\n    attrs = params.to_unsafe_h\n    User.create(attrs)\n  end\n  def b(attrs)\n    User.create(attrs)\n  end`)).filter(i => i === "mass-assignment")).toHaveLength(1);
  });
  it("an instance variable is shared by one class's methods, not by another class's", () => {
    expect(engine(ctl(`  before_action :set_f\n  def set_f\n    @f = params[:f]\n  end\n  def show\n    File.read(@f)\n  end`))).toContain("path-traversal");
    expect(engine(`class FirstController < ApplicationController\n  def load\n    @record = params[:record]\n  end\nend\nclass SecondController < ApplicationController\n  def show\n    File.read(@record)\n  end\nend\n`)).not.toContain("path-traversal");
  });
  it("a local reassigned to something else is no longer the class it was constructed as", () => {
    expect(engine(ctl(`  def go\n    client = Net::HTTP.new('api.example.com')\n    client = Rails.cache\n    client.get(params[:url])\n  end`))).not.toContain("ssrf");
  });
});

describe("a resolved path confined by a prefix check", () => {
  const read = (base: string, check: string) => ctl(`  def show\n    base = ${base}\n    path = File.expand_path(params[:f], base)\n    raise "no" unless ${check}\n    send_file path\n  end`);
  it("ending at a directory confines it", () => {
    expect(engine(read(`"/var/www/uploads"`, `path.start_with?("/var/www/uploads/")`))).not.toContain("path-traversal");
    expect(engine(read(`Rails.root.join("uploads").to_s`, `path.start_with?(base + "/")`))).not.toContain("path-traversal");
    expect(engine(read(`Rails.root.join("uploads").to_s`, `path.start_with?(File.join(base, ""))`))).not.toContain("path-traversal");
    expect(engine(read(`"/var/www/uploads"`, `path.start_with?("#{base}/")`))).not.toContain("path-traversal");
  });
  it("otherwise the sibling /var/www/uploads_evil passes too", () => {
    expect(engine(read(`"/var/www/uploads"`, `path.start_with?("/var/www/uploads")`))).toContain("path-traversal");
    expect(engine(read(`Rails.root.join("uploads").to_s`, `path.start_with?(base)`))).toContain("path-traversal");
    expect(engine(read(`"/var/www/uploads"`, `path.start_with?("#{base}")`))).toContain("path-traversal");
    expect(engine(read(`"/var/www/uploads"`, `path.start_with?("/var/www/" + "uploads")`))).toContain("path-traversal");
  });
});

describe("BOLA: authorization evidence must be about the record", () => {
  const upd = (extra: string, after = "") => ctl(`  def update\n${extra}    @report = Report.find(params[:id])\n${after}    @report.update!(report_params)\n  end`);
  it("authorize / authorize! / can? with the record clears it", () => {
    expect(engine(upd("", "    authorize @report\n"))).not.toContain("bola-missing-ownership-check");
    expect(engine(upd("", "    authorize! :update, @report\n"))).not.toContain("bola-missing-ownership-check");
    expect(engine(upd("", "    head :forbidden unless @report.user_id == current_user.id\n"))).not.toContain("bola-missing-ownership-check");
  });
  it("a headless or class-level authorize, or an owner check on another record, does not", () => {
    expect(engine(upd("    authorize :report, :update?\n"))).toContain("bola-missing-ownership-check");
    expect(engine(upd("    authorize Report\n"))).toContain("bola-missing-ownership-check");
    expect(engine(upd("    @team = Team.find(params[:team_id])\n    head :forbidden unless @team.owner_id == current_user.id\n"))).toContain("bola-missing-ownership-check");
    expect(engine(upd("    @team = current_user.teams.first\n", "    head :forbidden unless @team.owner_id == current_user.id\n"))).toContain("bola-missing-ownership-check");
  });
});

describe("parameter forms carry what the caller passed", () => {
  it("**opts receives the keyword arguments", () => {
    expect(engine(`def upd(**attributes)\n  system(attributes[:cmd])\nend\n` + ctl(`  def go\n    upd(cmd: params[:c])\n  end`))).toContain("command-injection");
    expect(engine(`def upd(**attributes)\n  system(attributes[:cmd])\nend\n` + ctl(`  def go\n    upd(cmd: "ls")\n  end`))).not.toContain("command-injection");
  });
  it("a destructured (a, b) parameter holds the parts of its argument; later positions still line up", () => {
    expect(engine(`def pair((name, email))\n  ${SQL}("SELECT * FROM u WHERE n = '#{name}'")\nend\n` + ctl(`  def go\n    pair([params[:n], params[:e]])\n  end`))).toContain("sql-injection");
    const two = `def pick((a, b), cmd)\n  system(cmd)\nend\n`;
    expect(engine(two + ctl(`  def go\n    pick([1, 2], params[:c])\n  end`))).toContain("command-injection");
    expect(engine(two + ctl(`  def go\n    pick([params[:x], 2], "ls")\n  end`))).not.toContain("command-injection");
  });
});
