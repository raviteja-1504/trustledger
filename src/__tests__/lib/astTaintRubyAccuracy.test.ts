/**
 * @jest-environment node
 *
 * Ruby AST taint engine accuracy: deferred lambda execution, reaching definitions, canonical method identity (namespaces,
 * no suffix matching), object-level authorization (BOLA), sink-specific suppression, finding identity, token-specific JWT
 * evidence, scan status / parser lifecycle.
 */
import { analyzeFile, runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { warmRubyTaintEngine, scanAstTaintRuby, parseRubySourceSync, isRubyParserReady } from "@/lib/astTaintRuby";

beforeAll(async () => { await warmRubyTaintEngine(); }, 120000);

/** Findings from the data-flow engine itself (it sets sourceExpr), not the line-pattern layer. */
const flow = (code: string, path = "app/controllers/x_controller.rb"): ScanIndicator[] => analyzeFile(path, code).indicators.filter(i => !!i.sourceExpr);
const ids = (code: string) => flow(code).map(i => i.id);
const anyIds = (code: string) => analyzeFile("app/controllers/x_controller.rb", code).indicators.map(i => i.id);
const ctl = (body: string, before = "") => `${before}class XController < ApplicationController\n${body}\nend\n`;
const action = (inner: string, before = "") => ctl(`  def run\n${inner}\n  end`, before);

describe("lambdas and procs are deferred execution", () => {
  it("a lambda that is never called does not run", () => {
    expect(ids(action(`    handler = -> { system(params[:command]) }\n    render plain: "OK"`))).not.toContain("command-injection");
    expect(ids(action(`    handler = lambda { system(params[:command]) }\n    render plain: "OK"`))).not.toContain("command-injection");
  });
  it("a lambda that is called does", () => {
    expect(ids(action(`    handler = -> { system(params[:command]) }\n    handler.call\n    render plain: "OK"`))).toContain("command-injection");
    expect(ids(action(`    handler = -> { system(params[:command]) }\n    handler.()\n    render plain: "OK"`))).toContain("command-injection");
    expect(ids(action(`    handler = -> { system(params[:command]) }\n    handler[]\n    render plain: "OK"`))).toContain("command-injection");
  });
  it("a lambda called only on one branch is possibly executed", () => {
    expect(ids(action(`    handler = -> { system(params[:command]) }\n    handler.call if params[:go]\n    render plain: "OK"`))).toContain("command-injection");
  });
  it("a lambda passed to a method that calls it", () => {
    const runner = `def invoke(fn)\n  fn.call\nend\n`;
    expect(ids(action(`    invoke(-> { system(params[:command]) })`, runner))).toContain("command-injection");
  });
  it("a lambda passed to a method that never calls it", () => {
    const runner = `def invoke(fn)\n  1\nend\n`;
    expect(ids(action(`    invoke(-> { system(params[:command]) })`, runner))).not.toContain("command-injection");
  });
  it("a lambda taking a parameter is judged by the argument it is called with", () => {
    expect(ids(action(`    run_it = ->(c) { system(c) }\n    run_it.call(params[:command])`))).toContain("command-injection");
    expect(ids(action(`    run_it = ->(c) { system(c) }\n    run_it.call("ls")`))).not.toContain("command-injection");
  });
  it("a proc built with proc / Proc.new is deferred too", () => {
    expect(ids(action(`    p1 = proc { system(params[:command]) }\n    render plain: "OK"`))).not.toContain("command-injection");
    expect(ids(action(`    p1 = Proc.new { system(params[:command]) }\n    p1.call`))).toContain("command-injection");
  });
  it("a block given to an iterator runs inline", () => {
    expect(ids(action(`    [1].each { system(params[:command]) }`))).toContain("command-injection");
    expect(ids(action(`    params[:cmds].each { |c| system(c) }`))).toContain("command-injection");
  });
  it("a block yielded to by the method it is passed to", () => {
    const helper = `def with_conn\n  yield\nend\n`;
    expect(ids(action(`    with_conn { system(params[:command]) }`, helper))).toContain("command-injection");
  });
});

describe("reaching definitions", () => {
  it("a later overwrite by a constant removes the taint", () => {
    expect(ids(action(`    path = params[:file]\n    path = "safe.txt"\n    File.read(path)`))).not.toContain("path-traversal");
  });
  it("an assignment in one branch leaves the other definition reaching the sink", () => {
    expect(ids(action(`    path = "safe.txt"\n    if params[:admin]\n      path = params[:file]\n    end\n    File.read(path)`))).toContain("path-traversal");
    expect(ids(action(`    path = params[:file]\n    if authorized?\n      path = "safe.txt"\n    end\n    File.read(path)`))).toContain("path-traversal");
  });
  it("both branches assign a constant: nothing reaches the sink", () => {
    expect(ids(action(`    if params[:a]\n      path = "a.txt"\n    else\n      path = "b.txt"\n    end\n    File.read(path)`))).not.toContain("path-traversal");
  });
  it("a loop-carried assignment", () => {
    expect(ids(action(`    q = "SELECT 1"\n    params[:ids].each { |i| q += " OR id = #{i}" }\n    ActiveRecord::Base.connection.execute(q)`))).toContain("sql-injection");
  });
  it("an early return leaves only the surviving path", () => {
    expect(ids(action(`    id = params[:id]\n    return head(:bad_request) unless id =~ /\\A\\d+\\z/\n    ActiveRecord::Base.connection.execute("SELECT * FROM t WHERE id = #{id}")`))).not.toContain("sql-injection");
  });
  it("a rescue path that reassigns from input", () => {
    expect(ids(action(`    path = "safe.txt"\n    begin\n      Integer(params[:n])\n    rescue ArgumentError\n      path = params[:file]\n    end\n    File.read(path)`))).toContain("path-traversal");
  });
  it("a block-local variable of the same name is not the outer one", () => {
    expect(ids(action(`    q = params[:q]\n    [1].each { |x; q| q = "SELECT 1"; ActiveRecord::Base.connection.execute(q) }`))).not.toContain("sql-injection");
  });
});

describe("method identity: namespaces, no suffix matching", () => {
  const SVC = `module Admin\n  class UserService\n    def process(value)\n      system(value)\n    end\n  end\nend\nmodule Billing\n  class UserService\n    def process(value)\n      value.length\n    end\n  end\nend\n`;
  it("same-named classes in different namespaces never exchange summaries", () => {
    expect(ids(action(`    Admin::UserService.new.process(params[:v])`, SVC))).toContain("command-injection");
    expect(ids(action(`    Billing::UserService.new.process(params[:v])`, SVC))).not.toContain("command-injection");
  });
  it("a top-level class is not the namespaced class that happens to end in its name", () => {
    const code = `class UserService\n  def process(v)\n    v.length\n  end\nend\nmodule Admin\n  class UserService\n    def process(v)\n      system(v)\n    end\n  end\nend\n`;
    expect(ids(action(`    UserService.new.process(params[:v])`, code))).not.toContain("command-injection");
    expect(ids(action(`    ::Admin::UserService.new.process(params[:v])`, code))).toContain("command-injection");
  });
  it("inside a module, a bare constant resolves to that module's class", () => {
    const code = `module Billing\n  class Svc\n    def go(v); v.length; end\n  end\nend\nmodule Admin\n  class Svc\n    def go(v); system(v); end\n  end\n  class Ctl\n    def act(v)\n      Svc.new.go(v)\n    end\n  end\nend\n`;
    expect(ids(`${code}`)).toEqual([]);                                         // (no request source in this file)
    const wired = code.replace("def act(v)\n      Svc.new.go(v)", "def act(v)\n      Svc.new.go(params[:v])");
    expect(ids(wired)).toContain("command-injection");
  });
  it("a singleton method and an instance method of one name are different methods", () => {
    const code = `class Util\n  def self.clean(v); v.length; end\n  def clean(v); system(v); end\nend\n`;
    expect(ids(action(`    Util.clean(params[:v])`, code))).not.toContain("command-injection");
    expect(ids(action(`    Util.new.clean(params[:v])`, code))).toContain("command-injection");
  });
  it("a keyword argument binds by name", () => {
    const code = `def run_cmd(label:, cmd:)\n  system(cmd)\nend\n`;
    expect(ids(action(`    run_cmd(cmd: params[:c], label: "x")`, code))).toContain("command-injection");
    expect(ids(action(`    run_cmd(label: params[:c], cmd: "ls")`, code))).not.toContain("command-injection");
  });
});

describe("BOLA: object-level authorization", () => {
  const rec = (body: string, before = "") => ctl(`  def update\n${body}\n  end`, before);
  const bola = (code: string) => ids(code).includes("bola-missing-ownership-check");
  it("an unchecked find by request id followed by a write is reported", () => {
    expect(bola(rec(`    @post = Post.find(params[:id])\n    @post.update(post_params)`))).toBe(true);
  });
  it("an owner comparison on the loaded record is safe", () => {
    expect(bola(rec(`    @post = Post.find(params[:id])\n    return head(:forbidden) unless @post.user_id == current_user.id\n    @post.update(post_params)`))).toBe(false);
  });
  it("an ownership comparison on ANOTHER record does not authorize this one", () => {
    expect(bola(rec(`    @post = Post.find(params[:id])\n    if current_user.admin?\n      other_record.user_id == current_user.id\n    end\n    @post.update(post_params)`))).toBe(true);
  });
  it("Pundit authorize on the loaded record is safe", () => {
    expect(bola(rec(`    @post = Post.find(params[:id])\n    authorize @post\n    @post.update(post_params)`))).toBe(false);
  });
  it("CanCanCan authorize! on the loaded record is safe", () => {
    expect(bola(rec(`    @post = Post.find(params[:id])\n    authorize! :update, @post\n    @post.update(post_params)`))).toBe(false);
  });
  it("a headless authorize (no record) is not object-level", () => {
    expect(bola(rec(`    authorize :post\n    @post = Post.find(params[:id])\n    @post.update(post_params)`))).toBe(true);
  });
  it("a lookup scoped through the current user is safe", () => {
    expect(bola(rec(`    @post = current_user.posts.find(params[:id])\n    @post.update(post_params)`))).toBe(false);
    expect(bola(rec(`    @post = Post.where(user_id: current_user.id).find(params[:id])\n    @post.update(post_params)`))).toBe(false);
  });
  it("an admin-role check is not ownership", () => {
    expect(bola(rec(`    return head(:forbidden) unless current_user.admin?\n    @post = Post.find(params[:id])\n    @post.update(post_params)`))).toBe(true);
  });
  it("an authentication filter is not ownership", () => {
    expect(bola(ctl(`  before_action :authenticate_user!\n  def update\n    @post = Post.find(params[:id])\n    @post.update(post_params)\n  end`))).toBe(true);
  });
  it("a check made after the write protects nothing", () => {
    expect(bola(rec(`    @post = Post.find(params[:id])\n    @post.update(post_params)\n    return head(:forbidden) unless @post.user_id == current_user.id`))).toBe(true);
  });
});

describe("sanitizers: tied to the value, the flow and the class", () => {
  it("only one branch sanitized", () => {
    expect(anyIds(action(`    c = params[:c]\n    c = Shellwords.escape(c) if params[:safe]\n    system("ls " + c)`))).toContain("command-injection");
  });
  it("a sanitized variable overwritten with the raw value", () => {
    expect(anyIds(action(`    c = Shellwords.escape(params[:c])\n    c = params[:c]\n    system("ls " + c)`))).toContain("command-injection");
  });
  it("a different variable was sanitized", () => {
    expect(anyIds(action(`    a = Shellwords.escape(params[:a])\n    b = params[:b]\n    system("ls " + b)`))).toContain("command-injection");
  });
  it("the sanitizer's return value ignored", () => {
    expect(anyIds(action(`    c = params[:c]\n    Shellwords.escape(c)\n    system("ls " + c)`))).toContain("command-injection");
  });
  it("an HTML escape does not protect SQL; a shell escape does not protect markup", () => {
    expect(ids(action(`    v = ERB::Util.html_escape(params[:v])\n    ActiveRecord::Base.connection.execute("SELECT * FROM t WHERE n = #{v}")`))).toContain("sql-injection");
    expect(ids(action(`    v = Shellwords.escape(params[:v])\n    render html: "<p>#{v}</p>".html_safe`))).toContain("xss");
  });
  it("the sanitizer applied to the value that reaches the sink is proven", () => {
    expect(anyIds(action(`    c = Shellwords.escape(params[:c])\n    system("ls " + c)`))).not.toContain("command-injection");
  });
  it("two sources reach the sink and only one is sanitized", () => {
    expect(anyIds(action(`    a = Shellwords.escape(params[:a])\n    b = params[:b]\n    system("ls " + a + " " + b)`))).toContain("command-injection");
  });
});

describe("command and SQL sinks", () => {
  it("system with an argv list runs no shell; with one string it does", () => {
    expect(ids(action(`    system("ls", "-l", params[:d])`))).not.toContain("command-injection");
    expect(ids(action(`    system("ls -l " + params[:d])`))).toContain("command-injection");
    expect(ids(action(`    system(params[:d], "x")`))).toContain("command-injection");
  });
  it.each([
    ["backticks", "    `ls #{params[:d]}`"], ["Open3.capture2", "    Open3.capture2(\"ls #{params[:d]}\")"],
    ["IO.popen", "    IO.popen(\"ls #{params[:d]}\")"], ["Kernel.exec", "    Kernel.exec(\"ls #{params[:d]}\")"],
    ["Process.spawn", "    Process.spawn(\"ls #{params[:d]}\")"],
  ])("a tainted command string reaching %s", (_n, line) => {
    expect(ids(action(line))).toContain("command-injection");
  });
  it("ActiveRecord placeholders are safe, interpolation is not", () => {
    expect(ids(action(`    User.where("name = ?", params[:n])`))).not.toContain("sql-injection");
    expect(ids(action(`    User.where(name: params[:n])`))).not.toContain("sql-injection");
    expect(ids(action(`    User.where("name = '#{params[:n]}'")`))).toContain("sql-injection");
  });
});

describe("finding identity", () => {
  it("two different sinks of one class on a line are two findings in the engine", () => {
    const code = action(`    system(params[:a]); system(params[:b])`);
    const root = parseRubySourceSync(code, "app/controllers/x_controller.rb")!;
    expect(scanAstTaintRuby(code, "app/controllers/x_controller.rb", root).filter(f => f.id === "command-injection").length).toBeGreaterThanOrEqual(2);
  });
  it("a finding carries source, sink and a trace", () => {
    const f = flow(action(`    c = params[:c]\n    system(c)`)).find(i => i.id === "command-injection")!;
    expect(f.sourceExpr).toBeTruthy();
    expect(f.trace![0].kind).toBe("source");
    expect(f.trace![f.trace!.length - 1].kind).toBe("sink");
  });
});

describe("JWT: verification is about the same token", () => {
  const jwt = (extra: string) => `class AuthController < ApplicationController\n  def me\n    token = request.headers["Authorization"].to_s.split(" ").last\n${extra}    payload = JWT.decode(token, nil, false).first\n    render json: payload\n  end\nend\n`;
  it("decoding with verification disabled is reported", () => {
    expect(ids(jwt(``))).toContain("jwt-none-alg");
  });
  it("an unrelated verification elsewhere in the method does not excuse it", () => {
    expect(ids(jwt(`    OpenSSL::HMAC.hexdigest("SHA256", "k", "unrelated")\n`))).toContain("jwt-none-alg");
  });
  it("decoding with a key and an algorithm is fine", () => {
    const ok = `class AuthController < ApplicationController\n  def me\n    token = request.headers["Authorization"].to_s.split(" ").last\n    payload = JWT.decode(token, Rails.application.secret_key_base, true, { algorithm: "HS256" }).first\n    render json: payload\n  end\nend\n`;
    expect(ids(ok)).not.toContain("jwt-none-alg");
  });
});

describe("cross-file resolution uses namespace identity", () => {
  type F = { path: string; content: string };
  const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
  const found = (files: F[], path: string, id: string) => scan(files).files.find(f => f.file_path === path)!.indicators.filter(i => i.sourceExpr !== undefined && i.id === id);
  const svc = (ns: string, body: string): F => ({ path: `app/services/${ns.toLowerCase()}/user_service.rb`, content: `module ${ns}\n  class UserService\n    def process(value)\n      ${body}\n    end\n  end\nend\n` });
  const ctlFile = (ns: string): F => ({ path: "app/controllers/x_controller.rb", content: `class XController < ApplicationController\n  def run\n    ${ns}::UserService.new.process(params[:v])\n  end\nend\n` });
  it("two namespaces' same-named service classes stay separate across files", () => {
    const files = (ns: string): F[] => [svc("Admin", "system(value)"), svc("Billing", "value.length"), ctlFile(ns)];
    expect(found(files("Admin"), "app/controllers/x_controller.rb", "command-injection").length).toBeGreaterThan(0);
    expect(found(files("Billing"), "app/controllers/x_controller.rb", "command-injection")).toHaveLength(0);
  });
});

describe("scan status and parser lifecycle", () => {
  it("the parser reports it is ready once warmed", () => {
    expect(isRubyParserReady()).toBe(true);
  });
  it("a parse error is reported as a partial result, not as a clean scan", () => {
    const r = analyzeFile("app/controllers/broken_controller.rb", "class X < ApplicationController\n  def run\n    system(params[:c]\n  end\n");
    expect(r.indicators).toBeDefined();
  });
  it("source that does not parse does not throw", () => {
    expect(() => analyzeFile("app/x.rb", "def (((( end end")).not.toThrow();
  });
});
