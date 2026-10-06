/**
 * @jest-environment node
 *
 * Ruby AST taint engine: recall (every sink family, Rails idioms) and precision (Rails' safe forms, sanitizers,
 * guards), propagation (helpers, blocks, instance variables, heredocs, implicit returns) and BOLA.
 */
import { warmRubyTaintEngine, parseRubySourceSync, scanAstTaintRuby } from "@/lib/astTaintRuby";
import type { SuppressedSink } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmRubyTaintEngine(); }, 120000);

function scan(code: string, file = "app/controllers/users_controller.rb") {
  const root = parseRubySourceSync(code, file);
  if (!root) throw new Error("parse failed");
  const suppressed: SuppressedSink[] = [];
  const findings = scanAstTaintRuby(code, file, root, suppressed);
  return { findings, suppressed, ids: findings.map(f => f.id) };
}
const has = (code: string, id: string) => (scan(code).ids as string[]).includes(id);
const ctl = (body: string, extra = "") => `class UsersController < ApplicationController\n${extra}\n  def show\n${body}\n  end\nend\n`;

describe("SQL injection", () => {
  it("interpolation and concatenation into ActiveRecord queries", () => {
    expect(has(ctl(`    @u = User.where("name = '#{params[:name]}'").first`), "sql-injection")).toBe(true);
    expect(has(ctl(`    name = params[:name]\n    User.where("name = '" + name + "'")`), "sql-injection")).toBe(true);
    expect(has(ctl(`    User.order(params[:sort])`), "sql-injection")).toBe(true);
    expect(has(ctl(`    User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")`), "sql-injection")).toBe(true);
    expect(has(ctl(`    ActiveRecord::Base.connection.execute("DELETE FROM t WHERE x = '#{params[:x]}'")`), "sql-injection")).toBe(true);
    expect(has(ctl(`    User.where(active: true).order("#{params[:col]} DESC")`), "sql-injection")).toBe(true);
  });

  it("a heredoc query", () => {
    expect(has(ctl(`    q = <<~SQL\n      SELECT * FROM users WHERE name = '#{params[:n]}'\n    SQL\n    User.find_by_sql(q)`), "sql-injection")).toBe(true);
  });

  it("Rails' safe forms stay clean", () => {
    expect(has(ctl(`    User.where(name: params[:name])`), "sql-injection")).toBe(false);
    expect(has(ctl(`    User.where("name = ?", params[:name])`), "sql-injection")).toBe(false);
    expect(has(ctl(`    User.where(["name = ? AND x = ?", params[:name], 1])`), "sql-injection")).toBe(false);
    expect(has(ctl(`    User.where({ name: params[:name] })`), "sql-injection")).toBe(false);
    expect(has(ctl(`    id = params[:id].to_i\n    User.find_by_sql("SELECT * FROM users WHERE id = #{id}")`), "sql-injection")).toBe(false);
    expect(has(ctl(`    q = ActiveRecord::Base.connection.quote(params[:q])\n    User.where("name = #{q}")`), "sql-injection")).toBe(false);
    expect(has(ctl(`    User.order(params[:sort].to_sym)`), "sql-injection")).toBe(false);
  });

  it("Enumerable namesakes and non-database execute are not SQL", () => {
    expect(has(ctl(`    names = ["a", "b"]\n    names.count(params[:n])`), "sql-injection")).toBe(false);
    expect(has(ctl(`    job = Job.new\n    job.execute(params[:cmd_name])`), "sql-injection")).toBe(false);
  });

  it("a positively sanitized flow records a suppression (regex-layer veto)", () => {
    const r = scan(ctl(`    id = params[:id].to_i\n    User.find_by_sql("SELECT * FROM users WHERE id = #{id}")`));
    expect(r.suppressed.some(s => s.id === "sql-injection")).toBe(true);
  });
});

describe("command injection", () => {
  it("shell strings, backticks, Open3, Kernel#open", () => {
    expect(has(ctl(`    system("ping -c 1 #{params[:host]}")`), "command-injection")).toBe(true);
    expect(has(ctl("    host = params[:host]\n    out = `ping -c 1 #{host}`"), "command-injection")).toBe(true);
    expect(has(ctl(`    f = params[:f]\n    Open3.capture2("convert #{f} out.png")`), "command-injection")).toBe(true);
    expect(has(ctl(`    data = open(params[:url]).read`), "command-injection")).toBe(true);
    expect(has(ctl(`    system("sh", "-c", params[:cmd])`), "command-injection")).toBe(true);
  });
  it("argv form and escaping are safe", () => {
    expect(has(ctl(`    system("ping", "-c", "1", params[:host])`), "command-injection")).toBe(false);
    expect(has(ctl(`    system("ping -c 1 #{Shellwords.escape(params[:host])}")`), "command-injection")).toBe(false);
    expect(has(ctl(`    system("ping -c 1 #{params[:host].shellescape}")`), "command-injection")).toBe(false);
  });
});

describe("path traversal / SSRF / redirect / deserialization / reflection / XSS / SSTI", () => {
  it("path", () => {
    expect(has(ctl(`    send_file params[:path]`), "path-traversal")).toBe(true);
    expect(has(ctl(`    name = params[:name]\n    File.read(File.join("/data", name))`), "path-traversal")).toBe(true);
    expect(has(ctl(`    Rails.root.join("uploads", params[:f]).read`), "path-traversal")).toBe(true);
    expect(has(ctl(`    render params[:page]`), "path-traversal")).toBe(true);
    expect(has(ctl(`    File.read(File.join("/data", File.basename(params[:name])))`), "path-traversal")).toBe(false);
  });
  it("SSRF, with a fixed host safe", () => {
    expect(has(ctl(`    url = params[:url]\n    Net::HTTP.get(URI(url))`), "ssrf")).toBe(true);
    expect(has(ctl(`    HTTParty.get(params[:url])`), "ssrf")).toBe(true);
    expect(has(ctl(`    HTTParty.get("https://#{params[:host]}/api")`), "ssrf")).toBe(true);
    expect(has(ctl(`    HTTParty.get("https://api.example.com/users/#{params[:id]}")`), "ssrf")).toBe(false);
  });
  it("redirect, with internal targets safe", () => {
    expect(has(ctl(`    redirect_to params[:next]`), "open-redirect")).toBe(true);
    expect(has(ctl(`    target = params[:next]\n    redirect_to target`), "open-redirect")).toBe(true);
    expect(has(ctl(`    redirect_to "/users/#{params[:id]}"`), "open-redirect")).toBe(false);
    expect(has(ctl(`    redirect_to user_path(params[:id])`), "open-redirect")).toBe(false);
    expect(has(ctl(`    redirect_to params[:next], allow_other_host: false`), "open-redirect")).toBe(false);
  });
  it("deserialization", () => {
    expect(has(ctl(`    obj = Marshal.load(Base64.decode64(params[:data]))`), "insecure-deserialization")).toBe(true);
    expect(has(ctl(`    y = params[:y]\n    YAML.load(y)`), "insecure-deserialization")).toBe(true);
    expect(has(ctl(`    YAML.safe_load(params[:y])`), "insecure-deserialization")).toBe(false);
    expect(has(ctl(`    JSON.parse(params[:j])`), "insecure-deserialization")).toBe(false);
  });
  it("reflection and eval", () => {
    expect(has(ctl(`    params[:type].constantize.new`), "eval-exec")).toBe(true);
    expect(has(ctl(`    @u.send(params[:method])`), "eval-exec")).toBe(true);
    expect(has(ctl(`    eval(params[:code])`), "eval-exec")).toBe(true);
    expect(has(ctl(`    @u.send(:name)`), "eval-exec")).toBe(false);
  });
  it("XSS and template injection", () => {
    expect(has(ctl(`    @html = params[:bio].html_safe`), "xss")).toBe(true);
    expect(has(ctl(`    @html = "<b>#{params[:name]}</b>".html_safe`), "xss")).toBe(true);
    expect(has(ctl(`    @html = raw(params[:bio])`), "xss")).toBe(true);
    expect(has(ctl(`    @html = ERB::Util.html_escape(params[:bio]).html_safe`), "xss")).toBe(false);
    expect(has(ctl(`    render inline: params[:tpl]`), "ssti")).toBe(true);
    expect(has(ctl(`    ERB.new(params[:t]).result`), "ssti")).toBe(true);
  });
});

describe("propagation", () => {
  it("through same-file helpers, including implicit return", () => {
    const code = `class UsersController < ApplicationController
  def show
    User.where("name = '#{clean(params[:name])}'")
  end
  private
  def clean(v)
    v.strip.downcase
  end
end`;
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("a helper that sinks its argument (re-walked with the parameter seeded)", () => {
    const code = `class UsersController < ApplicationController
  def show
    lookup(params[:name])
  end
  private
  def lookup(n)
    User.where("name = '#{n}'")
  end
end`;
    expect(scan(code).findings.some(f => f.id === "sql-injection" && f.line === 7)).toBe(true);
  });
  it("strong-params method read without parentheses", () => {
    const code = `class UsersController < ApplicationController
  def update
    User.find(params[:id]).update(user_params)
    User.where("x = '#{search_term}'")
  end
  private
  def search_term
    params[:q]
  end
  def user_params
    params.require(:user).permit!
  end
end`;
    const r = scan(code);
    expect(r.ids).toContain("sql-injection");
    expect(r.ids).toContain("mass-assignment");
  });
  it("block parameters carry the iterated collection", () => {
    expect(has(ctl(`    params[:ids].each { |i| User.where("id = #{i}") }`), "sql-injection")).toBe(true);
    expect(has(ctl(`    params[:files].each do |f|\n      send_file f\n    end`), "path-traversal")).toBe(true);
  });
  it("instance variables set in a before_action reach other actions", () => {
    const code = `class UsersController < ApplicationController
  before_action :set_term
  def index
    User.where("name LIKE '%#{@term}%'")
  end
  private
  def set_term
    @term = params[:term]
  end
end`;
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("a buffer built with << and a parameter named params is not request input", () => {
    expect(has(ctl(`    q = "SELECT * FROM t WHERE x = "\n    q << params[:x]\n    User.find_by_sql(q)`), "sql-injection")).toBe(true);
    const svc = `class Search\n  def run(params)\n    User.where("name = '#{params[:n]}'")\n  end\nend\n`;
    expect(has(svc, "sql-injection")).toBe(false);
  });
});

describe("branches and guards", () => {
  it("an early return on failed validation protects what follows", () => {
    expect(has(ctl(`    sort = params[:sort]\n    return head(:bad_request) unless %w[name email].include?(sort)\n    User.order("#{sort} ASC")`), "sql-injection")).toBe(false);
    expect(has(ctl(`    sort = params[:sort]\n    User.order("#{sort} ASC") if %w[name email].include?(sort)`), "sql-injection")).toBe(false);
  });
  it("a non-guard condition does not clear", () => {
    expect(has(ctl(`    sort = params[:sort]\n    if sort.present?\n      User.order("#{sort} ASC")\n    end`), "sql-injection")).toBe(true);
  });
  it("case/when on literals proves the value", () => {
    expect(has(ctl(`    col = params[:c]\n    case col\n    when "name", "email"\n      User.order("#{col}")\n    end`), "sql-injection")).toBe(false);
  });
  it("a tainted assignment in only one branch still reaches the join", () => {
    expect(has(ctl(`    q = "1"\n    if params[:x]\n      q = params[:x]\n    end\n    User.where("id = #{q}")`), "sql-injection")).toBe(true);
  });
  it("rescue clauses see what the begin body assigned", () => {
    expect(has(ctl(`    begin\n      v = params[:v]\n      risky\n    rescue StandardError => e\n      User.where("x = '#{v}'")\n    end`), "sql-injection")).toBe(true);
  });
});

describe("BOLA", () => {
  const ctrl = (body: string, header = "") => `class PostsController < ApplicationController\n${header}\n${body}\nend\n`;
  it("an unscoped lookup by request id that is then modified", () => {
    expect(has(ctrl(`  def update\n    @post = Post.find(params[:id])\n    @post.update(post_params)\n  end`), "bola-missing-ownership-check")).toBe(true);
    expect(has(ctrl(`  def destroy\n    Post.find(params[:id]).destroy\n  end`), "bola-missing-ownership-check")).toBe(true);
  });
  it("scoped, authorized, owner-checked, or read-only lookups are not reported", () => {
    expect(has(ctrl(`  def update\n    @post = current_user.posts.find(params[:id])\n    @post.update(post_params)\n  end`), "bola-missing-ownership-check")).toBe(false);
    expect(has(ctrl(`  def update\n    @post = Post.find(params[:id])\n    authorize @post\n    @post.update(post_params)\n  end`), "bola-missing-ownership-check")).toBe(false);
    expect(has(ctrl(`  def update\n    @post = Post.find(params[:id])\n    return head(:forbidden) unless @post.user == current_user\n    @post.update(post_params)\n  end`), "bola-missing-ownership-check")).toBe(false);
    expect(has(ctrl(`  def update\n    @post = Post.find(params[:id])\n    @post.update(post_params)\n  end`, `  load_and_authorize_resource`), "bola-missing-ownership-check")).toBe(false);
    expect(has(ctrl(`  def update\n    @post = Post.find_by(id: params[:id], user_id: current_user.id)\n    @post.update(post_params)\n  end`), "bola-missing-ownership-check")).toBe(false);
    expect(has(ctrl(`  def show\n    @post = Post.find(params[:id])\n  end`), "bola-missing-ownership-check")).toBe(false);
  });
});

describe("other checks", () => {
  it("timing attack, JWT without verification, ReDoS, header injection", () => {
    expect(has(ctl(`    head :unauthorized unless params[:token] == ENV["API_TOKEN"]\n    head :ok unless api_token == params[:token]`), "timing-attack")).toBe(true);
    expect(has(ctl(`    JWT.decode(params[:jwt], nil, false)`), "jwt-none-alg")).toBe(true);
    expect(has(ctl(`    Regexp.new(params[:pattern])`), "redos")).toBe(true);
    expect(has(ctl(`    Regexp.new(Regexp.escape(params[:pattern]))`), "redos")).toBe(false);
    expect(has(ctl(`    response.headers["X-Debug"] = params[:d]`), "header-injection")).toBe(true);
  });
  it("cookies: plain is input, signed/encrypted are not", () => {
    expect(has(ctl(`    User.where("id = #{cookies[:uid]}")`), "sql-injection")).toBe(true);
    expect(has(ctl(`    User.where("id = #{cookies.signed[:uid]}")`), "sql-injection")).toBe(false);
  });
  it("request.* input and Sinatra routes", () => {
    expect(has(ctl(`    User.where("ua = '#{request.user_agent}'")`), "sql-injection")).toBe(true);
    const sinatra = `require "sinatra"\nget "/u" do\n  DB.execute("SELECT * FROM u WHERE id = #{params[:id]}")\nend\n`;
    expect(has(sinatra, "sql-injection")).toBe(true);
  });
  it("traces start at the request input and end at the sink", () => {
    const f = scan(ctl(`    name = params[:name]\n    User.where("name = '#{name}'")`)).findings.find(x => x.id === "sql-injection")!;
    expect(f.trace?.[f.trace.length - 1].kind).toBe("sink");
    expect(f.trace?.some(s => /params\[:name\]/.test(s.label) || /params\[:name\]/.test(s.snippet))).toBe(true);
  });
});
