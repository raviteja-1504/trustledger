/**
 * Ruby line-based taint pass (rubyTaint.ts): the pattern layer that also covers Ruby when the tree-sitter
 * grammar isn't loaded. Tested on its own -- the AST engine has its own suite (astTaintRuby.test.ts).
 */
import { findRubyTaintFindings, rubyFirstArg, rubyReferencedNames, rubyTaintedNames } from "@/lib/rubyTaint";
import { analyzeFile } from "@/lib/scanner";
import { isRubyParserReady } from "@/lib/astTaintRuby";

it("runs inside the scanner for .rb files (the fallback when the Ruby grammar isn't loaded)", () => {
  expect(isRubyParserReady()).toBe(false);   // this file never warms the grammar: only the line layer can report
  const code = `class UsersController < ApplicationController\n  def show\n    h = params[:h]\n    out = \`ping #{h}\`\n  end\nend\n`;
  const found = (analyzeFile("app/controllers/users_controller.rb", code).indicators ?? []).filter(i => i.id === "command-injection");
  expect(found.map(i => i.line)).toContain(4);
});

const ids = (code: string) => findRubyTaintFindings(code.split("\n")).map(f => f.id);
const has = (code: string, id: string) => ids(code).includes(id);

describe("sources and propagation", () => {
  it("params / cookies / request.* through assignments, interpolation and ivars", () => {
    const t = rubyTaintedNames([
      "name = params[:name]", "@q = \"x #{name}\"", "c = cookies[:c]", "b = request.body.read",
      "n = params[:id].to_i", "safe = Shellwords.escape(params[:x])", "lit = \"fixed\"",
    ]);
    for (const v of ["name", "@q", "c", "b"]) expect(t.has(v)).toBe(true);
    for (const v of ["n", "safe", "lit"]) expect(t.has(v)).toBe(false);
  });

  it("names used in code and interpolation, not symbols, hash keys, comments or single-quoted strings", () => {
    expect(rubyReferencedNames(`foo(name: bar, :baz) # qux`)).toEqual(expect.arrayContaining(["foo", "bar"]));
    expect(rubyReferencedNames(`foo(name: bar, :baz) # qux`)).not.toEqual(expect.arrayContaining(["name"]));
    expect(rubyReferencedNames(`foo(name: bar, :baz) # qux`)).not.toContain("baz");
    expect(rubyReferencedNames(`foo(name: bar, :baz) # qux`)).not.toContain("qux");
    expect(rubyReferencedNames(`"a #{x} b"`)).toContain("x");
    expect(rubyReferencedNames(`'a #{x} b'`)).not.toContain("x");
    expect(rubyReferencedNames(`%Q(a #{y})`)).toContain("y");
    expect(rubyReferencedNames(`request.headers["X"]`)).toContain("params");
  });

  it("first argument ignores commas inside brackets and strings", () => {
    expect(rubyFirstArg(`"a, b", c`)).toBe(`"a, b"`);
    expect(rubyFirstArg(`foo(a, b), c`)).toBe(`foo(a, b)`);
  });
});

describe("sinks", () => {
  it("SQL: interpolation reported, Rails' safe forms not", () => {
    expect(has(`User.where("name = '#{params[:n]}'")`, "sql-injection")).toBe(true);
    expect(has(`q = params[:q]\nUser.find_by_sql("SELECT * FROM u WHERE a = " + q)`, "sql-injection")).toBe(true);
    expect(has(`User.where(name: params[:n])`, "sql-injection")).toBe(false);
    expect(has(`User.where("name = ?", params[:n])`, "sql-injection")).toBe(false);
  });

  it("command: system/backticks/%x and a shell -c argument; argv form with a fixed program is safe", () => {
    expect(has(`system("ping #{params[:h]}")`, "command-injection")).toBe(true);
    expect(has("h = params[:h]\nout = `ping #{h}`", "command-injection")).toBe(true);
    expect(has(`h = params[:h]\nout = %x(ping #{h})`, "command-injection")).toBe(true);
    expect(has(`system("sh", "-c", params[:cmd])`, "command-injection")).toBe(true);
    expect(has(`system("gzip", "-k", params[:f])`, "command-injection")).toBe(false);
    expect(has(`system("ping #{Shellwords.escape(params[:h])}")`, "command-injection")).toBe(true); // inline: line layer is coarse
    expect(has(`h = Shellwords.escape(params[:h])\nsystem("ping #{h}")`, "command-injection")).toBe(false);
  });

  it("path, SSRF, redirect, deserialization, reflection, XSS, SSTI", () => {
    expect(has(`send_file params[:path]`, "path-traversal")).toBe(true);
    expect(has(`File.read(Rails.root.join("x", params[:f]))`, "path-traversal")).toBe(true);
    expect(has(`f = File.basename(params[:f])\nFile.read(f)`, "path-traversal")).toBe(false);
    expect(has(`Net::HTTP.get(URI(params[:url]))`, "ssrf")).toBe(true);
    expect(has(`redirect_to params[:next]`, "open-redirect")).toBe(true);
    expect(has(`redirect_to root_path`, "open-redirect")).toBe(false);
    expect(has(`Marshal.load(params[:blob])`, "insecure-deserialization")).toBe(true);
    expect(has(`obj.send(params[:m])`, "eval-exec")).toBe(true);
    expect(has(`params[:klass].constantize`, "eval-exec")).toBe(true);
    expect(has(`params[:bio].html_safe`, "xss")).toBe(true);
    expect(has(`raw params[:bio]`, "xss")).toBe(true);
    expect(has(`render inline: params[:tpl]`, "ssti")).toBe(true);
  });

  it("commented-out lines and untainted values are not reported; one finding per id per line", () => {
    expect(ids(`# system(params[:c])`)).toEqual([]);
    expect(ids(`x = "ls"\nsystem(x)`)).toEqual([]);
    expect(ids(`system(params[:a]); system(params[:b])`)).toEqual(["command-injection"]);
  });
});
