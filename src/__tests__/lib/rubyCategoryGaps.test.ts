/**
 * @jest-environment node
 *
 * Ruby checks for the sast-benchmark categories that scored zero: an upload saved under its client-chosen name,
 * define_method with a request-chosen name, and a session cookie set by a hand-written Set-Cookie header without
 * HttpOnly / Secure. Each has a twin that stays silent.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";

beforeAll(async () => { await warmRubyTaintEngine(); }, 120000);

const handler = (body: string) => `require_relative 'shared'\ndef handler(req)\n${body}\nend\n`;
const ids = (code: string) => analyzeFile("testcode/h.rb", code).indicators.map(i => i.id);

describe("file upload", () => {
  it("the client's filename in the destination; a generated name is not", () => {
    expect(ids(handler(`  upload = req.file('file')\n  original_name = upload[:filename]\n  File.write("/uploads/#{original_name}", upload[:data])\n  BenchmarkResponse.ok('uploaded')`))).toContain("insecure-file-upload");
    expect(ids(handler(`  upload = req.file('file')\n  name = SecureRandom.hex(16) + '.bin'\n  File.write("/uploads/#{name}", upload[:data])\n  BenchmarkResponse.ok('uploaded')`))).not.toContain("insecure-file-upload");
  });
});

describe("dynamic methods", () => {
  it("define_method / send with a request-chosen name", () => {
    expect(ids(handler(`  method_name = req.param('method')\n  Worker.define_method(method_name) { |*a| a }\n  BenchmarkResponse.ok('ok')`))).toContain("unsafe-reflection");
    expect(ids(handler(`  Worker.define_method(:run) { |*a| a }\n  BenchmarkResponse.ok('ok')`))).not.toContain("unsafe-reflection");
  });

  it("an allow-list check before send clears it, whether the list is a constant or a local", () => {
    const send = (guard: string) => `ALLOWED = %w[start stop].freeze\n` + handler(`  action = req.param('action')\n${guard}  BenchmarkResponse.ok(Service.new.send(action))`);
    expect(ids(send(""))).toContain("unsafe-reflection");
    expect(ids(send(`  return BenchmarkResponse.bad_request('no') unless ALLOWED.include?(action)\n`))).not.toContain("unsafe-reflection");
    expect(ids(send(`  allowed = %w[start stop]\n  return BenchmarkResponse.bad_request('no') unless allowed.include?(action)\n`))).not.toContain("unsafe-reflection");
    expect(ids(send(`  allowed = req.param('list').split(',')\n  return BenchmarkResponse.bad_request('no') unless allowed.include?(action)\n`))).toContain("unsafe-reflection");
  });
});

describe("file inclusion", () => {
  it("load of a request-built path; a basename, or a resolved path checked against its base, is confined", () => {
    expect(ids(handler(`  name = req.param('plugin')\n  load("plugins/#{name}.rb")\n  BenchmarkResponse.ok('ok')`))).toContain("file-inclusion");
    expect(ids(handler(`  name = File.basename(req.param('plugin'), '.rb')\n  load("plugins/#{name}.rb")\n  BenchmarkResponse.ok('ok')`))).not.toContain("file-inclusion");
    expect(ids(handler(`  c = File.realpath(File.join(BASE, req.param('f') + '.rb'))\n  raise 'outside' unless c.start_with?(BASE)\n  load(c)\n  BenchmarkResponse.ok('ok')`))).not.toContain("file-inclusion");
  });
});

describe("hand-written Set-Cookie", () => {
  it("a session cookie without HttpOnly or Secure; with both, or a preference cookie, it is not", () => {
    const set = (v: string) => handler(`  session_id = req.param('session_id')\n  response = BenchmarkResponse.ok('ok')\n  response.headers['Set-Cookie'] = "${v}"\n  response`);
    expect(ids(set("session=#{session_id}"))).toContain("cookie-no-httponly");
    expect(ids(set("session=#{session_id}; HttpOnly"))).toContain("cookie-no-secure");
    expect(ids(set("session=#{session_id}; HttpOnly; Secure; SameSite=Strict"))).not.toContain("cookie-no-httponly");
    expect(ids(set("session=#{session_id}; HttpOnly; Secure; SameSite=Strict"))).not.toContain("cookie-no-secure");
    expect(ids(set("theme=dark"))).not.toContain("cookie-no-httponly");
  });
});
