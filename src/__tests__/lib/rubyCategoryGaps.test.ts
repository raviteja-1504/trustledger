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

describe("mass assignment from the whole submitted hash", () => {
  it("the request's full hash into a model write, directly, through a local, wrapped or nested", () => {
    expect(ids(handler(`  user = User.create(req.post_data)`))).toContain("mass-assignment");
    expect(ids(handler(`  attrs = req.post_data.merge('admin' => true)\n  User.create(attrs)`))).toContain("mass-assignment");
    expect(ids(handler(`  form = OpenStruct.new(req.post_data)\n  User.create(form.to_h)`))).toContain("mass-assignment");
    expect(ids(handler(`  User.new(profile_attributes: req.post_data)`))).toContain("mass-assignment");
    expect(ids(handler(`  User.update_all(req.post_data)`))).toContain("mass-assignment");
  });
  it("picked keys, explicit attributes, or wrapping the hash to permit it are not", () => {
    expect(ids(handler(`  User.create(req.post_data.slice('name', 'email'))`))).not.toContain("mass-assignment");
    expect(ids(handler(`  attrs = req.post_data.select { |k, _| ALLOWED.include?(k) }\n  User.create(attrs)`))).not.toContain("mass-assignment");
    expect(ids(handler(`  User.create(req.post_data.except('role', 'admin'))`))).not.toContain("mass-assignment");
    expect(ids(handler(`  User.create(name: req.post('name'), email: req.post('email'))`))).not.toContain("mass-assignment");
    expect(ids(handler(`  params = ActionController::Parameters.new(req.post_data)\n  User.create(params.permit(:name).to_h)`))).not.toContain("mass-assignment");
  });
});

describe("SSRF", () => {
  it("connections to a request-chosen host and HTTP client instances", () => {
    expect(ids(handler(`  Socket.tcp(req.param('host'), 80) { |s| s.read(10) }`))).toContain("ssrf");
    expect(ids(handler(`  Net::SMTP.start(req.param('smtp_host'), 25) { |s| s.finish }`))).toContain("ssrf");
    expect(ids(handler(`  Net::LDAP.new(host: req.param('ldap_host')).bind`))).toContain("ssrf");
    expect(ids(handler(`  sess = Patron::Session.new\n  sess.get(req.param('url'))`))).toContain("ssrf");
    expect(ids(handler(`  Async::HTTP::Internet.new.get(req.param('url'))`))).toContain("ssrf");
    expect(ids(handler(`  MiniMagick::Image.open(req.param('url'))`))).toContain("ssrf");
  });
  it("a fixed host, or a local path under a fixed directory, is not", () => {
    expect(ids(handler(`  Socket.tcp('db.internal', 5432) { |s| s.read(10) }`))).not.toContain("ssrf");
    expect(ids(handler(`  path = UPLOAD_DIR + '/' + File.basename(req.param('filename'))\n  MiniMagick::Image.open(path)`))).not.toContain("ssrf");
  });
  it("a request refused when its resolved address is private is cleared; one allowed only when internal is not", () => {
    const fetch = (guard: string) => handler(`  uri = URI.parse(req.param('url'))\n  ip = Resolv.getaddress(uri.host)\n${guard}\n  Net::HTTP.get(uri)`);
    expect(ids(fetch(`  raise 'blocked' if PRIVATE_RANGES.any? { |r| r.include?(IPAddr.new(ip)) }`))).not.toContain("ssrf");
    expect(ids(fetch(`  addr = IPAddr.new(ip)\n  return BenchmarkResponse.bad_request('no') if addr.private? || addr.loopback?`))).not.toContain("ssrf");
    expect(ids(fetch(`  parts = ip.split('.').map(&:to_i)\n  private = parts[0] == 10 || (parts[0] == 192 && parts[1] == 168)\n  return BenchmarkResponse.bad_request('no') if private`))).not.toContain("ssrf");
    expect(ids(fetch(`  return BenchmarkResponse.bad_request('no') unless INTERNAL_RANGES.any? { |r| ip.match?(r) }`))).toContain("ssrf");
    expect(ids(fetch(``))).toContain("ssrf");
  });
});

describe("log injection into the process's streams and log files", () => {
  it("$stderr / STDOUT writes, bare puts, appending to a .log file, Syslog", () => {
    expect(ids(handler(`  $stderr.write("Error: #{req.param('m')}\\n")`))).toContain("log-injection");
    expect(ids(handler(`  puts "DEBUG: #{req.body_str}"`))).toContain("log-injection");
    expect(ids(handler(`  File.open('application.log', 'a') { |f| f.puts(req.param('m')) }`))).toContain("log-injection");
    expect(ids(handler(`  log_file = '/tmp/app.log'\n  File.open(log_file, 'a') { |f| f.puts("A: #{req.param('m')}") }`))).toContain("log-injection");
    expect(ids(handler(`  Syslog.open('app') { |s| s.log(Syslog::LOG_INFO, req.param('u')) }`))).toContain("log-injection");
  });
  it("a data file, a constant, or a value with its line breaks removed is not", () => {
    expect(ids(handler(`  File.open('export.csv', 'a') { |f| f.puts(req.param('m')) }`))).not.toContain("log-injection");
    expect(ids(handler(`  $stderr.write("Error: fixed\\n")`))).not.toContain("log-injection");
    expect(ids(handler(`  puts req.param('m').gsub(/[\\r\\n\\x00]/, ' ')`))).not.toContain("log-injection");
    expect(ids(handler(`  puts req.param('m').gsub(/[[:cntrl:]]/, '?')`))).not.toContain("log-injection");
    expect(ids(handler(`  puts req.param('m').gsub(/[^a-zA-Z0-9_]/, '')`))).not.toContain("log-injection");
    // \\s keeps newlines, and a replacement can put them back: still reported
    expect(ids(handler(`  puts req.param('m').gsub(/[^\\w\\s@.]/, '')`))).toContain("log-injection");
    expect(ids(handler(`  puts req.param('m').gsub(/[^a-zA-Z0-9_]/, "\\n")`))).toContain("log-injection");
  });
});

describe("an alphabet does not make reflection safe", () => {
  it("Object.const_get on an identifier-only value is still unsafe reflection", () => {
    expect(ids(handler(`  safe = req.param('klass').gsub(/[^A-Za-z0-9:]/, '')\n  klass = Object.const_get(safe)`))).toContain("unsafe-reflection");
  });
});
