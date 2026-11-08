/**
 * @jest-environment node
 *
 * C/C++ engine precision checks from an external review, each with a twin:
 *  - a member call runs ITS class's method (in-class or out-of-line, by object, pointer or `this`);
 *  - a lambda's body is analysed where it runs -- called, invoked in place, or handed over as a callback;
 *  - standard-library flows: containers, std::move, optional/element accessors, string streams, std::swap;
 *  - `u.name = x` taints that field, not u's other fields; a global overwritten before the function returns is clean;
 *  - a macro defined in several #ifdef arms names the arm's modelled API;
 *  - freeing a pointer frees its copies; a unique_ptr's reset frees what .get() handed out.
 */
import { parseCppSourceSync, scanAstTaintCpp, warmCppTaintEngine } from "@/lib/astTaintCpp";

beforeAll(async () => { await warmCppTaintEngine(); }, 120000);

const ids = (code: string) => scanAstTaintCpp(code, "src/main.cpp", parseCppSourceSync(code, "src/main.cpp")!).map(f => f.id);
const fn = (body: string, before = "") => `${before}void h() {\n${body}\n}\n`;

describe("a member call runs its own class's method", () => {
  const CL = `class FileService {\npublic:\n  std::string process(std::string input) { return "fixed"; }\n};\nclass CommandService {\npublic:\n  std::string process(std::string input) { return input; }\n};\n`;
  it("by object and by pointer: the method of the receiver's class", () => {
    expect(ids(fn(`  CommandService s;\n  std::system(s.process(getenv("X")).c_str());`, CL))).toContain("command-injection");
    expect(ids(fn(`  FileService s;\n  std::system(s.process(getenv("X")).c_str());`, CL))).not.toContain("command-injection");
    expect(ids(CL + `void h(CommandService* s) {\n  std::system(s->process(getenv("X")).c_str());\n}\n`)).toContain("command-injection");
    expect(ids(CL + `void h(FileService* s) {\n  std::system(s->process(getenv("X")).c_str());\n}\n`)).not.toContain("command-injection");
  });
  it("an out-of-line definition (T::m) belongs to T", () => {
    const OOL = `class P { public: std::string t(std::string x); };\nclass Q { public: std::string t(std::string x); };\nstd::string P::t(std::string x) { return x; }\nstd::string Q::t(std::string x) { return "k"; }\n`;
    expect(ids(fn(`  P p;\n  std::system(p.t(getenv("X")).c_str());`, OOL))).toContain("command-injection");
    expect(ids(fn(`  Q q;\n  std::system(q.t(getenv("X")).c_str());`, OOL))).not.toContain("command-injection");
  });
  it("a sink inside the resolved method is reached; this-> stays in its own class", () => {
    const RN = `class Runner { public: void run(std::string c) { std::system(c.c_str()); } };\nclass Noop { public: void run(std::string c) { (void)c; } };\n`;
    expect(ids(fn(`  Runner r;\n  r.run(getenv("X"));`, RN))).toContain("command-injection");
    expect(ids(fn(`  Noop r;\n  r.run(getenv("X"));`, RN))).not.toContain("command-injection");
    const SELF = `class A {\npublic:\n  std::string wrap(std::string x) { return "k"; }\n  void go() { std::system(this->wrap(getenv("X")).c_str()); }\n};\nclass B { public: std::string wrap(std::string x) { return x; } };\n`;
    expect(ids(SELF)).not.toContain("command-injection");
    // ...and this-> reaches its own class's pass-through even when another class's same-named method doesn't pass
    const SELF2 = `class A {\npublic:\n  std::string wrap(std::string x) { return x; }\n  void go() { std::system(this->wrap(getenv("X")).c_str()); }\n};\nclass B { public: std::string wrap(std::string x) { return "k"; } };\n`;
    expect(ids(SELF2)).toContain("command-injection");
  });
  it("inheritance: an inherited method, and every override a base pointer may run", () => {
    expect(ids(`class Base { public: std::string t(std::string x) { return x; } };\nclass D : public Base {};\nvoid h() {\n  D d;\n  std::system(d.t(getenv("X")).c_str());\n}\n`)).toContain("command-injection");
    const VB = `class Base { public: virtual std::string t(std::string x) { return "k"; } };\nclass Bad : public Base { public: std::string t(std::string x) override { return x; } };\n`;
    expect(ids(VB + `void h(Base* b) {\n  std::system(b->t(getenv("X")).c_str());\n}\n`)).toContain("command-injection");
    expect(ids(`class Base { public: virtual void run(std::string c) {} };\nclass Bad : public Base { public: void run(std::string c) override { std::system(c.c_str()); } };\nvoid h(Base* b) {\n  b->run(getenv("X"));\n}\n`)).toContain("command-injection");
    // an unrelated class's override is not a candidate
    expect(ids(`class Base { public: virtual std::string t(std::string x) { return "k"; } };\nclass Other { public: std::string t(std::string x) { return x; } };\nvoid h(Base* b) {\n  std::system(b->t(getenv("X")).c_str());\n}\n`)).not.toContain("command-injection");
  });
});

describe("callbacks, captures and globals reached through seeding", () => {
  it("std::thread runs a lambda or a function with its arguments; an init capture binds its expression", () => {
    expect(ids(fn(`  std::string input = getenv("X");\n  std::thread t([&]() { std::system(input.c_str()); });\n  t.join();`))).toContain("command-injection");
    expect(ids(`void run(std::string c) { std::system(c.c_str()); }\nvoid h() {\n  std::thread t(run, std::string(getenv("X")));\n  t.join();\n}\n`)).toContain("command-injection");
    expect(ids(`void run(std::string c) { std::system(c.c_str()); }\nvoid h() {\n  std::thread t(run, std::string("ls"));\n  t.join();\n}\n`)).not.toContain("command-injection");
    expect(ids(`void run(std::string c) { std::system(c.c_str()); }\nvoid h() {\n  auto f = std::async(std::launch::async, run, std::string(getenv("X")));\n}\n`)).toContain("command-injection");
    expect(ids(fn(`  auto run = [c = std::string(getenv("X"))]() { std::system(c.c_str()); };\n  run();`))).toContain("command-injection");
    expect(ids(fn(`  auto run = [c = std::string("ls")]() { std::system(c.c_str()); };\n  run();`))).not.toContain("command-injection");
  });
  it("a global written by a function only a seeded call reaches is seen by its readers", () => {
    expect(ids(`std::string g;\nvoid set(std::string input) {\n  g = input;\n}\nvoid h() { set(getenv("X")); }\nvoid run() { std::system(g.c_str()); }\n`)).toContain("command-injection");
    expect(ids(`std::string g;\nvoid set(std::string input) {\n  g = input;\n}\nvoid h() { set("ls"); }\nvoid run() { std::system(g.c_str()); }\n`)).not.toContain("command-injection");
  });
});

describe("memory lifetimes: realloc, container storage, moved-from smart pointers", () => {
  it("realloc frees the old pointer when the result lands elsewhere", () => {
    expect(ids(fn(`  char* p = (char*)malloc(10);\n  if (!p) return;\n  char* q = (char*)realloc(p, 100);\n  if (!q) return;\n  p[0] = 'a';`))).toContain("use-after-free");
    expect(ids(fn(`  char* p = (char*)malloc(10);\n  if (!p) return;\n  p = (char*)realloc(p, 100);\n  if (!p) return;\n  p[0] = 'a';`))).not.toContain("use-after-free");
  });
  it("an iterator / data() pointer used after the container reallocates; before it is fine", () => {
    expect(ids(`void h(std::vector<int>& v) {\n  auto it = v.begin();\n  v.push_back(1);\n  std::cout << *it;\n}\n`)).toContain("use-after-free");
    expect(ids(fn(`  std::vector<char> v(10);\n  char* p = v.data();\n  v.clear();\n  std::cout << p[0];`))).toContain("use-after-free");
    expect(ids(`void h(std::vector<int>& v) {\n  auto it = v.begin();\n  std::cout << *it;\n  v.push_back(1);\n}\n`)).not.toContain("use-after-free");
    expect(ids(`void h(std::vector<int>& v) {\n  auto it = v.begin();\n  v.push_back(1);\n  it = v.begin();\n  std::cout << *it;\n}\n`)).not.toContain("use-after-free");
    // a std::list keeps its nodes in place
    expect(ids(`void h(std::list<int>& v) {\n  auto it = v.begin();\n  v.push_back(1);\n  std::cout << *it;\n}\n`)).not.toContain("use-after-free");
  });
  it("a unique_ptr dereferenced after std::move is empty; reassigned, it is fine", () => {
    expect(ids(fn(`  auto a = std::make_unique<int>(1);\n  auto b = std::move(a);\n  std::cout << *a;`))).toContain("null-dereference");
    expect(ids(fn(`  auto a = std::make_unique<int>(1);\n  auto b = std::move(a);\n  a = std::make_unique<int>(2);\n  std::cout << *a;`))).not.toContain("null-dereference");
  });
});

describe("XXE, deserialization and archive entry names", () => {
  it("libxml2 with entity substitution or DTD loading; the default options are fine", () => {
    expect(ids(`void h(const char* buf, int n) {\n  xmlDocPtr d = xmlReadMemory(buf, n, "x.xml", NULL, XML_PARSE_NOENT);\n}\n`)).toContain("xxe");
    expect(ids(`void h(xmlParserCtxtPtr ctx) {\n  xmlCtxtUseOptions(ctx, XML_PARSE_DTDLOAD | XML_PARSE_NOERROR);\n}\n`)).toContain("xxe");
    expect(ids(`void h() {\n  xmlSubstituteEntitiesDefault(1);\n}\n`)).toContain("xxe");
    expect(ids(`void h(const char* buf, int n) {\n  xmlDocPtr d = xmlReadMemory(buf, n, "x.xml", NULL, XML_PARSE_NONET);\n}\n`)).not.toContain("xxe");
  });
  it("a Boost archive over request bytes; over a constant stream it is not", () => {
    expect(ids(`void h(int fd) {\n  char buf[4096];\n  recv(fd, buf, sizeof(buf), 0);\n  std::istringstream is(buf);\n  boost::archive::text_iarchive ia(is);\n}\n`)).toContain("insecure-deserialization");
    expect(ids(`void h() {\n  std::istringstream is("22 serialization::archive");\n  boost::archive::text_iarchive ia(is);\n}\n`)).not.toContain("insecure-deserialization");
  });
  it("an archive member's name opened as a path; reduced to its basename it is not", () => {
    const loop = (name: string) => `void h(struct archive* a) {\n  struct archive_entry* e;\n  while (archive_read_next_header(a, &e) == ARCHIVE_OK) {\n    const char* name = ${name};\n    FILE* f = fopen(name, "wb");\n  }\n}\n`;
    expect(ids(loop(`archive_entry_pathname(e)`))).toContain("path-traversal");
    expect(ids(loop(`basename((char*)archive_entry_pathname(e))`))).not.toContain("path-traversal");
  });
});

describe("lambdas run where they are called", () => {
  it("[&] / [=] captures, a tainted parameter, an in-place call", () => {
    expect(ids(fn(`  std::string input = getenv("X");\n  auto run = [&]() { std::system(input.c_str()); };\n  run();`))).toContain("command-injection");
    expect(ids(fn(`  std::string input = getenv("X");\n  auto run = [=]() { std::system(input.c_str()); };\n  run();`))).toContain("command-injection");
    expect(ids(fn(`  auto run = [](const std::string& c) { std::system(c.c_str()); };\n  run(getenv("X"));`))).toContain("command-injection");
    expect(ids(fn(`  std::string input = getenv("X");\n  [&]() { std::system(input.c_str()); }();`))).toContain("command-injection");
  });
  it("a callback gets what the container behind the call's iterators holds", () => {
    expect(ids(`void h(std::vector<std::string>& v) {\n  v.push_back(getenv("X"));\n  std::for_each(v.begin(), v.end(), [](const std::string& c) { std::system(c.c_str()); });\n}\n`)).toContain("command-injection");
    expect(ids(`void h(std::vector<std::string>& v) {\n  v.push_back("ls");\n  std::for_each(v.begin(), v.end(), [](const std::string& c) { std::system(c.c_str()); });\n}\n`)).not.toContain("command-injection");
  });
  it("a lambda called with a constant, or never called, reaches no sink", () => {
    expect(ids(fn(`  auto run = [](const std::string& c) { std::system(c.c_str()); };\n  run("ls");`))).not.toContain("command-injection");
    expect(ids(fn(`  std::string input = getenv("X");\n  auto run = [&]() { std::system(input.c_str()); };`))).not.toContain("command-injection");
  });
});

describe("standard-library flows", () => {
  const input = `  std::string input = getenv("X");\n`;
  it("std::move, optional::value, vector::at, a string stream", () => {
    expect(ids(fn(`${input}  std::string cmd = std::move(input);\n  std::system(cmd.c_str());`))).toContain("command-injection");
    expect(ids(fn(`  std::optional<std::string> o = std::string(getenv("X"));\n  std::system(o.value().c_str());`))).toContain("command-injection");
    expect(ids(fn(`  std::vector<std::string> v;\n  v.push_back(getenv("X"));\n  std::system(v.at(0).c_str());`))).toContain("command-injection");
    expect(ids(fn(`${input}  std::stringstream ss;\n  ss << input;\n  std::string cmd;\n  ss >> cmd;\n  std::system(cmd.c_str());`))).toContain("command-injection");
    expect(ids(fn(`  std::stringstream ss;\n  ss << "ls";\n  std::string cmd;\n  ss >> cmd;\n  std::system(cmd.c_str());`))).not.toContain("command-injection");
  });
  it("std::swap moves the value: the other variable now holds it", () => {
    expect(ids(fn(`  std::string a = getenv("X");\n  std::string b = "ls";\n  std::swap(a, b);\n  std::system(b.c_str());`))).toContain("command-injection");
    expect(ids(fn(`  std::string a = getenv("X");\n  std::string b = "ls";\n  std::swap(a, b);\n  std::system(a.c_str());`))).not.toContain("command-injection");
  });
});

describe("fields and globals", () => {
  const user = `struct User { std::string name; std::string role; };\n`;
  it("a field written from input is tainted; its sibling is not; the object as a whole is", () => {
    expect(ids(fn(`  User u;\n  u.name = getenv("X");\n  std::system(u.name.c_str());`, user))).toContain("command-injection");
    expect(ids(fn(`  User u;\n  u.name = getenv("X");\n  std::system(u.role.c_str());`, user))).not.toContain("command-injection");
    expect(ids(user + `void run(User u) { std::system(u.name.c_str()); }\nvoid h() {\n  User u;\n  u.name = getenv("X");\n  run(u);\n}\n`)).toContain("command-injection");
  });
  it("a global keeps what it holds when the writing function returns", () => {
    expect(ids(`char * g;\nvoid set() {\n  g = getenv("X");\n  g = (char*)"ls";\n}\nvoid run() {\n  system(g);\n}\n`)).not.toContain("command-injection");
    expect(ids(`char * g;\nvoid set() {\n  g = getenv("X");\n}\nvoid run() {\n  system(g);\n}\n`)).toContain("command-injection");
    // cleared in another function: which runs first is unknown, so it may still hold the input
    expect(ids(`char * g;\nvoid set() {\n  g = getenv("X");\n}\nvoid clear() {\n  g = (char*)"ls";\n}\nvoid run() {\n  system(g);\n}\n`)).toContain("command-injection");
  });
});

describe("macros defined in several preprocessor arms", () => {
  it("name the arm's modelled API, whichever arm comes first", () => {
    expect(ids(`#ifdef _WIN32\n#define EXECUTE WinExec\n#else\n#define EXECUTE system\n#endif\nvoid h() {\n  EXECUTE(getenv("X"));\n}\n`)).toContain("command-injection");
    expect(ids(`#ifdef DEBUG\n#define RUN log_line\n#else\n#define RUN system\n#endif\nvoid h() {\n  RUN(getenv("X"));\n}\n`)).toContain("command-injection");
    expect(ids(`#ifdef DEBUG\n#define RUN log_line\n#else\n#define RUN puts\n#endif\nvoid h() {\n  RUN(getenv("X"));\n}\n`)).not.toContain("command-injection");
  });
});

describe("lifetimes through copies and smart pointers", () => {
  it("freeing a pointer frees its copies; a copy freed again is a double free", () => {
    expect(ids(fn(`  char* ptr = new char[100];\n  char* alias = ptr;\n  delete[] ptr;\n  std::cout << alias[0];`))).toContain("use-after-free");
    expect(ids(fn(`  char* ptr = new char[100];\n  char* alias = ptr;\n  delete[] ptr;\n  delete[] alias;`))).toContain("double-free");
    expect(ids(fn(`  char* ptr = new char[100];\n  char* alias = ptr;\n  alias = new char[10];\n  delete[] ptr;\n  std::cout << alias[0];`))).not.toContain("use-after-free");
  });
  it("a unique_ptr's reset or reassignment leaves its .get() pointers dangling; before it they are fine", () => {
    expect(ids(fn(`  auto ptr = std::make_unique<int>(10);\n  int* raw = ptr.get();\n  ptr.reset();\n  std::cout << *raw;`))).toContain("use-after-free");
    expect(ids(fn(`  std::unique_ptr<int> ptr(new int(1));\n  int* raw = ptr.get();\n  ptr = nullptr;\n  std::cout << *raw;`))).toContain("use-after-free");
    expect(ids(fn(`  auto ptr = std::make_unique<int>(10);\n  int* raw = ptr.get();\n  std::cout << *raw;\n  ptr.reset();`))).not.toContain("use-after-free");
    // a shared_ptr may have other owners: not judged
    expect(ids(fn(`  auto ptr = std::make_shared<int>(10);\n  int* raw = ptr.get();\n  ptr.reset();\n  std::cout << *raw;`))).not.toContain("use-after-free");
  });
});
