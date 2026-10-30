/**
 * C/C++ AST engine: sources (argv, getenv, fgets/recv/scanf/cin into buffers and their aliases), sinks (command,
 * format string, SQL, path, LDAP, curl URL, dlopen), unbounded copies, attacker-sized allocations and the
 * intraprocedural memory-safety checks. Every vulnerable case has a safe twin that must stay silent.
 */
import { warmCppTaintEngine, parseCppSourceSync, scanAstTaintCpp, computeCppFnSinkFacts, type AstTaintCppFinding } from "@/lib/astTaintCpp";
import type { SuppressedSink } from "@/lib/taint/taintCore";
import { analyzeFile } from "@/lib/scanner";
import { dataFlowLanguages } from "@/lib/ruleLanguages";
import { isScannablePath } from "@/lib/scannableFiles";

beforeAll(async () => { await warmCppTaintEngine(); }, 120000);

function scan(code: string, file = "src/main.c", opts?: Parameters<typeof scanAstTaintCpp>[4], suppressed?: SuppressedSink[]): AstTaintCppFinding[] {
  const root = parseCppSourceSync(code, file);
  if (!root) throw new Error("parser not ready");
  return scanAstTaintCpp(code, file, root, suppressed, opts);
}
const ids = (code: string, file?: string) => scan(code, file).map(f => f.id).sort();

describe("sources and command / format sinks", () => {
  it("argv into system is command injection; a literal is not", () => {
    expect(ids(`int main(int argc, char *argv[]) { system(argv[1]); return 0; }`)).toEqual(["command-injection"]);
    expect(ids(`int main(int argc, char *argv[]) { system("ls -l"); return 0; }`)).toEqual([]);
  });

  it("fgets into an alias of the buffer taints the buffer (Juliet data = dataBuffer shape)", () => {
    const bad = `
void f(void) {
  char dataBuffer[100] = "";
  char *data = dataBuffer;
  size_t len = strlen(data);
  if (fgets(data + len, (int)(100 - len), stdin) != NULL) { }
  popen(dataBuffer, "r");
}`;
    expect(ids(bad)).toEqual(["command-injection"]);
    expect(ids(bad.replace(`fgets(data + len, (int)(100 - len), stdin)`, `strcpy(data, "ls")`))).toEqual([]);
  });

  it("getenv as a printf format is format-string; printf(\"%s\", ...) is not", () => {
    expect(ids(`void f(void) { char *e = getenv("X"); printf(e); }`)).toEqual(["format-string"]);
    expect(ids(`void f(void) { char *e = getenv("X"); printf("%s", e); }`)).toEqual([]);
  });

  it("execl through /bin/sh -c with input is command injection; a fixed argv is not", () => {
    expect(ids(`void f(void) { char *d = getenv("X"); execl("/bin/sh", "sh", "-c", d, NULL); }`)).toEqual(["command-injection"]);
    expect(ids(`void f(void) { execl("/bin/sh", "sh", "-c", "ls", NULL); }`)).toEqual([]);
  });

  it("recv into a buffer then system; atoi of it is a number, not a command", () => {
    expect(ids(`void f(int s) { char buf[64]; recv(s, buf, 63, 0); system(buf); }`)).toEqual(["command-injection"]);
    expect(ids(`void f(int s) { char buf[64]; char cmd[64]; recv(s, buf, 63, 0); int n = atoi(buf); sprintf(cmd, "kill %d", n); system(cmd); }`)).toEqual([]);
  });

  it("std::cin >> s and std::string concatenation reach system(c_str())", () => {
    const code = `
#include <iostream>
void f() {
  std::string name;
  std::cin >> name;
  std::string cmd = "ping " + name;
  system(cmd.c_str());
}`;
    expect(ids(code, "src/main.cpp")).toEqual(["command-injection"]);
    expect(ids(code.replace("std::cin >> name;", `name = "localhost";`), "src/main.cpp")).toEqual([]);
  });
});

describe("other injection sinks", () => {
  it("SQL, path, LDAP, curl URL and dlopen take the argument their API defines", () => {
    expect(ids(`void f(sqlite3 *db) { char *q = getenv("Q"); sqlite3_exec(db, q, 0, 0, 0); }`)).toEqual(["sql-injection"]);
    expect(ids(`void f(sqlite3 *db) { char *q = getenv("Q"); sqlite3_exec(db, "SELECT 1", 0, 0, q); }`)).toEqual([]);
    expect(ids(`void f(void) { char *p = getenv("P"); FILE *fp = fopen(p, "r"); }`)).toEqual(["path-traversal"]);
    expect(ids(`void f(void) { char *p = getenv("P"); FILE *fp = fopen("/etc/app.conf", p); }`)).toEqual([]);
    expect(ids(`void f(LDAP *ld) { char *u = getenv("U"); ldap_search_ext_sA(ld, "dc=x", 2, u, 0, 0, 0, 0, 0, 0, 0); }`)).toEqual(["ldap-injection"]);
    expect(ids(`void f(CURL *c) { char *u = getenv("U"); curl_easy_setopt(c, CURLOPT_URL, u); }`)).toEqual(["ssrf"]);
    expect(ids(`void f(CURL *c) { char *u = getenv("U"); curl_easy_setopt(c, CURLOPT_USERAGENT, u); }`)).toEqual([]);
    expect(ids(`void f(void) { char *l = getenv("L"); dlopen(l, 0); }`)).toEqual(["eval-exec"]);
  });

  it("std::ifstream constructed from input is path traversal", () => {
    expect(ids(`void f() { std::string p; std::getline(std::cin, p); std::ifstream in(p); }`, "src/a.cpp")).toEqual(["path-traversal"]);
    expect(ids(`void f() { std::string p; std::getline(std::cin, p); std::ifstream in("data.txt"); }`, "src/a.cpp")).toEqual([]);
  });
});

describe("buffer and size checks", () => {
  it("gets and an unbounded scanf %s are overflows; fgets and %99s are not", () => {
    expect(ids(`void f(void) { char b[10]; gets(b); }`)).toEqual(["buffer-overflow"]);
    expect(ids(`void f(void) { char b[10]; scanf("%s", b); }`)).toEqual(["buffer-overflow"]);
    expect(ids(`void f(void) { char b[100]; scanf("%99s", b); }`)).toEqual([]);
    expect(ids(`void f(void) { char b[10]; fgets(b, sizeof(b), stdin); }`)).toEqual([]);
  });

  it("strcpy of input is an overflow; strncpy with a constant that fits is not", () => {
    expect(ids(`int main(int argc, char **argv) { char d[16]; strcpy(d, argv[1]); return 0; }`)).toEqual(["buffer-overflow"]);
    expect(ids(`int main(int argc, char **argv) { char d[16]; strncpy(d, argv[1], 15); d[15] = 0; return 0; }`)).toEqual([]);
  });

  it("a constant copy longer than the destination array is an overflow (Juliet CWE121 shape)", () => {
    expect(ids(`void f(void) { char d[50]; char s[100]; memset(s, 'C', 99); memcpy(d, s, 100 * sizeof(char)); }`)).toEqual(["buffer-overflow"]);
    expect(ids(`void f(void) { char d[100]; char s[100]; memset(s, 'C', 99); memcpy(d, s, 100 * sizeof(char)); }`)).toEqual([]);
    expect(ids(`void f(void) { char d[10]; strcpy(d, "0123456789"); }`)).toEqual(["buffer-overflow"]);
    expect(ids(`void f(void) { char d[11]; strcpy(d, "0123456789"); }`)).toEqual([]);
  });

  it("a heap buffer's capacity comes from its constant allocation size (Juliet CWE122 shape)", () => {
    const bad = `void f(void) { char *data = NULL; data = (char *)malloc(50*sizeof(char)); if (data == NULL) exit(-1); char source[100]; memset(source, 'C', 99); source[99] = '\\0'; memcpy(data, source, 100*sizeof(char)); free(data); }`;
    expect(ids(bad)).toEqual(["buffer-overflow"]);
    expect(ids(bad.replace("malloc(50*sizeof(char))", "malloc(100*sizeof(char))"))).toEqual([]);
    expect(ids(`void f() { wchar_t *d = new wchar_t[50]; wchar_t s[100]; wmemset(s, L'C', 99); s[99] = L'\\0'; wcscpy(d, s); delete [] d; }`, "src/a.cpp")).toEqual(["buffer-overflow"]);
    expect(ids(`void f() { wchar_t *d = new wchar_t[100]; wchar_t s[100]; wmemset(s, L'C', 99); s[99] = L'\\0'; wcscpy(d, s); delete [] d; }`, "src/a.cpp")).toEqual([]);
  });

  it("a copy is sized by the string's known length, not its buffer's capacity (Juliet CWE121 src_ / CWE806 shapes)", () => {
    const code = (n: number) => `void f(void) { char *data; char dataBuffer[100]; data = dataBuffer; memset(data, 'A', ${n}-1); data[${n}-1] = '\\0'; char dest[50] = ""; strcat(dest, data); }`;
    expect(ids(code(100))).toEqual(["buffer-overflow"]);
    expect(ids(code(50))).toEqual([]);
    const m = (n: number) => `void f(void) { char *data; char dataBuffer[100]; data = dataBuffer; memset(data, 'A', ${n}-1); data[${n}-1] = '\\0'; char dest[50] = ""; memcpy(dest, data, strlen(data)*sizeof(char)); }`;
    expect(ids(m(100))).toEqual(["buffer-overflow"]);
    expect(ids(m(50))).toEqual([]);
    // the length follows strcpy, a literal initialiser and a NUL written short of a memset — not the buffer's capacity
    expect(ids(`void f(void) { char mid[100]; char dest[50]; strcpy(mid, "short"); strcpy(dest, mid); }`)).toEqual([]);
    expect(ids(`void f(void) { char mid[100]; char dest[50]; strcpy(mid, "${"A".repeat(60)}"); strcpy(dest, mid); }`)).toEqual(["buffer-overflow"]);
    expect(ids(`void f(void) { char s[100] = "AAAAAAAAAA"; char d[11]; strcpy(d, s); }`)).toEqual([]);
    expect(ids(`void f(void) { char data[100]; memset(data, 'A', 99); data[49] = '\\0'; char dest[50] = ""; strcat(dest, data); }`)).toEqual([]);
    // CWE193: room for the characters but not the terminator
    expect(ids(`#define SRC "AAAAAAAAAA"\nvoid f(void) { char d[10]; char s[10+1] = SRC; strcpy(d, s); }`)).toEqual(["buffer-overflow"]);
    expect(ids(`#define SRC "AAAAAAAAAA"\nvoid f(void) { char d[10+1]; char s[10+1] = SRC; strcpy(d, s); }`)).toEqual([]);
  });

  it("an attacker-sized malloc needs an upper bound first", () => {
    const bad = `void f(void) { char in[16]; fgets(in, 16, stdin); size_t n = strtoul(in, 0, 10); char *p = (char *)malloc(n); if (!p) return; free(p); }`;
    expect(ids(bad)).toEqual(["integer-overflow"]);
    expect(ids(bad.replace("char *p = (char *)malloc(n);", "if (n > 1024) return; char *p = (char *)malloc(n);"))).toEqual([]);
    expect(ids(bad.replace("char *p = (char *)malloc(n);", "char *p = n < 1024 ? (char *)malloc(16) : 0;"))).toEqual([]);
  });

  it("a constant-bound loop writing past a smaller buffer, through an alias too", () => {
    const loop = (cap: string, bound: string, decl = "char") =>
      `void f(void) { ${decl} *data; ${decl} small[${cap}]; data = small; size_t i; ${decl} src[100]; for (i = 0; i < ${bound}; i++) { data[i] = src[i]; } }`;
    expect(ids(loop("50", "100"))).toEqual(["buffer-overflow"]);
    expect(ids(loop("100", "100"))).toEqual([]);
    expect(ids(loop("50", "100", "int"))).toEqual(["buffer-overflow"]);
    expect(ids(loop("100", "100", "int"))).toEqual([]);
    // alloca'd capacity in bytes vs wchar_t elements
    expect(ids(`void f(void) { wchar_t *d = (wchar_t *)alloca(50*sizeof(wchar_t)); size_t i; for (i = 0; i < 100; i++) d[i] = L'A'; }`)).toEqual(["buffer-overflow"]);
    expect(ids(`void f(void) { wchar_t *d = (wchar_t *)alloca(100*sizeof(wchar_t)); size_t i; for (i = 0; i < 100; i++) d[i] = L'A'; }`)).toEqual([]);
    // <= reaches the bound itself; a variable bound or start says nothing
    expect(ids(`void f(void) { char b[100]; int i; for (i = 0; i <= 100; i++) b[i] = 0; }`)).toEqual(["buffer-overflow"]);
    expect(ids(`void f(int n) { char b[100]; int i; for (i = 0; i < n; i++) b[i] = 0; }`)).toEqual([]);
    expect(ids(`void f(int n) { char b[50]; int i; for (i = n; i < 100; i++) b[i - n] = 0; }`)).toEqual([]);
    expect(ids(`void f(int n) { char b[50]; int i; for (i = n; i < 100; i++) b[i] = 0; }`)).toEqual([]);
  });

  it("so does an attacker-sized new T[n]", () => {
    const bad = `void f() { char in[16]; fgets(in, 16, stdin); size_t n = strtoul(in, 0, 10); char *p = new char[n]; delete [] p; }`;
    expect(ids(bad, "src/a.cpp")).toEqual(["integer-overflow"]);
    expect(ids(bad.replace("char *p = new char[n];", "if (n > 1024) return; char *p = new char[n];"), "src/a.cpp")).toEqual([]);
    expect(ids(bad.replace("new char[n]", "new char[64]"), "src/a.cpp")).toEqual([]);
  });

  it("an attacker-chosen memcpy length is an overflow unless bounded", () => {
    const bad = `void f(int s, char *dst) { int n; recv(s, (char *)&n, sizeof(n), 0); memcpy(dst, "abc", n); }`;
    expect(ids(bad)).toEqual(["buffer-overflow"]);
    expect(ids(bad.replace("memcpy(dst", "if (n < 4) memcpy(dst"))).toEqual([]);
  });
});

describe("memory safety", () => {
  it("use after free and double free; reassignment between them is fine", () => {
    expect(ids(`void f(void) { char *p = (char *)malloc(10); if (p == NULL) return; free(p); p[0] = 'a'; }`)).toEqual(["use-after-free"]);
    expect(ids(`void f(void) { char *p = (char *)malloc(10); if (p == NULL) return; free(p); free(p); }`)).toEqual(["double-free"]);
    expect(ids(`void f(void) { char *p = (char *)malloc(10); if (p == NULL) return; free(p); p = (char *)malloc(5); if (!p) return; p[0] = 'a'; free(p); }`)).toEqual([]);
  });

  it("a free in only one branch is still a double free on that path", () => {
    expect(ids(`void f(int c) { int *p = (int *)malloc(4); if (!p) return; if (c) { free(p); } free(p); }`)).toEqual(["double-free"]);
    expect(ids(`void f(int c) { int *p = (int *)malloc(4); if (!p) return; if (c) { free(p); return; } free(p); }`)).toEqual([]);
  });

  it("an unchecked malloc result dereferenced is a NULL dereference", () => {
    expect(ids(`void f(void) { int *p = (int *)malloc(sizeof(int)); *p = 5; free(p); }`)).toEqual(["null-dereference"]);
    expect(ids(`void f(void) { int *p = (int *)malloc(sizeof(int)); if (p == NULL) exit(1); *p = 5; free(p); }`)).toEqual([]);
  });

  it("malloc/delete, new/free and new[]/delete are mismatched; matching pairs are not", () => {
    expect(ids(`void f() { int *p = new int[10]; delete p; }`, "src/a.cpp")).toEqual(["mismatched-deallocation"]);
    expect(ids(`void f() { int *p = new int; free(p); }`, "src/a.cpp")).toEqual(["mismatched-deallocation"]);
    expect(ids(`void f() { int *p = new int[10]; delete [] p; }`, "src/a.cpp")).toEqual([]);
    expect(ids(`void f() { int *p = new int(3); delete p; }`, "src/a.cpp")).toEqual([]);
  });

  it("range-for variables are a fresh object each loop (sharp's two `for (auto *input : ...) delete input;`)", () => {
    const code = `void f(Baton *b) { for (Input *input : b->a) { delete input; } for (Input *input : b->c) { delete input; } }`;
    expect(ids(code, "src/a.cpp")).toEqual([]);
    expect(ids(`void f(Baton *b) { Input *x = new Input(); for (Input *input : b->a) { delete x; } delete x; }`, "src/a.cpp")).toEqual(["double-free"]);
  });

  it("a free inside a loop that runs once is not a double free; a second free after the loop is (Juliet _17)", () => {
    expect(ids(`void f(void) { int j; char *d = (char *)malloc(10); if (!d) exit(1); for (j = 0; j < 1; j++) { free(d); } }`)).toEqual([]);
    expect(ids(`void f(void) { int j; char *d = (char *)malloc(10); if (!d) exit(1); for (j = 0; j < 1; j++) { free(d); } free(d); }`)).toEqual(["double-free"]);
  });

  it("freeing through a helper that frees its parameter, and through a copy, is a double free (Juliet _41 / _31)", () => {
    const helper = `static void sink(char *data) { free(data); }\n`;
    expect(ids(helper + `void bad(void) { char *d = (char *)malloc(10); if (!d) exit(1); free(d); sink(d); }`)).toEqual(["double-free"]);
    expect(ids(helper + `void good(void) { char *d = (char *)malloc(10); if (!d) exit(1); sink(d); }`)).toEqual([]);
    expect(ids(`void bad(void) { char *d = (char *)malloc(10); if (!d) exit(1); free(d); { char *copy = d; free(copy); } }`)).toEqual(["double-free"]);
    expect(ids(`void good(void) { char *d = (char *)malloc(10); if (!d) exit(1); { char *copy = d; free(copy); } }`)).toEqual([]);
  });

  it("an unchecked malloc/fopen result passed to a dereferencing library call is a NULL dereference (Juliet CWE690)", () => {
    expect(ids(`void f(void) { char *d = (char *)malloc(20); strcpy(d, "Initialize"); free(d); }`)).toEqual(["null-dereference"]);
    expect(ids(`void f(void) { char *d = (char *)malloc(20); if (d == NULL) exit(1); strcpy(d, "Initialize"); free(d); }`)).toEqual([]);
    expect(ids(`void f(void) { FILE *fp = fopen("a.txt", "w"); fputs("x", fp); fclose(fp); }`)).toEqual(["null-dereference"]);
    expect(ids(`void f(void) { FILE *fp = fopen("a.txt", "w"); if (fp != NULL) { fputs("x", fp); fclose(fp); } }`)).toEqual([]);
  });

  it("the allocation state reaches helpers: one that frees it, one that dereferences it; wcsdup is a malloc", () => {
    const sink = `static void sink(int *data) { free(data); }\n`;
    expect(scan(sink + `void bad() { int *d = new int[10]; sink(d); }`, "src/a.cpp").map(f => [f.id, f.line])).toEqual([["mismatched-deallocation", 2]]);
    const use = `static void use(char *data) { strcpy(data, "x"); }\n`;
    expect(scan(use + `void bad(void) { char *d = (char *)malloc(10); use(d); }`).map(f => [f.id, f.line])).toEqual([["null-dereference", 1]]);
    expect(scan(use + `void good(void) { char *d = (char *)malloc(10); if (!d) return; use(d); }`)).toEqual([]);
    expect(scan(sink + `void good() { int *d = (int *)malloc(40); if (!d) exit(1); sink(d); }`, "src/a.cpp")).toEqual([]);
    // the helper's own deallocator is what is compared (Juliet goodG2BSink: new[] released with delete[])
    expect(scan(`static void sink(char *data) { delete [] data; }\nvoid good() { char *d = new char[100]; sink(d); }`, "src/a.cpp")).toEqual([]);
    expect(scan(`static void sink(char *data) { delete [] data; }\nvoid bad() { char *d = (char *)calloc(100, 1); if (!d) exit(1); sink(d); }`, "src/a.cpp").map(f => f.id)).toEqual(["mismatched-deallocation"]);
    expect(ids(`void f() { wchar_t s[] = L"x"; wchar_t *d = wcsdup(s); delete d; }`, "src/a.cpp")).toEqual(["mismatched-deallocation"]);
  });

  it("a tmpnam/mktemp name opened non-exclusively is an insecure temporary file; O_EXCL, \"wx\" and mkstemp are not", () => {
    expect(ids(`void f(void) { char n[L_tmpnam]; tmpnam(n); FILE *fp = fopen(n, "w"); }`)).toEqual(["insecure-temp-file"]);
    expect(ids(`void f(void) { char n[L_tmpnam]; tmpnam(n); FILE *fp = fopen(n, "wx"); }`)).toEqual([]);
    expect(ids(`void f(void) { char *n = tmpnam(NULL); int fd = open(n, O_RDWR|O_CREAT, 0600); }`)).toEqual(["insecure-temp-file"]);
    expect(ids(`void f(void) { char *n = tmpnam(NULL); int fd = open(n, O_RDWR|O_CREAT|O_EXCL, 0600); }`)).toEqual([]);
    expect(ids(`void f(void) { char d[MAX_PATH]; GetTempFileNameA(".", "x", 0, d); HANDLE h = CreateFileA(d, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL); }`)).toEqual(["insecure-temp-file"]);
    expect(ids(`void f(void) { char d[MAX_PATH]; GetTempFileNameA(".", "x", rand() + 1, d); HANDLE h = CreateFileA(d, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL); }`)).toEqual([]);
    expect(ids(`void f(void) { char n[] = "/tmp/xXXXXXX"; int fd = mkstemp(n); }`)).toEqual([]);
  });
});

describe("interprocedural", () => {
  it("a tainted argument reaches a sink inside a local function (Juliet badSink shape)", () => {
    const code = `
static void badSink(char *data) { system(data); }
void bad(void) { char buf[100]; fgets(buf, 100, stdin); badSink(buf); }
void good(void) { char buf[100] = "ls"; badSink(buf); }`;
    const fs = scan(code);
    expect(fs.map(f => [f.id, f.line])).toEqual([["command-injection", 2]]);
  });

  it("a helper that returns input is a source at its call site", () => {
    expect(ids(`static char *read_name(void) { return getenv("NAME"); }\nvoid f(void) { system(read_name()); }`)).toEqual(["command-injection"]);
    expect(ids(`static char *read_name(void) { return "fixed"; }\nvoid f(void) { system(read_name()); }`)).toEqual([]);
  });

  it("parameter -> sink facts cross files, and the caller reports the call", () => {
    const sinkFile = `void run_it(const char *cmd) { system(cmd); }\nvoid log_it(const char *m) { puts(m); }`;
    const root = parseCppSourceSync(sinkFile, "src/sink.c")!;
    const facts = computeCppFnSinkFacts(sinkFile, "src/sink.c", root, new Map());
    expect([...facts.keys()]).toEqual(["run_it"]);
    expect(facts.get("run_it")![0]).toMatchObject({ index: 0, id: "command-injection", file: "src/sink.c", line: 1 });
    const caller = `int main(int argc, char **argv) { run_it(argv[1]); log_it(argv[1]); run_it("ls"); return 0; }`;
    const fs = scan(caller, "src/main.c", { crossFileFacts: facts });
    expect(fs.map(f => [f.id, f.calleeSink?.file])).toEqual([["command-injection", "src/sink.c"]]);
  });

  it("entry-point seeding marks exported string parameters, and only in relaxed mode", () => {
    const code = `void api_exec(const char *cmd) { system(cmd); }`;
    expect(scan(code)).toEqual([]);
    expect(scan(code, "src/api.c", { entryPoints: true }).map(f => [f.id, f.entryPointSeeded])).toEqual([["command-injection", true]]);
    // a library taking a path or a buffer + length from its caller is the caller's contract, not the library's flaw
    expect(scan(`void save(const char *path) { FILE *f = fopen(path, "w"); if (f) fclose(f); }`, "src/api.c", { entryPoints: true })).toEqual([]);
    expect(scan(`void put(char *dst, const char *data, size_t length) { memcpy(dst, data, length); }`, "src/api.c", { entryPoints: true })).toEqual([]);
    // stat / lstat read metadata only
    expect(ids(`int main(int argc, char **argv) { struct stat st; return stat(argv[1], &st); }`)).toEqual([]);
    expect(ids(`int main(int argc, char **argv) { return unlink(argv[1]); }`)).toEqual(["path-traversal"]);
  });

  it("object-like macros name the real API and the real string (#define GETENV getenv / COMMAND_ARG1 \"-c\")", () => {
    const code = `
#define GETENV getenv
#define EXECL execl
#define SHELL "/bin/sh"
#define ARG1 "-c"
void f(void) { char *d = GETENV("X"); EXECL(SHELL, SHELL, ARG1, d, NULL); }`;
    expect(ids(code)).toEqual(["command-injection"]);
    expect(ids(code.replace(`#define SHELL "/bin/sh"`, `#define SHELL "/usr/bin/ls"`))).toEqual([]);
    expect(ids(`#define MKTEMP _wmktemp\n#define OPEN _wopen\nvoid f(void) { wchar_t t[] = L"fnXXXXXX"; wchar_t *n = MKTEMP(t); int fd = OPEN(n, O_RDWR|O_CREAT, 0600); }`)).toEqual(["insecure-temp-file"]);
    // a macro naming a variable (Juliet's #define COMMAND_ARG3 data) and the wide getenv
    expect(ids(`#define ARG3 data\nvoid f(void) { wchar_t *data = _wgetenv(L"X"); char *args[] = {"/bin/sh", "-c", ARG3, NULL}; execv("/bin/sh", args); }`)).toEqual(["command-injection"]);
    expect(ids(`#define ARG3 data\nvoid f(void) { wchar_t *data = L"ls"; char *args[] = {"/bin/sh", "-c", ARG3, NULL}; execv("/bin/sh", args); }`)).toEqual([]);
    expect(ids(`#define MKSTEMP mkstemp\nvoid f(void) { char t[] = "fnXXXXXX"; int fd = MKSTEMP(t); }`)).toEqual([]);
  });

  it("a call through a local function pointer reaches the function it points to (Juliet _44 shape)", () => {
    const code = `
static void badSink(char *data) { system(data); }
void bad(void) { char buf[100]; void (*funcPtr)(char *) = badSink; fgets(buf, 100, stdin); funcPtr(buf); }`;
    expect(scan(code).map(f => [f.id, f.line])).toEqual([["command-injection", 2]]);
    expect(scan(code.replace("fgets(buf, 100, stdin);", `strcpy(buf, "ls");`))).toEqual([]);
  });

  it("a file-scope variable written with input taints its readers; a hypothetical summary seed does not (Juliet _45)", () => {
    const code = `
static char *g_data;
static void badSink(void) { char *data = g_data; system(data); }
void bad(void) { char buf[100]; fgets(buf, 100, stdin); g_data = buf; badSink(); }`;
    expect(scan(code).map(f => [f.id, f.line])).toEqual([["command-injection", 3]]);
    // the only writer stores its own parameter, and nothing calls it with input
    expect(scan(`
static char *g_data;
static void sink(void) { system(g_data); }
void set_data(char *v) { g_data = v; }
void run(void) { set_data("ls"); sink(); }`)).toEqual([]);
  });

  it("the scanner runs the engine on .c / .cpp / .h files and the rule catalog lists C/C++", () => {
    const code = `int main(int argc, char **argv) { printf(argv[1]); return 0; }`;
    for (const file of ["src/main.c", "src/main.cpp", "include/util.h", "src/x.cc"]) {
      const f = analyzeFile(file, code).indicators.find(i => i.id === "format-string");
      expect(f).toMatchObject({ line: 1, severity: "high", confidence: 95 });
    }
    expect(analyzeFile("src/main.py", code).indicators.some(i => i.id === "format-string")).toBe(false);
    expect(dataFlowLanguages("use-after-free")).toEqual(["C/C++"]);
    expect(dataFlowLanguages("command-injection")).toContain("C/C++");
    expect(isScannablePath("include/util.hpp")).toBe(true);
  });

  it("a numeric conversion is recorded as a proof so the regex duplicate is vetoed", () => {
    const suppressed: SuppressedSink[] = [];
    scan(`int main(int argc, char **argv) { char c[32]; sprintf(c, "%d", atoi(argv[1])); system(c); return 0; }`, "src/main.c", undefined, suppressed);
    expect(suppressed).toContainEqual({ id: "command-injection", line: 1 });
  });
});
