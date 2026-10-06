/**
 * @jest-environment node
 *
 * Kotlin cross-file evidence through runScan. Kotlin and Java share one `Class.method` fact namespace and are
 * converged together, so a controller in either language that hands request input to a service in either
 * language is reported at the call -- and stays quiet when the service binds the value safely.
 */
import { runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { warmKotlinTaintEngine } from "@/lib/astTaintKotlin";

beforeAll(async () => { await warmKotlinTaintEngine(); }, 120000);

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const ast = (r: ReturnType<typeof scan>, path: string, id: string): ScanIndicator[] =>
  r.files.find(f => f.file_path === path)!.indicators.filter(i => i.confidence === 95 && i.id === id);

const KT_CTL = "src/main/kotlin/app/UserController.kt";
const ktController = (call: string) => `@RestController
class UserController(private val users: UserService) {
  @GetMapping("/users")
  fun search(@RequestParam name: String): Any {
    return ${call}
  }
}
`;
const KT_SERVICE: F = { path: "src/main/kotlin/app/UserService.kt", content: `@Service
class UserService(private val jdbc: JdbcTemplate) {
  fun find(name: String): Any = jdbc.queryForList("SELECT * FROM users WHERE name = '$name'")
  fun findSafe(name: String): Any = jdbc.queryForList("SELECT * FROM users WHERE name = ?", name)
}
` };

describe("Kotlin -> Kotlin", () => {
  it("an injected service that sinks its parameter is reported at the controller call", () => {
    const r = scan([KT_SERVICE, { path: KT_CTL, content: ktController("users.find(name)") }]);
    const f = ast(r, KT_CTL, "sql-injection");
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(5);
    expect(f[0].sinkExpr).toContain("UserService.find");
  });

  it("two tainted arguments reaching two SQL sinks are one finding at the call", () => {
    const svc: F = { path: KT_SERVICE.path, content: KT_SERVICE.content.replace("  fun findSafe", `  fun both(a: String, b: String): Any {\n    jdbc.update("UPDATE u SET seen = 1 WHERE a = '$a'")\n    return jdbc.queryForList("SELECT * FROM u WHERE b = '$b'")\n  }\n  fun findSafe`) };
    expect(ast(scan([svc, { path: KT_CTL, content: ktController("users.both(name, name)") }]), KT_CTL, "sql-injection")).toHaveLength(1);
  });

  it("no report for the safe method, a literal argument, or without the service in the batch", () => {
    expect(ast(scan([KT_SERVICE, { path: KT_CTL, content: ktController("users.findSafe(name)") }]), KT_CTL, "sql-injection")).toHaveLength(0);
    expect(ast(scan([KT_SERVICE, { path: KT_CTL, content: ktController(`users.find("bob")`) }]), KT_CTL, "sql-injection")).toHaveLength(0);
    expect(ast(scan([{ path: KT_CTL, content: ktController("users.find(name)") }]), KT_CTL, "sql-injection")).toHaveLength(0);
  });

  it("an object / companion function and a top-level function in another file", () => {
    const util: F = { path: "src/main/kotlin/app/Files.kt", content: `object Storage {\n  fun read(p: String) = File("/data", p).readText()\n}\nfun runCmd(c: String) = Runtime.getRuntime().exec(c)\n` };
    expect(ast(scan([util, { path: KT_CTL, content: ktController("Storage.read(name)") }]), KT_CTL, "path-traversal")).toHaveLength(1);
    expect(ast(scan([util, { path: KT_CTL, content: ktController("runCmd(name)") }]), KT_CTL, "command-injection")).toHaveLength(1);
  });

  it("through an interface the controller depends on", () => {
    const iface: F = { path: "src/main/kotlin/app/Repo.kt", content: `interface Repo { fun raw(q: String): Any }\nclass JdbcRepo(private val jdbc: JdbcTemplate) : Repo {\n  override fun raw(q: String): Any = jdbc.queryForList("SELECT * FROM t WHERE a = '$q'")\n}\n` };
    const ctl: F = { path: KT_CTL, content: `@RestController\nclass C(private val repo: Repo) {\n  @GetMapping("/x")\n  fun x(@RequestParam q: String) = repo.raw(q)\n}\n` };
    expect(ast(scan([iface, ctl]), KT_CTL, "sql-injection")).toHaveLength(1);
  });
});

describe("Kotlin <-> Java", () => {
  it("a Kotlin controller calling a Java service", () => {
    const javaSvc: F = { path: "src/main/java/app/UserService.java", content: `package app;
public class UserService {
  private JdbcTemplate jdbcTemplate;
  public java.util.List<?> find(String name) {
    return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
  }
}
` };
    expect(ast(scan([javaSvc, { path: KT_CTL, content: ktController("users.find(name)") }]), KT_CTL, "sql-injection")).toHaveLength(1);
  });

  it("a Java controller calling a Kotlin service", () => {
    const javaCtl: F = { path: "src/main/java/app/UserController.java", content: `package app;
@RestController
public class UserController {
  @Autowired private UserService users;
  @GetMapping("/users")
  public Object search(@RequestParam String name) {
    return users.find(name);
  }
}
` };
    expect(ast(scan([KT_SERVICE, javaCtl]), javaCtl.path, "sql-injection")).toHaveLength(1);
  });
});
