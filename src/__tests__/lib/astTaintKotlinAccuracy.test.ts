/**
 * @jest-environment node
 *
 * Kotlin AST taint engine accuracy: deferred lambda execution, function identity (same-named methods of different
 * classes), BOLA helper evidence tied to the record and the write, finding identity, scan status / parser lifecycle.
 */
import { warmKotlinTaintEngine, parseKotlinSourceSync, scanAstTaintKotlin, getKotlinEngineStatus } from "@/lib/astTaintKotlin";
import type { SuppressedSink } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmKotlinTaintEngine(); }, 120000);

function scan(code: string) {
  const root = parseKotlinSourceSync(code, "Api.kt");
  if (!root) throw new Error("parse failed");
  const suppressed: SuppressedSink[] = [];
  return scanAstTaintKotlin(code, "Api.kt", root, suppressed, {});
}
const ids = (code: string) => scan(code).map(f => f.id as string);
const ctl = (body: string, extra = "") =>
  `@RestController\nclass Api(private val jdbc: JdbcTemplate) {\n${extra}\n${body}\n}\n`;
const handler = (body: string, extra = "") => ctl(`  @GetMapping("/x")\n  fun x(@RequestParam cmd: String): String {\n${body}\n    return "OK"\n  }`, extra);

describe("lambdas are deferred execution", () => {
  it("a lambda that is never invoked does not run", () => {
    expect(ids(handler(`    val task = { Runtime.getRuntime().exec(cmd) }`))).not.toContain("command-injection");
  });
  it("a lambda that is invoked does", () => {
    expect(ids(handler(`    val task = { Runtime.getRuntime().exec(cmd) }\n    task()`))).toContain("command-injection");
    expect(ids(handler(`    val task = { Runtime.getRuntime().exec(cmd) }\n    task.invoke()`))).toContain("command-injection");
  });
  it("a lambda invoked conditionally still counts", () => {
    expect(ids(handler(`    val task = { Runtime.getRuntime().exec(cmd) }\n    if (cmd.length > 3) { task() }`))).toContain("command-injection");
  });
  it("a parameterised lambda gets its argument's taint", () => {
    expect(ids(handler(`    val run = { c: String -> Runtime.getRuntime().exec(c) }\n    run(cmd)`))).toContain("command-injection");
    expect(ids(handler(`    val run = { c: String -> Runtime.getRuntime().exec(c) }\n    run("ls")`))).not.toContain("command-injection");
  });
  it("re-binding the name drops the old lambda", () => {
    expect(ids(handler(`    var task = { Runtime.getRuntime().exec(cmd) }\n    task = { Runtime.getRuntime().exec("ls") }\n    task()`))).not.toContain("command-injection");
  });
  it("scope functions and collection lambdas still run immediately", () => {
    expect(ids(handler(`    cmd.let { Runtime.getRuntime().exec(it) }`))).toContain("command-injection");
    expect(ids(handler(`    listOf(cmd).forEach { Runtime.getRuntime().exec(it) }`))).toContain("command-injection");
  });
  it("a trailing lambda given to a function that never calls it does not run", () => {
    const extra = `  private fun ignore(block: () -> Unit) {}`;
    expect(ids(handler(`    ignore { Runtime.getRuntime().exec(cmd) }`, extra))).not.toContain("command-injection");
  });
  it("a trailing lambda given to a function that calls it does", () => {
    const extra = `  private fun apply2(block: () -> Unit) { block() }`;
    expect(ids(handler(`    apply2 { Runtime.getRuntime().exec(cmd) }`, extra))).toContain("command-injection");
  });
});

describe("function identity", () => {
  const two = (call: string) =>
    `class UserService { fun find(id: String): String = "fixed" }\nclass OrderService { fun find(id: String): String = id }\n` +
    `@RestController\nclass Api(private val jdbc: JdbcTemplate) {\n  @GetMapping("/x")\n  fun x(@RequestParam q: String): Any {\n${call}\n  }\n}\n`;
  it("same-named methods of different classes are separate", () => {
    expect(ids(two(`    val s = OrderService()\n    return jdbc.queryForList("SELECT * FROM t WHERE a = '" + s.find(q) + "'")`))).toContain("sql-injection");
    expect(ids(two(`    val s = UserService()\n    return jdbc.queryForList("SELECT * FROM t WHERE a = '" + s.find(q) + "'")`))).not.toContain("sql-injection");
  });
});

describe("BOLA: authorization evidence must name the record and precede the write", () => {
  const bola = (body: string) =>
    `@RestController\nclass OrderApi(private val orderRepository: OrderRepository) {\n  @DeleteMapping("/orders/{id}")\n  fun remove(@PathVariable id: Long, @AuthenticationPrincipal user: UserDetails): String {\n${body}\n    return "ok"\n  }\n}\n`;
  const has = (code: string) => ids(code).includes("bola-missing-ownership-check");
  it("no check flags", () => {
    expect(has(bola(`    val order = orderRepository.findById(id)\n    orderRepository.delete(order)`))).toBe(true);
  });
  it("an unrelated authorize(user) does not prove ownership", () => {
    expect(has(bola(`    val order = orderRepository.findById(id)\n    authorize(user)\n    orderRepository.delete(order)`))).toBe(true);
  });
  it("an authorization helper given the record is ownership evidence", () => {
    expect(has(bola(`    val order = orderRepository.findById(id)\n    assertOwner(user, order)\n    orderRepository.delete(order)`))).toBe(false);
  });
  it("a helper that runs after the write protects nothing", () => {
    expect(has(bola(`    orderRepository.deleteById(id)\n    assertOwner(user, id)`))).toBe(true);
  });
});

describe("finding identity", () => {
  it("two sink calls of one class on a line are two findings", () => {
    const code = handler(`    Runtime.getRuntime().exec(cmd); Runtime.getRuntime().exec(cmd)`);
    expect(scan(code).filter(f => f.id === "command-injection").length).toBe(2);
  });
  it("one call is one finding", () => {
    expect(scan(handler(`    Runtime.getRuntime().exec(cmd)`)).filter(f => f.id === "command-injection").length).toBe(1);
  });
});

describe("scan status and parser lifecycle", () => {
  it("is ready after warm-up", () => { expect(getKotlinEngineStatus().status).toBe("ready"); });
  it("records an analysis failure instead of silently returning clean", () => {
    const root = parseKotlinSourceSync("fun main() {}", "A.kt")!;
    const bad = { get type(): string { throw new Error("boom"); } } as unknown as typeof root;
    expect(scanAstTaintKotlin("fun main() {}", "A.kt", bad, [], {})).toEqual([]);
    expect(getKotlinEngineStatus().lastError).toMatch(/analysis_failed/);
  });
});
