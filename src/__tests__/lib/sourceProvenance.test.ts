/**
 * @jest-environment node
 *
 * Source provenance in the data-flow evidence (Universal Taint Model step 6): what kind of input a flow starts at
 * and how far it is trusted, from the source model that matched there (JVM) or from the recognised input shape.
 */
import { buildDataFlowEvidence, sourceModelAt } from "@/lib/dataFlowEvidence";
import { analyzeFile, jvmParamBinding } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
import type { TraceStep } from "@/lib/taint/taintCore";

const step = (kind: TraceStep["kind"], file: string, line: number, snippet: string, label = snippet): TraceStep => ({ kind, file, line, snippet, label } as TraceStep);
const flow = (file: string, sourceSnippet: string, extra: { sourceAssumed?: boolean } = {}) => buildDataFlowEvidence({
  id: "sql-injection", line: 9, sourceExpr: sourceSnippet, ...extra,
  trace: [step("source", file, 3, sourceSnippet), step("sink", file, 9, "db.query(q)")],
}, file)!.source;

describe("from a source model (JVM)", () => {
  it("a bound request header", () =>
    expect(flow("C.java", "public R h(@RequestHeader(\"X-Id\") String id)")).toMatchObject({ kind: "http.header", trust: "untrusted", model: "java+kt:spring:param-annotation:RequestHeader" }));
  it("the logged-in user's name is semi-trusted", () =>
    expect(flow("C.kt", "val who = request.getRemoteUser()")).toMatchObject({ kind: "identity", trust: "semi-trusted" }));
  it("an upload part", () => expect(flow("C.java", "Part p = request.getPart(\"f\")")).toMatchObject({ kind: "file.upload", trust: "untrusted" }));
  it("an annotation's name only counts as an annotation", () => expect(sourceModelAt(["MyRequestHeader h = parse(raw)"], "C.java")).toBeUndefined());
  it("a model only Kotlin reads is not matched in Java", () => expect(sourceModelAt(["val who = request.getRemoteUser()"], "C.java")).toBeUndefined());
  it("a property source isn't a call of the same name", () => {
    expect(sourceModelAt(["val q = request.queryString"], "C.kt")?.kind).toBe("http.query");
    expect(sourceModelAt(["val q = request.cookies()"], "C.kt")).toBeUndefined();
  });
});

describe("from the input shape (other languages)", () => {
  it("a query parameter", () => expect(flow("a.ts", "req.query.id")).toMatchObject({ kind: "http.query", trust: "untrusted" }));
  it("a parameter that is query or body has no kind, but is still client input", () => {
    const s = flow("a.php", "$_REQUEST['id']");
    expect(s.kind).toBeUndefined();
    expect(s.trust).toBe("untrusted");
  });
  it("an assumed-untrusted parameter: trust says so, and no model is claimed", () => {
    const s = flow("C.java", "@RequestHeader String id", { sourceAssumed: true });
    expect(s).toMatchObject({ trust: "assumed", assumed: true });
    expect(s.model).toBeUndefined();
  });
  it("an unrecognised start claims nothing", () => {
    const s = flow("a.go", "cfg.Name");
    expect(s.kind).toBeUndefined();
    expect(s.trust).toBeUndefined();
  });
});

describe("the binding of a bare-name parameter (jvmParamBinding)", () => {
  const ind = (name: string, line: number) => ({ sourceExpr: name, line, trace: [{ kind: "source", file: "C.java", line, label: name, snippet: name } as TraceStep] });
  const lines = ['  @GetMapping("/u") public void u(@RequestHeader("X-Id") String id, @RequestParam int page) {', "    use(id, page, other);", "  }"];
  it("finds the annotated declaration of that name", () => expect(jvmParamBinding(ind("id", 2), "C.java", lines)).toBe('@RequestHeader("X-Id") String id,'));
  it("not a different parameter's", () => expect(jvmParamBinding(ind("other", 2), "C.java", lines)).toBeUndefined());
  it("Kotlin parameters", () => expect(jvmParamBinding({ ...ind("u", 2), trace: [{ kind: "source", file: "C.kt", line: 2, label: "u", snippet: "u" } as TraceStep] }, "C.kt",
    ['  @GetMapping("/k") fun k(@RequestParam u: String) {', "    use(u)"])).toBe("@RequestParam u:"));
  it("only JVM files", () => expect(jvmParamBinding({ ...ind("id", 2), trace: [{ kind: "source", file: "c.ts", line: 2, label: "id", snippet: "id" } as TraceStep] }, "c.ts", lines)).toBeUndefined());
});

describe("real scanner output", () => {
  beforeAll(async () => { await ensureTaintEngines(); }, 120_000);
  it("a Spring header flowing into SQL carries kind and trust", () => {
    const src = ["import org.springframework.web.bind.annotation.*;", "@RestController", "public class C {", "  private java.sql.Statement st;",
      '  @GetMapping("/u") public void u(@RequestHeader("X-Id") String id) throws Exception {', '    st.executeQuery("SELECT * FROM t WHERE id = \'" + id + "\'");', "  }", "}"].join("\n");
    const f = analyzeFile("C.java", src).indicators.find(i => i.id === "sql-injection" && i.flow);
    expect(f?.flow?.source).toMatchObject({ kind: "http.header", trust: "untrusted" });
  });
});
