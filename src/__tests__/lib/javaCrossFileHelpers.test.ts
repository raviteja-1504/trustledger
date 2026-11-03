/**
 * @jest-environment node
 *
 * Java facts about other files' classes, as they shape a servlet's own analysis: a method of another class that
 * returns what it is given (an interface implemented in the batch) carries taint even when the call sits in a local
 * helper; one that returns only a literal is a constant, so SQL built from it is no finding at all -- the regex
 * layer's line guess is vetoed by the engine's proof.
 */
import { runScan } from "@/lib/scanner";

const THING = [
  { path: "helpers/ThingInterface.java", content: "package com.example.helpers;\npublic interface ThingInterface {\n  public String doSomething(String i);\n}\n" },
  { path: "helpers/Thing1.java", content: "package com.example.helpers;\npublic class Thing1 implements ThingInterface {\n  public String doSomething(String i) {\n    String r = i;\n    return r;\n  }\n}\n" },
  { path: "helpers/ThingFactory.java", content: "package com.example.helpers;\npublic class ThingFactory {\n  public static ThingInterface createThing() {\n    return new Thing1();\n  }\n}\n" },
];
const REQUEST = { path: "helpers/SeparateClassRequest.java", content: [
  "package com.example.helpers;",
  "import javax.servlet.http.HttpServletRequest;",
  "public class SeparateClassRequest {",
  "  private HttpServletRequest request;",
  "  public SeparateClassRequest(HttpServletRequest request) { this.request = request; }",
  "  public String getTheParameter(String p) { return request.getParameter(p); }",
  "  public String getTheValue(String p) { return \"bar\"; }",
  "}",
].join("\n") };

const servlet = (read: string, viaHelper: boolean) => ({ path: "app/Svc.java", content: [
  "package app;",
  "import javax.servlet.http.*;",
  "public class Svc extends HttpServlet {",
  "  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {",
  "    com.example.helpers.SeparateClassRequest scr = new com.example.helpers.SeparateClassRequest(request);",
  `    String param = scr.${read}("v");`,
  viaHelper ? "    String bar = doSomething(request, param);" : "    com.example.helpers.ThingInterface thing = com.example.helpers.ThingFactory.createThing();\n    String bar = thing.doSomething(param);",
  "    String sql = \"SELECT * from USERS where PASSWORD='\" + bar + \"'\";",
  "    java.sql.Connection connection = com.example.helpers.DatabaseHelper.getSqlConnection();",
  "    java.sql.PreparedStatement statement = connection.prepareStatement(sql);",
  "    statement.execute();",
  "  }",
  "  private static String doSomething(HttpServletRequest request, String param) {",
  "    com.example.helpers.ThingInterface thing = com.example.helpers.ThingFactory.createThing();",
  "    String bar = thing.doSomething(param);",
  "    return bar;",
  "  }",
  "}",
].join("\n") });

// a subclass may override the constant method with one that returns request input
const OVERRIDE = { path: "helpers/LiveRequest.java", content: [
  "package com.example.helpers;",
  "import javax.servlet.http.HttpServletRequest;",
  "public class LiveRequest extends SeparateClassRequest {",
  "  private HttpServletRequest req;",
  "  public LiveRequest(HttpServletRequest request) { super(request); this.req = request; }",
  "  public String getTheValue(String p) { return req.getParameter(p); }",
  "}",
].join("\n") };

const sqlFindings = (read: string, viaHelper: boolean, extra: Array<{ path: string; content: string }> = []) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [servlet(read, viaHelper), REQUEST, ...THING, ...extra] })
  .files.find(f => f.file_path === "app/Svc.java")!.indicators.filter(i => i.id === "sql-injection").map(i => (i.sourceExpr ? "engine" : "pattern"));

describe("an interface method that returns its argument", () => {
  it("in the handler itself", () => expect(sqlFindings("getTheParameter", false)).toContain("engine"));
  it("inside a local helper (its summary knows the other class's method)", () => expect(sqlFindings("getTheParameter", true)).toContain("engine"));
});

describe("another class's method that returns only a literal", () => {
  it("SQL built from it is no finding", () => expect(sqlFindings("getTheValue", false)).toEqual([]));
  it("not when a class of the batch extends it (an override may return input)", () =>
    expect(sqlFindings("getTheValue", false, [OVERRIDE]).length).toBeGreaterThan(0));
  it("a file with two classes: one's literal method is not credited to the other", () => {
    const twoClasses = { path: "helpers/Pair.java", content: [
      "package com.example.helpers;",
      "import javax.servlet.http.HttpServletRequest;",
      "class Live {",
      "  private HttpServletRequest r;",
      "  Live(HttpServletRequest r) { this.r = r; }",
      "  public String pick(String p) { return r.getParameter(p); }",
      "}",
      "class Fixed {",
      "  public String pick(String p) { return \"bar\"; }",
      "}",
    ].join("\n") };
    const svc = { path: "app/Svc.java", content: [
      "package app;",
      "import javax.servlet.http.*;",
      "public class Svc extends HttpServlet {",
      "  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {",
      "    com.example.helpers.Live live = new com.example.helpers.Live(request);",
      "    String bar = live.pick(\"v\");",
      "    String sql = \"SELECT * from USERS where PASSWORD='\" + bar + \"'\";",
      "    java.sql.Connection connection = com.example.helpers.DatabaseHelper.getSqlConnection();",
      "    java.sql.PreparedStatement statement = connection.prepareStatement(sql);",
      "    statement.execute();",
      "  }",
      "}",
    ].join("\n") };
    const found = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [svc, twoClasses, REQUEST] })
      .files.find(f => f.file_path === "app/Svc.java")!.indicators.filter(i => i.id === "sql-injection");
    expect(found.length).toBeGreaterThan(0);
  });
  it("nor through a local helper", () => expect(sqlFindings("getTheValue", true)).toEqual([]));
});
