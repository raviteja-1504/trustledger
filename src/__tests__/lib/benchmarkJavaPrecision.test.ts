/**
 * @jest-environment node
 *
 * Java coverage found scoring OWASP BenchmarkJava: constant folding (a `?:` / `if` / `switch` on a compile-time
 * constant runs one arm), literal-slot lists and maps (`get(1)` after add/remove, `get("keyA")` after put), request
 * data stored in the session (trust boundary), java.util.Random feeding a cookie / session value, and servlet cookies
 * with Secure / HttpOnly explicitly switched off.
 */
import { analyzeFile } from "@/lib/scanner";
import { evalConstExpr } from "@/lib/taint/constEval";

const servlet = (body: string) => `import javax.servlet.http.*;
public class T extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("p");
${body}
        java.io.File f = new java.io.File(bar);
    }
}
`;
const found = (code: string) => analyzeFile("src/T.java", code).indicators;
const pathFlow = (body: string) => found(servlet(body)).some(i => i.id === "path-traversal");

describe("constant expressions", () => {
  const l = (n: string) => ({ num: 106, guess: "ABC" } as Record<string, number | string>)[n];
  it("arithmetic, comparisons, charAt, concatenation", () => {
    expect(evalConstExpr("(7 * 18) + num > 200", l)).toBe(true);
    expect(evalConstExpr("(500 / 42) + num > 200", l)).toBe(false);   // integer division: 11 + 106
    expect(evalConstExpr("guess.charAt(1)", l)).toBe("B");
    expect(evalConstExpr("'B'", l)).toBe("B");
    expect(evalConstExpr("\"a\" + 1", l)).toBe("a1");
    expect(evalConstExpr("!(num == 106) || false", l)).toBe(false);
    expect(evalConstExpr("guess.length() == 3 && num != 1", l)).toBe(true);
  });
  it("anything unknown is not a constant", () => {
    expect(evalConstExpr("other > 1", l)).toBeUndefined();
    expect(evalConstExpr("num / 0", l)).toBeUndefined();
    expect(evalConstExpr("guess.charAt(9)", l)).toBeUndefined();
    expect(evalConstExpr("foo(1)", l)).toBeUndefined();
  });
});

describe("constant branches", () => {
  it("?: on a constant runs one arm", () => {
    expect(pathFlow(`        int num = 106;\n        String bar = (7 * 18) + num > 200 ? "safe" : param;`)).toBe(false);
    expect(pathFlow(`        int num = 106;\n        String bar = (7 * 18) + num > 200 ? param : "safe";`)).toBe(true);
    // reassigned: not a constant any more
    expect(pathFlow(`        int num = 106;\n        num = Integer.parseInt(param);\n        String bar = (7 * 18) + num > 200 ? "safe" : param;`)).toBe(true);
  });
  it("if on a constant runs one arm", () => {
    expect(pathFlow(`        String bar;\n        int num = 196;\n        if ((500 / 42) + num > 200) bar = param;\n        else bar = "safe";`)).toBe(true);
    expect(pathFlow(`        String bar;\n        int num = 86;\n        if ((7 * 42) - num > 200) bar = "safe";\n        else bar = param;`)).toBe(false);
  });
  it("switch on a constant runs the matching case, through to its break", () => {
    const sw = (idx: number) => `        String bar;\n        String guess = "ABC";\n        char switchTarget = guess.charAt(${idx});\n        switch (switchTarget) {\n            case 'A': bar = param; break;\n            case 'B': bar = "bob"; break;\n            case 'C':\n            case 'D': bar = param; break;\n            default: bar = "uncle"; break;\n        }`;
    expect(pathFlow(sw(1))).toBe(false);
    expect(pathFlow(sw(0))).toBe(true);
    expect(pathFlow(sw(2))).toBe(true);    // falls into 'D'
  });
});

describe("a pruned arm also vetoes the line rule", () => {
  const sql = (pick: string) => `import javax.servlet.http.*;
public class Q extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("p");
        String bar;
${pick}
        String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + bar + "'";
        java.sql.Statement statement = getConnection().createStatement();
        statement.execute(sql);
    }
}
`;
  const any = (code: string) => found(code).filter(i => i.id === "sql-injection").length;
  it("if / ?: / switch / map slot with the tainted arm dead: no SQL finding at all", () => {
    expect(any(sql(`        int num = 86;\n        if ((7 * 42) - num > 200) bar = "safe";\n        else bar = param;`))).toBe(0);
    expect(any(sql(`        int num = 106;\n        bar = (7 * 18) + num > 200 ? "safe" : param;`))).toBe(0);
    expect(any(sql(`        String guess = "ABC";\n        switch (guess.charAt(1)) {\n            case 'A': bar = param; break;\n            default: bar = "bob"; break;\n        }`))).toBe(0);
    expect(any(sql(`        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();\n        map.put("keyA", "a");\n        map.put("keyB", param);\n        bar = (String) map.get("keyA");`))).toBe(0);
  });
  it("the live arm is still reported", () => {
    expect(any(sql(`        int num = 86;\n        if ((7 * 42) - num > 200) bar = param;\n        else bar = "safe";`))).toBeGreaterThan(0);
  });
});

describe("literal-slot collections", () => {
  it("a list after add / remove(0) / get(1)", () => {
    const list = (get: number) => `        String bar = "alsosafe";\n        java.util.List<String> valuesList = new java.util.ArrayList<String>();\n        valuesList.add("safe");\n        valuesList.add(param);\n        valuesList.add("moresafe");\n        valuesList.remove(0);\n        bar = valuesList.get(${get});`;
    expect(pathFlow(list(1))).toBe(false);
    expect(pathFlow(list(0))).toBe(true);
  });
  it("a map's literal keys", () => {
    const map = (key: string) => `        String bar = "safe!";\n        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();\n        map.put("keyA", "a_Value");\n        map.put("keyB", param);\n        bar = (String) map.get("${key}");`;
    expect(pathFlow(map("keyA"))).toBe(false);
    expect(pathFlow(map("keyB"))).toBe(true);
  });
  it("unknowable: an op in a loop, a non-literal key, a list from elsewhere", () => {
    expect(pathFlow(`        String bar;\n        java.util.List<String> l = new java.util.ArrayList<String>();\n        for (int i = 0; i < 2; i++) l.add(param);\n        l.add("x");\n        bar = l.get(2);`)).toBe(true);
    expect(pathFlow(`        String bar;\n        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();\n        map.put(param, param);\n        map.put("keyA", "a");\n        bar = (String) map.get("keyA");`)).toBe(true);
  });
});

describe("Java line rules and the session sink", () => {
  it("java.util.Random into a cookie / session value; not SecureRandom, not a plain number", () => {
    const rnd = (gen: string, use: string) => `public class R {\n    void f(javax.servlet.http.HttpServletResponse response) {\n        float rand = ${gen};\n        String rememberMeKey = Float.toString(rand).substring(2);\n        ${use}\n    }\n}\n`;
    const weak = (code: string) => found(code).some(i => i.id === "insecure-randomness");
    expect(weak(rnd("new java.util.Random().nextFloat()", `response.addCookie(new javax.servlet.http.Cookie("rememberMe", rememberMeKey));`))).toBe(true);
    expect(weak(rnd("(float) Math.random()", `response.addCookie(new javax.servlet.http.Cookie("rememberMe", rememberMeKey));`))).toBe(true);
    expect(weak(rnd("java.security.SecureRandom.getInstance(\"SHA1PRNG\").nextFloat()", `response.addCookie(new javax.servlet.http.Cookie("rememberMe", rememberMeKey));`))).toBe(false);
    expect(weak(rnd("new java.util.Random().nextFloat()", `System.out.println(rememberMeKey.length());`).replace(/rememberMeKey/g, "jitter"))).toBe(false);
  });
  it("setSecure(false) / setHttpOnly(false) on any cookie", () => {
    const c = (flags: string) => `public class C {\n    void f(javax.servlet.http.HttpServletResponse response) {\n        javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("SomeCookie", "v");\n        ${flags}\n        response.addCookie(cookie);\n    }\n}\n`;
    expect(found(c("cookie.setSecure(false);")).some(i => i.id === "cookie-no-secure")).toBe(true);
    expect(found(c("cookie.setHttpOnly(false);")).some(i => i.id === "cookie-no-httponly")).toBe(true);
    expect(found(c("cookie.setSecure(true); cookie.setHttpOnly(true);")).some(i => /^cookie-no-/.test(i.id))).toBe(false);
  });
  it("request data stored in the session is a trust-boundary violation", () => {
    const s = (stmt: string) => `import javax.servlet.http.*;\npublic class S extends HttpServlet {\n    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n        String param = request.getParameter("p");\n        ${stmt}\n    }\n}\n`;
    const tb = (code: string) => found(code).some(i => i.id === "trust-boundary");
    expect(tb(s(`request.getSession().setAttribute(param, "10340");`))).toBe(true);
    expect(tb(s(`request.getSession().putValue("userid", param);`))).toBe(true);
    expect(tb(s(`request.getSession().setAttribute("userid", "fixed");`))).toBe(false);
    // not a session
    expect(tb(s(`request.setAttribute("userid", param);`))).toBe(false);
  });
});

describe("SQL proven independent of every input vetoes the line rule (BenchmarkJava sqli false positives)", () => {
  const sqlServlet = (pre: string, bar: string, extra = "") => `import javax.servlet.http.*;
public class T extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("p");
${pre}
        String bar = ${bar};
        String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + bar + "'";
        java.sql.Statement statement = org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
        statement.execute(sql);
    }
${extra}
}
`;
  const sqli = (code: string) => found(code).filter(i => i.id === "sql-injection").length;
  const helper = (ret: string) => `    private class Test {
        public String doSomething(HttpServletRequest request, String param) throws Exception {
            String bar;
            String guess = "ABC";
            char switchTarget = guess.charAt(1);
            switch (switchTarget) {
                case 'A': bar = param; break;
                case 'B': bar = ${ret}; break;
                default: bar = "bob's your uncle"; break;
            }
            return bar;
        }
    }`;
  it("a local helper whose result can't depend on its arguments; the same helper returning them still reports", () => {
    expect(sqli(sqlServlet("", "new Test().doSomething(request, param)", helper(`"bob"`)))).toBe(0);
    expect(sqli(sqlServlet("", "new Test().doSomething(request, param)", helper("param")))).toBeGreaterThan(0);
  });
  it("a static helper called by bare name, folding a constant ternary; the inverted ternary still reports", () => {
    const stat = (cond: string) => `    private static String doSomething(HttpServletRequest request, String param) {
        int num = 106;
        String bar = ${cond} ? "This_should_always_happen" : param;
        return bar;
    }`;
    expect(sqli(sqlServlet("", "doSomething(request, param)", stat("(7 * 18) + num > 200")))).toBe(0);
    expect(sqli(sqlServlet("", "doSomething(request, param)", stat("(500 / 42) + num > 200")))).toBeGreaterThan(0);
  });
  it("an unmodelled call carries its arguments: constant in, constant out; input in, still reported", () => {
    const thing = `        org.owasp.benchmark.helpers.ThingInterface thing = org.owasp.benchmark.helpers.ThingFactory.createThing();`;
    expect(sqli(sqlServlet(thing, `thing.doSomething("barbarians_at_the_gate")`))).toBe(0);
    expect(sqli(sqlServlet(thing, "thing.doSomething(param)"))).toBeGreaterThan(0);
  });
  it("fields, static readers and no-argument readers are never proven", () => {
    expect(sqli(sqlServlet("", "this.saved", "    private String saved;"))).toBeGreaterThan(0);
    // a helper of this class that returns a field with no argument at all: what it returns is not proven
    expect(sqli(sqlServlet("", "load()", "    private String saved;\n    private String load() { return saved; }"))).toBeGreaterThan(0);
    expect(sqli(sqlServlet("", `System.getenv("X")`))).toBeGreaterThan(0);
    expect(sqli(sqlServlet(`        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));`, "reader.readLine()"))).toBeGreaterThan(0);
  });
  it("only a local assigned once has its building line vetoed", () => {
    const twice = sqlServlet("", `"x"`).replace(`        statement.execute(sql);`, `        String q = "SELECT * from USERS where NAME='" + param + "'";\n        q = "SELECT 1";\n        statement.execute(q);`);
    expect(sqli(twice)).toBeGreaterThan(0);
  });
});