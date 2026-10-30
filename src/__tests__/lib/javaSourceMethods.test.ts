/**
 * Java cross-file sources: a request wrapper in another file (`SeparateClassRequest.getTheParameter(p)` returning
 * `request.getParameter(p)`) makes its callers' values request input; the same wrapper's method that returns a
 * constant does not, and neither does a helper that merely returns what it is given.
 */
import { runScan } from "@/lib/scanner";

const wrapper = `package app.helpers;
import javax.servlet.http.HttpServletRequest;
public class SeparateClassRequest {
    private HttpServletRequest request;
    public SeparateClassRequest(HttpServletRequest request) {
        this.request = request;
    }
    public String getTheParameter(String p) {
        return request.getParameter(p);
    }
    public String getTheValue(String p) {
        return "bar";
    }
}
`;
const servlet = (getter: string) => `package app;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class FileServlet extends HttpServlet {
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        app.helpers.SeparateClassRequest scr = new app.helpers.SeparateClassRequest(request);
        String param = scr.${getter}("name");
        if (param == null) param = "";
        java.io.FileInputStream fis = new java.io.FileInputStream(new java.io.File(param));
        fis.close();
    }
}
`;
const found = (files: { path: string; content: string }[]) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files })
    .files.flatMap(f => f.indicators.filter(i => i.id === "path-traversal" && !!i.sourceExpr).map(i => `${f.file_path}:${i.line}`));

describe("Java request wrappers in another file", () => {
  it("a wrapper method returning request.getParameter is a source; its constant-returning sibling is not", () => {
    expect(found([{ path: "helpers/SeparateClassRequest.java", content: wrapper }, { path: "FileServlet.java", content: servlet("getTheParameter") }])).toEqual(["FileServlet.java:12"]);
    expect(found([{ path: "helpers/SeparateClassRequest.java", content: wrapper }, { path: "FileServlet.java", content: servlet("getTheValue") }])).toEqual([]);
  });

  it("without the wrapper in the batch nothing is assumed", () => {
    expect(found([{ path: "FileServlet.java", content: servlet("getTheParameter") }, { path: "Other.java", content: "package app;\npublic class Other {}\n" }])).toEqual([]);
  });

  it("a helper that only returns what it is passed is not a source by itself", () => {
    const echo = `package app.helpers;\npublic class SeparateClassRequest {\n    public SeparateClassRequest(Object o) {}\n    public String getTheParameter(String p) {\n        return p;\n    }\n}\n`;
    expect(found([{ path: "helpers/SeparateClassRequest.java", content: echo }, { path: "FileServlet.java", content: servlet("getTheParameter") }])).toEqual([]);
  });
});
