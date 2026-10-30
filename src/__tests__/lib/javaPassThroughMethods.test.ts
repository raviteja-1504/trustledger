/**
 * Java cross-file pass-throughs: a call through an interface of the batch (`ThingInterface thing = factory();
 * thing.doSomething(param)`) carries its argument when the implementations in the batch return what they are given --
 * the union over implementations, since any of them may run. Implementations that all return a constant do not, and a
 * library interface a batch class happens to implement does not change what calls through that interface return.
 */
import { runScan } from "@/lib/scanner";

const iface = { path: "app/helpers/ThingInterface.java", content: `package app.helpers;
public interface ThingInterface {
    public String doSomething(String i);
}
` };
const impl = (name: string, body: string, implemented = "ThingInterface") => ({ path: `app/helpers/${name}.java`, content: `package app.helpers;
public class ${name} implements ${implemented} {
    @Override
    public String doSomething(String i) {
${body}
    }
}
` });
const passes = impl("Thing1", `        String r = i;\n        return r;`);
const builds = impl("Thing2", `        if (i == null) return "";\n        String r = new StringBuilder(i).toString();\n        return r;`);
const constant = impl("Thing3", `        return "fixed";`);
const servlet = (type = "app.helpers.ThingInterface") => ({ path: "app/FileServlet.java", content: `package app;
import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class FileServlet extends HttpServlet {
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String param = request.getHeader("X-Name");
        if (param == null) param = "";
        ${type} thing = app.helpers.ThingFactory.createThing();
        String bar = thing.doSomething(param);
        java.io.FileInputStream fis = new java.io.FileInputStream(new java.io.File("/srv/files/" + bar));
        fis.close();
    }
}
` });

const pathFindings = (files: { path: string; content: string }[]) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files })
    .files.find(f => f.file_path === "app/FileServlet.java")!.indicators.filter(i => i.id === "path-traversal");

describe("Java calls through a batch interface whose implementations return their argument", () => {
  it("carries the argument when every implementation passes it through", () => {
    expect(pathFindings([iface, passes, builds, servlet()])).toHaveLength(1);
  });

  it("carries it when any one implementation does (whichever runs)", () => {
    expect(pathFindings([iface, constant, passes, servlet()])).toHaveLength(1);
  });

  it("unions the arguments implementations pass through (one returns the first, another the second)", () => {
    const pick = { path: "app/helpers/Picker.java", content: `package app.helpers;\npublic interface Picker {\n    public String pick(String a, String b);\n}\n` };
    const pickImpl = (name: string, ret: string) => ({ path: `app/helpers/${name}.java`, content: `package app.helpers;\npublic class ${name} implements Picker {\n    @Override\n    public String pick(String a, String b) {\n        return ${ret};\n    }\n}\n` });
    const caller = { path: "app/FileServlet.java", content: servlet().content
      .replace("app.helpers.ThingInterface thing", "app.helpers.Picker thing").replace("thing.doSomething(param)", "thing.pick(\"default.txt\", param)") };
    // the implementation returning the request value comes first, so a later one must not replace it
    expect(pathFindings([pick, pickImpl("PickSecond", "b"), pickImpl("PickFirst", "a"), caller])).toHaveLength(1);
    expect(pathFindings([pick, pickImpl("PickFirst", "a"), caller])).toHaveLength(0);
  });

  it("does not when every implementation returns a constant", () => {
    expect(pathFindings([iface, constant, servlet()])).toHaveLength(0);
  });

  it("resolves a call on a receiver typed as the implementing class too", () => {
    expect(pathFindings([iface, passes, servlet("app.helpers.Thing1")])).toHaveLength(1);
  });

  it("keeps each file's own same-named inner class to itself", () => {
    const withInner = (path: string, ret: string) => ({ path, content: `package app;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
public class ${path.replace(/^.*\//, "").replace(".java", "")} extends HttpServlet {
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws java.io.IOException {
        String param = request.getHeader("X-Name");
        String bar = new Test().doSomething(param);
        java.io.FileInputStream fis = new java.io.FileInputStream(new java.io.File("/srv/files/" + bar));
        fis.close();
    }
    private class Test {
        public String doSomething(String param) {
            return ${ret};
        }
    }
}
` });
    const scanned = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [
      withInner("app/PassServlet.java", "param"), withInner("app/SafeServlet.java", "\"constant.txt\""),
    ] }).files;
    const count = (p: string) => scanned.find(f => f.file_path === p)!.indicators.filter(i => i.id === "path-traversal").length;
    expect(count("app/PassServlet.java")).toBe(1);
    expect(count("app/SafeServlet.java")).toBe(0);
  });

  it("ignores a library interface that is not declared in the batch", () => {
    const converter = impl("Identity", `        return i;`, "org.springframework.core.convert.converter.Converter");
    expect(pathFindings([iface, converter, constant, servlet("org.springframework.core.convert.converter.Converter")])).toHaveLength(0);
  });
});
