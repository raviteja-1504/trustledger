/**
 * A receiver named like an Object.prototype member (constructor, toString, valueOf...) used to make the JS taint engine
 * throw ("TEMPLATE_COMPILE[engine]?.has is not a function"), which silently dropped the WHOLE file's data-flow analysis.
 */
import { analyzeFile } from "@/lib/scanner";

describe("receivers named like Object.prototype members", () => {
  const code = (receiver: string) => `
const cp = require("child_process");
const ${receiver} = { render: (x) => x };
app.get("/run", (req, res) => {
  ${receiver}.render(req.query.t);
  cp.exec(req.query.cmd);
  res.send("ok");
});
`.trim();

  it.each(["constructor", "toString", "valueOf", "hasOwnProperty", "__proto__"])("%s does not stop the file being analysed", receiver => {
    const spy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const r = analyzeFile("src/routes.js", code(receiver));
      expect(spy.mock.calls.some(c => String(c[0]).includes("[astTaint] threw"))).toBe(false);
      expect(r.indicators.some(i => i.id === "command-injection")).toBe(true);     // the real finding later in the file is still found
    } finally { spy.mockRestore(); }
  });

  it("a real template engine is still recognised", () => {
    const r = analyzeFile("src/views.js", `const ejs = require("ejs");\napp.get("/p", (req, res) => { res.send(ejs.render(req.query.t, {})); });\n`);
    expect(r.indicators.some(i => i.id === "ssti")).toBe(true);
  });
});
