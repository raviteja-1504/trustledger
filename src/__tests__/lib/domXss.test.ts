/**
 * @jest-environment node
 *
 * Browser-side flows (DOM-based XSS and redirects): the page URL, the referrer, window.name and postMessage data as
 * sources; innerHTML / insertAdjacentHTML / document.writeln / srcdoc and location / window.open as sinks.
 */
import { analyzeFile } from "@/lib/scanner";

const ast = (code: string, id: string) => analyzeFile("public/js/app.js", code).indicators.some(i => i.id === id && !!i.sourceExpr);

describe("DOM-based XSS", () => {
  it("location.hash / search into innerHTML; a constant is not", () => {
    expect(ast(`const q = location.hash.slice(1);\ndocument.getElementById("out").innerHTML = "<b>" + q + "</b>";\n`, "xss")).toBe(true);
    expect(ast(`const params = new URLSearchParams(window.location.search);\nconst name = params.get("name");\ndocument.querySelector("#hi").insertAdjacentHTML("beforeend", "<p>" + name + "</p>");\n`, "xss")).toBe(true);
    expect(ast(`const q = "welcome";\ndocument.getElementById("out").innerHTML = "<b>" + q + "</b>";\n`, "xss")).toBe(false);
  });
  it("document.referrer into document.writeln, window.name into iframe.srcdoc", () => {
    expect(ast(`document.writeln("<a href='" + document.referrer + "'>back</a>");\n`, "xss")).toBe(true);
    expect(ast(`const f = document.createElement("iframe");\nf.srcdoc = window.name;\n`, "xss")).toBe(true);
    expect(ast(`const f = document.createElement("iframe");\nf.srcdoc = "<p>hi</p>";\n`, "xss")).toBe(false);
  });
  it("postMessage data in a message listener; the same name elsewhere is not a source", () => {
    expect(ast(`window.addEventListener("message", (e) => {\n  document.getElementById("msg").innerHTML = e.data;\n});\n`, "xss")).toBe(true);
    expect(ast(`window.onmessage = function (ev) {\n  document.body.innerHTML = ev.data;\n};\n`, "xss")).toBe(true);
    expect(ast(`button.addEventListener("click", (e) => {\n  document.getElementById("msg").innerHTML = e.data;\n});\n`, "xss")).toBe(false);
  });
  it("textContent is not an HTML sink", () => {
    expect(ast(`document.getElementById("out").textContent = location.hash;\n`, "xss")).toBe(false);
  });
});

describe("DOM-based redirects", () => {
  it("location = / location.href = / location.assign / window.open with the URL's own parameter", () => {
    expect(ast(`const next = new URLSearchParams(location.search).get("next");\nwindow.location.href = next;\n`, "open-redirect")).toBe(true);
    expect(ast(`const next = new URLSearchParams(location.search).get("next");\nlocation.assign(next);\n`, "open-redirect")).toBe(true);
    expect(ast(`const target = location.hash.slice(1);\nwindow.open(target);\n`, "open-redirect")).toBe(true);
    expect(ast(`window.location.href = "/home";\n`, "open-redirect")).toBe(false);
  });
});
