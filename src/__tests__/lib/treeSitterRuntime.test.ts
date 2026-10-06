/**
 * @jest-environment node
 *
 * Parser.init() must run once per PROCESS, not once per module copy: Next.js bundles instrumentation.ts and the
 * route handlers separately, so a module-level memo let each bundle re-init the shared runtime (production C#
 * failed with "Incompatible language version 0"). Simulated here by loading two isolated copies of the module.
 */
const init = jest.fn(() => Promise.resolve());
jest.mock("web-tree-sitter", () => ({ Parser: { init } }));

afterEach(() => { delete (globalThis as Record<string, unknown>).__trustledgerTreeSitterInit; init.mockClear(); });

it("shares one Parser.init() across separately bundled copies of the module", async () => {
  let a!: typeof import("@/lib/treeSitterRuntime"), b!: typeof import("@/lib/treeSitterRuntime");
  jest.isolateModules(() => { a = require("@/lib/treeSitterRuntime"); });
  jest.isolateModules(() => { b = require("@/lib/treeSitterRuntime"); });
  expect(a).not.toBe(b);
  const p1 = a.ensureTreeSitterInit(), p2 = b.ensureTreeSitterInit(), p3 = a.ensureTreeSitterInit();
  expect(p1).toBe(p2);
  expect(p1).toBe(p3);
  await p1;
  expect(init).toHaveBeenCalledTimes(1);
});
