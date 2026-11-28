import { runScan } from "@/lib/scanner";

/**
 * Precision: a guard called as a plain statement that refuses by throwing (`await assertCanRead(user, doc)`) protects the object it is
 * handed, the same as `if (!can(user, doc)) return`. A guard that names no authorization, one that never sees the object, and a guard
 * that runs after a mutating lookup do not.
 */
const bola = (handlerBody: string, verb = "get") => {
  const code = `import express from "express";\nconst app = express();\napp.${verb}("/x/:id", authenticate, async (req, res) => {\n${handlerBody}\n});\n`;
  return runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/a.ts", content: code }] })
    .files[0].indicators.filter(i => i.id === "bola-missing-ownership-check");
};

describe("a throwing guard statement that is handed the object", () => {
  it("assertCanRead(user, record) after the lookup", () => {
    expect(bola("  const f = await File.findById(req.params.id);\n  await assertCanRead(req.user, f);\n  res.json(f);")).toHaveLength(0);
  });
  it("ensureOwner(user, record) before use", () => {
    expect(bola("  const f = await File.findById(req.params.id);\n  ensureOwner(f, req.user);\n  res.json(f);")).toHaveLength(0);
  });
  it("authorize(user, 'read', id) before the lookup", () => {
    expect(bola("  await authorize(req.user, \"read\", req.params.id);\n  const f = await File.findById(req.params.id);\n  res.json(f);")).toHaveLength(0);
  });
});

describe("still reported", () => {
  it("no guard at all", () => {
    expect(bola("  const f = await File.findById(req.params.id);\n  res.json(f);").length).toBeGreaterThan(0);
  });
  it("a validation helper is not an authorization guard", () => {
    expect(bola("  const f = await File.findById(req.params.id);\n  assertValid(req.body);\n  res.json(f);").length).toBeGreaterThan(0);
  });
  it("a guard after a lookup that already mutates is too late", () => {
    expect(bola("  const f = await File.findByIdAndDelete(req.params.id);\n  await assertCanRead(req.user, f);\n  res.json(f);", "delete").length).toBeGreaterThan(0);
  });
  it("a role guard that never sees the object is role-level only (still reported, at reduced severity)", () => {
    const r = bola("  requireRole(\"admin\");\n  const f = await File.findById(req.params.id);\n  res.json(f);");
    expect(r.length).toBeGreaterThan(0);
  });
});
