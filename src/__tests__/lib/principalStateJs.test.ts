import { runScan } from "@/lib/scanner";
import { authzVerdict, classifyGuardName, isMutatingLookup, isOwnerField, mentionsRoleFeature } from "@/lib/taint/principal";

// BOLA as authorization STATE: what kind of check protects an object lookup -- ownership (proven), a role
// (a real control that still leaves the object unproven), or nothing.

const scan = (content: string) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/routes.ts", content }] });
const bola = (content: string) => scan(content).files[0].indicators.filter(i => i.id === "bola-missing-ownership-check");
const idor = (content: string) => scan(content).files[0].indicators.filter(i => i.id === "idor");
const handler = (body: string, mw = "") =>
  ["app.get(\"/d/:id\", " + mw + "async (req, res) => {", ...body.split("\n").map(l => "  " + l), "});"].join("\n");

describe("unchecked lookup (baseline)", () => {
  it("is reported", () => {
    expect(bola(handler("const doc = await Doc.findById(req.params.id);\nres.json(doc);"))).toHaveLength(1);
  });
  it("authentication alone is not authorization", () => {
    expect(bola(handler("const doc = await Doc.findById(req.params.id);\nres.json(doc);", "authenticate, "))).toHaveLength(1);
    expect(bola(handler("const doc = await Doc.findById(req.params.id);\nres.json(doc);", "requireAuth, "))).toHaveLength(1);
  });
});

describe("ownership IN the query is protection", () => {
  it.each([
    ["owner key with the principal", "const doc = await Doc.findOne({ _id: req.params.id, owner: req.user.id });"],
    ["ORM where clause + alias", "const id = req.params.id;\nconst uid = req.user.id;\nconst doc = await Doc.findOne({ where: { id, userId: uid } });"],
    ["shorthand principal alias", "const id = req.params.id;\nconst userId = req.user.id;\nconst doc = await Doc.findOne({ where: { id, userId } });"],
    ["nested relation filter", "const id = req.params.id;\nconst doc = await Doc.findUnique({ where: { id, user: { id: req.user.id } } });"],
    ["explicit $and", "const doc = await Doc.findOne({ $and: [{ _id: req.params.id }, { owner: req.user.id }] });"],
    ["mutating lookup scoped by owner", "await Doc.findOneAndDelete({ _id: req.params.id, owner: req.user.id });"],
  ])("%s -> no finding, and no regex duplicate", (_n, body) => {
    expect(bola(handler(body))).toHaveLength(0);
    expect(idor(handler(body))).toHaveLength(0);
  });

  it.each([
    ["$or does not scope", "const doc = await Doc.findOne({ $or: [{ _id: req.params.id }, { owner: req.user.id }] });"],
    ["principal under NOT", "const doc = await Doc.findOne({ _id: req.params.id, NOT: { owner: req.user.id } });"],
    ["owner key compared to something else", "const doc = await Doc.findOne({ _id: req.params.id, owner: req.body.owner });"],
    ["principal under a non-owner key", "const doc = await Doc.findOne({ _id: req.params.id, status: req.user.status });"],
  ])("%s -> still reported", (_n, body) => {
    expect(bola(handler(body))).toHaveLength(1);
  });
});

describe("ownership checked on the LOADED record", () => {
  const load = "const doc = await Doc.findById(req.params.id);\n";
  it.each([
    ["!== then return", load + "if (doc.owner !== req.user.id) return res.sendStatus(403);\nres.json(doc);"],
    ["string-coerced", load + "if (String(doc.ownerId) !== String(req.user.id)) return res.sendStatus(403);\nres.json(doc);"],
    ["nested owner id", load + "if (doc.user.id !== req.user.id) throw new Error('forbidden');\nres.json(doc);"],
    [".equals negated", load + "if (!doc.owner.equals(req.user.id)) return res.sendStatus(403);\nres.json(doc);"],
    ["=== with else terminating", load + "if (doc.owner === req.user.id) { res.json(doc); } else { return res.sendStatus(403); }"],
    ["a 404 guard first", load + "if (!doc) return res.sendStatus(404);\nif (doc.owner !== req.user.id) return res.sendStatus(403);\nres.json(doc);"],
  ])("%s -> protected", (_n, body) => {
    expect(bola(handler(body))).toHaveLength(0);
    expect(idor(handler(body))).toHaveLength(0);
  });

  it("a check that does NOT leave on failure protects nothing", () => {
    expect(bola(handler(load + "if (doc.owner !== req.user.id) { console.warn('not owner'); }\nres.json(doc);"))).toHaveLength(1);
  });
  it("a check on a different field is not ownership", () => {
    expect(bola(handler(load + "if (doc.status !== req.user.id) return res.sendStatus(403);\nres.json(doc);"))).toHaveLength(1);
  });
  it("a check of some OTHER record does not protect this one", () => {
    expect(bola(handler(load + "const other = await Other.find();\nif (other.owner !== req.user.id) return res.sendStatus(403);\nres.json(doc);"))).toHaveLength(1);
  });
  it("a check AFTER a lookup that mutates as it fetches is too late", () => {
    const body = "const doc = await Doc.findByIdAndUpdate(req.params.id, { title: req.body.title });\nif (doc.owner !== req.user.id) return res.sendStatus(403);\nres.json(doc);";
    expect(bola(handler(body))).toHaveLength(1);
  });
});

describe("guards named at the route or in the body", () => {
  const load = "const doc = await Doc.findById(req.params.id);\nres.json(doc);";
  it("ownership middleware is protection", () => {
    expect(bola(handler(load, "requireOwner, "))).toHaveLength(0);
    expect(bola(handler(load, "auth.selfOrAdmin(), "))).toHaveLength(0);
  });
  it("an object-level guard call that is HANDED the object is ownership", () => {
    expect(bola(handler("const doc = await Doc.findById(req.params.id);\nif (!can(req.user, 'read', doc)) return res.sendStatus(403);\nres.json(doc);"))).toHaveLength(0);
    expect(bola(handler("if (!isOwner(req.user, req.params.id)) return res.sendStatus(403);\nconst doc = await Doc.findById(req.params.id);\nres.json(doc);"))).toHaveLength(0);
  });
  it("a name that merely CONTAINS guard letters is not a guard (`scanner`, `oracle`)", () => {
    expect(bola(handler(load, "scanner, oracleLookup, "))).toHaveLength(1);
  });
});

describe("role-only: a real control, not object-level", () => {
  it("a role gate in the body still reports, downgraded, and says why", () => {
    const f = bola(handler("if (req.user.role !== 'admin') return res.sendStatus(403);\nconst doc = await Doc.findById(req.params.id);\nres.json(doc);"));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
    expect(f[0].detail).toMatch(/role\/permission check/);
    expect(f[0].detail).toMatch(/owns THIS object/);
  });
  it("role middleware is role-only", () => {
    const f = bola(handler("const doc = await Doc.findById(req.params.id);\nres.json(doc);", "authorize('admin'), "));
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("medium");
    expect(f[0].detail).toMatch(/route middleware 'authorize'/);
  });
  it("a WRITE endpoint is capped at medium when role-gated, but high when nothing guards it", () => {
    const write = (mw: string) => ["app.delete(\"/d/:id\", " + mw + "async (req, res) => {", "  await Doc.deleteOne({ _id: req.params.id });", "});"].join("\n");
    expect(bola(write(""))[0].severity).toBe("high");
    expect(bola(write("requireRole('editor'), "))[0].severity).toBe("medium");
  });
  it("a role gate PLUS ownership in the query is proven", () => {
    expect(bola(handler("if (req.user.role !== 'user') return res.sendStatus(403);\nconst doc = await Doc.findOne({ _id: req.params.id, owner: req.user.id });", "authorize('user'), "))).toHaveLength(0);
  });
  it("a role condition that does not leave on failure is not a gate", () => {
    const f = bola(handler("if (req.user.role !== 'admin') { console.warn('x'); }\nconst doc = await Doc.findById(req.params.id);\nres.json(doc);"));
    expect(f).toHaveLength(1);
    expect(f[0].detail).not.toMatch(/role\/permission check/);
  });
});

describe("existing id-vs-principal comparison still protects (and now removes the regex duplicate)", () => {
  it("guard clause", () => {
    const body = "if (req.params.id !== req.user.id) return res.sendStatus(403);\nconst doc = await Doc.findById(req.params.id);";
    expect(bola(handler(body))).toHaveLength(0);
    expect(idor(handler(body))).toHaveLength(0);
  });
});

describe("principal.ts vocabulary", () => {
  it("owner fields", () => {
    for (const n of ["owner", "ownerId", "owner_id", "userId", "user_id", "createdBy", "tenantId", "organizationId"]) expect(isOwnerField(n)).toBe(true);
    for (const n of ["id", "_id", "status", "title", "ownership"]) expect(isOwnerField(n)).toBe(false);
  });
  it("guard names are judged by words", () => {
    expect(classifyGuardName("requireOwner")).toBe("ownership");
    expect(classifyGuardName("selfOrAdmin")).toBe("ownership");
    expect(classifyGuardName("is_owner")).toBe("ownership");
    expect(classifyGuardName("authorize")).toBe("role");
    expect(classifyGuardName("requireAdmin")).toBe("role");
    expect(classifyGuardName("hasPermission")).toBe("role");
    expect(classifyGuardName("canAccess")).toBe("role");
    for (const n of ["authenticate", "requireAuth", "scanner", "oracle", "controller", "logger"]) expect(classifyGuardName(n)).toBeNull();
  });
  it("mutating lookups", () => {
    for (const n of ["findByIdAndUpdate", "deleteOne", "updateOne", "remove", "destroy", "findOneAndDelete"]) expect(isMutatingLookup(n)).toBe(true);
    for (const n of ["findById", "findOne", "get", "findUnique"]) expect(isMutatingLookup(n)).toBe(false);
  });
  it("role features", () => {
    expect(mentionsRoleFeature("req.user.role !== 'admin'")).toBe(true);
    expect(mentionsRoleFeature("!req.user.isAdmin")).toBe(true);
    expect(mentionsRoleFeature("req.user.permissions.includes('x')")).toBe(true);
    expect(mentionsRoleFeature("req.user.name === 'x'")).toBe(false);
  });
  it("verdict: ownership wins, role alone is role-only, nothing is unchecked", () => {
    expect(authzVerdict(new Set(["ownership", "role"]))).toBe("proven");
    expect(authzVerdict(new Set(["ownership"]))).toBe("proven");
    expect(authzVerdict(new Set(["role"]))).toBe("role-only");
    expect(authzVerdict(new Set())).toBe("unchecked");
  });
});
