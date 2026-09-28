import { isModelFile, scanAstTaint } from "@/lib/astTaint";
import { parseSourceFile } from "@/lib/astTaint";
import type { StoredProvenanceIO } from "@/lib/taint/taintCore";

// Stored/second-order provenance: a value persisted via an ORM write is a taint SOURCE for whoever reads
// that model back later. These pin the mechanism directly (scanAstTaint's own optional storedProvenance
// param), independent of scanner.ts's cross-file orchestration -- see storedProvenanceCrossFile.test.ts
// for the batch-wide, real-repo-shaped version.

const sp = (over: Partial<StoredProvenanceIO> = {}): StoredProvenanceIO =>
  ({ modelReceivers: new Map([["UserModel", "m"]]), incoming: new Map(), writesOut: new Map(), ...over });
const write = (body: string, provenance = sp()) => {
  scanAstTaint(body, "write.ts", undefined, undefined, undefined, undefined, provenance);
  return provenance.writesOut.get("m") ?? 0;
};
const read = (body: string, incomingMask: number) =>
  scanAstTaint(body, "read.ts", undefined, undefined, undefined, undefined, sp({ incoming: new Map([["m", incomingMask]]) }));

describe("isModelFile: gates recognition to real ORM declarations", () => {
  it("recognizes a Sequelize class model", () => {
    const sf = parseSourceFile("class User extends Model {}", "a.ts");
    expect(isModelFile(sf)).toBe(true);
  });
  it("recognizes mongoose.model(...)", () => {
    const sf = parseSourceFile('const User = mongoose.model("User", schema);', "a.ts");
    expect(isModelFile(sf)).toBe(true);
  });
  it("recognizes sequelize.define(...)", () => {
    const sf = parseSourceFile("const User = sequelize.define(\"User\", {});", "a.ts");
    expect(isModelFile(sf)).toBe(true);
  });
  it("does NOT recognize an ordinary class or an unrelated .model()/.define() call", () => {
    expect(isModelFile(parseSourceFile("class UserService {}", "a.ts"))).toBe(false);
    expect(isModelFile(parseSourceFile("formatter.define(x);", "a.ts"))).toBe(false);
    expect(isModelFile(parseSourceFile('registry.model("x", y);', "a.ts"))).toBe(false);
  });
});

describe("write side: recognized ORM writes fold the data argument's mask into writesOut", () => {
  it("create(data)", () => {
    expect(write(`UserModel.create({ name: req.body.name });`)).toBeGreaterThan(0);
  });
  it("bulkCreate([data])", () => {
    expect(write(`UserModel.bulkCreate([{ name: req.body.name }]);`)).toBeGreaterThan(0);
  });
  it("update-style calls take the payload from the LAST argument, not the filter", () => {
    const mask = write(`UserModel.updateOne({ id: 1 }, { name: req.body.name });`);
    expect(mask).toBeGreaterThan(0);
    // the FILTER alone must not be what's recorded -- swap which side is tainted and confirm it still fires
    const mask2 = write(`UserModel.updateOne({ id: req.query.id }, { name: "static" });`);
    expect(mask2).toBe(0);
  });
  it("an untainted write contributes nothing", () => {
    expect(write(`UserModel.create({ name: "static" });`)).toBe(0);
  });
  it("a call on a receiver NOT in modelReceivers is not a write, regardless of method name", () => {
    expect(write(`SomethingElse.create({ name: req.body.name });`)).toBe(0);
  });
});

describe("write side: build()-then-save() and the read-modify-save pattern", () => {
  it("build(data) followed by .save() folds the constructor data", () => {
    expect(write(`
      async function h(req, res) {
        const u = UserModel.build({ name: req.body.name });
        await u.save();
      }`)).toBeGreaterThan(0);
  });
  it("build(data) alone, with NO .save(), contributes nothing (not yet persisted)", () => {
    expect(write(`
      function h(req, res) {
        const u = UserModel.build({ name: req.body.name });
      }`)).toBe(0);
  });
  it("read (findByPk), mutate a field, then save -- the classic 2FA-style pattern", () => {
    expect(write(`
      async function h(req, res) {
        const u = await UserModel.findByPk(req.query.id);
        u.totpSecret = req.body.secret;
        await u.save();
      }`)).toBeGreaterThan(0);
  });
  it("a field mutation with an UNTAINTED value contributes nothing", () => {
    expect(write(`
      async function h(req, res) {
        const u = await UserModel.findByPk(req.query.id);
        u.totpSecret = "static";
        await u.save();
      }`)).toBe(0);
  });
  it(".save() on a variable that was never a model instance is ignored", () => {
    expect(write(`
      async function h(req, res) {
        const u = { name: req.body.name };
        await u.save();
      }`)).toBe(0);
  });
  it("Sequelize's instance-level .update(values) on a findByPk-obtained instance -- real shape from OWASP Juice Shop's updateUserProfile.ts", () => {
    expect(write(`
      async function h(req, res) {
        const u = await UserModel.findByPk(req.params.id);
        await u.update({ username: req.body.username });
      }`)).toBeGreaterThan(0);
  });
  it(".update({}) with an untainted payload, on an untainted instance, contributes nothing", () => {
    expect(write(`
      async function h(req, res) {
        const u = await UserModel.findByPk(1);
        await u.update({ username: "static" });
      }`)).toBe(0);
  });
  it(".update() on a variable that was never a model instance is ignored", () => {
    expect(write(`
      async function h(req, res) {
        const u = { name: req.body.name };
        await u.update({ name: req.body.name });
      }`)).toBe(0);
  });
});

describe("read side: a recognized ORM read carries whatever this batch ever wrote to the model", () => {
  it("findAll()'s result is tainted when incoming says the model was written to", () => {
    const findings = read(`
      async function h(req, res) {
        const users = await UserModel.findAll();
        res.send(users);
      }`, 1 << 2 /* XSS */);
    expect(findings.some(f => f.id === "xss")).toBe(true);
  });
  it("findOne()/findByPk()/findById() all read the same way", () => {
    for (const call of ["findOne()", "findByPk(1)", "findById(1)", "aggregate([])"]) {
      const findings = read(`
        async function h(req, res) {
          const u = await UserModel.${call};
          res.send(u);
        }`, 1 << 2);
      expect(findings.some(f => f.id === "xss")).toBe(true);
    }
  });
  it("nothing was ever written (incoming empty) -> the read is untainted", () => {
    const findings = read(`
      async function h(req, res) {
        const users = await UserModel.findAll();
        res.send(users);
      }`, 0);
    expect(findings.some(f => f.id === "xss")).toBe(false);
  });
  it("only the classes actually written propagate -- a model written to for SQL only doesn't fire XSS", () => {
    const findings = read(`
      async function h(req, res) {
        const users = await UserModel.findAll();
        res.send(users);
      }`, 1 /* SQL only */);
    expect(findings.some(f => f.id === "xss")).toBe(false);
  });
  it("a call on a receiver NOT in modelReceivers is not a read, regardless of method name", () => {
    const findings = read(`
      async function h(req, res) {
        const x = await SomethingElse.findAll();
        res.send(x);
      }`, 1 << 2);
    expect(findings.some(f => f.id === "xss")).toBe(false);
  });
  it("without a storedProvenance param at all, behavior is unchanged from before this feature existed", () => {
    const findings = scanAstTaint(`
      async function h(req, res) {
        const users = await UserModel.findAll();
        res.send(users);
      }`, "read.ts");
    expect(findings.some(f => f.id === "xss")).toBe(false);
  });
});
