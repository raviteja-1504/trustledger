import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

// End-to-end proof of the BATCH-WIDE stored/second-order provenance wiring in scanner.ts (see
// taintCore.ts's StoredProvenanceIO docblock): a write in one file and a read in a DIFFERENT file must
// correlate through the model's own file path, which corpus research (Juice Shop/PyGoat/crAPI) showed is
// the dominant real-world shape -- storedProvenanceJs.test.ts/storedProvenancePy.test.ts already pin the
// same-file mechanism directly; this file is the cross-file orchestration on top of it.

type F = { path: string; content: string };
const scan = (files: F[], prev_module_cache?: Record<string, unknown>) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files, prev_module_cache: prev_module_cache as never });
const idsOf = (r: ReturnType<typeof scan>, path: string) =>
  r.files.find(f => f.file_path === path)!.indicators.filter(i => i.confidence === 95).map(i => i.id);

describe("JS/TS: a Sequelize-style write in one file taints a read in another", () => {
  const MODEL = `export class UserModel extends Model {}\n`;
  const WRITE = `import { UserModel } from "./models/user";\napp.post("/signup", (req, res) => {\n  UserModel.create({ name: req.body.name });\n});\n`;
  const READ = `import { UserModel } from "./models/user";\napp.get("/users", async (req, res) => {\n  const users = await UserModel.findAll();\n  res.send(users);\n});\n`;

  it("create() in write.ts is visible to findAll() in read.ts as an XSS source", () => {
    const files = [
      { path: "src/models/user.ts", content: MODEL },
      { path: "src/write.ts", content: WRITE },
      { path: "src/read.ts", content: READ },
    ];
    const r = scan(files);
    expect(idsOf(r, "src/read.ts")).toContain("xss");
  });

  it("with NO write anywhere in the batch, the same read stays untainted", () => {
    const files = [
      { path: "src/models/user.ts", content: MODEL },
      { path: "src/read.ts", content: READ },
    ];
    const r = scan(files);
    expect(idsOf(r, "src/read.ts")).not.toContain("xss");
  });

  it("a write to an UNRELATED model does not taint this one", () => {
    const OTHER_MODEL = `export class OrderModel extends Model {}\n`;
    const OTHER_WRITE = `import { OrderModel } from "./models/order";\napp.post("/order", (req, res) => {\n  OrderModel.create({ note: req.body.note });\n});\n`;
    const files = [
      { path: "src/models/user.ts", content: MODEL },
      { path: "src/models/order.ts", content: OTHER_MODEL },
      { path: "src/otherWrite.ts", content: OTHER_WRITE },
      { path: "src/read.ts", content: READ },
    ];
    const r = scan(files);
    expect(idsOf(r, "src/read.ts")).not.toContain("xss");
  });

  it("the read-modify-save pattern (findByPk, mutate a field, save) in write.ts still reaches read.ts", () => {
    const RMW_WRITE = `import { UserModel } from "./models/user";\napp.post("/profile", async (req, res) => {\n  const u = await UserModel.findByPk(req.params.id);\n  u.bio = req.body.bio;\n  await u.save();\n});\n`;
    const files = [
      { path: "src/models/user.ts", content: MODEL },
      { path: "src/write.ts", content: RMW_WRITE },
      { path: "src/read.ts", content: READ },
    ];
    const r = scan(files);
    expect(idsOf(r, "src/read.ts")).toContain("xss");
  });

  it("adding a NEW write file on a rescan invalidates read.ts's cached (stale, untainted) file_cache entry", () => {
    // read.ts's own bytes AND its module-graph dependency (the model file) are IDENTICAL across both
    // scans -- only the batch-wide write aggregate changed, because write.ts is new. A cache key that
    // ignores storedProvenanceIncoming would wrongly reuse round 1's untainted result.
    const files1 = [{ path: "src/models/user.ts", content: MODEL }, { path: "src/read.ts", content: READ }];
    const first = scan(files1);
    expect(idsOf(first, "src/read.ts")).not.toContain("xss");

    const files2 = [...files1, { path: "src/write.ts", content: WRITE }];
    const second = runScan({
      repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: files2,
      prev_results: first.file_cache as never, prev_module_cache: first.module_cache as never,
    });
    expect(idsOf(second, "src/read.ts")).toContain("xss");
  });

  it("a model that declares AND uses itself (no import) still registers as a write receiver for a read elsewhere", () => {
    // model.ts both declares UserModel and calls .create() on it directly -- modelReceivers for THIS
    // file must come from the self-declared-name path (jsModelLocalNames), since there is no import
    // edge to derive it from.
    const SELF_WRITE = `export class UserModel extends Model {}\napp.post("/signup", (req, res) => {\n  UserModel.create({ name: req.body.name });\n});\n`;
    const files = [
      { path: "src/models/user.ts", content: SELF_WRITE },
      { path: "src/read.ts", content: READ },
    ];
    const r = scan(files);
    expect(idsOf(r, "src/read.ts")).toContain("xss");
  });

  it("survives a module_cache-reused rescan (cross-file model-receiver detection doesn't need a re-parse)", () => {
    const files = [
      { path: "src/models/user.ts", content: MODEL },
      { path: "src/write.ts", content: WRITE },
      { path: "src/read.ts", content: READ },
    ];
    const first = scan(files);
    expect(idsOf(first, "src/read.ts")).toContain("xss");
    const second = scan(files, first.module_cache);
    expect(second.module_cache_reused).toBe(3);
    expect(idsOf(second, "src/read.ts")).toContain("xss");
  });
});

describe("Python: a Django ORM write in one module taints a read in another", () => {
  const MODEL = "from django.db import models\n\nclass UserModel(models.Model):\n    name = models.CharField(max_length=100)\n";
  const WRITE = "from .models import UserModel\nfrom flask import request\n\ndef signup(request):\n    UserModel.objects.create(name=request.GET.get('name'))\n";
  const READ = "from .models import UserModel\nfrom django.http import HttpResponse\n\ndef list_users(request):\n    users = UserModel.objects.filter(active=True)\n    return HttpResponse(users)\n";

  it("objects.create() in write.py is visible to objects.filter() in read.py as an XSS source", () => {
    const files = [
      { path: "app/models.py", content: MODEL },
      { path: "app/write.py", content: WRITE },
      { path: "app/read.py", content: READ },
    ];
    const r = scan(files);
    expect(idsOf(r, "app/read.py")).toContain("xss");
  });

  it("with NO write anywhere in the batch, the same read stays untainted", () => {
    const files = [
      { path: "app/models.py", content: MODEL },
      { path: "app/read.py", content: READ },
    ];
    const r = scan(files);
    expect(idsOf(r, "app/read.py")).not.toContain("xss");
  });
});
