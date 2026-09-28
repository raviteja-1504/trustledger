import { isModelFilePy, parsePythonSourceSync, scanAstTaintPython, warmPythonTaintEngine } from "@/lib/astTaintPython";
import type { StoredProvenanceIO } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

// Stored/second-order provenance, Django ORM: a value persisted via `.objects.create()`/`.save()` is a
// taint SOURCE for whoever reads that model back later via `.objects.get()`/`.filter()`/etc.

const sp = (over: Partial<StoredProvenanceIO> = {}): StoredProvenanceIO =>
  ({ modelReceivers: new Map([["UserModel", "m"]]), incoming: new Map(), writesOut: new Map(), ...over });
const write = (body: string, provenance = sp()) => {
  scanAstTaintPython(body, "write.py", undefined, undefined, undefined, undefined, provenance);
  return provenance.writesOut.get("m") ?? 0;
};
const read = (body: string, incomingMask: number) =>
  scanAstTaintPython(body, "read.py", undefined, undefined, undefined, undefined, sp({ incoming: new Map([["m", incomingMask]]) }));

describe("isModelFilePy: gates recognition to a real Django model declaration", () => {
  it("recognizes class X(models.Model)", () => {
    const root = parsePythonSourceSync("class User(models.Model):\n    name = models.CharField()\n", "a.py")!;
    expect(isModelFilePy(root)).toBe(true);
  });
  it("recognizes class X(Model) (bare import)", () => {
    const root = parsePythonSourceSync("class User(Model):\n    pass\n", "a.py")!;
    expect(isModelFilePy(root)).toBe(true);
  });
  it("does NOT recognize an ordinary class", () => {
    const root = parsePythonSourceSync("class UserService:\n    pass\n", "a.py")!;
    expect(isModelFilePy(root)).toBe(false);
  });
  it("does NOT recognize a class with an unrelated base", () => {
    const root = parsePythonSourceSync("class UserSerializer(serializers.Serializer):\n    pass\n", "a.py")!;
    expect(isModelFilePy(root)).toBe(false);
  });
});

describe("write side: recognized Django ORM writes fold the data argument's mask into writesOut", () => {
  it("objects.create(**data)", () => {
    expect(write("def h(request):\n    UserModel.objects.create(name=request.GET.get('name'))\n")).toBeGreaterThan(0);
  });
  it("objects.bulk_create([...])", () => {
    expect(write("def h(request):\n    UserModel.objects.bulk_create([UserModel(name=request.GET.get('name'))])\n")).toBeGreaterThan(0);
  });
  it("an untainted write contributes nothing", () => {
    expect(write("def h(request):\n    UserModel.objects.create(name='static')\n")).toBe(0);
  });
  it("a call on a receiver NOT in modelReceivers is not a write, regardless of method name", () => {
    expect(write("def h(request):\n    SomethingElse.objects.create(name=request.GET.get('name'))\n")).toBe(0);
  });
});

describe("write side: direct construction and read-modify-save", () => {
  it("UserModel(field=value) constructs an instance as tainted as its kwargs, then .save() persists it", () => {
    expect(write("def h(request):\n    u = UserModel(name=request.GET.get('name'))\n    u.save()\n")).toBeGreaterThan(0);
  });
  it("construction alone, with no .save(), contributes nothing", () => {
    expect(write("def h(request):\n    u = UserModel(name=request.GET.get('name'))\n")).toBe(0);
  });
  it("read (objects.get), mutate a field, then save", () => {
    expect(write("def h(request):\n    u = UserModel.objects.get(id=request.GET.get('id'))\n    u.bio = request.GET.get('bio')\n    u.save()\n")).toBeGreaterThan(0);
  });
  it("a field mutation with an untainted value contributes nothing", () => {
    expect(write("def h(request):\n    u = UserModel.objects.get(id=1)\n    u.bio = 'static'\n    u.save()\n")).toBe(0);
  });
  it(".save() on a variable that was never a model instance is ignored", () => {
    expect(write("def h(request):\n    u = {'name': request.GET.get('name')}\n    u.save()\n")).toBe(0);
  });
});

describe("read side: a recognized Django read carries whatever this batch ever wrote to the model", () => {
  it("objects.filter()'s result is tainted when incoming says the model was written to", () => {
    const findings = read("def h(request):\n    users = UserModel.objects.filter(active=True)\n    return HttpResponse(users)\n", 1 << 2);
    expect(findings.some(f => f.id === "xss")).toBe(true);
  });
  it("objects.get()/.all()/.first() all read the same way", () => {
    for (const call of ["get(id=1)", "all()", "first()"]) {
      const findings = read(`def h(request):\n    u = UserModel.objects.${call}\n    return HttpResponse(u)\n`, 1 << 2);
      expect(findings.some(f => f.id === "xss")).toBe(true);
    }
  });
  it("nothing was ever written (incoming empty) -> the read is untainted", () => {
    const findings = read("def h(request):\n    users = UserModel.objects.filter(active=True)\n    return HttpResponse(users)\n", 0);
    expect(findings.some(f => f.id === "xss")).toBe(false);
  });
  it("only the classes actually written propagate", () => {
    const findings = read("def h(request):\n    users = UserModel.objects.filter(active=True)\n    return HttpResponse(users)\n", 1 /* SQL only */);
    expect(findings.some(f => f.id === "xss")).toBe(false);
  });
  it("a call on a receiver NOT in modelReceivers is not a read", () => {
    const findings = read("def h(request):\n    x = SomethingElse.objects.filter(active=True)\n    return HttpResponse(x)\n", 1 << 2);
    expect(findings.some(f => f.id === "xss")).toBe(false);
  });
  it("without a storedProvenance param at all, behavior is unchanged from before this feature existed", () => {
    const findings = scanAstTaintPython("def h(request):\n    users = UserModel.objects.filter(active=True)\n    return HttpResponse(users)\n", "read.py");
    expect(findings.some(f => f.id === "xss")).toBe(false);
  });
});
