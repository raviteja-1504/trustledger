import { detectorRegistry, type Detector, type DetectorContext } from "@/lib/detectorRegistry";

describe("detectorRegistry", () => {
  afterEach(() => detectorRegistry._reset());

  const ctx: DetectorContext = { content: "const x = 1;", lines: ["const x = 1;"], file_path: "a.ts", language: "typescript" };

  it("runs a registered detector and returns its findings", () => {
    const detector: Detector = {
      id: "always-fires",
      category: "security",
      scan: () => [{ id: "always-fires", label: "Always fires", severity: "low", line: 1 }],
    };
    detectorRegistry.register(detector);

    const results = detectorRegistry.runAll(ctx);
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe("always-fires");
  });

  it("filters by category", () => {
    detectorRegistry.register({ id: "sec-1", category: "security",  scan: () => [{ id: "sec-1",  label: "x", severity: "low" }] });
    detectorRegistry.register({ id: "ai-1",  category: "ai-signal", scan: () => [{ id: "ai-1",   label: "x", severity: "low" }] });

    expect(detectorRegistry.runAll(ctx, "security")).toHaveLength(1);
    expect(detectorRegistry.runAll(ctx, "ai-signal")).toHaveLength(1);
    expect(detectorRegistry.runAll(ctx)).toHaveLength(2);
  });

  it("does not let one throwing detector break the others", () => {
    detectorRegistry.register({ id: "broken", category: "security", scan: () => { throw new Error("boom"); } });
    detectorRegistry.register({ id: "fine",   category: "security", scan: () => [{ id: "fine", label: "x", severity: "low" }] });

    const results = detectorRegistry.runAll(ctx);
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe("fine");
  });

  it("rejects registering the same detector id twice", () => {
    detectorRegistry.register({ id: "dup", category: "security", scan: () => [] });
    expect(() => detectorRegistry.register({ id: "dup", category: "security", scan: () => [] })).toThrow();
  });

  it("returns no findings when nothing is registered", () => {
    expect(detectorRegistry.runAll(ctx)).toHaveLength(0);
  });
});
