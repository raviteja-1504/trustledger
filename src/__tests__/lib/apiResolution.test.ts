import {
  API_RULE_IDS, choicesFor, RESOLUTION_CHOICES, apiInsights, applyResolutions, endpointKey, findingKey, kindOfRule, normalizePath, resolutionsByRepo,
  type Resolution, type StoredResolution,
} from "@/lib/api/apiResolution";
import { buildApiSecurityReport, type ApiSecurityReport, type InventoryEndpoint } from "@/lib/api/apiSecurityReport";

const NOW = new Date("2026-06-30T12:00:00Z");
const res = (over: Partial<Resolution> = {}): Resolution => ({ kind: "auth-elsewhere", status: "accepted", reason: "gateway", expires_at: null, set_by_email: "a@x.io", set_at: "2026-06-01T00:00:00Z", ...over });
const stored = (over: Partial<StoredResolution> = {}): StoredResolution => ({ repo: "o/api", fingerprint: "api-x", rule_id: "api-auth-elsewhere", status: "accepted", reason: "gateway", expires_at: null, set_by_email: "a@x.io", set_at: "2026-06-01T00:00:00Z", ...over });

describe("endpoint keys", () => {
  it("ignore parameter names, a trailing slash, query strings and case", () => {
    const k = endpointKey("o/api", "GET", "/users/:id");
    expect(endpointKey("o/api", "get", "/users/{userId}")).toBe(k);
    expect(endpointKey("o/api", "GET", "/users/<int:uid>/")).toBe(k);
    expect(endpointKey("o/api", "GET", "/Users/:id?x=1")).toBe(k);
  });
  it("tell different endpoints apart: method, path, repository", () => {
    const k = endpointKey("o/api", "GET", "/users/:id");
    expect(endpointKey("o/api", "DELETE", "/users/:id")).not.toBe(k);
    expect(endpointKey("o/api", "GET", "/users")).not.toBe(k);
    expect(endpointKey("o/web", "GET", "/users/:id")).not.toBe(k);
  });
  it("are stored-key shaped: prefixed, long enough for the triage API, deterministic", () => {
    const k = endpointKey("o/api", "GET", "/x");
    expect(k).toMatch(/^api-[0-9a-f]{14}$/);
    expect(k.length).toBeGreaterThanOrEqual(8);
    expect(endpointKey("o/api", "GET", "/x")).toBe(k);
  });
  it("normalizePath keeps the root and collapses repeated slashes", () => {
    expect(normalizePath("/")).toBe("/");
    expect(normalizePath("//a///b/")).toBe("/a/b");
    expect(normalizePath("/a/:b/c/{d}")).toBe("/a/{}/c/{}");
  });
  it("a finding about no particular endpoint is keyed by what it says: digits in the detail don't change it", () => {
    const f = { repo: "o/api", id: "api-spec-weak", file: "openapi.yaml", detail: "scheme at line 12 uses basic" };
    expect(findingKey({ ...f, detail: "scheme at line 99 uses basic" })).toBe(findingKey(f));
    expect(findingKey({ ...f, file: "other.yaml" })).not.toBe(findingKey(f));
  });
});

describe("resolution choices", () => {
  it("each maps to one rule id and a triage status; unknown rules are not API resolutions", () => {
    expect(RESOLUTION_CHOICES.map(c => [c.kind, c.ruleId, c.status, c.appliesTo])).toEqual([
      ["auth-elsewhere", "api-auth-elsewhere", "accepted", "endpoint"], ["public-by-design", "api-public-by-design", "accepted", "endpoint"], ["not-an-endpoint", "api-not-an-endpoint", "false_positive", "endpoint"],
      ["accepted-risk", "api-accepted-risk", "accepted", "finding"], ["false-positive", "api-false-positive", "false_positive", "finding"],
    ]);
    expect(API_RULE_IDS).toEqual(["api-auth-elsewhere", "api-public-by-design", "api-not-an-endpoint", "api-accepted-risk", "api-false-positive"]);
    expect(kindOfRule("api-public-by-design")).toBe("public-by-design");
    expect(kindOfRule("sql-injection")).toBeNull();
    expect(kindOfRule(null)).toBeNull();
  });

  it("an endpoint is offered the auth-specific choices, any other finding the generic ones", () => {
    expect(choicesFor("endpoint").map(c => c.kind)).toEqual(["auth-elsewhere", "public-by-design", "not-an-endpoint"]);
    expect(choicesFor("finding").map(c => c.kind)).toEqual(["accepted-risk", "false-positive"]);
  });
});

describe("resolutionsByRepo", () => {
  it("groups by repository and key, keeping the rule's kind", () => {
    const m = resolutionsByRepo([stored(), stored({ repo: "o/web", fingerprint: "api-y", rule_id: "api-public-by-design" })], NOW);
    expect(m.get("o/api")!.get("api-x")).toMatchObject({ kind: "auth-elsewhere", reason: "gateway" });
    expect(m.get("o/web")!.get("api-y")!.kind).toBe("public-by-design");
  });
  it("drops expired decisions (the issue comes back) and decisions under other rules", () => {
    const m = resolutionsByRepo([
      stored({ fingerprint: "api-live", expires_at: "2026-12-01T00:00:00Z" }),
      stored({ fingerprint: "api-old", expires_at: "2026-06-01T00:00:00Z" }),
      stored({ fingerprint: "api-other", rule_id: "xss" }),
    ], NOW);
    expect([...m.get("o/api")!.keys()]).toEqual(["api-live"]);
  });
});

// A small real report: one repo, an unprotected DELETE next to protected routes, plus a spec.
const report = (): ApiSecurityReport => buildApiSecurityReport([{
  repo: "o/api", scan_id: "s1",
  files: [
    { file_path: "src/routes.ts", content: `const router = express.Router();\nrouter.get("/orders", requireUser, listOrders);\nrouter.post("/orders", requireUser, createOrder);\nrouter.delete("/orders/:id", deleteOrder);\nrouter.get("/health", health);\n` },
  ],
}]);

describe("applyResolutions", () => {
  const flaggedEp = (r: ApiSecurityReport) => r.endpoints.find(e => e.flagged)!;

  it("the report builder gives every endpoint a stable key and ties a missing-auth finding to its endpoint", () => {
    const r = report();
    const ep = flaggedEp(r);
    expect(ep.key).toBe(endpointKey("o/api", ep.method, ep.path));
    const finding = r.findings.find(f => f.line === ep.line)!;
    expect(finding.key).toBe(ep.key);
  });

  it("resolving an endpoint attaches it, lowers the missing-auth count, and moves it below the open ones", () => {
    const r = report();
    const ep = flaggedEp(r);
    const out = applyResolutions(r, new Map([["o/api", new Map([[ep.key, res()]])]]));
    expect(out.counts.flagged).toBe(r.counts.flagged - 1);
    expect(out.counts.resolvedEndpoints).toBe(1);
    expect(out.endpoints.find(e => e.key === ep.key)!.resolution).toMatchObject({ kind: "auth-elsewhere" });
    expect(out.endpoints.at(-1)!.key).toBe(ep.key);                                   // sinks to the bottom
    expect(out.repos[0]).toMatchObject({ flagged: r.repos[0].flagged - 1, resolved: 1 });
  });

  it("resolving an endpoint also settles the finding about it (and drops the findings count)", () => {
    const r = report();
    const ep = flaggedEp(r);
    const out = applyResolutions(r, new Map([["o/api", new Map([[ep.key, res()]])]]));
    const f = out.findings.find(x => x.line === ep.line)!;
    expect(f.resolution).toBeDefined();
    expect(out.counts.findings).toBe(r.counts.findings - 1);
    expect(out.counts.resolvedFindings).toBe(1);
    expect(out.repos[0].findings).toBe(r.repos[0].findings - 1);
  });

  it("a decision on another repository's endpoint doesn't touch this one", () => {
    const r = report();
    const ep = flaggedEp(r);
    const out = applyResolutions(r, new Map([["o/other", new Map([[ep.key, res()]])]]));
    expect(out.counts.flagged).toBe(r.counts.flagged);
    expect(out.endpoints.every(e => !e.resolution)).toBe(true);
  });

  it("does not modify the report it is given (it may be cached)", () => {
    const r = report();
    const before = JSON.stringify(r);
    applyResolutions(r, new Map([["o/api", new Map([[flaggedEp(r).key, res()]])]]));
    expect(JSON.stringify(r)).toBe(before);
  });

  it("with nothing resolved, the counts are unchanged and nothing is marked", () => {
    const r = report();
    const out = applyResolutions(r, new Map());
    expect(out.counts).toMatchObject({ flagged: r.counts.flagged, findings: r.counts.findings, resolvedEndpoints: 0, resolvedFindings: 0 });
  });
});

describe("apiInsights", () => {
  const ep = (over: Partial<InventoryEndpoint>): InventoryEndpoint => ({ method: "GET", path: "/x", file: "f.ts", line: 1, framework: "express", repo: "o/api", scan_id: "s", source: "code", auth: "required", flagged: false, key: "api-k", ...over } as InventoryEndpoint);
  const summary = (repo: string, endpoints: number, authRequired: number, explicitlyPublic = 0) => ({ repo, scan_id: "s", scanned_at: null, endpoints, authRequired, explicitlyPublic, noAuthVisible: endpoints - authRequired - explicitlyPublic, flagged: 0, specs: 0, findings: 0 });

  it("finds writes that show no auth, ignoring reads and resolved ones", () => {
    const i = apiInsights({
      endpoints: [ep({ method: "DELETE", auth: "none", path: "/a" }), ep({ method: "GET", auth: "none", path: "/b" }), ep({ method: "POST", auth: "none", path: "/c", resolution: res() }), ep({ method: "PUT", auth: "required", path: "/d" })],
      repos: [], counts: { endpoints: 4, authRequired: 1, explicitlyPublic: 0, noAuthVisible: 3, flagged: 0, specs: 0, findings: 0 },
    });
    expect(i.unprotectedWrites.map(e => e.path)).toEqual(["/a"]);
  });

  it("names the repository with the lowest coverage, among those big enough to judge", () => {
    const i = apiInsights({ endpoints: [], repos: [summary("o/tiny", 1, 0), summary("o/ok", 10, 10), summary("o/weak", 10, 4, 1), summary("o/mid", 8, 6)], counts: { endpoints: 29, authRequired: 20, explicitlyPublic: 1, noAuthVisible: 8, flagged: 0, specs: 0, findings: 0 } });
    expect(i.weakestRepo).toEqual({ repo: "o/weak", coverage: 50, endpoints: 10 });
  });

  it("says nothing about coverage when every repository is fully covered", () => {
    expect(apiInsights({ endpoints: [], repos: [summary("o/ok", 10, 10)], counts: { endpoints: 10, authRequired: 10, explicitlyPublic: 0, noAuthVisible: 0, flagged: 0, specs: 0, findings: 0 } }).weakestRepo).toBeNull();
  });

  it("reports spec coverage and the number still needing a decision", () => {
    const i = apiInsights({ endpoints: [ep({ source: "spec" }), ep({}), ep({}), ep({})], repos: [], counts: { endpoints: 4, authRequired: 4, explicitlyPublic: 0, noAuthVisible: 0, flagged: 3, specs: 1, findings: 0 } });
    expect(i.specCoverage).toBe(25);
    expect(i.needDecision).toBe(3);
    expect(apiInsights({ endpoints: [], repos: [], counts: { endpoints: 0, authRequired: 0, explicitlyPublic: 0, noAuthVisible: 0, flagged: 0, specs: 0, findings: 0 } }).specCoverage).toBeNull();
  });
});
