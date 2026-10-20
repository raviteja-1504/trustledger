/**
 * API security report (lib/api/apiSecurityReport.ts): every endpoint and finding carries its scan; per-repository
 * counts stay exact even when the endpoint list is capped.
 */
import { buildApiSecurityReport } from "@/lib/api/apiSecurityReport";

const routes = (n: number, guard = "requireUser") =>
  `const router = express.Router();\n${Array.from({ length: n }, (_, i) => `router.get("/r${i}", ${guard}, h${i});`).join("\n")}\nrouter.delete("/open", del);\n`;

describe("buildApiSecurityReport", () => {
  it("endpoints and findings carry their repository's scan; repositories are summarised", () => {
    const r = buildApiSecurityReport([
      { repo: "o/api", scan_id: "s-api", scanned_at: "2026-10-19T00:00:00Z", files: [{ file_path: "src/routes.ts", content: routes(3) }] },
      { repo: "o/web", scan_id: "s-web", files: [{ file_path: "README.md", content: "# nothing" }] },
    ]);
    expect(r.endpoints.every(e => e.scan_id === "s-api")).toBe(true);
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.findings.every(f => f.scan_id === "s-api")).toBe(true);
    expect(r.repos[0]).toMatchObject({ repo: "o/api", scan_id: "s-api", scanned_at: "2026-10-19T00:00:00Z", endpoints: 4, authRequired: 3, flagged: 1, findings: r.findings.length });
    expect(r.repos[1]).toMatchObject({ repo: "o/web", scan_id: "s-web", scanned_at: null, endpoints: 0, findings: 0 });
    expect(r.truncated).toBe(false);
  });

  it("past the endpoint cap the list is truncated, the counts and per-repo numbers are not", () => {
    const r = buildApiSecurityReport([{ repo: "o/big", scan_id: "s", files: [{ file_path: "src/a.ts", content: routes(2100) }] }]);
    expect(r.endpoints).toHaveLength(2000);
    expect(r.truncated).toBe(true);
    expect(r.counts.endpoints).toBe(2101);
    expect(r.repos[0].endpoints).toBe(2101);
    expect(r.endpoints[0].flagged).toBe(true);            // missing auth first, so it's never the part cut off
  });
});
