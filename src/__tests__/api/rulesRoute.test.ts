/**
 * @jest-environment node
 *
 * GET /api/rules?usage=1: rule usage from the latest scan of each ACTIVE repository, paged past the row cap, and
 * scoped to a developer's own pull requests.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let auth: Record<string, unknown> = { org_id: "org-1", role: "admin", user_id: "u1" };
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => auth }));
jest.mock("@/lib/ruleCatalog", () => ({ buildRuleCatalog: () => [{ id: "sql-injection" }, { id: "eval-exec" }] }));

import { GET } from "@/app/api/rules/route";

const get = async (q = "?usage=1") => {
  const res = await GET(new NextRequest(new URL(`/api/rules${q}`, "https://app.example")));
  return { res, body: await res.json() as { rules: unknown[]; usage?: Record<string, { files: number; repos: number }>; scope?: string } };
};
const scan = (id: string, repo: string, at: string, author = "dev1") => ({ id, org_id: "org-1", repo_full_name: repo, created_at: at, pr_author: author });
const file = (scan_id: string, path: string, ind: string[]) => ({ org_id: "org-1", scan_id, file_path: path, risk_indicators: ind });

function seed(extra: { scans?: unknown[]; files?: unknown[] } = {}, opts: Parameters<typeof fakeSupabase>[1] = {}) {
  db = fakeSupabase({
    repositories: [{ org_id: "org-1", repo_full_name: "o/api", is_active: true }, { org_id: "org-1", repo_full_name: "o/web", is_active: true }, { org_id: "org-1", repo_full_name: "o/off", is_active: false }],
    org_members: [{ org_id: "org-1", user_id: "u-dev", github_login: "dev1" }],
    scans: (extra.scans ?? [scan("a1", "o/api", "2026-10-01"), scan("a2", "o/api", "2026-10-05", "dev2"), scan("w1", "o/web", "2026-10-03"), scan("x1", "o/off", "2026-10-06")]) as Record<string, unknown>[],
    scan_files: (extra.files ?? [
      file("a1", "old.py", ["sql-injection"]), file("a2", "db.py", ["sql-injection"]), file("a2", "run.py", ["eval-exec"]),
      file("w1", "q.ts", ["sql-injection"]), file("x1", "off.py", ["sql-injection"]),
    ]) as Record<string, unknown>[],
  }, opts);
}

beforeEach(() => { auth = { org_id: "org-1", role: "admin", user_id: "u1" }; seed(); });

describe("GET /api/rules", () => {
  it("without usage: just the catalog", async () => {
    const { body } = await get("");
    expect(body.rules).toHaveLength(2);
    expect(body.usage).toBeUndefined();
  });

  it("usage counts the latest scan of each active repository", async () => {
    const { res, body } = await get();
    expect(body.scope).toBe("org");
    expect(body.usage!["sql-injection"]).toMatchObject({ files: 2, repos: 2 });   // a2/db.py + w1/q.ts (not a1's old file, not the inactive repo)
    expect(body.usage!["eval-exec"]).toMatchObject({ files: 1, repos: 1 });
    expect(res.headers.get("Cache-Control")).toBe("private, no-store");
  });

  it("developers count only their own pull requests' scans; unlinked developers get nothing", async () => {
    auth = { org_id: "org-1", role: "developer", user_id: "u-dev" };
    const { body } = await get();
    expect(body.scope).toBe("own");
    expect(body.usage!["sql-injection"]).toMatchObject({ files: 2, repos: 2 });   // dev1's latest api scan is a1
    expect(body.usage!["eval-exec"]).toBeUndefined();
    auth = { org_id: "org-1", role: "developer", user_id: "u-nobody" };
    expect((await get()).body.usage).toEqual({});
  });

  it("usage compares each repository's latest scan with its previous one: new and fixed files", async () => {
    // o/api: previous a1 had old.py firing; latest a2 has db.py firing and old.py no longer firing -> 1 new, 1 fixed.
    // A file that simply wasn't rescanned is not "fixed". o/web has one scan: nothing claimed.
    seed({ files: [file("a1", "old.py", ["sql-injection"]), file("a1", "gone.py", ["sql-injection"]), file("a2", "db.py", ["sql-injection"]), file("a2", "old.py", []), file("w1", "q.ts", ["sql-injection"]), file("a2", "run.py", ["eval-exec"])] });
    const { body } = await get();
    expect(body.usage!["sql-injection"]).toMatchObject({ files: 2, new: 1, fixed: 1, compared: true });
    expect(body.usage!["eval-exec"]).toMatchObject({ new: 1, fixed: 0 });
  });

  describe("?rule=<id>: every file the rule fires on", () => {
    type Loc = { locations: { repo: string; file_path: string; scan_id: string }[]; total: number; truncated: boolean; scope: string };
    const loc = async (q: string) => { const r = await get(q); return { res: r.res, body: r.body as unknown as Loc & { error?: string } }; };

    it("lists them from the latest scans of active repos, sorted, with the scan to open", async () => {
      const { res, body } = await loc("?rule=sql-injection");
      expect(res.headers.get("Cache-Control")).toBe("private, no-store");
      expect(body.locations).toEqual([
        { repo: "o/api", file_path: "db.py", scan_id: "a2" },
        { repo: "o/web", file_path: "q.ts", scan_id: "w1" },
      ]);
      expect(body).toMatchObject({ total: 2, truncated: false, scope: "org" });
    });

    it("can be narrowed to one repository", async () => {
      expect((await loc("?rule=sql-injection&repo=o%2Fweb")).body.locations.map(l => l.file_path)).toEqual(["q.ts"]);
    });

    it("an unknown rule is a 404, not an empty list", async () => {
      const { res, body } = await loc("?rule=nope");
      expect(res.status).toBe(404);
      expect(body.error).toBe("unknown_rule");
    });

    it("developers only see files from their own pull requests", async () => {
      auth = { org_id: "org-1", role: "developer", user_id: "u-dev" };
      const { body } = await loc("?rule=sql-injection");
      expect(body.scope).toBe("own");
      expect(body.locations.map(l => l.file_path)).toEqual(["old.py", "q.ts"]);          // dev1's latest api scan is a1
    });

    it("past the cap it says so, with the real total", async () => {
      const many = Array.from({ length: 2300 }, (_, i) => file("a2", `f${String(i).padStart(4, "0")}.py`, ["sql-injection"]));
      seed({ files: many }, { maxRows: 1000 });
      const { body } = await loc("?rule=sql-injection");
      expect(body.locations).toHaveLength(2000);
      expect(body).toMatchObject({ total: 2300, truncated: true });
    });
  });

  it("reads past the 1000-row cap", async () => {
    const files = Array.from({ length: 2500 }, (_, i) => file("a2", `f${i}.py`, ["sql-injection"]));
    // o/web's only scan is older than 1500 newer o/api scans: an unpaged scans read (newest first) never reaches it.
    const busy = Array.from({ length: 1500 }, (_, i) => scan(`o${i}`, "o/api", `2026-09-${String(1 + (i % 28)).padStart(2, "0")}`));
    seed({ scans: [scan("w-old", "o/web", "2026-01-01"), ...busy, scan("a2", "o/api", "2026-10-05")],
      files: [...files, file("w-old", "web.ts", ["eval-exec"])] }, { maxRows: 1000 });
    const u = (await get()).body.usage!;
    expect(u["sql-injection"].files).toBe(2500);
    expect(u["eval-exec"]).toMatchObject({ files: 1, repos: 1 });
  });
});
