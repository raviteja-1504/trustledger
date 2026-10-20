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
