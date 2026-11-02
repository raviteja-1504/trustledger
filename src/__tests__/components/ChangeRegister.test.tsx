/**
 * Report section: the change-management register -- built on request (it reads GitHub), the summary, an incomplete
 * population stated, exceptions vs all pull requests, an auditor sample re-drawn for any seed exactly as the server
 * draws it, and the CSV / JSON downloads from the loaded register.
 */
import React from "react";
import { act, fireEvent, render, screen, within } from "@testing-library/react";

let fail = false;
const urls: string[] = [];
jest.mock("@/lib/useRealData", () => ({
  authedFetch: jest.fn(async (url: string) => {
    urls.push(url);
    if (fail) throw new Error("GitHub down");
    return register;
  }),
}));

import ChangeRegister from "@/components/reports/ChangeRegister";
import { buildRegister, drawSample, registerToCsv, pullKey } from "@/lib/changeRegister";
import { normalizeProtection } from "@/lib/branchProtection";

const pull = (number: number) => ({ repo: "acme/api", number, title: `Change ${number}`, author: "alice",
  merged_at: `2026-10-${String(number).padStart(2, "0")}T12:00:00Z`, merged_by: "carol", head_sha: `sha${number}`, url: `https://github.com/acme/api/pull/${number}` });
// 1-20 approved by bob on the merged commit and scanned; 21-30 merged with neither
const protection = [
  normalizeProtection({ repo: "acme/api", branch: "main", protected: true, classic: "none",
    rules: [{ type: "pull_request", parameters: { required_approving_review_count: 2 } }, { type: "non_fast_forward" }] }),
  normalizeProtection({ repo: "acme/web", branch: null, protected: null, rules: null, classic: "unreadable", error: "not installed" }),
  normalizeProtection({ repo: "acme/app", branch: "main", protected: true, rules: [], classic: "unreadable" }),
];
const register = { ...buildRegister({
  period_start: "2026-10-01T00:00:00Z", period_end: "2026-10-31T23:59:59Z",
  pulls: Array.from({ length: 30 }, (_, i) => pull(i + 1)),
  reviews: new Map(Array.from({ length: 20 }, (_, i) => [pullKey("acme/api", i + 1), [{ reviewer: "bob", state: "APPROVED", submitted_at: `2026-10-${String(i + 1).padStart(2, "0")}T10:00:00Z`, commit_id: `sha${i + 1}` }]])),
  scans: Array.from({ length: 20 }, (_, i) => ({ scan_id: `s${i + 1}`, repo: "acme/api", pr_number: i + 1, commit_sha: `sha${i + 1}`, created_at: `2026-10-${String(i + 1).padStart(2, "0")}T09:00:00Z`, overall_risk: "LOW" })),
  riskyFiles: [], signoffs: [],
  coverage: [{ repo: "acme/api", read: true, pulls: 30 }, { repo: "acme/web", read: false, pulls: 0, reason: "The TrustLedger GitHub App is not installed" }],
}), branch_protection: protection };

const view = (start = "2026-10-01") => <ChangeRegister start={start} end="2026-10-31" control="CC8.1" color="#6366f1" />;
async function built(start?: string) {
  const r = render(view(start));
  await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Build change register" })); });
  return r;
}
const blobText = (b: Blob) => new Promise<string>(res => { const r = new FileReader(); r.onload = () => res(r.result as string); r.readAsText(b); });
const prsIn =(label: string) => within(screen.getByRole("table", { name: label })).getAllByRole("link", { name: /^acme\/api#\d+$/ }).map(a => a.textContent);

beforeEach(() => { fail = false; urls.length = 0; });
// jsdom's FileReader and table renders are slow under full-suite load; the 5 s default timed out there
jest.setTimeout(30_000);

describe("ChangeRegister", () => {
  it("doesn't read GitHub until asked, then asks for the whole period through the end of its last day", async () => {
    render(view());
    expect(urls).toEqual([]);
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Build change register" })); });
    const qs = new URLSearchParams(urls[0].split("?")[1]);
    expect(urls[0]).toMatch(/^\/api\/report\/change-register\?/);
    expect([qs.get("period_start"), qs.get("period_end")]).toEqual(["2026-10-01T00:00:00.000Z", "2026-10-31T23:59:59.999Z"]);
  });

  it("shows the summary and states an incomplete population with the reason", async () => {
    await built();
    const summary = screen.getByRole("region", { name: "Change register summary" });
    expect(within(summary).getByText("Pull requests merged").previousSibling?.textContent).toBe("30");
    expect(within(summary).getByText("Approved before merge").previousSibling?.textContent).toBe("20");
    expect(within(summary).getByText("With exceptions").previousSibling?.textContent).toBe("10");
    expect(screen.getByRole("alert")).toHaveTextContent("Population incomplete");
    expect(screen.getByRole("alert")).toHaveTextContent("The TrustLedger GitHub App is not installed (1 repository): acme/web");
  });

  it("shows how merging is protected for the repositories read, Unknown where GitHub wouldn't say", async () => {
    await built();
    const table = screen.getByRole("table", { name: "Branch protection" });
    const api = within(table).getByText("acme/api").closest("tr")!;
    expect(within(api).getAllByText("Yes")).toHaveLength(2);       // pull request required, force push blocked
    expect(within(api).getByText("2")).toBeInTheDocument();
    const app = within(table).getByText("acme/app").closest("tr")!;
    expect(within(app).getAllByText("Unknown").length).toBeGreaterThan(0);
    expect(screen.getByText(/Administration: read.*\(acme\/app\)/)).toBeInTheDocument();
    // a repository GitHub couldn't be read for is listed once under the population, not as a row of Unknowns
    expect(within(table).queryByText("acme/web")).toBeNull();
  });

  it("no repository readable: says the register isn't available, once per reason", async () => {
    const saved = { ...register };
    Object.assign(register, { coverage: [{ repo: "acme/api", read: false, pulls: 0, reason: "The TrustLedger GitHub App is not installed" },
      { repo: "acme/web", read: false, pulls: 0, reason: "The TrustLedger GitHub App is not installed" }], complete: false });
    try {
      await built();
      const alert = screen.getByRole("alert");
      expect(alert).toHaveTextContent("Register not available: no repository could be read");
      expect(alert).toHaveTextContent("The TrustLedger GitHub App is not installed (2 repositories): acme/api, acme/web");
      expect(alert).toHaveTextContent("missing evidence, not evidence that no changes were made");
    } finally {
      Object.assign(register, saved);
    }
  });

  it("lists the exceptions first, and every pull request on the other tab", async () => {
    await built();
    expect(prsIn("Pull requests with exceptions")).toEqual(Array.from({ length: 10 }, (_, i) => `acme/api#${i + 21}`));
    fireEvent.click(screen.getByRole("tab", { name: "All pull requests (30)" }));
    expect(prsIn("All merged pull requests")).toHaveLength(30);
  });

  it("the sample is the one the server and anyone with the register draw for that seed and size", async () => {
    await built();
    fireEvent.change(screen.getByLabelText("Sample seed"), { target: { value: "audit-2026" } });
    fireEvent.change(screen.getByLabelText("Sample size"), { target: { value: "5" } });
    const expected = drawSample(register.rows, 5, "audit-2026").map(r => `acme/api#${r.number}`);
    expect(prsIn("Auditor sample")).toEqual(expected);
    fireEvent.change(screen.getByLabelText("Sample seed"), { target: { value: "another" } });
    expect(prsIn("Auditor sample")).not.toEqual(expected);
  });

  it("downloads the register as CSV and as JSON with the sample", async () => {
    const blobs: Blob[] = [];
    const names: string[] = [];
    URL.createObjectURL = jest.fn((b: Blob) => { blobs.push(b); return "blob:x"; });
    URL.revokeObjectURL = jest.fn();
    const click = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) { names.push(this.download); });
    await built();
    fireEvent.change(screen.getByLabelText("Sample seed"), { target: { value: "s1" } });
    fireEvent.click(screen.getByRole("button", { name: "Download CSV" }));
    fireEvent.click(screen.getByRole("button", { name: "Download JSON (with sample)" }));
    expect(names).toEqual(["trustledger-change-register-2026-10-01-2026-10-31.csv", "trustledger-change-register-2026-10-01-2026-10-31.json"]);
    expect(await blobText(blobs[0])).toBe(registerToCsv(register.rows));
    const json = JSON.parse(await blobText(blobs[1]));
    expect(json.sample.seed).toBe("s1");
    expect(json.sample.rows.map((r: { number: number }) => r.number)).toEqual(drawSample(register.rows, 25, "s1").map(r => r.number));
    click.mockRestore();
  });

  it("a failure says so; a different period needs building again", async () => {
    fail = true;
    const { rerender } = await built();
    expect(screen.getByRole("alert")).toHaveTextContent("Couldn't build the change register. GitHub down");
    fail = false;
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Build change register" })); });
    expect(screen.getByRole("region", { name: "Change register summary" })).toBeInTheDocument();
    rerender(view("2026-09-01"));
    expect(screen.queryByRole("region", { name: "Change register summary" })).toBeNull();
    expect(screen.getByRole("button", { name: "Build change register" })).toBeInTheDocument();
  });
});
