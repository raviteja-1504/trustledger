/**
 * API security page: the filter bar sits above the numbers; endpoints and findings can be RESOLVED (kind, reason,
 * expiry), after which they leave the open list, stay findable under Resolved, and can be reopened.
 */
import React from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1" } }) }));
jest.mock("@/lib/realtime", () => ({ useScansRealtime: () => {} }));
let canTriage = true;
jest.mock("@/lib/roles", () => ({ useRole: () => ({ permissions: { canTriage } }) }));

type Ep = Record<string, unknown>;
let endpoints: Ep[] = [];
let findings: Array<Record<string, unknown>> = [];
let truncated = false;
const calls: Array<{ url: string; init?: { method?: string; body?: string } }> = [];
const KEY_DELETE = "api-00000000000001", KEY_ADMIN = "api-00000000000002";
const ep = (path: string, o: Ep = {}): Ep => ({ method: "GET", path, file: "src/r.ts", line: 3, framework: "express", repo: "o/api", scan_id: "s1", source: "code", auth: "required", flagged: false, key: `api-${path.replace(/\W/g, "")}`, ...o });
const report = () => {
  const open = endpoints.filter(e => !e.resolution);
  const flagged = open.filter(e => e.flagged).length;
  const resolvedEndpoints = endpoints.filter(e => e.resolution).length;
  return {
    endpoints, findings, truncated,
    counts: { endpoints: truncated ? 2500 : endpoints.length, authRequired: endpoints.filter(e => e.auth === "required").length, explicitlyPublic: 0, noAuthVisible: endpoints.filter(e => e.auth === "none").length, flagged, specs: 0, findings: findings.filter(f => !f.resolution).length, resolvedEndpoints, resolvedFindings: findings.filter(f => f.resolution).length },
    repos: [{ repo: "o/api", scan_id: "s1", scanned_at: null, endpoints: endpoints.length, authRequired: 2, explicitlyPublic: 0, noAuthVisible: endpoints.filter(e => e.auth === "none").length, flagged, specs: 0, findings: findings.filter(f => !f.resolution).length, resolved: resolvedEndpoints },
      { repo: "o/web", scan_id: "s2", scanned_at: null, endpoints: 4, authRequired: 1, explicitlyPublic: 0, noAuthVisible: 3, flagged: 0, specs: 0, findings: 0, resolved: 0 }],
  };
};
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(async (url: string, init?: { method?: string; body?: string }) => {
    calls.push({ url, init });
    if (url === "/api/findings/triage" && init?.method === "POST") {
      const b = JSON.parse(init.body!) as { fingerprint: string; reason: string; rule_id: string };
      for (const e of endpoints) if (e.key === b.fingerprint) e.resolution = { kind: "auth-elsewhere", status: "accepted", reason: b.reason, expires_at: null, set_by_email: "me@x.io", set_at: "2026-06-01T00:00:00Z" };
      for (const f of findings) if (f.key === b.fingerprint) f.resolution = { kind: "accepted-risk", status: "accepted", reason: b.reason, expires_at: null, set_by_email: "me@x.io", set_at: "2026-06-01T00:00:00Z" };
      return { ok: true };
    }
    if (url === "/api/findings/triage" && init?.method === "DELETE") {
      const b = JSON.parse(init.body!) as { fingerprint: string };
      for (const e of endpoints) if (e.key === b.fingerprint) delete e.resolution;
      for (const f of findings) if (f.key === b.fingerprint) delete f.resolution;
      return { ok: true };
    }
    return JSON.parse(JSON.stringify(report()));
  }),
}));

import ApiSecurityPage from "@/app/api-security/page";
import { authedFetch } from "@/lib/useRealData";

jest.setTimeout(30_000);
beforeEach(() => {
  canTriage = true; truncated = false; calls.length = 0;
  (authedFetch as jest.Mock).mockClear();
  endpoints = [
    ep("/admin", { method: "DELETE", auth: "none", flagged: true, key: KEY_DELETE }),
    ep("/export", { method: "POST", auth: "none", key: KEY_ADMIN }),
    ep("/orders"), ep("/orders/:id"),
  ];
  findings = [
    { id: "api-endpoint-missing-auth", title: "Endpoint missing auth", severity: "high", cwe: "CWE-306", repo: "o/api", scan_id: "s1", file: "src/r.ts", line: 3, detail: "DELETE /admin", fix: "Add requireUser", key: KEY_DELETE },
    { id: "api-spec-http-server", title: "Spec uses http", severity: "medium", cwe: "CWE-319", repo: "o/api", scan_id: "s1", file: "openapi.yaml", line: 4, detail: "http://", fix: "Use https", key: "api-spec00000000" },
  ];
});

const inventory = () => within(screen.getByRole("region", { name: "Endpoint inventory" }));
const findingsRegion = () => within(screen.getByRole("region", { name: "Findings" }));
const paths = () => inventory().getAllByRole("row").slice(1).map(r => within(r).queryAllByRole("cell")[1]?.textContent).filter(Boolean);
const renderPage = async () => { render(<ApiSecurityPage />); await screen.findByRole("region", { name: "API summary" }); };
const resolveEndpoint = async (name: RegExp, reason = "The gateway checks every call") => {
  fireEvent.click(inventory().getByRole("button", { name }));
  fireEvent.change(await screen.findByLabelText("Reason"), { target: { value: reason } });
  fireEvent.click(screen.getByRole("button", { name: "Save resolution" }));
};

describe("filter bar", () => {
  it("sits above the summary and the repository table, with the repository filter in it", async () => {
    await renderPage();
    const bar = screen.getByRole("search", { name: "Filters" });
    const repoSelect = within(bar).getByLabelText("Repository");
    const summary = screen.getByRole("region", { name: "API summary" });
    const repoTable = screen.getByRole("region", { name: "Repositories" });
    expect(bar.compareDocumentPosition(summary) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(bar.compareDocumentPosition(repoTable) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    fireEvent.change(repoSelect, { target: { value: "o/web" } });
    expect(within(bar).getByText("Scoped to o/web")).toBeInTheDocument();
    expect(within(summary).getByText("Endpoints").parentElement).toHaveTextContent("4");
  });

  it("search and Clear filters live there too, and Clear resets everything including the open/resolved switch", async () => {
    await renderPage();
    const bar = screen.getByRole("search", { name: "Filters" });
    fireEvent.change(within(bar).getByLabelText("Search endpoints"), { target: { value: "export" } });
    expect(paths()).toEqual(["/export"]);
    fireEvent.click(within(bar).getByRole("button", { name: /^Resolved/ }));
    fireEvent.click(within(bar).getByRole("button", { name: "Clear filters" }));
    expect(paths()).toHaveLength(4);
    expect(within(bar).getByRole("button", { name: "Open" })).toHaveAttribute("aria-pressed", "true");
  });
});

describe("resolving an endpoint", () => {
  it("records the decision, then the endpoint leaves the open list and the missing-auth count drops", async () => {
    await renderPage();
    const summary = screen.getByRole("region", { name: "API summary" });
    expect(within(summary).getByText("Missing auth").parentElement).toHaveTextContent("1");
    await resolveEndpoint(/Resolve DELETE \/admin/);
    await waitFor(() => expect(paths()).not.toContain("/admin"));
    const post = calls.find(c => c.init?.method === "POST")!;
    expect(post.url).toBe("/api/findings/triage");
    expect(JSON.parse(post.init!.body!)).toMatchObject({ repo: "o/api", fingerprint: KEY_DELETE, rule_id: "api-auth-elsewhere", status: "accepted", reason: "The gateway checks every call", expires_in_days: 90, file_path: "src/r.ts" });
    await waitFor(() => expect(within(summary).getByText("Missing auth").parentElement).toHaveTextContent("0"));
    expect(within(summary).getByText(/1 resolved/)).toBeInTheDocument();
  });

  it("the resolved endpoint is found under Resolved, with its kind, and can be reopened", async () => {
    await renderPage();
    await resolveEndpoint(/Resolve DELETE \/admin/);
    await waitFor(() => expect(paths()).not.toContain("/admin"));
    fireEvent.click(within(screen.getByRole("search", { name: "Filters" })).getByRole("button", { name: /^Resolved/ }));
    expect(paths()).toEqual(["/admin"]);
    expect(inventory().getByText(/Resolved · Auth is handled elsewhere/)).toBeInTheDocument();
    fireEvent.click(inventory().getByRole("button", { name: "Reopen" }));
    await waitFor(() => expect(calls.some(c => c.init?.method === "DELETE")).toBe(true));
    expect(JSON.parse(calls.find(c => c.init?.method === "DELETE")!.init!.body!)).toEqual({ repo: "o/api", fingerprint: KEY_DELETE });
    await waitFor(() => expect(inventory().queryByText("/admin")).toBeNull());               // no longer resolved: back in the Open list
    fireEvent.click(within(screen.getByRole("search", { name: "Filters" })).getByRole("button", { name: "Open" }));
    expect(paths()).toContain("/admin");
  });

  it("the same decision settles the finding about that endpoint", async () => {
    await renderPage();
    expect(findingsRegion().getByText("Endpoint missing auth")).toBeInTheDocument();
    await resolveEndpoint(/Resolve DELETE \/admin/);
    await waitFor(() => expect(findingsRegion().queryByText("Endpoint missing auth")).toBeNull());
    expect(findingsRegion().getByText("Spec uses http")).toBeInTheDocument();                 // the unrelated finding stays open
  });

  it("needs a reason; nothing is sent without one", async () => {
    await renderPage();
    fireEvent.click(inventory().getByRole("button", { name: /Resolve DELETE \/admin/ }));
    fireEvent.change(await screen.findByLabelText("Reason"), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: "Save resolution" }));
    expect(await screen.findByText(/Give a short reason/)).toBeInTheDocument();
    expect(calls.some(c => c.init?.method === "POST")).toBe(false);
  });

  it("a refusal from the server is shown and the panel stays open", async () => {
    (authedFetch as jest.Mock).mockImplementationOnce(async (url: string) => JSON.parse(JSON.stringify(report()))).mockImplementationOnce(async () => { throw new Error("Finding triage isn't set up on this database yet"); });
    await renderPage();
    fireEvent.click(inventory().getByRole("button", { name: /Resolve DELETE \/admin/ }));
    fireEvent.change(await screen.findByLabelText("Reason"), { target: { value: "gateway handles it" } });
    fireEvent.click(screen.getByRole("button", { name: "Save resolution" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("isn't set up on this database yet");
    expect(screen.getByTestId("resolve-panel")).toBeInTheDocument();
  });

  it("offers the endpoint choices, and the chosen kind goes to the right rule", async () => {
    await renderPage();
    fireEvent.click(inventory().getByRole("button", { name: /Resolve POST \/export/ }));
    const group = within(await screen.findByRole("radiogroup", { name: "Resolution" }));
    expect(group.getAllByRole("radio").map(r => r.textContent?.split(/(?=[A-Z][a-z])/)[0])).toHaveLength(3);
    fireEvent.click(group.getByRole("radio", { name: /Public on purpose/ }));
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "It is the public webhook" } });
    fireEvent.click(screen.getByRole("button", { name: "Save resolution" }));
    await waitFor(() => expect(calls.some(c => c.init?.method === "POST")).toBe(true));
    expect(JSON.parse(calls.find(c => c.init?.method === "POST")!.init!.body!)).toMatchObject({ rule_id: "api-public-by-design", status: "accepted" });
  });
});

describe("resolving a finding that is not about one endpoint", () => {
  it("offers 'Accept the risk' and 'False positive' instead of the auth choices", async () => {
    await renderPage();
    fireEvent.click(findingsRegion().getByText("Spec uses http"));
    fireEvent.click(findingsRegion().getByRole("button", { name: "Resolve…" }));
    const group = within(await screen.findByRole("radiogroup", { name: "Resolution" }));
    expect(group.getAllByRole("radio")).toHaveLength(2);
    expect(group.getByRole("radio", { name: /Accept the risk/ })).toBeInTheDocument();
    expect(group.getByRole("radio", { name: /False positive/ })).toBeInTheDocument();
    expect(group.queryByRole("radio", { name: /Auth is handled elsewhere/ })).toBeNull();
  });
});

describe("who can resolve", () => {
  it("others see that a reviewer is needed, and no Resolve buttons", async () => {
    canTriage = false;
    await renderPage();
    expect(inventory().queryByRole("button", { name: /Resolve/ })).toBeNull();
    expect(inventory().getAllByText("Needs a reviewer").length).toBeGreaterThan(0);
    fireEvent.click(findingsRegion().getByText("Endpoint missing auth"));
    expect(findingsRegion().getByText(/Only security reviewers and admins can resolve findings/)).toBeInTheDocument();
  });
});

describe("what to look at first", () => {
  it("points at data-changing endpoints with no auth, and 'Show them' filters to exactly those", async () => {
    await renderPage();
    const first = screen.getByRole("region", { name: "What to look at first" });
    expect(within(first).getByText(/2 data-changing endpoints with no auth visible/)).toBeInTheDocument();
    fireEvent.click(within(first).getByRole("button", { name: /Show them/ }));
    expect(paths().sort()).toEqual(["/admin", "/export"]);
    expect(screen.getByLabelText("Authentication")).toHaveValue("none");
    expect(screen.getByLabelText("Method")).toHaveValue("writes");
  });

  it("names the weakest repository and scopes the page to it on request", async () => {
    await renderPage();
    const first = screen.getByRole("region", { name: "What to look at first" });
    expect(within(first).getByText(/Weakest coverage/)).toHaveTextContent("o/web");
    fireEvent.click(within(first).getByRole("button", { name: /Open this repository/ }));
    expect(within(screen.getByRole("search", { name: "Filters" })).getByText("Scoped to o/web")).toBeInTheDocument();
  });
});

describe("caps", () => {
  it("says when the endpoint list was cut at the cap, with the real total", async () => {
    truncated = true;
    await renderPage();
    expect(screen.getByRole("status")).toHaveTextContent(/Showing 4 of 2,500 endpoints/);
  });
  it("says nothing when nothing was cut", async () => {
    await renderPage();
    expect(screen.queryByRole("status")).toBeNull();
  });
});
