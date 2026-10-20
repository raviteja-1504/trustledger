/**
 * API security page: one repository filter scopes stats, findings and endpoints; links to scans; an error state
 * instead of silent zeros.
 */
import React from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1" } }) }));
jest.mock("@/lib/realtime", () => ({ useScansRealtime: () => {} }));
let fail = false;
const ep = (repo: string, scan: string, path: string, o: Record<string, unknown> = {}) => ({ method: "GET", path, file: "src/r.ts", line: 3, framework: "express", repo, scan_id: scan, source: "code", auth: "required", flagged: false, ...o });
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(async () => {
    if (fail) throw new Error("down");
    return {
      endpoints: [ep("o/api", "s1", "/admin", { method: "DELETE", auth: "none", flagged: true }), ep("o/api", "s1", "/orders"), ep("o/web", "s2", "/spec", { source: "spec", auth: "public", framework: "openapi" })],
      findings: [
        { id: "api-endpoint-missing-auth", title: "Endpoint missing auth", severity: "high", cwe: "CWE-306", repo: "o/api", scan_id: "s1", file: "src/r.ts", line: 3, detail: "DELETE /admin", fix: "Add requireUser" },
        { id: "api-spec-http-server", title: "Spec uses http", severity: "medium", cwe: "CWE-319", repo: "o/web", scan_id: "s2", file: "openapi.yaml", line: 4, detail: "http://", fix: "Use https" },
      ],
      counts: { endpoints: 3, authRequired: 1, explicitlyPublic: 1, noAuthVisible: 1, flagged: 1, specs: 1, findings: 2 },
      repos: [
        { repo: "o/api", scan_id: "s1", scanned_at: new Date().toISOString(), endpoints: 2, authRequired: 1, explicitlyPublic: 0, noAuthVisible: 1, flagged: 1, specs: 0, findings: 1 },
        { repo: "o/web", scan_id: "s2", scanned_at: null, endpoints: 1, authRequired: 0, explicitlyPublic: 1, noAuthVisible: 0, flagged: 0, specs: 1, findings: 1 },
      ],
      truncated: false,
    };
  }),
}));

import ApiSecurityPage from "@/app/api-security/page";

beforeEach(() => { fail = false; });

describe("API security page", () => {
  it("summary, per-repo table, findings with links; a repository scopes everything", async () => {
    render(<ApiSecurityPage />);
    const summary = await screen.findByRole("region", { name: "API summary" });
    expect(within(summary).getByText("Auth coverage").parentElement).toHaveTextContent("67%");
    const findings = screen.getByRole("region", { name: "Findings" });
    fireEvent.click(within(findings).getByText("Endpoint missing auth"));
    expect(within(findings).getByRole("link", { name: /Open in the scan/ })).toHaveAttribute("href", "/pr/s1");
    expect(within(findings).getByRole("link", { name: /Rule/ })).toHaveAttribute("href", "/rules#api-endpoint-missing-auth");
    expect(within(findings).getByRole("link", { name: /CWE-306/ })).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/306.html");

    fireEvent.click(within(screen.getByRole("region", { name: "Repositories" })).getByText("o/web"));
    expect(within(summary).getByText("Endpoints").parentElement).toHaveTextContent("1");
    expect(within(screen.getByRole("region", { name: "Findings" })).queryByText("Endpoint missing auth")).toBeNull();
    expect(within(screen.getByRole("region", { name: "Endpoint inventory" })).getAllByRole("row")).toHaveLength(2);   // header + /spec
  });

  it("inventory filters by auth, method and source", async () => {
    render(<ApiSecurityPage />);
    const inv = await screen.findByRole("region", { name: "Endpoint inventory" });
    fireEvent.change(screen.getByLabelText("Authentication"), { target: { value: "flagged" } });
    expect(within(inv).getAllByRole("row")).toHaveLength(2);
    expect(within(inv).getByRole("link", { name: /r\.ts:3/ })).toHaveAttribute("href", "/pr/s1");
    fireEvent.change(screen.getByLabelText("Authentication"), { target: { value: "all" } });
    fireEvent.change(screen.getByLabelText("Method"), { target: { value: "GET" } });
    expect(within(inv).getAllByRole("row")).toHaveLength(3);
    fireEvent.change(screen.getByLabelText("Declared in"), { target: { value: "spec" } });
    expect(within(inv).getAllByRole("row")).toHaveLength(2);
  });

  it("a failed load shows an error, not zeros", async () => {
    fail = true;
    render(<ApiSecurityPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load the API security report");
    expect(screen.queryByRole("region", { name: "API summary" })).toBeNull();
  });
});
