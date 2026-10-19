/**
 * Threat intel page: only advisories from the org's real dependency findings, with links to the advisory and repos.
 */
import React from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1" } }) }));
jest.mock("@/lib/realtime", () => ({ useScansRealtime: () => {} }));
let findings: unknown[] = [];
jest.mock("@/lib/useRealData", () => ({ isSeedMode: () => false, authedFetch: jest.fn(async () => ({ findings })) }));

import ThreatIntelPage from "@/app/threat-intel/page";

const base = { file_path: "package.json", scan_id: "s1", ecosystem: "npm", fix: "Upgrade", exploit_public: false };

describe("Threat intel page", () => {
  it("lists real advisories with their ids, repos and exploit / reachability flags", async () => {
    findings = [
      { ...base, id: "1", type: "vulnerable", package_name: "lodash", version_used: "4.17.15", risk: "HIGH", repo: "acme/api", description: "Prototype pollution", cve: "CVE-2020-8203", cvss: 7.4 },
      { ...base, id: "2", type: "vulnerable", package_name: "axios", version_used: "0.21.0", risk: "HIGH", repo: "acme/web", description: "SSRF", cve: "GHSA-4w2v-q235-vp99", exploit_public: true, reachability: { tier: "called" } },
      { ...base, id: "3", type: "hallucinated", package_name: "react-utils-pro", version_used: "*", risk: "CRITICAL", repo: "acme/web", description: "Not on npm" },
    ];
    render(<ThreatIntelPage />);
    const list = await screen.findByRole("region", { name: "Advisories" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent("axios@0.21.0");
    expect(rows[0]).toHaveTextContent("Public exploit");
    expect(rows[0]).toHaveTextContent("Reachable");
    expect(within(rows[0]).getByRole("link", { name: "GHSA-4w2v-q235-vp99" })).toHaveAttribute("href", "https://github.com/advisories/GHSA-4w2v-q235-vp99");
    expect(within(rows[1]).getByRole("link", { name: "CVE-2020-8203" })).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2020-8203");
    expect(within(rows[1]).getByRole("link", { name: "acme/api" })).toHaveAttribute("href", "/repo/acme/api");
    expect(screen.getByRole("region", { name: "Supply-chain risks" })).toHaveTextContent("react-utils-proDoesn't exist");
    // No static catalogue: nothing about threats that don't touch these packages.
    expect(document.body.textContent).not.toMatch(/Jenkins|runc|XZ Utils|SLA BREACHED/);

    fireEvent.click(screen.getByRole("button", { name: "Public exploit" }));
    expect(within(list).getAllByRole("listitem")).toHaveLength(1);
  });

  it("no vulnerable packages → says so", async () => {
    findings = [];
    render(<ThreatIntelPage />);
    expect(await screen.findByText("No known vulnerabilities in the packages your repositories use.")).toBeInTheDocument();
  });
});
