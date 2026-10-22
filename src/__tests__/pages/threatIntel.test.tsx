/**
 * Threat intel page: only advisories from the org's real dependency findings, with links to the advisory and repos.
 */
import React from "react";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

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
    expect(within(rows[0]).getByRole("link", { name: /^GHSA-4w2v-q235-vp99/ })).toHaveAttribute("href", "https://github.com/advisories/GHSA-4w2v-q235-vp99");
    expect(within(rows[1]).getByRole("link", { name: /^CVE-2020-8203/ })).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2020-8203");
    // each repository links to the PR whose scan found it
    expect(within(rows[1]).getByRole("link", { name: "acme/api" })).toHaveAttribute("href", "/pr/s1");
    expect(screen.getByRole("region", { name: "Supply-chain risks" })).toHaveTextContent("react-utils-proDoesn't exist");
    // No static catalogue: nothing about threats that don't touch these packages.
    expect(document.body.textContent).not.toMatch(/Jenkins|runc|XZ Utils|SLA BREACHED/);

    fireEvent.click(screen.getByRole("button", { name: "Public exploit" }));
    expect(within(list).getAllByRole("listitem")).toHaveLength(1);
  });

  it("repository, ecosystem and severity filters narrow the advisories, stats and supply-chain list", async () => {
    findings = [
      { ...base, id: "1", type: "vulnerable", package_name: "lodash", version_used: "4.17.15", risk: "HIGH", repo: "acme/api", description: "Prototype pollution", cve: "CVE-2020-8203" },
      { ...base, id: "1b", type: "vulnerable", package_name: "lodash", version_used: "4.17.15", risk: "HIGH", repo: "acme/web", description: "Prototype pollution", cve: "CVE-2020-8203", reachability: { tier: "called" } },
      { ...base, id: "2", type: "vulnerable", package_name: "requests", version_used: "2.19.0", risk: "MEDIUM", repo: "acme/api", ecosystem: "pypi", description: "Cert leak", cve: "CVE-2018-18074" },
      { ...base, id: "3", type: "hallucinated", package_name: "react-utils-pro", version_used: "*", risk: "CRITICAL", repo: "acme/web", description: "Not on npm" },
    ];
    render(<ThreatIntelPage />);
    const list = await screen.findByRole("region", { name: "Advisories" });
    const names = () => within(list).queryAllByRole("listitem").map(li => li.querySelector("p > span.font-mono")!.textContent);
    expect(names()).toEqual(["lodash@4.17.15", "requests@2.19.0"]);
    expect(screen.getByRole("option", { name: "All repositories (2)" })).toBeInTheDocument();

    // One repository: its advisories only, and reachability as it is THERE (lodash is called in acme/web, not acme/api).
    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "acme/api" } });
    expect(names()).toEqual(["lodash@4.17.15", "requests@2.19.0"]);
    expect(within(list).getAllByRole("listitem")[0]).not.toHaveTextContent("Reachable");
    expect(screen.getByRole("region", { name: "Supply-chain risks" })).toHaveTextContent("None found.");
    expect(screen.getByText("Reachable from your code").parentElement).toHaveTextContent("0");
    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "acme/web" } });
    expect(names()).toEqual(["lodash@4.17.15"]);
    expect(within(list).getAllByRole("listitem")[0]).toHaveTextContent("Reachable");
    expect(screen.getByRole("region", { name: "Supply-chain risks" })).toHaveTextContent("react-utils-pro");

    // Ecosystem and severity.
    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "all" } });
    fireEvent.change(screen.getByLabelText("Ecosystem"), { target: { value: "pypi" } });
    expect(names()).toEqual(["requests@2.19.0"]);
    fireEvent.change(screen.getByLabelText("Ecosystem"), { target: { value: "all" } });
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "HIGH" } });
    expect(names()).toEqual(["lodash@4.17.15"]);
    expect(list).toHaveTextContent("1 of 2 shown");

    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(names()).toEqual(["lodash@4.17.15", "requests@2.19.0"]);
    expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
  });

  it("a chosen repository that's gone after a refresh falls back to all, instead of an empty page", async () => {
    findings = [
      { ...base, id: "1", type: "vulnerable", package_name: "lodash", version_used: "4.17.15", risk: "HIGH", repo: "acme/api", description: "Prototype pollution", cve: "CVE-2020-8203" },
      { ...base, id: "2", type: "vulnerable", package_name: "axios", version_used: "0.21.0", risk: "HIGH", repo: "acme/web", description: "SSRF", cve: "CVE-2021-3749" },
    ];
    render(<ThreatIntelPage />);
    const list = await screen.findByRole("region", { name: "Advisories" });
    fireEvent.change(screen.getByLabelText("Repository"), { target: { value: "acme/web" } });
    expect(within(list).getAllByRole("listitem")).toHaveLength(1);
    findings = [findings[0]];                        // acme/web disconnected
    await act(async () => { window.dispatchEvent(new Event("focus")); });
    await waitFor(() => expect(within(list).getAllByRole("listitem")).toHaveLength(1));
    expect(within(list).getAllByRole("listitem")[0]).toHaveTextContent("lodash@4.17.15");
    expect(screen.getByLabelText("Repository")).toHaveValue("all");
  });

  it("no vulnerable packages → says so", async () => {
    findings = [];
    render(<ThreatIntelPage />);
    expect(await screen.findByText("No known vulnerabilities in the packages your repositories use.")).toBeInTheDocument();
  });
});
