/**
 * Dependencies page: says it's loading (never "no packages" while fetching), shows where each version comes from,
 * every advisory, dev scope, and filters by scope.
 */
import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ profile: { org_id: "org-1" } }) }));

let resolveFetch!: (v: unknown) => void;
const finding = (o: Record<string, unknown>) => ({
  id: String(o.package_name), version_used: "1.0.0", ecosystem: "javascript", manager: "npm", risk: "HIGH", type: "vulnerable", repo: "acme/api",
  file_path: "package.json", pr_number: 1, scan_id: "s1", description: "desc", exploit_public: false, ai_introduced: false, is_transitive: false,
  license_risk: "safe", license_spdx: "MIT", is_archived: false, is_deprecated: false, health_score: 50, ...o,
});
jest.mock("@/lib/useRealData", () => ({
  isSeedMode: () => false,
  authedFetch: jest.fn(() => new Promise(r => { resolveFetch = r; })),
}));

import DependenciesPage from "@/app/dependencies/page";

const data = {
  manifestPackages: [],
  findings: [
    finding({ package_name: "axios", version_used: "0.21.0", version_source: "lockfile", version_range: "^0.21.0", scope: "runtime", cve: "CVE-2021-3749",
      fix: "Update axios to 1.6.0 or later (fixes all 2 advisories)", latest_version: "1.6.0",
      advisories: [
        { id: "GHSA-hi", aliases: ["CVE-2021-3749"], severity: "HIGH", summary: "ReDoS", fixedIn: "0.21.2" },
        { id: "GHSA-md", aliases: [], severity: "MEDIUM", summary: "CSRF token leak", fixedIn: "1.6.0" },
      ] }),
    finding({ package_name: "jest-util", risk: "MEDIUM", scope: "dev", version_source: "manifest", version_range: "^29.0.0", version_used: "^29.0.0" }),
  ],
};

describe("Dependencies page", () => {
  it("says it's loading until the findings arrive, instead of showing an empty list", async () => {
    render(<DependenciesPage />);
    expect(screen.getByRole("status", { name: "Loading dependencies" })).toHaveTextContent("Loading dependencies…");
    expect(screen.queryByText(/No packages match/)).toBeNull();
    resolveFetch(data);
    expect(await screen.findByText("axios")).toBeInTheDocument();
  });

  it("an expanded finding shows every advisory, the fix, and where its version comes from", async () => {
    render(<DependenciesPage />);
    resolveFetch(data);
    fireEvent.click(await screen.findByText("axios"));
    expect(screen.getByText("All 2 advisories for this version")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "CVE-2021-3749" })).toHaveAttribute("href", "https://osv.dev/vulnerability/GHSA-hi");
    expect(screen.getByText("fixed in 1.6.0")).toBeInTheDocument();
    expect(screen.getByText("Version 0.21.0 is what's installed, from the lockfile (the manifest asks for ^0.21.0).")).toBeInTheDocument();
  });

  it("dev dependencies are marked and can be filtered out", async () => {
    render(<DependenciesPage />);
    resolveFetch(data);
    expect(await screen.findByText("jest-util")).toBeInTheDocument();
    expect(screen.getByTitle(/Only used to develop/)).toHaveTextContent("dev");
    fireEvent.change(screen.getByLabelText("Scope"), { target: { value: "runtime" } });
    expect(screen.queryByText("jest-util")).toBeNull();
    expect(screen.getByText("axios")).toBeInTheDocument();
  });
});
