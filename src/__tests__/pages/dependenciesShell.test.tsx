/**
 * Dependencies is one page with two views (packages / vulnerabilities & fixes); /threat-intel redirects into it.
 */
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("@/components/DependencyInventory", () => ({ __esModule: true, default: () => <div>INVENTORY VIEW</div> }));
jest.mock("@/components/ThreatIntelView", () => ({ __esModule: true, default: () => <div>ADVISORIES VIEW</div> }));
const redirect = jest.fn();
jest.mock("next/navigation", () => ({ redirect: (p: string) => redirect(p) }));

import DependenciesPage from "@/app/dependencies/page";
import ThreatIntelRedirect from "@/app/threat-intel/page";
import { viewFromLocation, ADVISORIES_PATH } from "@/lib/dependencyViews";

beforeEach(() => { window.history.replaceState(null, "", "/dependencies"); redirect.mockReset(); });

describe("Dependencies page", () => {
  it("opens on the package list", () => {
    render(<DependenciesPage />);
    expect(screen.getByText("INVENTORY VIEW")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "All packages" })).toHaveAttribute("aria-selected", "true");
  });
  it("?view=advisories opens the vulnerabilities view (what /threat-intel links to)", () => {
    window.history.replaceState(null, "", "/dependencies?view=advisories");
    render(<DependenciesPage />);
    expect(screen.getByText("ADVISORIES VIEW")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Vulnerabilities & fixes" })).toHaveAttribute("aria-selected", "true");
  });
  it("switching views swaps the content and keeps the choice in the address", () => {
    render(<DependenciesPage />);
    fireEvent.click(screen.getByRole("tab", { name: "Vulnerabilities & fixes" }));
    expect(screen.getByText("ADVISORIES VIEW")).toBeInTheDocument();
    expect(screen.queryByText("INVENTORY VIEW")).toBeNull();
    expect(window.location.search).toBe("?view=advisories");
    fireEvent.click(screen.getByRole("tab", { name: "All packages" }));
    expect(screen.getByText("INVENTORY VIEW")).toBeInTheDocument();
    expect(window.location.search).toBe("");
  });
  it("reminds that large lists are capped", () => {
    render(<DependenciesPage />);
    expect(screen.getByText(/50,000 rows/)).toBeInTheDocument();
  });
});

describe("old Threat intel address", () => {
  it("redirects to the vulnerabilities view", () => {
    ThreatIntelRedirect();
    expect(redirect).toHaveBeenCalledWith("/dependencies?view=advisories");
    expect(ADVISORIES_PATH).toBe("/dependencies?view=advisories");
  });
  it("viewFromLocation accepts the two spellings and defaults to packages", () => {
    expect(viewFromLocation("?view=advisories")).toBe("advisories");
    expect(viewFromLocation("?view=vulnerabilities")).toBe("advisories");
    expect(viewFromLocation("?view=other")).toBe("packages");
    expect(viewFromLocation("")).toBe("packages");
  });
});
