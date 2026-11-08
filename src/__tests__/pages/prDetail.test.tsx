/**
 * The PR scan page, mounted with a realistic scan: the summary cards, tooltips on the headers / filters / badges /
 * buttons, the full-screen review of flagged files, and triage producing the "rescan to apply" notice.
 */
import React from "react";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom";
import type { ScanResult } from "@/types";

jest.mock("@/components/AuthGuard", () => ({ __esModule: true, default: ({ children }: { children: React.ReactNode }) => <>{children}</> }));
jest.mock("next/navigation", () => ({ useParams: () => ({ id: "s1" }), useSearchParams: () => new URLSearchParams() }));
jest.mock("@/lib/auth", () => ({ useAuth: () => ({ user: { id: "u1" }, profile: { org_id: "org-1", email: "rev@x.io", role: "admin" } }) }));
jest.mock("@/lib/presence", () => ({ usePresence: () => ({ reviewers: [] }), initials: () => "R" }));
jest.mock("@/lib/realtime", () => ({ useAttestationsRealtime: () => undefined }));
jest.mock("@/lib/roles", () => ({
  ROLE_LABELS: { developer: "Developer", security_reviewer: "Security Reviewer", admin: "Admin" },
  useRole: () => ({ permissions: { canTriage: true, canAttest: true }, canAttestRisk: () => true, role: "admin", isDemo: false }),
}));
jest.mock("@/lib/useRealData", () => ({ isSeedMode: () => false, authedFetch: jest.fn() }));
let scan: ScanResult;
jest.mock("@/lib/api", () => ({ api: { getScan: jest.fn(async () => scan) } }));

import PRDetailPage from "@/app/pr/[id]/page";
import { authedFetch } from "@/lib/useRealData";
import { COLUMN_TIP, FILTER_TIP } from "@/lib/prTooltips";

jest.setTimeout(60_000);

const code = Array.from({ length: 30 }, (_, i) => `const line${i + 1} = ${i + 1};`).join("\n");
const ind = (id: string, line: number, severity: string, over: Record<string, unknown> = {}) => ({
  id, label: id, severity, line, cwe: "CWE-89", fingerprint: `fingerprint-${id}-${line}`, introduced: true, lifecycle_status: "new", ...over,
});
const file = (path: string, risk: string, indicators: ReturnType<typeof ind>[], over: Record<string, unknown> = {}) => ({
  file_path: path, language: "typescript", ai_percentage: 0.3, risk_score: risk, risk_indicators: [...new Set(indicators.map(i => i.id))],
  indicators, attested: false, content: code, fix_suggestions: [], ...over,
});

beforeAll(() => {
  Element.prototype.scrollTo = jest.fn() as unknown as typeof Element.prototype.scrollTo;
  Element.prototype.scrollIntoView = jest.fn();
});
beforeEach(() => {
  (authedFetch as jest.Mock).mockReset();
  (authedFetch as jest.Mock).mockResolvedValue({});
  scan = {
    scan_id: "s1", repo: "acme/shop", pr_number: 7, commit_sha: "abcdef1234567890", overall_risk: "CRITICAL", total_ai_percentage: 0.3,
    timestamp: "2026-06-01T10:00:00Z", evidence_breakdown: null, ai_tooling: [],
    lifecycle: {
      summary: { new: 3, existing: 0, reopened: 0, accepted: 0, false_positive: 0, fixed: 0 }, fixed: [], has_previous_scan: true,
      previous_scan: { scan_id: "s0", commit_sha: "0123456789abcdef", created_at: "2026-05-31T09:00:00Z" },
    },
    files: [
      file("src/db.ts", "CRITICAL", [ind("sql-injection", 5, "critical"), ind("xss", 12, "high", { cwe: "CWE-79" })]),
      file("src/api.ts", "HIGH", [ind("path-traversal", 8, "high", { cwe: "CWE-22" })]),
      file("src/util.ts", "LOW", []),
    ],
  } as unknown as ScanResult;
});

const renderPage = async () => {
  render(<PRDetailPage />);
  await screen.findByText(/Scan Detail/);
};
const tipOf = (el: HTMLElement) => { fireEvent.focus(el); const t = screen.getByRole("tooltip").textContent ?? ""; fireEvent.blur(el); return t; };
/** A file's name inside the files table (the same name also appears elsewhere on the page). */
const fileCell = (name: string) => within(screen.getByRole("table")).getByText(name);
const rowOf = (name: string) => fileCell(name).closest("tr")!;

describe("PR page: the numbers", () => {
  it("shows files, findings and changes as three cards, each with its own unit", async () => {
    await renderPage();
    const files = within(screen.getByTestId("card-files"));
    expect(files.getByText("files scanned").previousElementSibling).toHaveTextContent("3");
    expect(files.getByText(/need review/).closest("li")).toHaveTextContent("2 need review");   // CRITICAL + HIGH
    const findings = within(screen.getByTestId("card-findings"));
    expect(findings.getByText("findings").previousElementSibling).toHaveTextContent("3");
    expect(findings.getByText("1 critical")).toBeInTheDocument();
    expect(findings.getByText("2 high")).toBeInTheDocument();
    const changes = within(screen.getByTestId("card-changes"));
    expect(changes.getByText("0123456")).toBeInTheDocument();                          // names the scan it compared with
  });
});

describe("PR page: AI share", () => {
  it("says the share by code volume and what it rests on, when the scan has it", async () => {
    scan = { ...scan, ai_attribution: { estimated_ai_percentage: 0.41, estimated_ai_loc: 410, analyzed_loc: 1000, eligible_loc: 1010, unknown_loc: 10, excluded_loc: 5000, analysis_coverage: 0.99, ai_leaning_loc: 0, mixed_loc: 0, human_leaning_loc: 0, high_confidence_loc: 0, medium_confidence_loc: 0, low_confidence_loc: 0 } } as ScanResult;
    await renderPage();
    expect(screen.getByText(/41% of the 1,000 source lines analysed look AI-written · 10 lines too short to judge · 5,000 lines of config or generated files left out/)).toBeInTheDocument();
  });
  it("says how much to rely on the percentage, why, and what evidence was not available", async () => {
    scan = { ...scan, evidence_breakdown: { code_evidence: 0.4, pr_evidence: 0, git_evidence: 0, tool_evidence: 0, baseline_evidence: 0, combined: 0.3, likelihood: "Mixed Authorship", boosts: [],
      attribution: { groups: [], confidence: { level: "medium", reasons: ["96% of the source code could be analysed.", "Only the code's own style supports the number: nothing about its history or author can confirm it."], unavailable: ["git history", "the author's baseline"] } } } } as ScanResult;
    await renderPage();
    const line = screen.getByTestId("ai-confidence");
    expect(line).toHaveTextContent("How much to rely on it: medium.");
    expect(line).toHaveTextContent("Only the code's own style supports the number");
    expect(line).toHaveTextContent("Not available for this scan: git history, the author's baseline.");
  });
  it("shows nothing about confidence when nothing could be analysed, or for an older scan", async () => {
    scan = { ...scan, evidence_breakdown: { code_evidence: 0, pr_evidence: 0, git_evidence: 0, tool_evidence: 0, baseline_evidence: 0, combined: 0, likelihood: "Likely Human", boosts: [], attribution: { groups: [], confidence: { level: "none", reasons: ["No source file was long enough to analyse."], unavailable: [] } } } } as ScanResult;
    await renderPage();
    expect(screen.queryByTestId("ai-confidence")).toBeNull();
  });
  it("falls back to the plain average for a scan without it", async () => {
    await renderPage();
    expect(screen.getByText(/30.0% avg AI content/)).toBeInTheDocument();
  });
});

describe("PR page: tooltips", () => {
  it("every table column header explains itself", async () => {
    await renderPage();
    const table = screen.getByRole("table");
    for (const [name, text] of Object.entries(COLUMN_TIP)) {
      expect(tipOf(within(table).getByText(name))).toBe(text);
    }
  });

  it("no column header is left without one", async () => {
    await renderPage();
    const headers = within(screen.getByRole("table")).getAllByRole("columnheader");
    expect(headers.map(h => h.textContent)).toEqual(Object.keys(COLUMN_TIP));
    for (const h of headers) expect(tipOf(h.querySelector("[tabindex]") as HTMLElement).length).toBeGreaterThan(10);
  });

  it("the filter tabs, risk badges, status and Attest button explain themselves", async () => {
    await renderPage();
    expect(tipOf(screen.getByRole("button", { name: /Critical & High/ }))).toBe(FILTER_TIP.high);
    expect(tipOf(screen.getByRole("button", { name: /All Files/ }))).toBe(FILTER_TIP.all);
    const row = rowOf("db.ts");
    expect(tipOf(within(row).getByText("CRITICAL").closest("[tabindex]") as HTMLElement)).toMatch(/worst finding: critical/);
    expect(tipOf(within(row).getByText("Pending"))).toMatch(/not yet signed off/);
    expect(tipOf(within(row).getByRole("button", { name: /Attest/ }))).toMatch(/Sign off this file/);
  });

  it("the header badge and commit say what they are; the Rescan button says what it does", async () => {
    await renderPage();
    expect(tipOf(screen.getByText("abcdef12"))).toBe("The commit this scan analysed.");
    expect(tipOf(screen.getAllByText("CRITICAL")[0].closest("[tabindex]") as HTMLElement)).toMatch(/worst rating among its files/);
    expect(tipOf(screen.getByRole("button", { name: "Rescan" }))).toMatch(/creates a new scan/);
    expect(tipOf(screen.getByRole("button", { name: /Review flagged files/ }))).toMatch(/full-screen view/);
  });
});

describe("PR page: moving through flagged files", () => {
  it("the Review button opens the full-screen review on the worst file, and Esc leaves it", async () => {
    await renderPage();
    fireEvent.click(screen.getByRole("button", { name: /Review flagged files/ }));
    const dialog = await screen.findByRole("dialog", { name: "Review flagged files" });
    expect(within(dialog).getByTestId("file-position")).toHaveTextContent("File 1 of 2");
    expect(within(dialog).getByRole("heading", { name: "db.ts" })).toBeInTheDocument();    // CRITICAL first
    fireEvent.click(within(dialog).getByRole("button", { name: "Next file" }));
    expect(within(dialog).getByRole("heading", { name: "api.ts" })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("an expanded row shows where the file is in the flagged list and steps to its neighbours", async () => {
    await renderPage();
    fireEvent.click(fileCell("db.ts"));
    expect(await screen.findByTestId("flagged-position")).toHaveTextContent("Flagged file 1 of 2");
    expect(screen.getByRole("button", { name: "Previous flagged file" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next flagged file" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: /Open full-screen review/ }));
    expect(await screen.findByRole("dialog", { name: "Review flagged files" })).toBeInTheDocument();
  });
});

describe("PR page: triage", () => {
  it("saving a decision shows the 'applies after a rescan' notice with a Rescan now button", async () => {
    await renderPage();
    fireEvent.click(fileCell("db.ts"));
    const toggles = await screen.findAllByRole("button", { name: "Triage" });
    fireEvent.click(toggles[0]);
    (authedFetch as jest.Mock).mockResolvedValue({ decision: { status: "accepted", reason: "Behind the VPN", expires_at: null, set_by_email: "rev@x.io" } });
    fireEvent.change(await screen.findByLabelText("Reason"), { target: { value: "Behind the VPN" } });
    await act(async () => { fireEvent.click(screen.getByRole("button", { name: "Save decision" })); });
    expect(await screen.findByText(/1 triage decision saved/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rescan now" })).toBeInTheDocument();
    // the finding counts split into open vs under a decision, at once
    await waitFor(() => expect(within(screen.getByTestId("card-findings")).getByRole("button", { name: /1 under a triage decision/ })).toBeInTheDocument());
    const [url, init] = (authedFetch as jest.Mock).mock.calls.find(c => c[0] === "/api/findings/triage")!;
    expect(url).toBe("/api/findings/triage");
    expect(JSON.parse(init.body)).toMatchObject({ repo: "acme/shop", status: "accepted", reason: "Behind the VPN" });
  });
});
