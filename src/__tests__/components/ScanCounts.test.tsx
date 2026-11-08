import { render, screen, fireEvent, within, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn() }));
import ScanCountsSummary from "@/components/ScanCounts";
import { FindingTriageContext, TriageDecisionsList } from "@/components/FindingTriage";
import type { ScanCounts, ChangedFinding } from "@/lib/scanCounts";
import type { FileIndicator } from "@/types";

const counts = (over: Partial<ScanCounts> = {}): ScanCounts => ({
  files: { scanned: 399, toReview: 80, signedOff: 0, withFindings: 61 },
  security: { total: 160, bySeverity: { critical: 75, high: 57, medium: 20, low: 8 }, suppressed: 0, open: 160, introduced: 150, preexisting: 10 },
  otherSignals: 483,
  changes: { new: 12, existing: 140, reopened: 0, accepted: 0, falsePositive: 0, fixed: 8, fixedIsLowerBound: false },
  ...over,
});
const card = (id: string) => within(screen.getByTestId(id));
const newOne = (over: Partial<ChangedFinding> = {}): ChangedFinding => ({ file: "src/a.ts", line: 4, id: "sqli", label: "SQL Injection", severity: "critical", status: "new", ...over });

describe("ScanCountsSummary: each number says what it counts", () => {
  it("files, findings and changes are three cards with their own units", () => {
    render(<ScanCountsSummary counts={counts()} newFindings={[]} fixed={[]} />);
    expect(card("card-files").getByText("399")).toBeInTheDocument();
    expect(card("card-files").getByText(/files scanned/)).toBeInTheDocument();
    expect(card("card-files").getByText(/need review/)).toBeInTheDocument();
    expect(card("card-files").getByText("0 of 80")).toBeInTheDocument();

    expect(card("card-findings").getByText("160")).toBeInTheDocument();
    expect(card("card-findings").getByText("75 critical")).toBeInTheDocument();
    expect(card("card-findings").getByText("57 high")).toBeInTheDocument();
    expect(card("card-findings").getByText(/introduced by this PR/)).toBeInTheDocument();
    expect(card("card-findings").getByText(/already in the files it touches/)).toBeInTheDocument();

    expect(card("card-changes").getByText("new")).toBeInTheDocument();
    expect(card("card-changes").getByText("fixed")).toBeInTheDocument();
    expect(card("card-changes").getByText("unchanged")).toBeInTheDocument();
  });

  it("explains why the file count and finding count differ, and keeps other signals out of the total", () => {
    render(<ScanCountsSummary counts={counts()} newFindings={[]} fixed={[]} />);
    expect(screen.getByText(/different counts \(160 findings in 61 files\)/)).toBeInTheDocument();
    expect(screen.getByText((_, el) => el?.tagName === "P" && /483 other signals \(AI-provenance and code-hygiene hints\) are not vulnerabilities and are not counted above/.test(el.textContent ?? ""))).toBeInTheDocument();
  });

  it("explains each term on hover or keyboard focus", () => {
    render(<ScanCountsSummary counts={counts({ security: { ...counts().security, suppressed: 12, open: 148 } })} newFindings={[]} fixed={[]} />);
    const tipOf = (el: HTMLElement) => { fireEvent.focus(el); const t = screen.getByRole("tooltip").textContent; fireEvent.blur(el); return t; };
    expect(tipOf(screen.getByText("need review"))).toMatch(/High or Critical.*sign/);
    expect(tipOf(screen.getByText("signed off"))).toMatch(/attested/);
    expect(tipOf(screen.getByText("introduced by this PR"))).toMatch(/adds or changes/);
    expect(tipOf(screen.getByText("already in the files it touches"))).toMatch(/before this pull request/);
    expect(tipOf(screen.getByText("75 critical"))).toMatch(/^Critical:/);
    expect(tipOf(screen.getByText("57 high"))).toMatch(/^High:/);
    expect(tipOf(screen.getByRole("button", { name: /12 under a triage decision/ }))).toMatch(/accepted as a risk or marked as a false positive/);
    expect(tipOf(screen.getByText("483 other signals"))).toMatch(/not vulnerabilities/);
  });

  it("each card title has an info tooltip saying what the card counts", () => {
    render(<ScanCountsSummary counts={counts()} newFindings={[]} fixed={[]} />);
    for (const [card_, title, re] of [["card-files", "Files", /rated by its worst finding/i], ["card-findings", "Security findings", /tied to a weakness type/], ["card-changes", "Since the previous scan", /Fixed: in that scan, gone now/]] as const) {
      const info = card(card_).getByRole("button", { name: `Info: ${title}` });
      fireEvent.mouseEnter(info);
      expect(screen.getByRole("tooltip").textContent).toMatch(re);
      fireEvent.mouseLeave(info);
    }
  });

  it("a first scan says there is nothing to compare with, instead of showing 'new' for everything", () => {
    render(<ScanCountsSummary counts={counts({ changes: null })} newFindings={[]} fixed={[]} />);
    expect(card("card-changes").getByText("First scan of this PR")).toBeInTheDocument();
    expect(card("card-changes").queryByText("new")).toBeNull();
  });

  it("names the scan it compared with, and warns when that is the same commit", () => {
    const prev = { commit_sha: "abcdef1234567", created_at: "2026-06-01T10:00:00Z" };
    const { rerender } = render(<ScanCountsSummary counts={counts()} previousScan={prev} commitSha="ffffffffffff" newFindings={[]} fixed={[]} formatWhen={() => "1 Jun, 10:00"} />);
    expect(card("card-changes").getByText("abcdef1")).toBeInTheDocument();
    expect(card("card-changes").getByText(/1 Jun, 10:00/)).toBeInTheDocument();
    expect(screen.queryByText(/Same commit as that scan/)).toBeNull();
    rerender(<ScanCountsSummary counts={counts()} previousScan={prev} commitSha="abcdef1234567" newFindings={[]} fixed={[]} />);
    expect(screen.getByText(/Same commit as that scan, so changes here come from the scanner or your triage decisions, not new code/)).toBeInTheDocument();
  });

  it("with no PR diff there is no introduced/already-there line (and no invented 0)", () => {
    render(<ScanCountsSummary counts={counts({ security: { ...counts().security, introduced: null, preexisting: null } })} newFindings={[]} fixed={[]} />);
    expect(screen.queryByText(/introduced by this PR/)).toBeNull();
  });

  it("zero findings reads as none found, not as a row of zero pills", () => {
    render(<ScanCountsSummary counts={counts({ security: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, suppressed: 0, open: 0, introduced: null, preexisting: null } })} newFindings={[]} fixed={[]} />);
    expect(card("card-findings").getByText(/None found in the files scanned/)).toBeInTheDocument();
    expect(card("card-findings").queryByText(/critical/)).toBeNull();
  });

  it("a capped 'fixed' count is shown as 'N+'", () => {
    render(<ScanCountsSummary counts={counts({ changes: { ...counts().changes!, fixed: 100, fixedIsLowerBound: true } })} newFindings={[]} fixed={[]} />);
    expect(card("card-changes").getByText("100+")).toBeInTheDocument();
  });
});

describe("ScanCountsSummary: what changed", () => {
  it("expands to the actual findings, each opening its file at its line", () => {
    const onOpenFile = jest.fn();
    render(<ScanCountsSummary counts={counts()} newFindings={[newOne(), newOne({ file: "src/b.ts", line: 9, label: "XSS", severity: "high", status: "reopened" })]}
      fixed={[{ fingerprint: "f1", id: "x", label: "Hardcoded Secret", file_path: "src/c.ts", line: 2 }]}
      canOpenFile={p => p !== "src/c.ts"} onOpenFile={onOpenFile} />);
    expect(screen.queryByTestId("what-changed")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /see what changed/i }));
    const panel = within(screen.getByTestId("what-changed"));
    expect(panel.getByText("12 new security findings: not in the previous scan")).toBeInTheDocument();
    expect(panel.getByText("came back")).toBeInTheDocument();
    fireEvent.click(panel.getByRole("button", { name: "src/a.ts:4" }));
    expect(onOpenFile).toHaveBeenCalledWith("src/a.ts", 4);
    expect(panel.queryByRole("button", { name: /src\/c\.ts/ })).toBeNull();      // not a file of this scan: shown, not a link
    expect(panel.getByText("src/c.ts:2")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /hide what changed/i }));
    expect(screen.queryByTestId("what-changed")).toBeNull();
  });

  it("offers no 'what changed' link when nothing is new or fixed", () => {
    render(<ScanCountsSummary counts={counts({ changes: { new: 0, existing: 5, reopened: 0, accepted: 0, falsePositive: 0, fixed: 0, fixedIsLowerBound: false } })} newFindings={[]} fixed={[]} />);
    expect(screen.queryByRole("button", { name: /see what changed/i })).toBeNull();
  });
});

describe("ScanCountsSummary: triage decisions", () => {
  it("shows open vs under-a-decision, and the decisions node opens from that count", () => {
    render(<ScanCountsSummary counts={counts({ security: { ...counts().security, suppressed: 12, open: 148 } })} newFindings={[]} fixed={[]} decisions={<p>DECISIONS LIST</p>} />);
    expect(screen.queryByText("DECISIONS LIST")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /12 under a triage decision/ }));
    expect(screen.getByText("DECISIONS LIST")).toBeInTheDocument();
    expect(card("card-findings").getByText("148")).toBeInTheDocument();
  });
  it("no such count when nothing is under a decision", () => {
    render(<ScanCountsSummary counts={counts()} newFindings={[]} fixed={[]} />);
    expect(screen.queryByText(/under a triage decision/)).toBeNull();
  });
});

describe("TriageDecisionsList", () => {
  const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
  beforeEach(() => authedFetch.mockReset());
  const ind = (over: Partial<FileIndicator> = {}): FileIndicator => ({
    id: "sqli", label: "SQL", severity: "high", line: 12, fingerprint: "fp1",
    triage: { status: "accepted", reason: "Internal tool behind the VPN", expires_at: "2099-01-01T00:00:00Z", set_by_email: "sec@x.io", set_at: "2026-01-02T00:00:00Z" },
    ...over,
  } as FileIndicator);
  const files = [{ file_path: "src/a.ts", indicators: [ind(), ind({ fingerprint: "fp2", triage: undefined }), ind({ fingerprint: "fp3", triage: { status: "false_positive", reason: "enum", expires_at: "2020-01-01T00:00:00Z", set_by_email: null, set_at: "2019-01-01T00:00:00Z" } })] }];
  const wrap = (ui: React.ReactNode, over = {}) => render(
    <FindingTriageContext.Provider value={{ repo: "o/r", canTriage: true, onDecision: jest.fn(), ...over }}>{ui}</FindingTriageContext.Provider>);

  it("lists only findings under an ACTIVE decision, with who, why and until when", () => {
    wrap(<TriageDecisionsList files={files} labelOf={() => "SQL Injection"} />);
    expect(screen.getByText("Triage decisions on this scan (1)")).toBeInTheDocument();     // fp2 has none; fp3's expired
    expect(screen.getByText("“Internal tool behind the VPN”")).toBeInTheDocument();
    expect(screen.getByText(/by sec@x\.io/)).toBeInTheDocument();
    expect(screen.getByText(/until/)).toBeInTheDocument();
    expect(screen.getByText("Accepted risk")).toBeInTheDocument();
  });

  it("Reopen sends a DELETE for that finding, then reports the decision removed", async () => {
    authedFetch.mockResolvedValue({ ok: true });
    const onDecision = jest.fn();
    wrap(<TriageDecisionsList files={files} />, { onDecision });
    fireEvent.click(screen.getByRole("button", { name: "Reopen" }));
    await waitFor(() => expect(onDecision).toHaveBeenCalledWith("fp1", null));
    expect(authedFetch).toHaveBeenCalledWith("/api/findings/triage", { method: "DELETE", body: JSON.stringify({ repo: "o/r", fingerprint: "fp1" }) });
  });

  it("a failed reopen shows why and keeps the decision", async () => {
    authedFetch.mockRejectedValue(new Error("Finding triage isn't set up on this database yet"));
    const onDecision = jest.fn();
    wrap(<TriageDecisionsList files={files} />, { onDecision });
    fireEvent.click(screen.getByRole("button", { name: "Reopen" }));
    expect(await screen.findByText(/isn't set up on this database yet/)).toBeInTheDocument();
    expect(onDecision).not.toHaveBeenCalled();
  });

  it("viewers who can't triage see the decisions but no Reopen", () => {
    wrap(<TriageDecisionsList files={files} />, { canTriage: false });
    expect(screen.getByText("Triage decisions on this scan (1)")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reopen" })).toBeNull();
  });

  it("renders nothing with no decisions, or outside the triage provider", () => {
    const { container, unmount } = wrap(<TriageDecisionsList files={[{ file_path: "a", indicators: [ind({ triage: undefined })] }]} />);
    expect(container).toBeEmptyDOMElement();
    unmount();
    const outside = render(<TriageDecisionsList files={files} />);
    expect(outside.container).toBeEmptyDOMElement();
  });
});
