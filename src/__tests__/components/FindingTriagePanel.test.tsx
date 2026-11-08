import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn() }));
import { FindingTriageContext, FindingTriagePanel, FindingStatusChip } from "@/components/FindingTriage";
import type { FileIndicator } from "@/types";

const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
const ind = (over: Partial<FileIndicator> = {}): FileIndicator => ({ id: "sqli", label: "SQL", severity: "high", line: 12, fingerprint: "fp1", lifecycle_status: "new", ...over } as FileIndicator);
const wrap = (ui: React.ReactNode, over = {}) => {
  const onDecision = jest.fn();
  render(<FindingTriageContext.Provider value={{ repo: "o/r", canTriage: true, onDecision, ...over }}>{ui}</FindingTriageContext.Provider>);
  return { onDecision };
};
beforeEach(() => authedFetch.mockReset());

describe("FindingTriagePanel: saving a decision", () => {
  it("sends the decision for this finding to the triage API, then reports it so the page updates at once", async () => {
    authedFetch.mockResolvedValue({ decision: { status: "accepted", reason: "Behind the VPN", expires_at: "2099-01-01T00:00:00Z", set_by_email: "me@x.io" } });
    const { onDecision } = wrap(<FindingTriagePanel ind={ind()} filePath="src/a.ts" />);
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "  Behind the VPN  " } });
    fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
    await waitFor(() => expect(onDecision).toHaveBeenCalled());

    const [url, init] = authedFetch.mock.calls[0];
    expect(url).toBe("/api/findings/triage");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({ repo: "o/r", fingerprint: "fp1", rule_id: "sqli", file_path: "src/a.ts", status: "accepted", reason: "Behind the VPN", expires_in_days: 90 });
    expect(onDecision).toHaveBeenCalledWith("fp1", expect.objectContaining({ status: "accepted", reason: "Behind the VPN", set_at: expect.any(String) }));
  });

  it("'False positive' and 'No expiry' go through as chosen", async () => {
    authedFetch.mockResolvedValue({ decision: { status: "false_positive", reason: "enum", expires_at: null, set_by_email: null } });
    wrap(<FindingTriagePanel ind={ind()} filePath="src/a.ts" />);
    fireEvent.click(screen.getByRole("radio", { name: "False positive" }));
    fireEvent.change(screen.getByLabelText("Expires"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "validated enum" } });
    fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
    await waitFor(() => expect(authedFetch).toHaveBeenCalled());
    expect(JSON.parse(authedFetch.mock.calls[0][1].body)).toMatchObject({ status: "false_positive", expires_in_days: null });
  });

  it("needs a reason, and sends nothing without one", () => {
    const { onDecision } = wrap(<FindingTriagePanel ind={ind()} filePath="src/a.ts" />);
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "ok" } });
    fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
    expect(screen.getByText(/Give a short reason/)).toBeInTheDocument();
    expect(authedFetch).not.toHaveBeenCalled();
    expect(onDecision).not.toHaveBeenCalled();
  });

  it("when the server refuses (e.g. triage isn't set up on the database), the reason is shown and nothing is recorded", async () => {
    authedFetch.mockRejectedValue(new Error("We couldn't save that decision. Finding triage isn't set up on this database yet (migration 20260930_finding_triage_scan_health)."));
    const { onDecision } = wrap(<FindingTriagePanel ind={ind()} filePath="src/a.ts" />);
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Behind the VPN" } });
    fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
    expect(await screen.findByText(/isn't set up on this database yet/)).toBeInTheDocument();
    expect(onDecision).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Save decision" })).toBeEnabled();    // can try again
  });

  it("a finding with no fingerprint (older scans) offers no triage", () => {
    wrap(<FindingTriagePanel ind={ind({ fingerprint: undefined })} filePath="src/a.ts" />);
    expect(screen.queryByRole("button", { name: "Save decision" })).toBeNull();
  });

  it("roles that can't triage are told so instead of getting a form", () => {
    wrap(<FindingTriagePanel ind={ind()} filePath="src/a.ts" />, { canTriage: false });
    expect(screen.getByText(/Only security reviewers and admins can accept risk or mark false positives/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save decision" })).toBeNull();
  });
});

describe("FindingTriagePanel: an existing decision", () => {
  const decided = ind({ lifecycle_status: "accepted", triage: { status: "accepted", reason: "Behind the VPN", expires_at: null, set_by_email: "me@x.io", set_at: "2026-01-02T00:00:00Z" } });

  it("shows who decided, why and that it needs a rescan to affect the merge check", () => {
    wrap(<FindingTriagePanel ind={decided} filePath="src/a.ts" />);
    expect(screen.getByText(/Risk accepted/)).toBeInTheDocument();
    expect(screen.getByText("me@x.io")).toBeInTheDocument();
    expect(screen.getByText("“Behind the VPN”")).toBeInTheDocument();
    expect(screen.getByText(/applies to the merge check from the next scan/)).toBeInTheDocument();
  });

  it("Reopen removes it through the API", async () => {
    authedFetch.mockResolvedValue({ ok: true });
    const { onDecision } = wrap(<FindingTriagePanel ind={decided} filePath="src/a.ts" />);
    fireEvent.click(screen.getByRole("button", { name: "Reopen" }));
    await waitFor(() => expect(onDecision).toHaveBeenCalledWith("fp1", null));
    expect(authedFetch).toHaveBeenCalledWith("/api/findings/triage", { method: "DELETE", body: JSON.stringify({ repo: "o/r", fingerprint: "fp1" }) });
  });

  it("the status chip reads Accepted risk, with the reason on hover", () => {
    wrap(<FindingStatusChip ind={decided} />);
    const chip = screen.getByText("Accepted risk");
    expect(chip).toHaveAttribute("title", expect.stringContaining("Behind the VPN"));
  });
});
