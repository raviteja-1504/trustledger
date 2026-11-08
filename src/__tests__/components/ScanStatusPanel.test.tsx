import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn() }));
import ScanStatusPanel, { sinceParam, newestNewerScan } from "@/components/ScanStatusPanel";
import type { ScanHealth } from "@/lib/scanHealth";

const health = (files: string[]): ScanHealth => ({
  status: "degraded", engine_version: "6.5", gap_counts: { "engine-unavailable": files.length }, engines_unavailable: ["python"],
  gaps: files.map(file => ({ file, language: "python", reason: "engine-unavailable" as const })),
});
jest.setTimeout(30000);
const base = { scanId: "s1", canTriage: true, onChanged: () => {} };



describe("sinceParam", () => {
  it("is plain UTC ISO", () => {
    expect(sinceParam("2026-06-01T10:00:00.123456+00:00")).toBe("2026-06-01T10:00:00.123Z");
    expect(sinceParam("2026-06-01T12:00:00+02:00")).toBe("2026-06-01T10:00:00.000Z");
    expect(sinceParam("2026-06-01T10:00:00Z")).toBe("2026-06-01T10:00:00.000Z");
    expect(sinceParam("garbage")).toBe("garbage");
  });
});

describe("ScanStatusPanel", () => {
  it("clicking 'Incomplete scan' opens the one affected file directly", () => {
    const onOpenFile = jest.fn();
    render(<ScanStatusPanel {...base} health={health(["app/views.py"])} canOpenFile={() => true} onOpenFile={onOpenFile} />);
    fireEvent.click(screen.getByRole("button", { name: /incomplete scan/i }));
    expect(onOpenFile).toHaveBeenCalledWith("app/views.py");
  });

  it("with several affected files it lists them, and each one opens its file", () => {
    const onOpenFile = jest.fn();
    render(<ScanStatusPanel {...base} health={health(["a.py", "b.py"])} canOpenFile={p => p === "a.py"} onOpenFile={onOpenFile} />);
    fireEvent.click(screen.getByRole("button", { name: /incomplete scan/i }));
    expect(onOpenFile).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "a.py" }));
    expect(onOpenFile).toHaveBeenCalledWith("a.py");
    expect(screen.queryByRole("button", { name: "b.py" })).toBeNull();          // not on the page: shown, not a link
    expect(screen.getByText("b.py")).toBeInTheDocument();
  });

  describe("rescan", () => {
    const rescanProps = { ...base, repo: "o/r", prNumber: 7, commitSha: "aaaaaaa1111", scanCreatedAt: "2026-06-01T10:00:00Z", rescanPollMs: 10, summaryMarkdown: "x" };
    const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
    beforeEach(() => authedFetch.mockReset());

    it("explains what Rescan does, then says it is waiting and that this page stays as it is", async () => {
      authedFetch.mockImplementation((url: string) => url.includes("/rescan") ? Promise.resolve({ head_sha: "aaaaaaa1111" }) : new Promise(() => {}));
      render(<ScanStatusPanel {...rescanProps} />);
      fireEvent.focus(screen.getByRole("button", { name: "Rescan" }));
      expect(screen.getByRole("tooltip")).toHaveTextContent(/creates a new scan; this page stays as it is/i);
      fireEvent.blur(screen.getByRole("button", { name: "Rescan" }));
      fireEvent.click(screen.getByRole("button", { name: "Rescan" }));
      expect(await screen.findByText(/This page stays as it is/)).toBeInTheDocument();
      expect(screen.getByText(/aaaaaaa/)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Rescanning…" })).toBeDisabled();
    });

    it("looks for the new scan with a plain UTC time even when the scan time came as +00:00 with microseconds (the database's spelling)", async () => {
      authedFetch.mockImplementation((url: string) => url.includes("/rescan")
        ? Promise.resolve({ head_sha: "aaaaaaa1111" })
        : Promise.resolve({ scans: [{ scan_id: "new1", pr_number: 7, commit_sha: "aaaaaaa1111", created_at: "2026-06-01T10:02:00.5+00:00" }] }));
      render(<ScanStatusPanel {...rescanProps} scanCreatedAt="2026-06-01T10:00:00.123456+00:00" />);
      fireEvent.click(screen.getByRole("button", { name: "Rescan" }));
      expect(await screen.findByRole("link", { name: /open the new results/i })).toHaveAttribute("href", "/pr/new1");
      const poll = authedFetch.mock.calls.map(c => String(c[0])).find(u => u.startsWith("/api/scans?"))!;
      expect(decodeURIComponent(poll)).toContain("since=2026-06-01T10:00:00.123Z");
      expect(poll).not.toContain("%2B");
    });

    it("when the new scan appears it links to it, and says a same-commit rescan has no new code", async () => {
      authedFetch.mockImplementation((url: string) => url.includes("/rescan")
        ? Promise.resolve({ head_sha: "aaaaaaa1111" })
        : Promise.resolve({ scans: [
            { scan_id: "s1", pr_number: 7, created_at: "2026-06-01T10:00:00Z" },        // the scan on screen
            { scan_id: "other-pr", pr_number: 8, created_at: "2026-06-01T10:05:00Z" },  // another PR
            { scan_id: "new1", pr_number: 7, commit_sha: "aaaaaaa1111", created_at: "2026-06-01T10:02:00Z" },
          ] }));
      render(<ScanStatusPanel {...rescanProps} />);
      fireEvent.click(screen.getByRole("button", { name: "Rescan" }));
      const link = await screen.findByRole("link", { name: /open the new results/i });
      expect(link).toHaveAttribute("href", "/pr/new1");
      expect(screen.getByText(/same commit, so differences come from the scanner or your triage decisions/i)).toBeInTheDocument();
    });

    it("a different commit says code changes show up too", async () => {
      authedFetch.mockImplementation((url: string) => url.includes("/rescan")
        ? Promise.resolve({ head_sha: "bbbbbbb2222" })
        : Promise.resolve({ scans: [{ scan_id: "new2", pr_number: 7, commit_sha: "bbbbbbb2222", created_at: "2026-06-01T10:03:00Z" }] }));
      render(<ScanStatusPanel {...rescanProps} />);
      fireEvent.click(screen.getByRole("button", { name: "Rescan" }));
      expect(await screen.findByText(/newer commits than this scan, so code changes show up too/i)).toBeInTheDocument();
    });

    it("a rescan the server refuses shows its reason and does not wait", async () => {
      authedFetch.mockRejectedValue(new Error("This PR was scanned less than a minute ago. Try again shortly."));
      render(<ScanStatusPanel {...rescanProps} />);
      fireEvent.click(screen.getByRole("button", { name: "Rescan" }));
      expect(await screen.findByText(/scanned less than a minute ago/)).toBeInTheDocument();
      expect(screen.queryByText(/This page stays as it is/)).toBeNull();
      expect(screen.getByRole("button", { name: "Rescan" })).toBeEnabled();
    });
  });

  describe("triage decisions waiting for a rescan", () => {
    const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
    beforeEach(() => authedFetch.mockReset());
    it("says saved decisions apply only after a rescan, and offers one", async () => {
      authedFetch.mockResolvedValue({ head_sha: "x" });
      render(<ScanStatusPanel {...base} unappliedDecisions={2} />);
      expect(screen.getByText(/2 triage decisions saved/)).toBeInTheDocument();
      expect(screen.getByText(/only change after a rescan/)).toBeInTheDocument();
      fireEvent.click(screen.getByRole("button", { name: "Rescan now" }));
      await waitFor(() => expect(authedFetch).toHaveBeenCalledWith("/api/scans/s1/rescan", { method: "POST" }));
    });
    it("shows nothing when no decision is waiting", () => {
      render(<ScanStatusPanel {...base} unappliedDecisions={0} summaryMarkdown="x" />);
      expect(screen.queryByText(/triage decision/)).toBeNull();
    });
  });

  describe("tooltips", () => {
    const tipOf = (name: string | RegExp) => {
      const el = screen.getByRole("button", { name });
      fireEvent.focus(el);
      const text = screen.getByRole("tooltip").textContent ?? "";
      fireEvent.blur(el);
      return text;
    };
    it("every action button says what it does", () => {
      const lifecycle = { summary: { new: 1, existing: 0, reopened: 0, accepted: 0, false_positive: 0, fixed: 0 }, fixed: [], has_previous_scan: true };
      render(<ScanStatusPanel {...base} lifecycle={lifecycle} summaryMarkdown="x"
        telemetry={{ engine_version: "6.5", total_ms: 4000, cross_file_ms: 1000, per_file_ms: 2500, post_ms: 500, files_analyzed: 3, files_reused: 0, slowest: [] }} />);
      expect(tipOf("Rescan")).toMatch(/Scan the PR's latest commit again/);
      expect(tipOf("Rescan")).toMatch(/Limit: 1 rescan of the same pull request per minute/);
      expect(tipOf("Copy summary")).toMatch(/markdown summary/);
      expect(tipOf("Trust Record")).toMatch(/signed JSON record/);
      expect(tipOf("Baseline")).toMatch(/Accept every current finding/);
      expect(tipOf(/4\.0s/)).toMatch(/how long the scan took/i);
      fireEvent.click(screen.getByRole("button", { name: "Baseline" }));
      expect(tipOf("Accept as baseline")).toMatch(/accepted risk/);
    });
    it("'Older engine' names both versions", () => {
      const health = { status: "complete", engine_version: "6.0", gap_counts: {}, engines_unavailable: [], gaps: [] } as unknown as ScanHealth;
      render(<ScanStatusPanel {...base} health={health} currentEngineVersion="6.5" summaryMarkdown="x" />);
      const pill = screen.getByText("Older engine");
      fireEvent.focus(pill);
      expect(screen.getByRole("tooltip")).toHaveTextContent(/This scan: engine 6\.0; current: 6\.5/);
    });
    it("'Which files?' explains itself", () => {
      render(<ScanStatusPanel {...base} health={health(["a.py", "b.py"])} />);
      expect(tipOf("Which files?")).toMatch(/could only partly analyse/);
    });
  });

  it("the baseline confirmation says what it will accept: security findings and other signals", () => {
    const lifecycle = { summary: { new: 600, existing: 43, reopened: 0, accepted: 0, false_positive: 0, fixed: 0 }, fixed: [], has_previous_scan: true };
    render(<ScanStatusPanel {...base} lifecycle={lifecycle} securityOpen={160} />);
    fireEvent.click(screen.getByRole("button", { name: "Baseline" }));
    expect(screen.getByText(/Accept all 643 open items \(160 security findings and 483 other signals\)\?/)).toBeInTheDocument();
  });

  it("past 5,000 open items the baseline confirmation says only that many are accepted per run", () => {
    const lifecycle = { summary: { new: 6000, existing: 100, reopened: 0, accepted: 0, false_positive: 0, fixed: 0 }, fixed: [], has_previous_scan: true };
    render(<ScanStatusPanel {...base} lifecycle={lifecycle} securityOpen={900} />);
    fireEvent.click(screen.getByRole("button", { name: "Baseline" }));
    expect(screen.getByRole("note")).toHaveTextContent("Baseline accepts at most 5,000 findings in one go. Run Baseline again to accept the rest.");
  });

  it("under the cap there is no cap note", () => {
    const lifecycle = { summary: { new: 10, existing: 5, reopened: 0, accepted: 0, false_positive: 0, fixed: 0 }, fixed: [], has_previous_scan: true };
    render(<ScanStatusPanel {...base} lifecycle={lifecycle} securityOpen={9} />);
    fireEvent.click(screen.getByRole("button", { name: "Baseline" }));
    expect(screen.queryByRole("note")).toBeNull();
  });

  it("copies the summary; if the clipboard is blocked, shows it to copy by hand", async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    const { unmount } = render(<ScanStatusPanel {...base} summaryMarkdown="### summary" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy summary" }));
    await waitFor(() => expect(screen.getByRole("button", { name: /copied/i })).toBeInTheDocument(), { timeout: 5000 });
    expect(writeText).toHaveBeenCalledWith("### summary");
    unmount();

    Object.assign(navigator, { clipboard: { writeText: jest.fn().mockRejectedValue(new Error("denied")) } });
    render(<ScanStatusPanel {...base} summaryMarkdown="### summary" />);
    fireEvent.click(screen.getByRole("button", { name: "Copy summary" }));
    expect(await screen.findByLabelText("Security summary", {}, { timeout: 5000 })).toHaveValue("### summary");
  });

  it("the timing expands into phases and slowest files", () => {
    render(<ScanStatusPanel {...base} telemetry={{ engine_version: "6.5", total_ms: 4000, cross_file_ms: 1000, per_file_ms: 2500, post_ms: 500, files_analyzed: 3, files_reused: 1, slowest: [{ file: "big.ts", ms: 1200 }] }} />);
    fireEvent.click(screen.getByRole("button", { name: /4\.0s · 3 analyzed/ }));
    expect(screen.getByText("Per-file analysis")).toBeInTheDocument();
    expect(screen.getByText("big.ts")).toBeInTheDocument();
  });
});

describe("link to a newer scan", () => {
  const { authedFetch } = jest.requireMock("@/lib/useRealData") as { authedFetch: jest.Mock };
  const props = { ...base, repo: "o/r", prNumber: 7, commitSha: "aaaaaaa1111", scanCreatedAt: "2026-06-01T10:00:00.5+00:00", summaryMarkdown: "x" };
  const serve = (scans: unknown[]) => authedFetch.mockImplementation((url: string) => (url.startsWith("/api/scans?") ? Promise.resolve({ scans }) : new Promise(() => {})));
  beforeEach(() => authedFetch.mockReset());

  it("an older scan says so and links to the newest scan of the same PR, without any click on Rescan", async () => {
    serve([
      { scan_id: "s1", pr_number: 7, created_at: "2026-06-01T10:00:00.5+00:00" },                                  // this scan
      { scan_id: "mid", pr_number: 7, commit_sha: "bbbbbbb2222", created_at: "2026-06-01T11:00:00+00:00" },
      { scan_id: "latest", pr_number: 7, commit_sha: "ccccccc3333", created_at: "2026-06-01T12:00:00+00:00" },
      { scan_id: "other-pr", pr_number: 8, created_at: "2026-06-01T13:00:00+00:00" },
    ]);
    render(<ScanStatusPanel {...props} />);
    const banner = await screen.findByTestId("newer-scan");
    expect(banner).toHaveTextContent("This isn't the latest scan of this pull request");
    expect(banner).toHaveTextContent("ccccccc");
    expect(screen.getByRole("link", { name: /open the latest scan/i })).toHaveAttribute("href", "/pr/latest");
    expect(authedFetch.mock.calls[0][0]).toContain("since=2026-06-01T10%3A00%3A00.500Z");
  });

  it("the latest scan shows no banner", async () => {
    serve([{ scan_id: "s1", pr_number: 7, created_at: "2026-06-01T10:00:00.5+00:00" }, { scan_id: "x", pr_number: 8, created_at: "2026-06-01T12:00:00Z" }]);
    render(<ScanStatusPanel {...props} />);
    await waitFor(() => expect(authedFetch).toHaveBeenCalled());
    await new Promise(r => setTimeout(r, 20));
    expect(screen.queryByTestId("newer-scan")).toBeNull();
  });

  it("if the lookup fails there is no banner and the panel still works", async () => {
    authedFetch.mockImplementation(() => Promise.reject(new Error("down")));
    render(<ScanStatusPanel {...props} />);
    await waitFor(() => expect(authedFetch).toHaveBeenCalled());
    await new Promise(r => setTimeout(r, 20));
    expect(screen.queryByTestId("newer-scan")).toBeNull();
    expect(screen.getByRole("button", { name: "Rescan" })).toBeEnabled();
  });

  it("without the repo, PR number and time it does not look", () => {
    render(<ScanStatusPanel {...base} summaryMarkdown="x" />);
    expect(authedFetch).not.toHaveBeenCalled();
  });
});

describe("newestNewerScan", () => {
  const scans = [
    { scan_id: "a", pr_number: 7, created_at: "2026-06-01T10:00:00Z" },
    { scan_id: "b", pr_number: 7, created_at: "2026-06-01T11:00:00Z" },
    { scan_id: "c", pr_number: 7, created_at: "2026-06-01T12:00:00Z" },
    { scan_id: "d", pr_number: 9, created_at: "2026-06-01T13:00:00Z" },
  ];
  it("picks the newest later scan of the same PR", () => {
    expect(newestNewerScan(scans, 7, "a", "2026-06-01T10:00:00Z")?.scan_id).toBe("c");
  });
  it("is null when this scan is the newest", () => {
    expect(newestNewerScan(scans, 7, "c", "2026-06-01T12:00:00Z")).toBeNull();
  });
});
