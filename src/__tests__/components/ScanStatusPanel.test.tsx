import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";

jest.mock("@/lib/useRealData", () => ({ authedFetch: jest.fn() }));
import ScanStatusPanel from "@/components/ScanStatusPanel";
import type { ScanHealth } from "@/lib/scanHealth";

const health = (files: string[]): ScanHealth => ({
  status: "degraded", engine_version: "6.5", gap_counts: { "engine-unavailable": files.length }, engines_unavailable: ["python"],
  gaps: files.map(file => ({ file, language: "python", reason: "engine-unavailable" as const })),
});
jest.setTimeout(30000);
const base = { scanId: "s1", canTriage: true, onChanged: () => {} };

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

  it("the security delta line", () => {
    render(<ScanStatusPanel {...base} delta={{ introduced: 2, critical: 1, high: 0, preexisting: 3 }} />);
    expect(screen.getByText("This PR introduces 2 security findings")).toBeInTheDocument();
    expect(screen.getByText("1 critical")).toBeInTheDocument();
    expect(screen.getByText(/3 already in the files it touches/)).toBeInTheDocument();
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
