import { render, screen, fireEvent, within, act } from "@testing-library/react";
import "@testing-library/jest-dom";
import FlaggedFilesReview from "@/components/FlaggedFilesReview";
import type { FileIndicator, FileResult } from "@/types";

const code = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`).join("\n");
const sec = (line: number, id: string, severity = "high"): FileIndicator => ({ id, label: id, severity, line, cwe: "CWE-1", fingerprint: `fp-${id}-${line}` } as FileIndicator);
const file = (path: string, indicators: FileIndicator[], over: Partial<FileResult> = {}): FileResult => ({
  file_path: path, language: "typescript", ai_percentage: 0.1, risk_score: "HIGH", risk_indicators: [], indicators, content: code, attested: false, ...over,
} as FileResult);

const FILES = [
  file("src/a.ts", [sec(3, "sql-injection", "critical"), sec(9, "xss")], { risk_score: "CRITICAL" }),
  file("src/b.ts", [sec(7, "path-traversal")]),
  file("lib/c.ts", [sec(2, "ssrf"), sec(20, "open-redirect", "medium")], { attested: true }),
];
const isSecurity = (i: FileIndicator) => !!i.cwe;
const describe_ = (id: string) => ({ label: `Title ${id}`, security: true });

beforeAll(() => {
  Element.prototype.scrollTo = jest.fn() as unknown as typeof Element.prototype.scrollTo;
  Element.prototype.scrollIntoView = jest.fn();
});

const open = (over: Partial<React.ComponentProps<typeof FlaggedFilesReview>> = {}) => {
  const onClose = jest.fn();
  const utils = render(<FlaggedFilesReview files={FILES} initialFile="src/a.ts" describe={describe_} isSecurity={isSecurity} onClose={onClose} {...over} />);
  return { onClose, ...utils };
};
const filePos = () => screen.getByTestId("file-position").textContent;
const findingPos = () => screen.getByTestId("finding-position").textContent;
const clickNextFinding = () => fireEvent.click(screen.getByRole("button", { name: "Next finding" }));
const clickPrevFinding = () => fireEvent.click(screen.getByRole("button", { name: "Previous finding" }));
const rail = () => within(screen.getByRole("navigation", { name: "Flagged files" }));

describe("FlaggedFilesReview: the file list", () => {
  it("opens on the requested file as a modal, saying where it is in the list", () => {
    open({ initialFile: "src/b.ts" });
    expect(screen.getByRole("dialog", { name: "Review flagged files" })).toHaveAttribute("aria-modal", "true");
    expect(filePos()).toBe("File 2 of 3");
    expect(screen.getByRole("heading", { name: "b.ts" })).toBeInTheDocument();
  });

  it("the rail lists every file with its finding counts, marks the current one, and signed-off files", () => {
    open();
    expect(rail().getAllByRole("button")).toHaveLength(3);
    const a = rail().getByRole("button", { name: /a\.ts/ });
    expect(a).toHaveAttribute("aria-current", "true");
    expect(a).toHaveTextContent("2 total");
    expect(rail().getByRole("button", { name: /c\.ts/ })).toHaveTextContent("✓");
    expect(rail().getByRole("button", { name: /b\.ts/ })).not.toHaveAttribute("aria-current");
  });

  it("clicking a file in the rail opens it", () => {
    open();
    fireEvent.click(rail().getByRole("button", { name: /c\.ts/ }));
    expect(filePos()).toBe("File 3 of 3");
    expect(screen.getByRole("heading", { name: "c.ts" })).toBeInTheDocument();
    expect(rail().getByRole("button", { name: /c\.ts/ })).toHaveAttribute("aria-current", "true");
  });

  it("Previous / Next file buttons move, and stop at the ends", () => {
    open();
    expect(screen.getByRole("button", { name: "Previous file" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Next file" }));
    expect(filePos()).toBe("File 2 of 3");
    fireEvent.click(screen.getByRole("button", { name: "Next file" }));
    expect(screen.getByRole("button", { name: "Next file" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Previous file" }));
    expect(filePos()).toBe("File 2 of 3");
  });

  it("the ] and [ keys move between files, but not while typing", () => {
    open();
    fireEvent.keyDown(window, { key: "]" });
    expect(filePos()).toBe("File 2 of 3");
    fireEvent.keyDown(window, { key: "[" });
    expect(filePos()).toBe("File 1 of 3");
    const field = document.createElement("textarea");
    document.body.appendChild(field);
    fireEvent.keyDown(field, { key: "]" });
    expect(filePos()).toBe("File 1 of 3");
    field.remove();
  });
});

describe("FlaggedFilesReview: one pass through every finding", () => {
  it("stepping past a file's last finding carries on into the next file's first", () => {
    open();                                                          // a.ts: 2 findings
    expect(findingPos()).toBe("Finding 1 of 2");
    clickNextFinding();
    expect(findingPos()).toBe("Finding 2 of 2");
    clickNextFinding();                                              // past the end
    expect(filePos()).toBe("File 2 of 3");
    expect(screen.getByRole("heading", { name: "b.ts" })).toBeInTheDocument();
    expect(findingPos()).toBe("Finding 1 of 1");
  });

  it("stepping back from a file's first finding lands on the previous file's LAST finding", () => {
    jest.useFakeTimers();
    try {
      open({ initialFile: "lib/c.ts" });                            // c.ts: 2 findings
      expect(findingPos()).toBe("Finding 1 of 2");
      clickPrevFinding();                                            // before the start
      act(() => { jest.runOnlyPendingTimers(); });
      expect(filePos()).toBe("File 2 of 3");
      // b.ts has one finding: "last" is also its first
      expect(findingPos()).toBe("Finding 1 of 1");
      fireEvent.click(rail().getByRole("button", { name: /c\.ts/ }));
      fireEvent.click(rail().getByRole("button", { name: /a\.ts/ }));
      clickNextFinding(); clickNextFinding();                        // a.ts -> b.ts
      fireEvent.click(rail().getByRole("button", { name: /c\.ts/ }));
      // back from c.ts's first finding into b.ts, then back again into a.ts: lands on a.ts's last finding
      clickPrevFinding();
      act(() => { jest.runOnlyPendingTimers(); });
      clickPrevFinding();
      act(() => { jest.runOnlyPendingTimers(); });
      expect(filePos()).toBe("File 1 of 3");
      expect(findingPos()).toBe("Finding 2 of 2");
    } finally { jest.useRealTimers(); }
  });

  it("at the very last finding of the very last file, Next stays put instead of wrapping", () => {
    open({ initialFile: "lib/c.ts" });
    clickNextFinding();                                              // c.ts finding 2
    clickNextFinding();                                              // past the end of the whole PR
    expect(filePos()).toBe("File 3 of 3");
    expect(findingPos()).toBe("Finding 2 of 2");
  });
});

describe("FlaggedFilesReview: tooltips", () => {
  it("the header controls and the risk badge explain themselves", () => {
    open({ canAttest: () => true, onRequestAttest: jest.fn() });
    const tip = (el: HTMLElement) => { fireEvent.focus(el); const t = screen.getByRole("tooltip").textContent ?? ""; fireEvent.blur(el); return t; };
    expect(tip(screen.getByRole("button", { name: "Close review" }))).toMatch(/Close the full-screen review \(Esc\)/);
    expect(tip(screen.getByRole("button", { name: "Next file" }))).toMatch(/Next flagged file \(\]\)/);
    expect(tip(screen.getByRole("button", { name: "Previous file" }))).toMatch(/Previous flagged file \(\[\)/);
    expect(tip(screen.getByRole("button", { name: /Review & Attest/ }))).toMatch(/Sign off this file/);
    expect(tip(screen.getByText("CRITICAL").closest("[tabindex]") as HTMLElement)).toMatch(/worst finding: critical/);
  });
});

describe("FlaggedFilesReview: leaving, and attesting", () => {
  it("Esc and the close button close it", () => {
    const { onClose } = open();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Close review" }));
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("locks the page's scroll while open and gives it back", () => {
    document.body.style.overflow = "auto";
    const { unmount } = open();
    expect(document.body.style.overflow).toBe("hidden");
    unmount();
    expect(document.body.style.overflow).toBe("auto");
  });

  it("offers Review & Attest only for a file the viewer may sign off, and hands over to the attest flow", () => {
    const onRequestAttest = jest.fn();
    const { rerender, onClose } = open({ canAttest: () => true, onRequestAttest });
    fireEvent.click(screen.getByRole("button", { name: /Review & Attest/ }));
    expect(onRequestAttest).toHaveBeenCalledWith(expect.objectContaining({ file_path: "src/a.ts" }));

    rerender(<FlaggedFilesReview files={FILES} initialFile="src/a.ts" describe={describe_} isSecurity={isSecurity} onClose={onClose} canAttest={() => false} onRequestAttest={onRequestAttest} />);
    expect(screen.queryByRole("button", { name: /Review & Attest/ })).toBeNull();      // role can't sign this off

  });

  it("a file that is already signed off offers no attest button", () => {
    open({ initialFile: "lib/c.ts", canAttest: () => true, onRequestAttest: jest.fn() });
    expect(screen.queryByRole("button", { name: /Review & Attest/ })).toBeNull();
  });

  it("a file whose source wasn't captured says so instead of an empty window", () => {
    open({ files: [file("src/x.ts", [sec(1, "xss")], { content: undefined })], initialFile: "src/x.ts" });
    expect(screen.getByText(/Source wasn.t captured for this file/)).toBeInTheDocument();
  });

  it("renders nothing for an empty list", () => {
    open({ files: [], initialFile: "none" });
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
