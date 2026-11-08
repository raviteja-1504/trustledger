import { render, screen, fireEvent, within, act } from "@testing-library/react";
import "@testing-library/jest-dom";
import CodeViewer from "@/components/CodeViewer";
import type { FileIndicator } from "@/types";

const code = Array.from({ length: 40 }, (_, i) => `line ${i + 1}`).join("\n");
const sec = (line: number, id: string, severity = "high"): FileIndicator => ({ id, label: id, severity, line, cwe: "CWE-1", fingerprint: `fp-${id}-${line}` } as FileIndicator);
// the critical one (line 5) is the viewer's auto-opened finding
const three = [sec(5, "sql-injection", "critical"), sec(18, "xss"), sec(33, "path-traversal", "medium")];
const describe_ = (id: string) => ({ label: `Title ${id}`, security: true });

const scrollTo = jest.fn();
beforeAll(() => {
  Element.prototype.scrollTo = scrollTo as unknown as typeof Element.prototype.scrollTo;
  Element.prototype.scrollIntoView = jest.fn();
});
beforeEach(() => scrollTo.mockClear());

const viewer = (props: Partial<React.ComponentProps<typeof CodeViewer>> = {}) =>
  render(<CodeViewer code={code} language="typescript" filename="src/a.ts" indicators={three} describe={describe_} maxHeight="300px" {...props} />);
const position = () => screen.getByTestId("finding-position").textContent;
const next = () => fireEvent.click(screen.getByRole("button", { name: "Next finding" }));
const prev = () => fireEvent.click(screen.getByRole("button", { name: "Previous finding" }));
const strip = () => within(screen.getByRole("group", { name: "Findings in this file" }));
const openEvidence = () => screen.queryAllByRole("button", { name: /Hide evidence/ });

describe("CodeViewer: moving through the findings of a file", () => {
  it("always says which finding you are on: the first one when the viewer opens", () => {
    viewer();
    expect(position()).toBe("Finding 1 of 3");
    next();
    expect(position()).toBe("Finding 2 of 3");
    next();
    expect(position()).toBe("Finding 3 of 3");
    prev();
    expect(position()).toBe("Finding 2 of 3");
  });

  it("wraps from the last finding to the first, and back", () => {
    viewer();
    next(); next();
    expect(position()).toBe("Finding 3 of 3");
    next();
    expect(position()).toBe("Finding 1 of 3");
    prev();
    expect(position()).toBe("Finding 3 of 3");
  });

  it("lists every finding as a chip with its line and title; clicking one goes to it and marks it current", () => {
    viewer();
    expect(strip().getAllByRole("button")).toHaveLength(3);
    expect(strip().getByRole("button", { name: /L5.*Title sql-injection/ })).toHaveAttribute("aria-current", "true");
    const chip = strip().getByRole("button", { name: /L18.*Title xss/ });
    fireEvent.click(chip);
    expect(position()).toBe("Finding 2 of 3");
    expect(chip).toHaveAttribute("aria-current", "true");
    expect(strip().getByRole("button", { name: /L5/ })).not.toHaveAttribute("aria-current");
    expect(scrollTo).toHaveBeenCalled();
  });

  it("the n and p keys step; typing in a field or using a modifier does not", () => {
    viewer();
    const root = screen.getByRole("button", { name: "Next finding" }).closest("[tabindex]") as HTMLElement;
    fireEvent.keyDown(root, { key: "n" });
    expect(position()).toBe("Finding 2 of 3");
    fireEvent.keyDown(root, { key: "n" });
    expect(position()).toBe("Finding 3 of 3");
    fireEvent.keyDown(root, { key: "p" });
    expect(position()).toBe("Finding 2 of 3");
    // inside a text field (e.g. the triage reason) the same keys are just letters
    const field = document.createElement("textarea");
    root.appendChild(field);
    fireEvent.keyDown(field, { key: "n" });
    expect(position()).toBe("Finding 2 of 3");
    fireEvent.keyDown(root, { key: "n", ctrlKey: true });
    expect(position()).toBe("Finding 2 of 3");
  });

  it("stepping to a finding opens its evidence, even one that was closed", () => {
    viewer();
    expect(openEvidence()).toHaveLength(1);                         // the most severe finding opens by itself
    next();                                                         // finding 2: opens too
    expect(openEvidence()).toHaveLength(2);
    for (const b of openEvidence()) fireEvent.click(b);
    expect(openEvidence()).toHaveLength(0);
    next();                                                         // finding 3
    expect(openEvidence()).toHaveLength(1);
    prev();                                                         // back to 2: it was closed, and opens again
    expect(openEvidence()).toHaveLength(2);
  });
});

describe("CodeViewer: handing over to the next and previous file", () => {
  it("past the last finding it asks the host for the next file instead of wrapping", () => {
    const onEdge = jest.fn();
    viewer({ onEdge });
    next(); next();
    expect(onEdge).not.toHaveBeenCalled();
    next();
    expect(onEdge).toHaveBeenCalledWith(1);
    expect(position()).toBe("Finding 3 of 3");                       // stayed put
  });

  it("before the first finding it asks for the previous file", () => {
    const onEdge = jest.fn();
    viewer({ onEdge });
    prev();
    expect(onEdge).toHaveBeenCalledWith(-1);
    expect(position()).toBe("Finding 1 of 3");
  });

  it("a file with a single finding still gets Previous / Next when a host can take over", () => {
    const onEdge = jest.fn();
    viewer({ indicators: [sec(5, "sql-injection")], onEdge });
    next();
    expect(onEdge).toHaveBeenCalledWith(1);
    prev();
    expect(onEdge).toHaveBeenCalledWith(-1);
  });

  it("and without a host, a single finding has nothing to step to", () => {
    viewer({ indicators: [sec(5, "sql-injection")] });
    expect(position()).toBe("Finding 1 of 1");
    expect(screen.queryByRole("button", { name: "Next finding" })).toBeNull();
  });

  it("arriving from the next file, it opens on its last finding", () => {
    jest.useFakeTimers();
    try {
      viewer({ initialFinding: "last" });
      act(() => { jest.runOnlyPendingTimers(); });
      expect(position()).toBe("Finding 3 of 3");
    } finally { jest.useRealTimers(); }
  });

  it("autoFocus puts the viewer in the key path so n / p work immediately", () => {
    viewer({ autoFocus: true });
    expect(screen.getByRole("button", { name: "Next finding" }).closest("[tabindex]")).toHaveFocus();
  });
});

describe("CodeViewer: tooltips", () => {
  it("Previous and Next say what they do, including the hand-over to other files and the keys", () => {
    viewer();
    const tip = (name: string) => { const b = screen.getByRole("button", { name }); fireEvent.focus(b); const t = screen.getByRole("tooltip").textContent ?? ""; fireEvent.blur(b); return t; };
    expect(tip("Next finding")).toMatch(/Next finding in this file \(n\)\. At the last one, goes to the next flagged file/);
    expect(tip("Previous finding")).toMatch(/Previous finding in this file \(p\)\. At the first one, goes to the previous flagged file/);
  });
});

describe("CodeViewer: files with nothing flagged", () => {
  it("shows no navigation", () => {
    viewer({ indicators: [] });
    expect(screen.queryByTestId("finding-position")).toBeNull();
    expect(screen.queryByRole("button", { name: "Next finding" })).toBeNull();
  });
  it("non-security signals don't count as findings to step through", () => {
    viewer({ indicators: [{ id: "ai-style", label: "ai", severity: "low", line: 3 } as FileIndicator], describe: () => ({ label: "AI", security: false }) });
    expect(screen.queryByTestId("finding-position")).toBeNull();
  });
});
