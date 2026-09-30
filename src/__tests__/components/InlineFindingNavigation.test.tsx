import { render, screen, fireEvent } from "@testing-library/react";
import "@testing-library/jest-dom";
import { InlineSecurityFinding, type FileNavigation } from "@/components/InlineFinding";
import { runScan } from "@/lib/scanner";
import { toStoredIndicators } from "@/lib/indicatorStorage";
import type { FileIndicator } from "@/types";

// A real three-file flow: route -> service -> repository.
function crossFileFinding(): FileIndicator {
  const r = runScan({ repo: "t", pr_number: 1, commit_sha: "a", files: [
    { path: "src/repo.ts", content: `export function find(id) {\n  return db.query("SELECT * FROM u WHERE id = " + id);\n}\n` },
    { path: "src/svc.ts", content: `import { find } from "./repo";\nexport function load(id) {\n  return find(id);\n}\n` },
    { path: "src/r.ts", content: `import { load } from "./svc";\napp.get("/u", (req, res) => load(req.query.id));\n` },
  ] });
  const f = r.files.find(x => x.file_path === "src/r.ts")!;
  return toStoredIndicators(f.indicators).find(i => i.id === "sql-injection" && i.flow?.crossesFiles)!;
}

const nav = (): FileNavigation & { openFile: jest.Mock } => ({ canOpenFile: () => true, openFile: jest.fn() });

describe("finding evidence navigation", () => {
  it("every step of a cross-file flow is one click away: the sink, each crossed file, and each step", () => {
    const ind = crossFileFinding();
    const n = nav();
    const onJump = jest.fn();
    render(<InlineSecurityFinding ind={ind} filePath="src/r.ts" siblings={[ind]} onJump={onJump} nav={n} defaultOpen />);

    // The ribbon: the service file the flow passes through opens at its first line in that file.
    fireEvent.click(screen.getAllByRole("button", { name: "svc.ts" })[0]);
    expect(n.openFile).toHaveBeenCalledWith("src/svc.ts", expect.any(Number));

    // The sink, in another file.
    n.openFile.mockClear();
    fireEvent.click(screen.getAllByRole("button", { name: /^repo\.ts:2$/ })[0]);
    expect(n.openFile).toHaveBeenCalledWith("src/repo.ts", 2);

    // The full path's file headers open their file too.
    n.openFile.mockClear();
    fireEvent.click(screen.getByRole("button", { name: "src/repo.ts" }));
    expect(n.openFile).toHaveBeenCalledWith("src/repo.ts", expect.any(Number));

    // A step in this file scrolls the viewer.
    fireEvent.click(screen.getAllByRole("button", { name: /^L2$/ })[0]);
    expect(onJump).toHaveBeenCalledWith(2);
  });

  it("a related location in another file opens THAT file (it used to jump to the same line number here)", () => {
    const ind: FileIndicator = {
      id: "sql-injection", label: "SQL Injection", severity: "critical", line: 2, cwe: "CWE-89",
      relatedLocations: [{ id: "sql-injection", label: "SQL Injection", line: 7, reason: "cross-file", file: "src/other.ts", detector: "data-flow" }],
    };
    const n = nav();
    const onJump = jest.fn();
    render(<InlineSecurityFinding ind={ind} filePath="src/r.ts" siblings={[ind]} onJump={onJump} nav={n} />);
    fireEvent.click(screen.getByRole("button", { name: "other.ts:7" }));
    expect(n.openFile).toHaveBeenCalledWith("src/other.ts", 7);
    expect(onJump).not.toHaveBeenCalled();
  });

  it("shows the confidence level and whether the PR introduced it", () => {
    const ind = { ...crossFileFinding(), introduced: true };
    render(<InlineSecurityFinding ind={ind} filePath="src/r.ts" siblings={[ind]} nav={nav()} />);
    expect(screen.getByText(/· Confirmed/)).toBeInTheDocument();
    expect(screen.getByText("Introduced by this PR")).toBeInTheDocument();
  });
});
