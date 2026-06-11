import { runScan, detectAIToolingArtifacts } from "@/lib/scanner";
import { analyzeGitProvenance } from "@/lib/gitProvenance";

describe("AI tooling artifact detection", () => {
  it("detects known AI coding-agent config/rule files", () => {
    const found = detectAIToolingArtifacts([
      "src/index.ts",
      ".cursorrules",
      ".windsurf/rules/style.md",
      "CLAUDE.md",
      ".github/copilot-instructions.md",
      ".aider.conf.yml",
      "AGENTS.md",
      "README.md",
    ]);

    const tools = found.map(f => f.tool).sort();
    expect(tools).toEqual([
      "AI Agents", "Aider", "Claude Code", "Cursor", "GitHub Copilot", "Windsurf",
    ]);
  });

  it("returns empty for repos with no AI tooling artifacts", () => {
    expect(detectAIToolingArtifacts(["src/index.ts", "README.md", "package.json"])).toEqual([]);
  });

  it("surfaces ai_tooling on the ScanOutput", () => {
    const result = runScan({
      repo: "test/ai-tooling", pr_number: 1, commit_sha: "abc1234", branch: "main",
      files: [
        { path: "CLAUDE.md", content: "# Project instructions" },
        { path: "src/index.ts", content: "export const x = 1;" },
      ],
    });

    expect(result.ai_tooling.some(a => a.tool === "Claude Code" && a.file === "CLAUDE.md")).toBe(true);
  });
});

describe("AI-era commit subject detection", () => {
  function logLine(subject: string): string {
    return `abc123def4567890|Jane Dev|jane@example.com|1700000000|G|${subject}`;
  }

  it("flags Co-Authored-By trailers for AI agents in the commit message", () => {
    const summary = analyzeGitProvenance(
      logLine("feat: add login flow Co-Authored-By: Claude <noreply@anthropic.com>"),
    );
    expect(summary.aiAuthoredCommits).toBe(1);
  });

  it("flags 'Generated with Claude Code' markers", () => {
    const summary = analyzeGitProvenance(
      logLine("fix: handle null case - 🤖 Generated with [Claude Code]"),
    );
    expect(summary.aiAuthoredCommits).toBe(1);
  });

  it("flags Windsurf/Devin/Aider/Cline tool mentions", () => {
    for (const tool of ["windsurf", "devin", "aider", "cline"]) {
      const summary = analyzeGitProvenance(logLine(`chore: refactor via ${tool} agent`));
      expect(summary.aiAuthoredCommits).toBe(1);
    }
  });

  it("does not flag ordinary human commit subjects", () => {
    const summary = analyzeGitProvenance(logLine("fix: correct off-by-one error in pagination"));
    expect(summary.aiAuthoredCommits).toBe(0);
  });
});
