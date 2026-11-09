/**
 * @jest-environment node
 *
 * End to end through runScan: when an engine throws on a file, the scan is "degraded" (not "complete"), the file is a
 * "analysis-failed" gap, and its (empty) result is NOT cached for the next scan to replay as clean.
 */
import { recordEngineFailure } from "@/lib/taint/engineFailures";

jest.mock("@/lib/astTaintRuby", () => {
  const actual = jest.requireActual("@/lib/astTaintRuby");
  return {
    ...actual,
    scanAstTaintRuby: (...args: unknown[]) => {
      if (String(args[1]).endsWith("broken.rb")) {          // what the engine's own catch block does
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        require("@/lib/taint/engineFailures").recordEngineFailure(args[1] as string, "analysis-failed");
        return [];
      }
      return (actual.scanAstTaintRuby as (...a: unknown[]) => unknown)(...args);
    },
  };
});

import { runScan } from "@/lib/scanner";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";

beforeAll(async () => { await warmRubyTaintEngine(); }, 120000);
void recordEngineFailure;

const rb = "class X < ApplicationController\n  def run\n    system(params[:c])\n  end\nend\n";
const scan = (paths: string[], prev?: Record<string, never>) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", files: paths.map(path => ({ path, content: rb })), ...(prev ? { prev_results: prev } : {}) });

describe("a failed engine is visible", () => {
  it("degrades the scan and names the file", () => {
    const r = scan(["app/controllers/ok_controller.rb", "app/controllers/broken.rb"]);
    expect(r.health!.status).toBe("degraded");
    expect(r.health!.gaps).toContainEqual({ file: "app/controllers/broken.rb", language: "ruby", reason: "analysis-failed" });
    expect(r.health!.gaps.some(g => g.file.includes("ok_controller"))).toBe(false);
  });
  it("does not cache the failed file, but caches the healthy one", () => {
    const r = scan(["app/controllers/ok_controller.rb", "app/controllers/broken.rb"]);
    expect(Object.keys(r.file_cache ?? {})).toEqual(["app/controllers/ok_controller.rb"]);
  });
  it("a scan with no failures is complete", () => {
    expect(scan(["app/controllers/ok_controller.rb"]).health!.status).toBe("complete");
  });
});
