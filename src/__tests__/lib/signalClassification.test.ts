import { isSecuritySignal, realSeverity } from "@/lib/signalClassification";
import type { FileResult } from "@/types";

function makeFile(indicators: FileResult["indicators"]): FileResult {
  return {
    file_path: "app.py",
    language: "python",
    ai_percentage: 0,
    risk_score: "CRITICAL",
    risk_indicators: (indicators ?? []).map(i => i.id),
    indicators,
    attested: false,
  };
}

describe("PR page signal classification (found via real-world scanner testing)", () => {
  it("classifies a CWE-mapped id with no curated SIGNAL_META entry as a security signal", () => {
    // insecure-deserialization and cookie-no-httponly are both real,
    // CWE-mapped backend findings that were falling into the "AI Detection
    // Signals" bucket because SIGNAL_META had no entry for them at all.
    const file = makeFile([
      { id: "insecure-deserialization", label: "Insecure Deserialization", severity: "critical", line: 171, cwe: "CWE-502" },
    ]);
    expect(isSecuritySignal("insecure-deserialization", file, undefined)).toBe(true);
  });

  it("still classifies an id with a curated SIGNAL_META security entry as a security signal", () => {
    const file = makeFile([{ id: "sql-injection", label: "SQL Injection", severity: "critical", line: 140 }]);
    expect(isSecuritySignal("sql-injection", file, true)).toBe(true);
  });

  it("does not classify a plain AI-style heuristic signal (no CWE, no SIGNAL_META security entry) as security", () => {
    const file = makeFile([{ id: "nesting-depth", label: "Shallow Nesting", severity: "low", line: undefined }]);
    expect(isSecuritySignal("nesting-depth", file, undefined)).toBe(false);
  });

  it("uses the real per-instance severity instead of a stale static SIGNAL_META value", () => {
    // backdoor-detection has a static sev:"critical" in SIGNAL_META, but a
    // low-confidence heuristic instance can legitimately compute "low" --
    // the real instance value must win, not the static table.
    const file = makeFile([{ id: "backdoor-detection", label: "Backdoor / Logic Bomb", severity: "low", line: undefined }]);
    const instances = file.indicators!.filter(i => i.id === "backdoor-detection");
    expect(realSeverity(instances, "critical")).toBe("low");
  });

  it("falls back to the static SIGNAL_META severity only when no real instance is present", () => {
    expect(realSeverity([], "critical")).toBe("critical");
  });
});
