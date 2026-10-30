/**
 * The public live demo's scan (POST /api/demo/scan): the real TrustLedger scan -- runScan, so every language engine,
 * cross-file flows and the AI-provenance signals -- on one of the demo's sample applications or a visitor's edit of
 * one. Returns what a pull-request check would report: findings with their traces, each file's risk level, content
 * hash and AI estimate, and the default merge-gate decision (lib/mergeGate.ts).
 *
 * Sandboxed by construction: only the sample's own file paths are accepted, each up to DEMO_LIMITS.maxFileBytes;
 * code is parsed as text and never executed; nothing is stored.
 */
import { z } from "zod";
import { runScan } from "@/lib/scanner";
import { blocksMerge, DEFAULT_GATE } from "@/lib/mergeGate";
import { DEMO_LIMITS, demoSample } from "@/lib/demoSamples";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmGoTaintEngine } from "@/lib/astTaintGo";

export const DemoScanBody = z.object({
  sampleId: z.string().max(40),
  variant: z.enum(["vulnerable", "fixed", "custom"]),
  files: z.array(z.object({ path: z.string().max(200), content: z.string() })).max(DEMO_LIMITS.maxFiles).optional(),
});
export type DemoScanRequest = z.infer<typeof DemoScanBody>;

/** Detector families that describe code style or provenance, not a security weakness. */
const NON_SECURITY_RE = /^(?:ai-|license|watermark|attribution|structural|magic-number|dead-code|nesting|line-length|blank-line|boilerplate|zero-debug|naming|comment|hallucinat|style|consistency|language-specific)/;

export interface DemoFinding {
  id: string; label: string; severity: string; line: number | null; cwe: string | null; detail: string;
  sourceExpr: string | null; sinkExpr: string | null;
  trace: { file: string; line: number; kind: string; label: string; snippet: string }[];
}
export interface DemoFileResult {
  path: string; language: string; risk: string; aiPercentage: number; aiModel: string; aiConfidence: number;
  contentHash: string; lineCount: number; findings: DemoFinding[]; blocksMerge: boolean;
}
export interface DemoScanResponse {
  sampleId: string; variant: string; scannedAt: string; durationMs: number; overallRisk: string;
  mergeBlocked: boolean; files: DemoFileResult[];
}
export type DemoScanError = { error: string; status: number };

/** Prepares the language engines the files need (the JS/TS and Java parsers need no warm-up). */
async function warmFor(paths: string[]): Promise<void> {
  const jobs: Promise<void>[] = [];
  if (paths.some(p => p.endsWith(".py"))) jobs.push(warmPythonTaintEngine());
  if (paths.some(p => p.endsWith(".go"))) jobs.push(warmGoTaintEngine());
  await Promise.all(jobs);
}

export async function scanDemo(input: DemoScanRequest): Promise<DemoScanResponse | DemoScanError> {
  const sample = demoSample(input.sampleId);
  if (!sample) return { error: "unknown_sample", status: 404 };
  let files: { path: string; content: string }[];
  if (input.variant === "custom") {
    const allowed = new Set(sample.files.map(f => f.path));
    if (!input.files?.length || input.files.some(f => !allowed.has(f.path))) return { error: "files_must_be_the_samples_own", status: 400 };
    if (input.files.some(f => Buffer.byteLength(f.content, "utf8") > DEMO_LIMITS.maxFileBytes)) return { error: "file_too_large", status: 413 };
    files = input.files;
  } else {
    files = sample.files.map(f => ({ path: f.path, content: input.variant === "fixed" ? f.fixed : f.vulnerable }));
  }
  await warmFor(files.map(f => f.path));

  const started = Date.now();
  const out = runScan({ repo: "demo/sandbox", pr_number: 1, commit_sha: "demo", branch: "demo", files });
  const durationMs = Date.now() - started;

  const results: DemoFileResult[] = out.files.map(f => ({
    path: f.file_path,
    language: f.language,
    risk: f.risk_score,
    aiPercentage: f.ai_percentage,
    aiModel: f.attribution?.model ?? "unknown",
    aiConfidence: f.attribution?.confidence ?? 0,
    contentHash: f.content_hash,
    lineCount: f.line_count,
    blocksMerge: blocksMerge(f.risk_score, DEFAULT_GATE),
    findings: f.indicators
      .filter(i => !NON_SECURITY_RE.test(i.id) && (i.severity === "critical" || i.severity === "high" || i.severity === "medium"))
      .map(i => ({
        id: i.id, label: i.label, severity: i.severity, line: i.line ?? null, cwe: i.cwe ?? null, detail: i.detail ?? "",
        sourceExpr: i.sourceExpr ?? null, sinkExpr: i.sinkExpr ?? null,
        trace: (i.trace ?? []).map(s => ({ file: s.file, line: s.line, kind: s.kind, label: s.label, snippet: s.snippet })),
      })),
  }));
  return {
    sampleId: sample.id, variant: input.variant, scannedAt: new Date().toISOString(), durationMs,
    overallRisk: out.overall_risk, mergeBlocked: results.some(r => r.blocksMerge), files: results,
  };
}
