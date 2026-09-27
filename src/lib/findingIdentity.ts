// ── Stable finding identity ──────────────────────────────────────────────────
//
// A fingerprint answers "is this the same finding as the one I saw last scan?" -- the basis for
// suppression/acknowledgement state, "new vs. existing" diffing across a PR's pushes, and trend lines.
// That makes the two ways it can be wrong asymmetric:
//
//   * UNSTABLE (same finding, new id): triage state is lost and a known issue re-appears as "new".
//     Annoying, recoverable.
//   * COLLIDING (two findings, one id): acknowledging one silently acknowledges the other. A real,
//     unreviewed vulnerability inherits someone else's "accepted risk". Worse.
//
// So the design resolves ties toward "distinct", and treats a lost identity (e.g. after a function is
// renamed) as the safe failure mode.
//
// The identity tuple is [rule id, file path, enclosing function, flow]:
//   - NOT the line number: surviving unrelated edits that shift lines is the whole point.
//   - flow = `source=>sink` text for an AST data-flow finding (the flow itself), else the matched line's
//     whitespace-collapsed text (regex findings), else the detail with digits masked (see below).
//   - enclosing function: the same flow in two different handlers of one file are two findings. Without
//     this they collapse to one id (the previous implementation's behavior), so triaging handler A hid
//     handler B.
//   - an ordinal breaks the remaining ties (two textually identical findings in the SAME function), taken
//     in source order so it is deterministic. Including the function keeps deleting one duplicate from
//     handing its identity to a duplicate living in a different function.
//
// File-level signals (AI style signals, model attribution, ...) have no line and their `detail` carries
// volatile numbers ("42% match"), which would change the id on every scan for the same signal. They are
// identified by (rule id, file) alone -- there is at most one per file per rule.
//
// Fill-only: an indicator that already has a fingerprint is left untouched, so this is safe to call again
// after later passes (runScan appends cross-file-taint-exposure / ai-blast-radius) without disturbing ids.

import crypto from "crypto";
import type { ScanIndicator } from "./scanner";

/** Part of the hashed payload: bump only if the tuple's meaning changes, so old ids never alias new ones. */
export const FINGERPRINT_VERSION = 2;

export interface FingerprintContext {
  filePath: string;
  /** Source lines (0-indexed array; `line` on an indicator is 1-based). Needed only for line-bearing regex findings. */
  lines?: readonly string[];
  /** Name of the function containing a 1-based line; "unknown"/"" means not resolvable. */
  enclosingFunction?: (line: number) => string;
  /** Rule ids that are one-per-file signals whose `detail` must not feed the identity. */
  fileLevelIds?: ReadonlySet<string>;
}

const collapse = (s: string): string => s.replace(/\s+/g, " ").trim();
const maskDigits = (s: string): string => s.replace(/\d+/g, "#");

function flowOf(i: ScanIndicator, ctx: FingerprintContext): string {
  if (i.sourceExpr && i.sinkExpr) return collapse(`${i.sourceExpr}=>${i.sinkExpr}`);
  if (i.line !== undefined) {
    const text = ctx.lines?.[i.line - 1];
    if (text !== undefined) return collapse(text);
  }
  if (ctx.fileLevelIds?.has(i.id)) return "";
  return maskDigits(collapse(i.detail ?? ""));
}

function functionOf(i: ScanIndicator, ctx: FingerprintContext): string {
  if (i.line === undefined || !ctx.enclosingFunction) return "";
  try {
    const fn = ctx.enclosingFunction(i.line);
    return fn === "unknown" ? "" : fn;
  } catch {
    return ""; // an engine that can't resolve a position must never break scanning -- fall back to no scoping
  }
}

export function assignFingerprints(indicators: ScanIndicator[], ctx: FingerprintContext): void {
  const groups = new Map<string, { tuple: string[]; members: ScanIndicator[] }>();
  for (const i of indicators) {
    if (i.fingerprint) continue;
    const tuple = [i.id, ctx.filePath, functionOf(i, ctx), flowOf(i, ctx)];
    const key = JSON.stringify(tuple);
    const g = groups.get(key);
    if (g) g.members.push(i);
    else groups.set(key, { tuple, members: [i] });
  }
  for (const { tuple, members } of groups.values()) {
    // Source order, ties keeping insertion order (Array.prototype.sort is stable) => deterministic ordinals.
    members.sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
    members.forEach((m, ordinal) => {
      m.fingerprint = crypto.createHash("sha256")
        .update(JSON.stringify([FINGERPRINT_VERSION, ...tuple, ordinal]))
        .digest("hex").slice(0, 16);
    });
  }
}
