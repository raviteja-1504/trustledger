import type { ScanIndicator } from "./scanner";

/**
 * Finding correlation: one issue, one finding.
 *
 * The regex layer, the taint engines and their shape checks run independently, so a single vulnerability used
 * to surface as several findings. The exact same id+line case is merged by analyzeFile's dedup pass; this pass
 * handles what that one can't see, measured on DVWA / Juice Shop / WebGoat / PyGoat / crAPI:
 *
 *  1. Same line, same weakness (CWE), different finding ids -- e.g. the regex `idor` and the engine's
 *     `bola-missing-ownership-check` on the same lookup.
 *  2. The same data flow reported at two points -- a finding sitting on an intermediate step of another
 *     finding's source -> sink trace, with the same CWE: the line where the SQL string is concatenated (regex,
 *     or the engine's own "SQL string construction" shape check) next to the line where it is executed;
 *     `new File(..)` / `os.path.join(..)` right before the `open(..)` that uses the path. The downstream
 *     finding -- the sink, which carries the whole trace -- is kept.
 *
 * Merged findings are not dropped silently: each becomes a RelatedLocation on the one that is kept, and its
 * detector joins supportingDetectors. Findings in the same function on UNRELATED lines are deliberately left
 * alone: measured, those were distinct sinks (separate lookups, separate response writes).
 */

export interface RelatedLocation {
  line: number;
  id: string;
  label: string;
  /** How the merged finding was detected. */
  detector: "data-flow" | "pattern";
  /** Why it is the same issue. */
  reason: "same-line" | "on-path" | "cross-file";
  /** Set when the merged finding was reported in another file (cross-file correlation). */
  file?: string;
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Which of two findings for the same issue carries the stronger evidence (and so is kept). */
function stronger(a: ScanIndicator, b: ScanIndicator): ScanIndicator {
  if (!!a.sourceExpr !== !!b.sourceExpr) return a.sourceExpr ? a : b;
  if ((a.trace?.length ?? 0) !== (b.trace?.length ?? 0)) return (a.trace?.length ?? 0) > (b.trace?.length ?? 0) ? a : b;
  if ((a.confidence ?? 0) !== (b.confidence ?? 0)) return (a.confidence ?? 0) > (b.confidence ?? 0) ? a : b;
  return (SEVERITY_RANK[a.severity] ?? 0) >= (SEVERITY_RANK[b.severity] ?? 0) ? a : b;
}

const correlatable = (i: ScanIndicator): i is ScanIndicator & { line: number; cwe: string } =>
  i.line != null && !!i.cwe;

/** Does a trace step's file refer to this file? (Engines record the path they were given; be lenient on prefixes.) */
const sameFile = (stepFile: string | undefined, filePath: string) =>
  !stepFile || stepFile === filePath || stepFile.endsWith(`/${filePath}`) || filePath.endsWith(`/${stepFile}`);

/**
 * Merge `absorbed` into `kept`: record it as a related location (plus the ones it had already absorbed), add
 * its detector to supportingDetectors, and keep the higher severity.
 */
function absorb(kept: ScanIndicator, absorbed: ScanIndicator, reason: RelatedLocation["reason"]): void {
  const related = kept.relatedLocations ?? [];
  const add = (loc: RelatedLocation) => {
    if (!loc.file && loc.line === kept.line && loc.id === kept.id) return;
    if (!related.some(r => r.line === loc.line && r.id === loc.id && r.file === loc.file)) related.push(loc);
  };
  add({ line: absorbed.line!, id: absorbed.id, label: absorbed.label, detector: absorbed.sourceExpr ? "data-flow" : "pattern", reason });
  for (const r of absorbed.relatedLocations ?? []) add(r);
  kept.relatedLocations = related.sort((a, b) => a.line - b.line || a.id.localeCompare(b.id));
  const supporting = new Set([...(kept.supportingDetectors ?? []), ...(absorbed.supportingDetectors ?? [])]);
  if (absorbed.label !== kept.label) supporting.add(absorbed.label);
  supporting.delete(kept.label);
  if (supporting.size) kept.supportingDetectors = [...supporting];
  // A higher severity is taken over only from evidence at least as strong: the data-flow engines grade
  // severity on what they proved (a read-only lookup, a role gate in front of it), and a pattern match's
  // fixed severity for its id must not overrule that.
  const atLeastAsStrong = !!absorbed.sourceExpr || !kept.sourceExpr;
  if (atLeastAsStrong && (SEVERITY_RANK[absorbed.severity] ?? 0) > (SEVERITY_RANK[kept.severity] ?? 0)) kept.severity = absorbed.severity;
}

const URGENCY_RANK: Record<string, number> = { monitor: 0, backlog: 1, sprint: 2, immediate: 3 };

/** A finding in another file whose confirmed data-flow path runs through this finding's line. */
export interface FlowOrigin {
  file: string;
  line: number;
  id: string;
  /** Where that flow starts (the request input), when known. */
  source?: string;
}

/**
 * The files of a stored scan whose findings depend on OTHER files: one holds a flow whose path leaves it, is
 * crossed by another file's flow, carries a backlink, or had a finding folded into another file's. Re-analysing
 * such a file on its own (api/scans/[id]'s live re-analysis) would lose that context -- drop the cross-file
 * finding, or report a folded duplicate again -- so its stored, full-context result must be used instead.
 */
export function filesWithCrossFileContext(files: ReadonlyArray<{
  file_path: string;
  indicators?: ReadonlyArray<{ trace?: ReadonlyArray<{ file?: string }>; reachedFrom?: ReadonlyArray<{ file: string }>; relatedLocations?: ReadonlyArray<{ file?: string }> }> | null;
}>): Set<string> {
  const out = new Set<string>();
  for (const f of files) {
    for (const i of f.indicators ?? []) {
      for (const s of i.trace ?? []) if (s.file && s.file !== f.file_path) { out.add(f.file_path); out.add(s.file); }
      for (const o of i.reachedFrom ?? []) { out.add(f.file_path); out.add(o.file); }
      for (const r of i.relatedLocations ?? []) if (r.file && r.file !== f.file_path) { out.add(f.file_path); out.add(r.file); }
    }
  }
  return out;
}

/** A finding with no request input of its own: a pattern match, or a flow that starts at an assumed parameter. */
const lacksOwnSource = (i: ScanIndicator) => !i.sourceExpr || !!i.flow?.source.assumed;

/**
 * Cross-file deduplication, after linkCrossFileFlows: a finding in file B that is reached by a confirmed flow
 * from file A (its line is on that flow's path) and has no request input of its own is the SAME issue as A's
 * finding -- B's view of it. It is folded into A's finding as a cross-file related location (so the PR reports
 * one issue, where the input enters), instead of being reported again in B. A finding in B with its OWN request
 * source is a separate entry point and stays. Returns the files whose findings changed.
 */
export function mergeCrossFileDuplicates(files: ReadonlyArray<{ file_path: string; indicators: ScanIndicator[] }>): Set<string> {
  const byPath = new Map(files.map(f => [f.file_path, f]));
  const findOrigin = (o: FlowOrigin) => byPath.get(o.file)?.indicators.find(i => i.line === o.line && i.id === o.id);
  // Where each secondary finding goes: the first origin with a real request source that isn't itself folded.
  const target = new Map<ScanIndicator, { host: ScanIndicator; file: string }>();
  for (const g of files) {
    for (const y of g.indicators) {
      if (!y.reachedFrom?.length || !lacksOwnSource(y)) continue;
      for (const o of y.reachedFrom) {
        const x = findOrigin(o);
        if (x && x !== y && !lacksOwnSource(x)) { target.set(y, { host: x, file: g.file_path }); break; }
      }
    }
  }
  const touched = new Set<string>();
  if (target.size === 0) return touched;
  for (const [y, { host, file }] of target) {
    const related = host.relatedLocations ?? [];
    const add = (loc: RelatedLocation) => {
      if (!related.some(r => r.line === loc.line && r.id === loc.id && r.file === loc.file)) related.push(loc);
    };
    add({ file, line: y.line!, id: y.id, label: y.label, detector: y.sourceExpr ? "data-flow" : "pattern", reason: "cross-file" });
    for (const r of y.relatedLocations ?? []) add({ ...r, file: r.file ?? file, reason: "cross-file" });
    host.relatedLocations = related.sort((a, b) => (a.file ?? "").localeCompare(b.file ?? "") || a.line - b.line || a.id.localeCompare(b.id));
    const supporting = new Set([...(host.supportingDetectors ?? []), ...(y.supportingDetectors ?? [])]);
    if (y.label !== host.label) supporting.add(y.label);
    supporting.delete(host.label);
    if (supporting.size) host.supportingDetectors = [...supporting];
    touched.add(file);
  }
  for (const g of files) {
    if (touched.has(g.file_path)) g.indicators.splice(0, g.indicators.length, ...g.indicators.filter(i => !target.has(i)));
    // Backlinks may only name findings that are still reported.
    for (const i of g.indicators) {
      if (!i.reachedFrom) continue;
      const live = i.reachedFrom.filter(o => { const x = findOrigin(o); return !!x && !target.has(x); });
      if (live.length) i.reachedFrom = live; else delete i.reachedFrom;
    }
  }
  return touched;
}

/**
 * Cross-file backlinks: a data-flow finding reported at a call site in file A whose path runs into file B
 * (ParamSinkFact.steps) proves that B's matching lines are reached by that flow. B's own finding for the
 * same weakness on such a line -- typically a pattern match that could not see the input, or a callee-side
 * finding that thinks the flow starts at its own parameter -- records the origin, so it can say what actually
 * reaches it instead of "no data flow was traced" / "possibly dead code". Scan-wide, so it runs after every
 * file has been analyzed (see runScan).
 */
export function linkCrossFileFlows(files: ReadonlyArray<{ file_path: string; indicators: ScanIndicator[] }>): void {
  const byPath = new Map(files.map(f => [f.file_path, f]));
  const resolve = (p: string) => byPath.get(p) ?? files.find(f => f.file_path.endsWith(`/${p}`) || p.endsWith(`/${f.file_path}`));
  for (const f of files) {
    for (const x of f.indicators) {
      if (!x.trace?.length || !x.cwe || x.line == null) continue;
      for (const s of x.trace) {
        if (!s.file || s.file === f.file_path) continue;
        const g = resolve(s.file);
        if (!g || g === f) continue;
        for (const y of g.indicators) {
          if (y.cwe !== x.cwe || y.line !== s.line) continue;
          const origins = y.reachedFrom ?? [];
          if (!origins.some(o => o.file === f.file_path && o.line === x.line && o.id === x.id)) {
            origins.push({ file: f.file_path, line: x.line, id: x.id, source: x.trace[0]?.kind === "source" ? x.trace[0].label : x.sourceExpr });
          }
          y.reachedFrom = origins;
          // Its own file's call graph can't see the caller, so it may have judged this line unreachable. The
          // proven flow says otherwise: it is as reachable, exploitable and urgent as the flow that reaches it.
          // Only corrects "unreachable"/unknown: a cross-file tier the call graph already gave it is left alone.
          if (x.reachability && x.reachability !== "unreachable" && (!y.reachability || y.reachability === "unreachable")) {
            y.reachability = "tainted-path";
          }
          if ((x.exploitability_score ?? 0) > (y.exploitability_score ?? 0)) y.exploitability_score = x.exploitability_score;
          if (x.remediation_urgency && URGENCY_RANK[x.remediation_urgency] > URGENCY_RANK[y.remediation_urgency ?? "monitor"]) {
            y.remediation_urgency = x.remediation_urgency;
          }
        }
      }
    }
  }
}

export function correlateFindings(indicators: ScanIndicator[], filePath: string): ScanIndicator[] {
  const candidates = indicators.filter(correlatable);
  if (candidates.length < 2) return indicators;
  const merged = new Set<ScanIndicator>();

  // 1. Same line, same CWE.
  const byLineCwe = new Map<string, ScanIndicator[]>();
  for (const i of candidates) {
    const k = `${i.line}|${i.cwe}`;
    byLineCwe.set(k, [...(byLineCwe.get(k) ?? []), i]);
  }
  for (const group of byLineCwe.values()) {
    if (group.length < 2) continue;
    const kept = group.reduce(stronger);
    for (const other of group) if (other !== kept) { absorb(kept, other, "same-line"); merged.add(other); }
  }

  // 2. On another finding's data-flow path, same CWE. The kept finding is the downstream one (its trace
  //    contains the other's line); a finding on several paths joins the one with the longest trace. Two
  //    findings on each other's paths (a loop) are ambiguous and left alone.
  const onPath = (x: ScanIndicator, y: ScanIndicator) =>
    x !== y && x.cwe === y.cwe && x.line !== y.line && !!y.trace &&
    y.trace.slice(0, -1).some(s => s.line === x.line && sameFile(s.file, filePath));
  const live = candidates.filter(i => !merged.has(i));
  const target = new Map<ScanIndicator, ScanIndicator>();
  for (const x of live) {
    const hosts = live.filter(y => onPath(x, y) && !onPath(y, x));
    if (hosts.length) target.set(x, hosts.reduce((a, b) => ((b.trace?.length ?? 0) > (a.trace?.length ?? 0) ? b : a)));
  }
  // Resolve chains (x -> y -> z) to their final host, visiting upstream findings first so each absorbs into
  // an already-complete host.
  const root = (x: ScanIndicator): ScanIndicator => {
    const seen = new Set<ScanIndicator>();
    let cur = x;
    while (target.has(cur) && !seen.has(cur)) { seen.add(cur); cur = target.get(cur)!; }
    return cur;
  };
  for (const x of [...target.keys()].sort((a, b) => a.line! - b.line!)) {
    const host = root(x);
    if (host === x) continue;
    absorb(host, x, "on-path");
    merged.add(x);
  }

  return merged.size ? indicators.filter(i => !merged.has(i)) : indicators;
}
