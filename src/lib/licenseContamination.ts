/**
 * License/IP Contamination detector
 *
 * AI coding assistants have been documented (the GitHub Copilot lawsuit is
 * the well-known case) to sometimes reproduce copyrighted/licensed
 * training-data code verbatim or near-verbatim. Nobody checks for this
 * today -- it's a real legal/IP exposure that classic SAST tools don't
 * cover either, since it isn't a security vulnerability.
 *
 * This is distinct from TrustLedger's existing "license risk" feature
 * (dependencyScan.ts, surfaced on /dependencies) which classifies the
 * license of imported THIRD-PARTY PACKAGES (a supply-chain/SBOM concern).
 * This detector instead looks at the scanned file's own CONTENT for
 * embedded license headers, SPDX identifiers, and third-party copyright
 * notices -- a sign that some or all of the file may have been copied
 * from a licensed/copyrighted source rather than written for this project.
 *
 * Pattern-based, not corpus-matching: the synchronous analyzeFile()/
 * runScan() pipeline can't make network calls, and there's no
 * fuzzy-matching/hashing dependency in this codebase to build genuine
 * near-duplicate detection against an external corpus. This catches the
 * clearest, most legally-unambiguous signal -- an actual license header or
 * SPDX tag being present -- not true plagiarism detection.
 *
 * Language-agnostic (unlike hallucinatedMethodCall.ts's JS/TS-only scope):
 * license header/SPDX/copyright text is comment content, not
 * language-specific API surface, so this runs for every language
 * TrustLedger scans.
 *
 * Severity is capped at "medium" (confirmed with the product owner) --
 * never escalates a file to CRITICAL/HIGH on its own. This avoids a real
 * noise scenario: an open-source repo that legitimately puts its own
 * MIT/Apache header on every file would otherwise flood every PR with
 * high-severity findings for its own declared license. Framed as a real,
 * worth-a-look finding for human/legal review, not an automatic
 * accusation.
 */

import type { ScanIndicator } from "./scanner";
import type { DetectorContext } from "./detectorRegistry";

const ID = "license-header-contamination";

// ── Doc/example-field filter ────────────────────────────────────────────────
// License header text usually appears IN comments -- unlike
// hallucinatedMethodCall.ts, this detector must NOT skip comment-prefixed
// lines (that would defeat its entire purpose). It only skips lines that
// look like a fix-suggestion example/snippet field holding illustrative
// text, not real file content.
const EXAMPLE_FIELD_LINE_RE = /^["']?(?:code_before|code_after|example|sample|snippet|before|after)["']?\s*:/i;
function isDocExampleLine(line: string): boolean {
  return EXAMPLE_FIELD_LINE_RE.test(line.trim());
}

// ── SPDX license identifiers (highest confidence -- a standardized, ────────
// unambiguous machine-readable tag) ─────────────────────────────────────────
const SPDX_RE = /SPDX-License-Identifier:\s*(AGPL|GPL|LGPL|MPL|MIT|BSD|Apache-2\.0|ISC|EPL)[\w.\-+]*/;

const SPDX_LABEL: Record<string, string> = {
  AGPL: "GNU Affero General Public License (network copyleft)",
  GPL:  "GNU General Public License (copyleft)",
  LGPL: "GNU Lesser General Public License (weak copyleft)",
  MPL:  "Mozilla Public License",
  MIT:  "MIT License",
  BSD:  "BSD License",
  "Apache-2.0": "Apache License 2.0",
  ISC:  "ISC License",
  EPL:  "Eclipse Public License",
};

// ── Third-party copyright notices ───────────────────────────────────────────
// Lower confidence than an SPDX tag or full boilerplate (could be a
// citation comment referencing external work, not reproduced code), so
// worded neutrally as something worth a look rather than an accusation.
const COPYRIGHT_RE = /Copyright\s*(?:\(c\)|©)\s*\d{4}[\d,\-\s]*\s+[A-Z][\w.,'&\-]{2,60}/;

// ── Full-text license header boilerplate ────────────────────────────────────
// Standard FSF/OSI preamble text, not short phrases -- keeps false
// positives low by construction, since legitimate human-written
// application code essentially never contains this verbatim unless it was
// actually copied from somewhere. Spans multiple lines, so matched against
// the whole file content (not per-line) with the match's line number
// computed from its character offset.
interface BoilerplatePattern {
  re:    RegExp;
  label: string;
}
// Bounded [\s\S]{0,N}? gaps (not \s*) at each join point -- real license
// headers are almost always wrapped across many //-/#-/*-prefixed comment
// lines, and \s* alone can't bridge a literal "//" or "#" line-continuation
// marker between words. Bounded to a tight window (well under one typical
// line length) so this still only bridges a single wrap point rather than
// matching across unrelated, distant text.
const BOILERPLATE_PATTERNS: BoilerplatePattern[] = [
  {
    // Matches both GPL and AGPL preambles; the "Affero" group distinguishes
    // which one for the detail text below.
    re: /is free software[\s\S]{0,200}?redistribute it and\/or modify[\s\S]{0,200}?GNU (Affero )?General Public License/i,
    label: "GNU (Affero) General Public License preamble",
  },
  {
    re: /Licensed under the Apache License,[\s\S]{0,40}?Version 2\.0/i,
    label: "Apache License 2.0 header",
  },
  {
    re: /Permission is hereby granted,[\s\S]{0,40}?free of charge,[\s\S]{0,60}?to any person[\s\S]{0,40}?obtaining a copy/i,
    label: "MIT License header",
  },
  {
    re: /Redistribution and use in source and binary forms,[\s\S]{0,80}?with or without[\s\S]{0,80}?modification,[\s\S]{0,80}?are permitted/i,
    label: "BSD License header",
  },
];

function lineNumberAt(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

// ── Entry point (registered via detectorRegistry) ──────────────────────────

/**
 * A project's own license / notice file (`LICENSE`, `LICENSE-MIT`, `COPYING`, `NOTICE`, `licenses/Apache-2.0.txt`): it IS the license
 * text, so finding license text in it says nothing. (Found scanning ms, eve and others: the LICENSE file was the only finding.)
 */
export function isLicenseOrNoticeFile(filePath: string): boolean {
  return /(?:^|\/)(?:LICEN[CS]E|COPYING|NOTICE|UNLICENSE|COPYRIGHT|PATENTS)(?:[-_.][\w.-]*)?$/i.test(filePath)
    || /(?:^|\/)LICEN[CS]ES\//i.test(filePath);
}

export function scanLicenseContamination(ctx: DetectorContext): ScanIndicator[] {
  if (isLicenseOrNoticeFile(ctx.file_path)) return [];
  const out: ScanIndicator[] = [];

  // SPDX identifiers + copyright notices -- per line, real line numbers.
  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];
    if (isDocExampleLine(line)) continue;

    const spdx = SPDX_RE.exec(line);
    if (spdx) {
      const family = spdx[1];
      out.push({
        id: ID,
        label: "License Header Contamination",
        severity: "medium",
        line: i + 1,
        detail: `SPDX-License-Identifier found: ${SPDX_LABEL[family] ?? family} -- verify this file's content doesn't conflict with your project's own license.`,
        confidence: 80,
      });
      continue; // don't also fire the weaker copyright pattern on the same line
    }

    const copyright = COPYRIGHT_RE.exec(line);
    if (copyright) {
      out.push({
        id: ID,
        label: "License Header Contamination",
        severity: "medium",
        line: i + 1,
        detail: "A third-party copyright notice was found in this file -- verify this doesn't conflict with your codebase's own licensing.",
        confidence: 55,
      });
    }
  }

  // Full-text license boilerplate -- multi-line, scanned against the whole
  // file content once per pattern.
  const seenLines = new Set<number>();
  for (const p of BOILERPLATE_PATTERNS) {
    const m = p.re.exec(ctx.content);
    if (!m) continue;
    const line = lineNumberAt(ctx.content, m.index);
    if (seenLines.has(line)) continue;
    seenLines.add(line);
    out.push({
      id: ID,
      label: "License Header Contamination",
      severity: "medium",
      line,
      detail: `Verbatim ${p.label} text found -- this file may contain code copied from a licensed source. Verify before merging.`,
      confidence: 75,
    });
  }

  return out;
}

// ── A header the whole project carries ──────────────────────────────────────

/** The same notice on at least this many files of one scan is the project's own header (a Circle / Cloudflare / Apache file header
 * on every source file: 388, 395 and 1,171 findings on three public repositories), not text copied into a file. */
export const PROJECT_HEADER_MIN_FILES = 3;

/** What a finding says, with the parts that differ per file (comment marker, year, spacing) removed. */
function headerKey(ind: ScanIndicator, linesOf: (path: string) => string[] | undefined, path: string): string | null {
  if (ind.detail?.startsWith("Verbatim ")) return `boilerplate:${ind.detail.split(" text found")[0]}`;
  if (ind.line == null) return null;
  const text = linesOf(path)?.[ind.line - 1];
  if (text == null) return null;
  const key = text.replace(/^[\s/*#;>"'!\-]+/, "").replace(/\d+/g, "0").replace(/\s+/g, " ").trim().toLowerCase();
  return key ? `line:${key}` : null;
}

/**
 * Drops the license findings whose notice appears on {@link PROJECT_HEADER_MIN_FILES}+ files of this scan, in place. A copied snippet
 * carries one file's header; a project-wide header is on file after file. Returns the paths that lost findings (their risk is
 * re-derived by the caller). A header on one or two files, or a different holder on each, is still reported.
 */
export function dropProjectWideLicenseHeaders(
  files: Array<{ file_path: string; indicators: ScanIndicator[] }>,
  contentOf: ReadonlyMap<string, string>,
): Set<string> {
  const cache = new Map<string, string[]>();
  const linesOf = (path: string) => {
    let l = cache.get(path);
    if (!l) { l = (contentOf.get(path) ?? "").split("\n"); cache.set(path, l); }
    return l;
  };
  const filesByKey = new Map<string, Set<string>>();
  const keyOf = new Map<ScanIndicator, string>();
  for (const f of files) {
    for (const ind of f.indicators) {
      if (ind.id !== ID) continue;
      const key = headerKey(ind, linesOf, f.file_path);
      if (!key) continue;
      keyOf.set(ind, key);
      (filesByKey.get(key) ?? filesByKey.set(key, new Set()).get(key)!).add(f.file_path);
    }
  }
  const changed = new Set<string>();
  for (const f of files) {
    const kept = f.indicators.filter(ind => {
      const key = keyOf.get(ind);
      return !(key && (filesByKey.get(key)?.size ?? 0) >= PROJECT_HEADER_MIN_FILES);
    });
    if (kept.length !== f.indicators.length) { f.indicators = kept; changed.add(f.file_path); }
  }
  return changed;
}
