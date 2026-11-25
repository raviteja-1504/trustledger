/**
 * Self-contained per-file and per-scan analyzers split out of scanner.ts (Task 9, scanner modularization):
 * line-level AI attribution, behavioral risk, provenance, CI/CD trust, AI tooling artifacts, scan integrity chain.
 * scanner.ts re-exports every public name, so existing importers are unchanged.
 */
import crypto from "crypto";
import type { BehavioralRisk, ProvenanceInfo, CICDTrustScore, AIToolingArtifact, FileAnalysis } from "./scanner";

// ── Line-level AI attribution ─────────────────────────────────────────────────

const LINE_AI_PATTERNS: RegExp[] = [
  /\bconst\s+(?:result|response|data)\s*=\s*await\s+/,
  /\b(?:validateInput|handleError|processData|sanitizeInput)\s*\(/,
  /\bif\s*\(\s*!(?:input|data|value|params|options|config|request|body)\s*\)/,
  /\breturn\s+\{\s*(?:success|data|error|result|message|status)\s*:/,
  /\bthrow\s+new\s+(?:Error|[A-Z]\w*Error)\s*\(\s*["'`]/,
  /^\s*\/\/\s*[A-Z][a-z].{15,}[.!]?\s*$/,  // sentence-style comment
  /\bconsole\.(?:log|error|warn)\s*\(\s*\{/,  // structured log
  /\bconst\s+\{\s*\w+(?:\s*,\s*\w+)+\s*\}\s*=/,  // destructuring
];

export function computeLineAttribution(content: string): number[] {
  const lines = content.split("\n");
  return lines.map(line => {
    if (line.trim().length < 5) return 0;
    let hits = 0;
    for (const re of LINE_AI_PATTERNS) if (re.test(line)) hits++;
    return Math.min(1, hits * 0.22);
  });
}

// ── Behavioral risk engine ────────────────────────────────────────────────────

export function analyzeBehavioralRisk(content: string): BehavioralRisk {
  const lines = content.split("\n");
  let logic_bombs = 0, exfil = 0, timing = 0, hidden = 0;

  for (const line of lines) {
    if (/new\s+Date\(\)\.\w+\(\)\s*[><=!]+\s*\d|Date\.now\(\)\s*[><=!]+\s*\d{10}/.test(line)) logic_bombs++;
    if (/(?:fetch|XMLHttpRequest|axios)\s*\(/.test(line) &&
        /\$\{(?:user|session|token|pass|secret|cookie|auth)\b/i.test(line)) exfil++;
    if (/navigator\.sendBeacon|new\s+Image\(\)/.test(line) && /\.src\s*=|sendBeacon/.test(line)) exfil++;
    if (/setTimeout\s*\([^,]+,\s*(?:\w+)\.length/.test(line)) timing++;
    if (/\\u00[0-9a-f]{2}\\u00[0-9a-f]{2}\\u00[0-9a-f]{2}/i.test(line)) hidden++;
    if (/(?:atob|btoa)\s*\(\s*["'][A-Za-z0-9+/=]{20,}/.test(line)) hidden++;
  }

  const score = Math.min(1,
    logic_bombs * 0.25 + exfil * 0.35 + timing * 0.20 + hidden * 0.20
  );
  return { score, logic_bombs, exfiltration_patterns: exfil, timing_channels: timing, hidden_channels: hidden };
}

// ── Provenance / temporal risk analyzer ──────────────────────────────────────

const AGENTIC_ARTIFACT_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\bgenerated\s+by\s+(?:claude|chatgpt|gpt-?[34]|copilot|cursor|gemini)\b/i,  label: "AI generator attribution comment" },
  { re: /\bai[_-]?generated\b/i,                                                     label: "ai-generated marker" },
  { re: /\bdo\s+not\s+(?:edit|modify)\s+(?:this\s+)?(?:file|code)\s+manually\b/i,   label: "do-not-edit directive" },
  { re: /\bauto[_-]?generated\s+by\s+\w/i,                                           label: "auto-generated header" },
  { re: /\bprompt[_-]?id\s*[:=]\s*["']?\w/i,                                         label: "prompt-id artifact" },
  { re: /\bsession[_-]?id\s*[:=]\s*["'][\w-]{20,}["']/i,                             label: "session-id artifact" },
  { re: /@generated\b/,                                                               label: "@generated JSDoc tag" },
  { re: /\/\/\s*@ai\b/i,                                                             label: "@ai annotation" },
];

export function analyzeProvenance(content: string, lineCount: number, drift_score: number): ProvenanceInfo {
  const artifacts: string[] = [];
  for (const { re, label } of AGENTIC_ARTIFACT_PATTERNS) {
    if (re.test(content)) artifacts.push(label);
  }

  // Temporal risk — rushed code markers
  const temporalMarkers = [
    /\bTODO\s*:/gi, /\bHACK\s*:/gi, /\bFIXME\s*:/gi,
    /\btemporary\b/gi, /\bquick[_\s-]?fix\b/gi, /\bworkaround\b/gi,
  ];
  let temporalHits = 0;
  for (const re of temporalMarkers) {
    const m = content.match(re);
    if (m) temporalHits += m.length;
  }
  const temporal_risk = Math.min(1, temporalHits / Math.max(10, lineCount / 20));

  return { drift_score, temporal_risk, agentic_artifacts: artifacts };
}

// ── CI/CD trust scorer ────────────────────────────────────────────────────────

const DANGEROUS_CICD_PATTERNS: Array<{ re: RegExp; msg: string }> = [
  { re: /\$\{\{\s*github\.event\.(?:issue|comment|pull_request)\.body/,   msg: "Unsanitised PR/issue body in expression" },
  { re: /\$\{\{\s*github\.event\.(?:head_commit|commits)\[.+\]\.message/, msg: "Commit message injected into expression" },
  { re: /run:\s*\|\n[^#\n]*\$\{\{/m,                                      msg: "Expression inside run: shell step (injection risk)" },
  { re: /pull_request_target[\s\S]{0,200}actions\/checkout/,              msg: "pull_request_target with checkout (potential fork poisoning)" },
  { re: /curl\s+.*\|\s*(?:bash|sh)/,                                      msg: "curl-pipe-bash in CI step" },
  { re: /npm\s+install\s+--production\s+&&\s+npm\s+run/,                  msg: "Production install before audit in CI" },
  { re: /secrets\.\w+\s*==\s*["']/,                                       msg: "Secret compared in condition (leaks via timing)" },
];

export function scoreCICDTrust(filePaths: string[], contentMap: Map<string, string>): CICDTrustScore {
  const ciFiles = filePaths.filter(p =>
    /\.github[\\/]workflows[\\/]/.test(p) ||
    /Jenkinsfile/.test(p) ||
    /\.circleci[\\/]config/.test(p) ||
    /\.gitlab-ci\.yml$/.test(p)
  );

  if (ciFiles.length === 0) return { score: 1, findings: [], dangerous_steps: [], pinned_actions: true, secret_scanning: true };

  const findings: string[] = [];
  const dangerous_steps: string[] = [];
  let pinnedAll = true;
  let hasSecretScanning = false;

  for (const fp of ciFiles) {
    const c = contentMap.get(fp) ?? "";
    for (const { re, msg } of DANGEROUS_CICD_PATTERNS) {
      if (re.test(c)) { findings.push(`${fp}: ${msg}`); dangerous_steps.push(msg); }
    }
    // Check for pinned action versions (uses: owner/repo@sha or @vX.Y.Z)
    const uses = c.match(/uses:\s*\S+/g) ?? [];
    if (uses.some(u => /@[a-f0-9]{40}$/.test(u) === false && !/@v\d+\.\d+\.\d+$/.test(u) && /@/.test(u))) {
      pinnedAll = false;
    }
    if (/trivy|snyk|dependabot|secret.?scan|gitleaks|truffle/i.test(c)) hasSecretScanning = true;
  }

  const penaltyPerFinding = 0.15;
  const unpinnedPenalty   = pinnedAll ? 0 : 0.10;
  const noScanPenalty     = hasSecretScanning ? 0 : 0.08;
  const score = Math.max(0, 1 - findings.length * penaltyPerFinding - unpinnedPenalty - noScanPenalty);

  return { score, findings, dangerous_steps, pinned_actions: pinnedAll, secret_scanning: hasSecretScanning };
}

// ── AI tooling artifact detection ───────────────────────────────────────────
//
// Repo-level visibility into which AI coding agents/assistants are configured
// for this project. These config/rule files steer how an AI agent edits code
// (custom instructions, allowed commands, persona) — knowing they exist is
// part of "AI governance": a rule file with broad permissions or no review
// requirement is itself a provenance/risk signal, even before looking at code.
const AI_TOOLING_PATTERNS: Array<{ re: RegExp; tool: string; label: string }> = [
  { re: /(?:^|[\\/])\.cursorrules$/i,                 tool: "Cursor",        label: "Cursor AI agent rules file" },
  { re: /(?:^|[\\/])\.cursor[\\/]rules[\\/]/i,        tool: "Cursor",        label: "Cursor project rules directory" },
  { re: /(?:^|[\\/])\.windsurfrules$/i,               tool: "Windsurf",      label: "Windsurf AI agent rules file" },
  { re: /(?:^|[\\/])\.windsurf[\\/]/i,                tool: "Windsurf",      label: "Windsurf agent configuration directory" },
  { re: /(?:^|[\\/])CLAUDE\.md$/i,                    tool: "Claude Code",   label: "Claude Code project instructions" },
  { re: /(?:^|[\\/])\.claude[\\/]/i,                  tool: "Claude Code",   label: "Claude Code agent configuration directory" },
  { re: /(?:^|[\\/])\.github[\\/]copilot-instructions\.md$/i, tool: "GitHub Copilot", label: "Copilot custom instructions" },
  { re: /(?:^|[\\/])\.aider\.conf\.ya?ml$/i,          tool: "Aider",         label: "Aider configuration file" },
  { re: /(?:^|[\\/])\.aiderignore$/i,                 tool: "Aider",         label: "Aider ignore rules" },
  { re: /(?:^|[\\/])\.continue[\\/]/i,                tool: "Continue",      label: "Continue agent configuration directory" },
  { re: /(?:^|[\\/])\.codeium[\\/]/i,                 tool: "Codeium",       label: "Codeium agent configuration directory" },
  { re: /(?:^|[\\/])\.clinerules$/i,                  tool: "Cline",         label: "Cline AI agent rules file" },
  { re: /(?:^|[\\/])\.clinerules[\\/]/i,              tool: "Cline",         label: "Cline project rules directory" },
  { re: /(?:^|[\\/])\.devin[\\/]/i,                   tool: "Devin",         label: "Devin agent configuration directory" },
  { re: /(?:^|[\\/])AGENTS\.md$/i,                    tool: "AI Agents",     label: "Generic AI agent instructions (Codex/Agents-style)" },
];

// Path-based detection only fires when a PR touches a repo-level agent
// config file (.cursorrules, CLAUDE.md, etc.) -- those are typically added
// once, early in a project's life, and essentially never appear again in a
// normal feature PR. That made tool_evidence read 0% on almost every scan
// regardless of whether the changed code was actually AI-authored. This
// second pattern set catches attribution markers AI tools commonly leave
// directly in file content -- generated-by comments, co-authorship
// trailers copied into source files, etc. -- which real AI-assisted PRs
// carry far more often than a fresh agent-config file.
const AI_ATTRIBUTION_CONTENT_PATTERNS: Array<{ re: RegExp; tool: string; label: string }> = [
  { re: /co-authored-by:\s*claude/i,                        tool: "Claude Code",   label: "Claude co-authorship trailer in file" },
  { re: /generated\s+(?:with|by)\s+\[?claude\s*code\]?/i,    tool: "Claude Code",   label: "\"Generated with Claude Code\" marker" },
  { re: /co-authored-by:\s*(?:github\s*)?copilot/i,          tool: "GitHub Copilot", label: "Copilot co-authorship trailer in file" },
  { re: /generated\s+(?:with|by)\s+(?:github\s*)?copilot/i,  tool: "GitHub Copilot", label: "\"Generated by Copilot\" marker" },
  { re: /co-authored-by:\s*(?:chatgpt|openai\s*codex)/i,     tool: "ChatGPT",       label: "ChatGPT/Codex co-authorship trailer in file" },
  { re: /generated\s+(?:with|by)\s+(?:chatgpt|openai\s*codex)/i, tool: "ChatGPT",   label: "\"Generated by ChatGPT\" marker" },
  { re: /co-authored-by:\s*cursor/i,                         tool: "Cursor",        label: "Cursor co-authorship trailer in file" },
  { re: /generated\s+(?:with|by)\s+cursor/i,                 tool: "Cursor",        label: "\"Generated with Cursor\" marker" },
  { re: /co-authored-by:\s*(?:google\s*)?gemini/i,           tool: "Gemini",        label: "Gemini co-authorship trailer in file" },
  { re: /generated\s+(?:with|by)\s+(?:google\s*)?gemini/i,   tool: "Gemini",        label: "\"Generated by Gemini\" marker" },
  { re: /generated\s+(?:with|by)\s+windsurf/i,                tool: "Windsurf",     label: "\"Generated with Windsurf\" marker" },
  { re: /generated\s+(?:with|by)\s+devin/i,                   tool: "Devin",        label: "\"Generated by Devin\" marker" },
  { re: /this (?:file|code) was (?:generated|written) by (?:an? )?(?:ai|llm)\b/i, tool: "AI Agents", label: "Explicit AI-generated disclosure" },
];

/**
 * Scan repo file paths for AI coding-agent config/rule files (governance
 * visibility), and optionally file content for AI-attribution markers left
 * directly in source (generated-by comments, co-authorship trailers).
 * `fileContents` only needs to cover whatever subset of `filePaths` has
 * content available (e.g. scannable files) -- content-based detection is
 * simply skipped for paths without a matching entry.
 */
export function detectAIToolingArtifacts(
  filePaths: string[],
  fileContents?: Array<{ path: string; content: string }>,
): AIToolingArtifact[] {
  const out: AIToolingArtifact[] = [];
  for (const fp of filePaths) {
    for (const { re, tool, label } of AI_TOOLING_PATTERNS) {
      if (re.test(fp)) out.push({ tool, file: fp, label });
    }
  }
  if (fileContents) {
    for (const { path, content } of fileContents) {
      for (const { re, tool, label } of AI_ATTRIBUTION_CONTENT_PATTERNS) {
        if (re.test(content)) out.push({ tool, file: path, label });
      }
    }
  }
  return out;
}

// ── TrustLedger scan integrity chain ──────────────────────────────────────────
//
// A hash chain over a scan's files: it commits to exactly which file contents the scan covered, so a copy of the scan
// result can be compared with the original. It is an INTEGRITY COMMITMENT, not a signature: it uses no secret, so anyone
// able to rewrite a stored scan can recompute it, and it does not prove who ran the scan. Authenticated evidence is the
// Ed25519-signed Trust Record / audit export (exportSigning.ts), which a verifier checks against the published public
// key. The attestation and audit-log hashes (buildAttestationHash, buildAuditHash) are persisted in that form and
// verified as-is, so their format is deliberately unchanged here.

export interface TrustChain {
  genesis_hash:  string;
  file_hashes:   Array<{ path: string; hash: string }>;  // in canonical (path) order
  chain_hash:    string;  // rolling SHA-256 over the file hashes, in canonical order: the same files give the same value
  scan_seal:     string;  // final hash: chain_hash + scan_id + timestamp (the timestamp makes this one differ per run)
  timestamp:     string;
}

export function buildTrustChain(files: FileAnalysis[], scan_id: string): TrustChain {
  const timestamp = new Date().toISOString();
  const genesis_hash = crypto.createHash("sha256").update("TrustLedger::GENESIS").digest("hex");
  // Canonical order, so the chain does not depend on the order files happened to be analysed in; and each step hashes a
  // JSON array, so a path or hash containing the old "::" separator cannot be moved between fields to collide.
  const ordered = [...files].sort((x, y) => (x.file_path < y.file_path ? -1 : x.file_path > y.file_path ? 1 : 0));
  let chain = genesis_hash;
  const file_hashes = ordered.map(f => {
    chain = crypto.createHash("sha256").update(JSON.stringify([chain, f.file_path, f.content_hash])).digest("hex");
    return { path: f.file_path, hash: f.content_hash };
  });
  const chain_hash = chain;
  const scan_seal  = crypto.createHash("sha256").update(JSON.stringify([chain_hash, scan_id, timestamp])).digest("hex");
  return { genesis_hash, file_hashes, chain_hash, scan_seal, timestamp };
}
