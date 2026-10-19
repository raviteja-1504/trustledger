/**
 * One catalog of AI coding tools for Shadow AI and the Trust Score.
 *
 * Two parts of the scanner name tools differently: detectAIToolingArtifacts() (scanner.ts) reports "Claude Code",
 * "GitHub Copilot", "Windsurf"...; the style guesser (aiAttribution.ts) reports "claude", "github-copilot"...
 * toolId() maps both onto one canonical id, so an org's approved-tools policy means the same thing everywhere.
 *
 * Client-safe: no imports.
 */

export interface AiTool { id: string; label: string; vendor: string }

/** Every tool an org can approve. `unspecified` = AI use is evident but the tool can't be named (AGENTS.md, an
 * "AI-generated" disclosure): it is never approved or unapproved by policy -- a person has to look. */
export const AI_TOOLS: readonly AiTool[] = [
  { id: "github-copilot", label: "GitHub Copilot",       vendor: "GitHub / Microsoft" },
  { id: "chatgpt",        label: "ChatGPT / OpenAI Codex", vendor: "OpenAI" },
  { id: "claude",         label: "Claude / Claude Code", vendor: "Anthropic" },
  { id: "gemini",         label: "Gemini",               vendor: "Google" },
  { id: "cursor",         label: "Cursor",               vendor: "Anysphere" },
  { id: "windsurf",       label: "Windsurf (Codeium)",   vendor: "Windsurf" },
  { id: "codewhisperer",  label: "Amazon Q / CodeWhisperer", vendor: "AWS" },
  { id: "tabnine",        label: "Tabnine",              vendor: "Tabnine" },
  { id: "aider",          label: "Aider",                vendor: "Open source" },
  { id: "continue",       label: "Continue",             vendor: "Open source" },
  { id: "cline",          label: "Cline",                vendor: "Open source" },
  { id: "devin",          label: "Devin",                vendor: "Cognition" },
];

export const UNSPECIFIED_TOOL = "unspecified";

const BY_NAME: Record<string, string> = {
  // scanner.ts detectAIToolingArtifacts() names
  "github copilot": "github-copilot", "chatgpt": "chatgpt", "claude code": "claude", "gemini": "gemini",
  "cursor": "cursor", "windsurf": "windsurf", "codeium": "windsurf", "aider": "aider", "continue": "continue",
  "cline": "cline", "devin": "devin", "ai agents": UNSPECIFIED_TOOL,
  // aiAttribution.ts AIModel ids
  "github-copilot": "github-copilot", "claude": "claude", "codewhisperer": "codewhisperer", "tabnine": "tabnine",
};

/** Canonical tool id for any name the scanner uses, or null when it isn't an AI tool ("human", "unknown"). */
export function toolId(name: string | null | undefined): string | null {
  if (!name) return null;
  return BY_NAME[name.trim().toLowerCase()] ?? null;
}

export function toolLabel(id: string): string {
  if (id === UNSPECIFIED_TOOL) return "Unidentified AI tool";
  return AI_TOOLS.find(t => t.id === id)?.label ?? id;
}

/** Only known tool ids, deduplicated, in catalog order -- for validating a submitted policy. */
export function normalizePolicy(ids: unknown): string[] {
  if (!Array.isArray(ids)) return [];
  const wanted = new Set(ids.filter((x): x is string => typeof x === "string"));
  return AI_TOOLS.map(t => t.id).filter(id => wanted.has(id));
}

// ── Commit evidence ─────────────────────────────────────────────────────────────
// AI tools sign the commits they make: a "Co-authored-by:" trailer, a "Generated with" line, or a bot author.
// The scan worker used to keep only each commit's first line, discarding exactly this evidence.

const COMMIT_PATTERNS: Array<{ re: RegExp; tool: string; label: string }> = [
  { re: /^co-authored-by:\s*claude\b/im,                              tool: "claude",         label: "Claude co-author trailer on commit" },
  { re: /generated (?:with|by) \[?claude code\]?/i,                   tool: "claude",         label: "\"Generated with Claude Code\" on commit" },
  { re: /^co-authored-by:\s*(?:github\s*)?copilot\b/im,               tool: "github-copilot", label: "Copilot co-author trailer on commit" },
  { re: /^co-authored-by:\s*(?:chatgpt|openai|codex)\b/im,            tool: "chatgpt",        label: "ChatGPT/Codex co-author trailer on commit" },
  { re: /^co-authored-by:\s*cursor(?:agent)?\b/im,                    tool: "cursor",         label: "Cursor co-author trailer on commit" },
  { re: /^co-authored-by:\s*(?:google\s*)?gemini\b/im,                tool: "gemini",         label: "Gemini co-author trailer on commit" },
  { re: /^co-authored-by:\s*devin\b/im,                               tool: "devin",          label: "Devin co-author trailer on commit" },
  { re: /^co-authored-by:\s*aider\b/im,                               tool: "aider",          label: "Aider co-author trailer on commit" },
];

const BOT_AUTHORS: Array<{ re: RegExp; tool: string; label: string }> = [
  { re: /^copilot(?:-swe-agent)?\[bot\]$/i,       tool: "github-copilot", label: "Commit authored by the Copilot coding agent" },
  { re: /^devin-ai-integration\[bot\]$/i,         tool: "devin",          label: "Commit authored by Devin" },
  { re: /^(?:claude|claude-code)\[bot\]$/i,       tool: "claude",         label: "Commit authored by Claude" },
  { re: /^(?:cursor|cursoragent)\[bot\]$/i,       tool: "cursor",         label: "Commit authored by Cursor" },
  { re: /^(?:chatgpt-codex-connector|codex)\[bot\]$/i, tool: "chatgpt",   label: "Commit authored by OpenAI Codex" },
];

export interface CommitEvidence { tool: string; sha: string; label: string }

/** AI tools that signed these commits: one entry per (commit, tool). */
export function detectCommitEvidence(commits: ReadonlyArray<{ sha: string; message: string; author_login?: string | null }>): CommitEvidence[] {
  const out: CommitEvidence[] = [];
  for (const c of commits) {
    const seen = new Set<string>();
    const add = (tool: string, label: string) => { if (!seen.has(tool)) { seen.add(tool); out.push({ tool, sha: c.sha, label }); } };
    for (const p of COMMIT_PATTERNS) if (p.re.test(c.message ?? "")) add(p.tool, p.label);
    const login = (c.author_login ?? "").trim();
    if (login) for (const b of BOT_AUTHORS) if (b.re.test(login)) add(b.tool, b.label);
  }
  return out;
}
