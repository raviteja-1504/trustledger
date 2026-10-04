"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { authedFetch, isSeedMode } from "@/lib/useRealData";

/**
 * New Scan panel (dashboard).
 *
 *  - Pull request: pick one of the org's connected repositories and one of its open PRs (or type a number);
 *    POST /api/scans/pr queues the same GitHub-backed scan a webhook runs, then we wait for the result and
 *    open it.
 *  - Paste code: scan pasted files against one of the connected repositories (POST /api/scans).
 *
 * Repositories come from the org (GET /api/repos) — scans of a repo that isn't connected never show up in
 * Scan History or the dashboard. Demo mode (no backend) only offers paste mode, on sample repo names.
 */

const DEMO_MODE = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";
const DEMO_ORG = process.env.NEXT_PUBLIC_ORG ?? "acme";
const DEMO_REPOS = ["payments-api", "auth-service", "order-service"].map(r => `${DEMO_ORG}/${r}`);

/** How long to wait for a queued PR scan before handing the user over to Scan History. */
const POLL_EVERY_MS = 3000;
const POLL_FOR_MS = 4 * 60_000;

// ── Examples ──────────────────────────────────────────────────────────────────
const EXAMPLES: Record<string, {
  path: string; content: string;
  icon: string; risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  tag: string; detects: string;
}> = {
  "SQL Injection": {
    icon: "💉", risk: "CRITICAL", tag: "Injection", detects: "Unparameterized queries + hardcoded DB credentials",
    path: "src/db/users.ts",
    content: `import { Pool } from 'pg';

const DB_PASSWORD = "prod_password_2024";
const pool = new Pool({ password: DB_PASSWORD, database: "app" });

export async function getUser(userId: string) {
  const res = await pool.query(
    \`SELECT * FROM users WHERE id = \${userId}\`
  );
  return res.rows[0];
}

export async function updateEmail(userId: string, email: string) {
  await pool.query(
    "UPDATE users SET email = '" + email + "' WHERE id = " + userId
  );
}`,
  },
  "JWT Bypass": {
    icon: "🔑", risk: "CRITICAL", tag: "Auth", detects: "Signature verification skipped + weak secret",
    path: "pkg/auth/jwt.go",
    content: `package auth

import "github.com/golang-jwt/jwt/v4"

const JWTSecret = "my_super_secret_key_2024"

// VerifyToken — signature validation disabled, accepts any token
func VerifyToken(tokenStr string) (map[string]interface{}, error) {
    parser := &jwt.Parser{}
    token, _, _ := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
    claims, _ := token.Claims.(jwt.MapClaims)
    return claims, nil
}

func CreateToken(userID int, role string) (string, error) {
    claims := jwt.MapClaims{"sub": userID, "role": role}
    return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
        SignedString([]byte(JWTSecret))
}`,
  },
  "Remote Code Exec": {
    icon: "💣", risk: "CRITICAL", tag: "RCE", detects: "eval() / new Function() on user-controlled input",
    path: "src/utils/calculator.js",
    content: `const STRIPE_KEY = "sk_live_51Hx2trustledger_demo";

function calculate(expression) {
  // CRITICAL: arbitrary code execution
  return eval(expression);
}

function runFormula(formula, context) {
  // CRITICAL: new Function() on user-controlled input
  const fn = new Function('ctx', formula);
  return fn(context || {});
}

module.exports = { calculate, runFormula };`,
  },
  "Clean code": {
    icon: "✅", risk: "LOW", tag: "No issues", detects: "No AI patterns or vulnerabilities detected",
    path: "src/utils.rs",
    content: `pub fn slugify(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn truncate(text: &str, max_len: usize) -> &str {
    if text.len() <= max_len { text } else { &text[..max_len] }
}

pub fn parse_int(s: &str, default: i64) -> i64 {
    s.parse::<i64>().unwrap_or(default)
}`,
  },
};

const RISK_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "#fef2f2", text: "#be123c", border: "#fecdd3" },
  HIGH:     { bg: "#fff7ed", text: "#c2410c", border: "#fed7aa" },
  MEDIUM:   { bg: "#fffbeb", text: "#b45309", border: "#fde68a" },
  LOW:      { bg: "#f0fdf4", text: "#15803d", border: "#bbf7d0" },
};

// ── Icons ─────────────────────────────────────────────────────────────────────
function XIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}
function PlusIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
    </svg>
  );
}
function TrashIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
      <path d="M10 11v6" /><path d="M14 11v6" />
      <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
    </svg>
  );
}
function Spinner({ className = "w-4 h-4" }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
      <path d="M21 12a9 9 0 1 1-6.219-8.56" />
    </svg>
  );
}

// ── Types ─────────────────────────────────────────────────────────────────────
interface FileEntry { id: number; path: string; content: string; }
interface Props { open: boolean; onClose: () => void; }
interface Pull { number: number; title: string; author: string | null; branch: string; head_sha: string; draft: boolean; updated_at: string }
type StartResult =
  | { status: "queued"; repo: string; pr_number: number; head_sha: string }
  | { status: "already_scanned"; scan_id: string; repo: string; pr_number: number; head_sha: string };
type Phase =
  | { kind: "form" }
  | { kind: "submitting" }
  | { kind: "waiting"; repo: string; pr: number; headSha: string; notScanId: string | null; startedAt: number }
  | { kind: "already"; repo: string; pr: number; scanId: string }
  | { kind: "timeout"; repo: string; pr: number };

let nextId = 1;

function ago(iso: string): string {
  const mins = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 60_000));
  if (mins < 60) return `${mins}m ago`;
  const h = Math.round(mins / 60);
  return h < 48 ? `${h}h ago` : `${Math.round(h / 24)}d ago`;
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function NewScanPanel({ open, onClose }: Props) {
  const router = useRouter();
  const demo = DEMO_MODE || isSeedMode();
  const [mode,       setMode]       = useState<"pr" | "paste">(demo ? "paste" : "pr");
  const [repos,      setRepos]      = useState<string[] | null>(null);
  const [reposError, setReposError] = useState<string | null>(null);
  const [repo,       setRepo]       = useState("");
  const [pulls,      setPulls]      = useState<Pull[] | null>(null);
  const [pullsError, setPullsError] = useState<string | null>(null);
  const [pullsBusy,  setPullsBusy]  = useState(false);
  const [prNumber,   setPrNumber]   = useState("");
  const [files,      setFiles]      = useState<FileEntry[]>([{ id: nextId++, path: "", content: "" }]);
  const [activeFile, setActiveFile] = useState(0);
  const [error,      setError]      = useState<string | null>(null);
  const [phase,      setPhase]      = useState<Phase>({ kind: "form" });
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const stopPolling = () => { if (pollTimer.current) { clearTimeout(pollTimer.current); pollTimer.current = null; } };

  // Load the org's connected repositories each time the panel opens.
  useEffect(() => {
    if (!open) { stopPolling(); return; }
    setPhase({ kind: "form" });
    setError(null);
    setActiveFile(0);
    if (demo) { setRepos(DEMO_REPOS); setRepo(r => r || DEMO_REPOS[0]); return; }
    let cancelled = false;
    setRepos(null); setReposError(null);
    authedFetch<{ repos: Array<{ repo_full_name: string; is_active: boolean }> }>("/api/repos")
      .then(d => {
        if (cancelled) return;
        const names = d.repos.filter(r => r.is_active !== false).map(r => r.repo_full_name);
        setRepos(names);
        setRepo(r => (r && names.includes(r) ? r : names[0] ?? ""));
      })
      .catch(e => { if (!cancelled) { setRepos([]); setReposError(e instanceof Error ? e.message : "Couldn't load your repositories."); } });
    return () => { cancelled = true; };
  }, [open, demo]);

  // Open pull requests of the chosen repository (pull-request mode).
  useEffect(() => {
    if (!open || demo || mode !== "pr" || !repo) { setPulls(null); return; }
    let cancelled = false;
    setPulls(null); setPullsError(null); setPullsBusy(true); setPrNumber("");
    authedFetch<{ pulls: Pull[] }>(`/api/repos/pulls?repo=${encodeURIComponent(repo)}`)
      .then(d => { if (!cancelled) { setPulls(d.pulls); if (d.pulls[0]) setPrNumber(String(d.pulls[0].number)); } })
      .catch(e => { if (!cancelled) setPullsError(e instanceof Error ? e.message : "Couldn't load pull requests."); })
      .finally(() => { if (!cancelled) setPullsBusy(false); });
    return () => { cancelled = true; };
  }, [open, demo, mode, repo]);

  // Escape to close; stop polling when the panel goes away.
  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") onClose(); }
    if (open) document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  useEffect(() => () => stopPolling(), []);

  // Wait for the queued PR scan to land, then open it.
  const poll = useCallback((p: Extract<Phase, { kind: "waiting" }>) => {
    const tick = async () => {
      try {
        const d = await authedFetch<{ scans: Array<{ scan_id: string; pr_number: number; commit_sha: string }> }>(`/api/scans?repo=${encodeURIComponent(p.repo)}&limit=25`);
        const hit = d.scans.find(s => s.pr_number === p.pr && s.commit_sha === p.headSha && s.scan_id !== p.notScanId);
        if (hit) { stopPolling(); router.push(`/pr/${hit.scan_id}`); return; }
      } catch { /* keep waiting; a transient error shouldn't end the wait */ }
      if (Date.now() - p.startedAt > POLL_FOR_MS) { setPhase({ kind: "timeout", repo: p.repo, pr: p.pr }); return; }
      pollTimer.current = setTimeout(tick, POLL_EVERY_MS);
    };
    pollTimer.current = setTimeout(tick, POLL_EVERY_MS);
  }, [router]);

  async function startPrScan(force = false, notScanId: string | null = null) {
    const n = Number(prNumber);
    if (!repo) { setError("Choose a repository."); return; }
    if (!Number.isInteger(n) || n < 1) { setError("Choose a pull request."); return; }
    setError(null);
    setPhase({ kind: "submitting" });
    try {
      const r = await authedFetch<StartResult>("/api/scans/pr", { method: "POST", body: JSON.stringify({ repo, pr_number: n, force }) });
      if (r.status === "already_scanned") { setPhase({ kind: "already", repo: r.repo, pr: r.pr_number, scanId: r.scan_id }); return; }
      const waiting = { kind: "waiting" as const, repo: r.repo, pr: r.pr_number, headSha: r.head_sha, notScanId, startedAt: Date.now() };
      setPhase(waiting);
      poll(waiting);
    } catch (e) {
      setError(e instanceof Error ? e.message : "We couldn't start that scan. Please try again.");
      setPhase({ kind: "form" });
    }
  }

  function randomSha() {
    return Array.from({ length: 40 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
  }

  async function startPasteScan() {
    if (!repo) { setError("Choose a repository."); return; }
    if (prNumber && (!Number.isInteger(Number(prNumber)) || Number(prNumber) < 1)) { setError("The PR number must be a positive whole number, or leave it empty."); return; }
    if (files.some(f => f.content.trim() && !f.path.trim())) { setError("Give every file a path, e.g. src/db/users.ts."); return; }
    setError(null);
    setPhase({ kind: "submitting" });
    try {
      const result = await api.scan({
        repo,
        pr_number: prNumber ? Number(prNumber) : 0, // 0 = not attached to a pull request
        commit_sha: randomSha(),
        files: validFiles.map(f => ({ path: f.path.trim(), content: f.content })),
      });
      // Demo mode has no database: the PR page reads the result from here.
      try { localStorage.setItem(`tl_demo_scan_${result.scan_id}`, JSON.stringify(result)); } catch {}
      router.push(`/pr/${result.scan_id}`);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "We couldn't submit that scan. Please try again.");
      setPhase({ kind: "form" });
    }
  }

  function addFile() {
    const newId = nextId++;
    setFiles(fs => [...fs, { id: newId, path: "", content: "" }]);
    setActiveFile(files.length);
  }
  function removeFile(idx: number) {
    if (files.length <= 1) return;
    setFiles(fs => fs.filter((_, i) => i !== idx));
    setActiveFile(Math.max(0, Math.min(activeFile, files.length - 2)));
  }
  function updateFile(idx: number, field: "path" | "content", value: string) {
    setFiles(fs => fs.map((f, i) => i === idx ? { ...f, [field]: value } : f));
  }
  function loadExample(name: string) {
    const ex = EXAMPLES[name];
    if (!ex) return;
    setFiles([{ id: nextId++, path: ex.path, content: ex.content }]);
    setActiveFile(0);
  }

  const validFiles  = files.filter(f => f.path.trim() && f.content.trim());
  const activeEntry = files[activeFile] ?? files[0];
  const lang = (path: string) =>
    path.endsWith(".py")                                    ? "Python"
    : path.endsWith(".ts") || path.endsWith(".tsx")         ? "TypeScript"
    : path.endsWith(".js") || path.endsWith(".jsx")         ? "JavaScript"
    : path.endsWith(".go")                                  ? "Go"
    : path.endsWith(".java")                                ? "Java"
    : path.endsWith(".kt") || path.endsWith(".kts")         ? "Kotlin"
    : path.endsWith(".rb")                                  ? "Ruby"
    : path.endsWith(".rs")                                  ? "Rust"
    : path.endsWith(".cs")                                  ? "C#"
    : path.endsWith(".php")                                 ? "PHP"
    : path.endsWith(".cpp") || path.endsWith(".cc")         ? "C++"
    : path.endsWith(".c")                                   ? "C"
    : path.endsWith(".swift")                               ? "Swift"
    : path.endsWith(".sh") || path.endsWith(".bash")        ? "Shell"
    : path.endsWith(".sql")                                 ? "SQL"
    : path.endsWith(".tf")                                  ? "Terraform"
    : path.endsWith(".yaml") || path.endsWith(".yml")       ? "YAML"
    : path.endsWith(".json")                                ? "JSON"
    : path.endsWith(".ex") || path.endsWith(".exs")         ? "Elixir"
    : path.endsWith(".md")                                  ? "Markdown"
    : "Plain text";

  if (!open) return null;

  const noRepos = repos !== null && repos.length === 0;
  const busy = phase.kind === "submitting";
  const selectedPull = pulls?.find(p => String(p.number) === prNumber) ?? null;
  const canSubmit = !busy && !!repo && (mode === "pr" ? Number(prNumber) >= 1 : validFiles.length > 0);
  const inputCls = "w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-gray-50/50";

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm" onClick={onClose} />

      {/* Panel */}
      <div role="dialog" aria-label="New scan"
        className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-2xl bg-white shadow-2xl flex flex-col"
        style={{ animation: "slideIn 0.22s cubic-bezier(0.16,1,0.3,1)" }}>

        {/* ── Header ─────────────────────────────────────────────────────────── */}
        <div className="shrink-0 border-b border-gray-100">
          <div className="flex items-center justify-between px-6 pt-5 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center shadow-md shadow-indigo-200">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/>
                  <path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>
                  <rect x="7" y="7" width="10" height="10" rx="1"/>
                </svg>
              </div>
              <div>
                <h2 className="text-sm font-black text-gray-900">New Scan</h2>
                <p className="text-[11px] text-gray-400 mt-0.5">Scan a pull request from GitHub, or paste code</p>
              </div>
            </div>
            <button onClick={onClose} aria-label="Close"
              className="w-8 h-8 rounded-lg flex items-center justify-center text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors">
              <XIcon />
            </button>
          </div>

          {phase.kind === "form" || phase.kind === "submitting" ? (
            <div className="px-6 pb-4">
              <div className="grid grid-cols-2 gap-1 p-1 rounded-xl bg-gray-100" role="tablist" aria-label="Scan source">
                {([["pr", "Pull request"], ["paste", "Paste code"]] as const).map(([m, label]) => (
                  <button key={m} role="tab" aria-selected={mode === m} disabled={demo && m === "pr"}
                    onClick={() => { setMode(m); setError(null); setPrNumber(""); }}
                    title={demo && m === "pr" ? "Needs the GitHub App — not available in demo mode" : undefined}
                    className={`py-2 rounded-lg text-xs font-bold transition-all disabled:opacity-40 ${mode === m ? "bg-white text-indigo-700 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                    {label}
                  </button>
                ))}
              </div>
            </div>
          ) : null}
        </div>

        {/* ── Waiting for a queued PR scan ───────────────────────────────────── */}
        {phase.kind === "waiting" && (
          <div className="flex-1 flex flex-col items-center justify-center gap-4 px-8 text-center">
            <Spinner className="w-10 h-10 text-indigo-500" />
            <div className="space-y-1">
              <p className="text-sm font-bold text-gray-900">Scanning {phase.repo} #{phase.pr}…</p>
              <p className="text-xs text-gray-500 max-w-sm">Fetching the PR's files from GitHub and analysing them. This usually takes under a minute; the result opens here when it's ready.</p>
              <p className="text-[11px] text-gray-400 font-mono">commit {phase.headSha.slice(0, 7)}</p>
            </div>
            <button onClick={onClose} className="text-xs font-semibold text-gray-500 hover:text-gray-700 underline underline-offset-4">
              Close — it keeps running and will appear in Scan History
            </button>
          </div>
        )}

        {/* ── Already scanned ─────────────────────────────────────────────────── */}
        {phase.kind === "already" && (
          <div className="flex-1 flex flex-col items-center justify-center gap-4 px-8 text-center">
            <p className="text-sm font-bold text-gray-900">{phase.repo} #{phase.pr} is already scanned at its latest commit</p>
            <p className="text-xs text-gray-500 max-w-sm">Nothing has been pushed since the last scan. Open that result, or scan it again with the current engine.</p>
            <div className="flex gap-2">
              <button onClick={() => router.push(`/pr/${phase.scanId}`)}
                className="px-4 py-2 text-sm font-bold bg-gradient-to-r from-indigo-600 to-violet-600 text-white rounded-xl">Open scan</button>
              <button onClick={() => startPrScan(true, phase.scanId)}
                className="px-4 py-2 text-sm font-semibold border border-gray-200 text-gray-700 rounded-xl hover:bg-gray-50">Scan again</button>
            </div>
            {error && <p role="alert" className="text-xs text-rose-600">{error}</p>}
          </div>
        )}

        {/* ── Took longer than we wait ────────────────────────────────────────── */}
        {phase.kind === "timeout" && (
          <div className="flex-1 flex flex-col items-center justify-center gap-4 px-8 text-center">
            <p className="text-sm font-bold text-gray-900">Still scanning {phase.repo} #{phase.pr}</p>
            <p className="text-xs text-gray-500 max-w-sm">Large pull requests can take a few minutes. It keeps running in the background and appears in Scan History when it's done.</p>
            <button onClick={() => router.push("/scans")}
              className="px-4 py-2 text-sm font-bold bg-gradient-to-r from-indigo-600 to-violet-600 text-white rounded-xl">Go to Scan History</button>
          </div>
        )}

        {/* ── Form ───────────────────────────────────────────────────────────── */}
        {(phase.kind === "form" || phase.kind === "submitting") && (
          <div className="flex-1 overflow-y-auto">
            <div className="px-6 py-5 space-y-4 border-b border-gray-50">
              {/* Repository */}
              <div>
                <label htmlFor="ns-repo" className="block text-xs font-semibold text-gray-600 mb-1.5">Repository</label>
                {repos === null ? (
                  <div className="flex items-center gap-2 text-xs text-gray-400 py-2.5"><Spinner /> Loading your repositories…</div>
                ) : noRepos ? (
                  <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-xs text-amber-800 space-y-1">
                    <p className="font-bold">{reposError ? "Couldn't load your repositories" : "No repositories connected yet"}</p>
                    <p>{reposError ?? "Install the TrustLedger GitHub App and add repositories, then scan their pull requests here."}</p>
                    <a href="/settings" className="inline-block font-bold underline underline-offset-2">Go to Settings →</a>
                  </div>
                ) : (
                  <select id="ns-repo" value={repo} onChange={e => setRepo(e.target.value)} className={`${inputCls} font-mono`}>
                    {repos.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                )}
              </div>

              {/* Pull request (PR mode) */}
              {mode === "pr" && !noRepos && repos !== null && (
                <div className="space-y-2">
                  <p className="text-xs font-semibold text-gray-600">Pull request</p>
                  {pullsBusy && <div className="flex items-center gap-2 text-xs text-gray-400 py-2"><Spinner /> Loading open pull requests…</div>}
                  {pullsError && <p className="text-xs text-rose-600">{pullsError}</p>}
                  {pulls && pulls.length === 0 && <p className="text-xs text-gray-400">No open pull requests in {repo}. Enter a PR number below to scan a closed one.</p>}
                  {pulls && pulls.length > 0 && (
                    <div className="max-h-64 overflow-y-auto rounded-xl border border-gray-200 divide-y divide-gray-100" role="radiogroup" aria-label="Open pull requests">
                      {pulls.map(p => {
                        const on = String(p.number) === prNumber;
                        return (
                          <button key={p.number} type="button" role="radio" aria-checked={on} onClick={() => setPrNumber(String(p.number))}
                            className={`w-full text-left px-3.5 py-2.5 flex items-start gap-3 transition-colors ${on ? "bg-indigo-50" : "hover:bg-gray-50"}`}>
                            <span className={`mt-0.5 w-4 h-4 rounded-full border-2 shrink-0 ${on ? "border-indigo-500 bg-indigo-500 ring-2 ring-indigo-100" : "border-gray-300"}`} />
                            <span className="min-w-0 flex-1">
                              <span className="flex items-center gap-1.5">
                                <span className="text-xs font-mono font-bold text-gray-500">#{p.number}</span>
                                <span className="text-sm font-semibold text-gray-900 truncate">{p.title}</span>
                                {p.draft && <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-gray-100 text-gray-500">Draft</span>}
                              </span>
                              <span className="block text-[11px] text-gray-400 mt-0.5 truncate">
                                {p.author ?? "unknown"} · <span className="font-mono">{p.branch}</span> · updated {ago(p.updated_at)}
                              </span>
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                  <div className="flex items-center gap-2">
                    <label htmlFor="ns-pr" className="text-[11px] text-gray-500 shrink-0">PR number</label>
                    <input id="ns-pr" type="number" min={1} value={prNumber} onChange={e => setPrNumber(e.target.value)} placeholder="e.g. 42"
                      className={`${inputCls} max-w-[9rem] py-1.5`} />
                    {selectedPull && <span className="text-[11px] text-gray-400 truncate">{selectedPull.title}</span>}
                  </div>
                </div>
              )}

              {/* PR number (paste mode, optional) */}
              {mode === "paste" && !noRepos && repos !== null && (
                <div>
                  <label htmlFor="ns-pr-paste" className="block text-xs font-semibold text-gray-600 mb-1.5">
                    PR number <span className="text-gray-400 font-normal">(optional — attach the result to a PR)</span>
                  </label>
                  <input id="ns-pr-paste" type="number" min={1} value={prNumber} onChange={e => setPrNumber(e.target.value)} placeholder="none"
                    className={`${inputCls} max-w-[12rem]`} />
                </div>
              )}
            </div>

            {mode === "paste" && !noRepos && repos !== null && (
              <>
                {/* Quick examples */}
                <div className="px-6 py-5 border-b border-gray-50 space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Try an example</p>
                    <span className="text-[10px] text-gray-400">Loads sample code with known issues</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(EXAMPLES).map(([name, ex]) => {
                      const rc = RISK_COLORS[ex.risk];
                      return (
                        <button key={name} onClick={() => loadExample(name)}
                          className="flex items-start gap-2.5 px-3 py-3 rounded-xl border border-gray-200 text-left hover:border-indigo-200 hover:bg-indigo-50/50 transition-all group">
                          <span className="text-lg leading-none">{ex.icon}</span>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <p className="text-xs font-bold text-gray-800 group-hover:text-indigo-700 transition-colors">{name}</p>
                              <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full" style={{ background: rc.bg, color: rc.text, border: `1px solid ${rc.border}` }}>{ex.risk}</span>
                            </div>
                            <p className="text-[10px] text-gray-400 mt-0.5 leading-tight">{ex.detects}</p>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Files — tabbed editor */}
                <div className="px-6 py-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest">
                      Files
                      {validFiles.length > 0 && <span className="ml-2 normal-case font-bold text-indigo-500">{validFiles.length}/{files.length} ready</span>}
                    </p>
                    <button onClick={addFile} className="flex items-center gap-1 text-xs font-bold text-indigo-600 hover:text-indigo-700 px-2.5 py-1 rounded-lg hover:bg-indigo-50 transition-colors">
                      <PlusIcon /> Add file
                    </button>
                  </div>

                  {files.length > 1 && (
                    <div className="flex gap-1 overflow-x-auto pb-1 -mx-1 px-1">
                      {files.map((f, i) => (
                        <button key={f.id} onClick={() => setActiveFile(i)}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono whitespace-nowrap shrink-0 transition-all ${i === activeFile ? "bg-indigo-600 text-white shadow-sm" : "bg-gray-100 text-gray-600 hover:bg-gray-200"}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${f.content.trim() ? (i === activeFile ? "bg-white" : "bg-green-500") : "bg-gray-300"}`} />
                          {f.path.split("/").pop() || `file ${i + 1}`}
                        </button>
                      ))}
                    </div>
                  )}

                  {activeEntry && (
                    <div className="border border-gray-200 rounded-xl overflow-hidden shadow-sm">
                      <div className="flex items-center gap-2 px-3 py-2.5 bg-gray-900 border-b border-gray-700">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#6b7280" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
                        </svg>
                        <input type="text" aria-label="File path" value={activeEntry.path} onChange={e => updateFile(activeFile, "path", e.target.value)}
                          placeholder="src/example.ts, pkg/handler.go, src/main.rs…"
                          className="flex-1 text-xs font-mono bg-transparent border-0 outline-none text-gray-300 placeholder-gray-600" />
                        <div className="flex items-center gap-2 shrink-0">
                          {activeEntry.path && <span className="text-[9px] font-bold bg-gray-700 text-gray-400 px-1.5 py-0.5 rounded">{lang(activeEntry.path)}</span>}
                          {files.length > 1 && (
                            <button onClick={() => removeFile(activeFile)} aria-label="Remove file" className="text-gray-600 hover:text-rose-400 transition-colors"><TrashIcon /></button>
                          )}
                        </div>
                      </div>
                      <div className="relative bg-gray-950">
                        <div className="absolute left-0 top-0 bottom-0 w-10 bg-gray-900 border-r border-gray-800 pointer-events-none flex flex-col pt-3">
                          {(activeEntry.content || "\n").split("\n").slice(0, 20).map((_, i) => (
                            <span key={i} className="text-[10px] text-gray-600 text-right pr-2 leading-5 font-mono">{i + 1}</span>
                          ))}
                        </div>
                        <textarea aria-label="File content" value={activeEntry.content} onChange={e => updateFile(activeFile, "content", e.target.value)}
                          placeholder={"Paste your code here...\n// TrustLedger scans any language for AI patterns & vulnerabilities"}
                          rows={12} spellCheck={false}
                          className="w-full pl-12 pr-4 py-3 text-xs font-mono text-gray-200 bg-transparent resize-y focus:outline-none leading-5 placeholder-gray-700"
                          style={{ caretColor: "#818cf8" }} />
                      </div>
                      <div className="px-3 py-2 bg-gray-900 border-t border-gray-800 flex items-center justify-between">
                        {activeEntry.content ? (
                          <>
                            <span className="text-[10px] text-gray-500 font-mono">{activeEntry.content.split("\n").length} lines · {activeEntry.content.length} chars</span>
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded text-emerald-400 bg-emerald-900/40">● Ready to scan</span>
                          </>
                        ) : <span className="text-[10px] text-gray-600">Paste code to begin</span>}
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {/* ── Footer ──────────────────────────────────────────────────────────── */}
        {(phase.kind === "form" || phase.kind === "submitting") && (
          <div className="shrink-0 px-6 py-4 border-t border-gray-100 bg-gray-50/60 space-y-3">
            {error && (
              <div role="alert" className="flex items-center gap-2 px-3 py-2.5 bg-rose-50 border border-rose-200 rounded-xl">
                <p className="text-xs text-rose-600 font-medium">{error}</p>
              </div>
            )}
            <div className="flex items-center justify-between gap-3">
              <p className="text-xs text-gray-500 min-w-0 truncate">
                {mode === "pr"
                  ? (repo && Number(prNumber) >= 1 ? <><span className="font-bold text-gray-700 font-mono">{repo}</span> #{prNumber}</> : "Choose a repository and pull request")
                  : (validFiles.length === 0 ? "Paste code into a file to begin" : <><span className="font-bold text-gray-700">{validFiles.length} file{validFiles.length !== 1 ? "s" : ""}</span> → <span className="font-mono">{repo}</span></>)}
              </p>
              <div className="flex items-center gap-2 shrink-0">
                <button onClick={onClose} className="px-4 py-2 text-sm font-semibold text-gray-500 rounded-xl hover:bg-gray-100 transition-colors">Cancel</button>
                <button onClick={() => (mode === "pr" ? startPrScan() : startPasteScan())} disabled={!canSubmit}
                  className="flex items-center gap-2 px-5 py-2 text-sm font-bold bg-gradient-to-r from-indigo-600 to-violet-600 text-white rounded-xl hover:from-indigo-700 hover:to-violet-700 disabled:opacity-40 transition-all active:scale-[0.98] shadow-md shadow-indigo-200">
                  {busy && <Spinner />}
                  {busy ? "Starting…" : mode === "pr" ? (Number(prNumber) >= 1 ? `Scan PR #${prNumber}` : "Scan PR") : `Scan ${validFiles.length || ""} file${validFiles.length === 1 ? "" : "s"}`.replace("  ", " ")}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      <style>{`
        @keyframes slideIn {
          from { transform: translateX(100%); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
      `}</style>
    </>
  );
}
