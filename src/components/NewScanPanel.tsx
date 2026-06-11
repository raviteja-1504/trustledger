"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

const DEMO_REPOS = [
  `${ORG}/payments-api`,
  `${ORG}/auth-service`,
  `${ORG}/fraud-detection`,
  `${ORG}/risk-engine`,
  `${ORG}/data-platform`,
  `${ORG}/ml-platform`,
  `${ORG}/order-service`,
  `${ORG}/billing-service`,
  `${ORG}/cli-tools`,
];

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

// ── Scan scopes ───────────────────────────────────────────────────────────────
const SCAN_SCOPES = [
  { id: "ai",     label: "AI Detection",      icon: "🤖", desc: "Detects AI-generated code patterns" },
  { id: "secrets",label: "Secrets Scanner",   icon: "🔐", desc: "Finds API keys, passwords, tokens" },
  { id: "vuln",   label: "Vulnerabilities",   icon: "🛡️", desc: "SQL injection, XSS, RCE, eval/exec" },
  { id: "deps",   label: "Dependency Check",  icon: "📦", desc: "Phantom & outdated packages" },
];

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

// ── Types ─────────────────────────────────────────────────────────────────────
interface FileEntry { id: number; path: string; content: string; }

interface Props { open: boolean; onClose: () => void; }

let nextId = 1;

// ── Scanning animation ─────────────────────────────────────────────────────────
function ScanningState({ files, onDone }: { files: FileEntry[]; onDone: () => void }) {
  const [step, setStep]     = useState(0);
  const [fileIdx, setFileIdx] = useState(0);

  const steps = [
    "Parsing file structure…",
    "Running AI pattern detection…",
    "Scanning for hardcoded secrets…",
    "Checking security vulnerabilities…",
    "Computing risk scores…",
    "Building attestation report…",
  ];

  useEffect(() => {
    let s = 0, f = 0;
    const tick = () => {
      s++;
      if (s < steps.length) {
        setStep(s);
        if (s % 2 === 0 && f < files.length - 1) { f++; setFileIdx(f); }
        setTimeout(tick, 380 + Math.random() * 180);
      } else {
        setTimeout(onDone, 300);
      }
    };
    setTimeout(tick, 420);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="flex flex-col items-center justify-center flex-1 gap-6 px-8">
      {/* Orbit animation */}
      <div className="relative w-20 h-20">
        <div className="absolute inset-0 rounded-full border-2 border-indigo-100" />
        <div className="absolute inset-0 rounded-full border-2 border-t-indigo-500 animate-spin" />
        <div className="absolute inset-2 rounded-full border border-violet-100" />
        <div className="absolute inset-2 rounded-full border border-t-violet-400 animate-spin" style={{ animationDuration: "0.8s", animationDirection: "reverse" }} />
        <div className="absolute inset-0 flex items-center justify-center">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/>
            <path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>
            <rect x="7" y="7" width="10" height="10" rx="1"/>
          </svg>
        </div>
      </div>

      <div className="text-center space-y-1">
        <p className="text-sm font-bold text-gray-900">Analysing {files[fileIdx]?.path ?? "files"}…</p>
        <p className="text-xs text-indigo-500 font-medium">{steps[step]}</p>
      </div>

      {/* Step dots */}
      <div className="flex gap-1.5">
        {steps.map((_, i) => (
          <span key={i} className={`w-1.5 h-1.5 rounded-full transition-all duration-300 ${i <= step ? "bg-indigo-500 scale-110" : "bg-gray-200"}`} />
        ))}
      </div>

      {/* File list */}
      <div className="w-full max-w-xs space-y-1.5">
        {files.map((f, i) => (
          <div key={f.id} className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-all ${i === fileIdx ? "bg-indigo-50 border border-indigo-200" : i < fileIdx ? "bg-green-50 border border-green-100" : "bg-gray-50 border border-gray-100"}`}>
            <span className="text-sm">
              {i < fileIdx ? "✓" : i === fileIdx ? "⟳" : "·"}
            </span>
            <span className={`text-xs font-mono truncate ${i === fileIdx ? "text-indigo-700 font-semibold" : i < fileIdx ? "text-green-700" : "text-gray-400"}`}>
              {f.path || "untitled"}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function NewScanPanel({ open, onClose }: Props) {
  const router = useRouter();
  const [step,         setStep]         = useState<"config" | "scanning">("config");
  const [repo,         setRepo]         = useState(`${ORG}/payments-api`);
  const [prNumber,     setPrNumber]     = useState("50");
  const [commitSha,    setCommitSha]    = useState("");
  const [branch,       setBranch]       = useState("main");
  const [files,        setFiles]        = useState<FileEntry[]>([{ id: nextId++, path: "", content: "" }]);
  const [activeFile,   setActiveFile]   = useState(0);
  const [scopes,       setScopes]       = useState(new Set(["ai", "secrets", "vuln"]));
  const [error,        setError]        = useState<string | null>(null);
  const [repoOpen,     setRepoOpen]     = useState(false);
  // Use refs so animation callbacks always see the latest values without stale-closure issues
  const scanIdRef  = useRef<string | null>(null);
  const animDone   = useRef(false);
  const panelRef   = useRef<HTMLDivElement>(null);

  // Reset when opened
  useEffect(() => {
    if (open) {
      setStep("config");
      setError(null);
      scanIdRef.current = null;
      animDone.current  = false;
      setActiveFile(0);
    }
  }, [open]);

  // Escape to close
  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") onClose(); }
    if (open) document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  function addFile() {
    const newId = nextId++;
    setFiles(fs => [...fs, { id: newId, path: "", content: "" }]);
    setActiveFile(files.length); // switch to new tab
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
    const newId = nextId++;
    const updated = { id: newId, path: ex.path, content: ex.content };
    setFiles([updated]);
    setActiveFile(0);
  }
  function toggleScope(id: string) {
    setScopes(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }
  function randomSha() {
    return Array.from({ length: 8 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
  }

  async function handleSubmit() {
    if (!repo.trim())                    { setError("Repository name is required."); return; }
    if (!prNumber || isNaN(Number(prNumber))) { setError("PR number must be a valid integer."); return; }
    const badFile = files.find(f => !f.path.trim());
    if (badFile)                         { setError("All files need a path."); return; }

    setError(null);
    setStep("scanning");

    const sha = commitSha.trim() || randomSha();
    try {
      const result = await api.scan({
        repo: repo.trim(),
        pr_number: Number(prNumber),
        commit_sha: sha,
        files: files.map(f => ({ path: f.path.trim(), content: f.content })),
      });
      // Persist so the PR detail page can load it without a DB round-trip
      try { localStorage.setItem(`tl_demo_scan_${result.scan_id}`, JSON.stringify(result)); } catch {}
      scanIdRef.current = result.scan_id;
      // If the animation already finished before the API returned, navigate now
      if (animDone.current) router.push(`/pr/${result.scan_id}`);
    } catch (e: unknown) {
      setError(String(e));
      setStep("config");
    }
  }

  function onScanAnimDone() {
    animDone.current = true;
    // If the API already returned, navigate now; otherwise handleSubmit will navigate
    if (scanIdRef.current) router.push(`/pr/${scanIdRef.current}`);
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

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm" onClick={onClose} />

      {/* Panel */}
      <div
        ref={panelRef}
        className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-2xl bg-white shadow-2xl flex flex-col"
        style={{ animation: "slideIn 0.22s cubic-bezier(0.16,1,0.3,1)" }}
      >

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
                <p className="text-[11px] text-gray-400 mt-0.5">Submit a pull request for AI code analysis</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg flex items-center justify-center text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
            >
              <XIcon />
            </button>
          </div>

          {/* Step progress bar */}
          {step === "config" && (
            <div className="flex px-6 pb-4 gap-2">
              {["PR Details", "Scan Scope", "Files"].map((label, i) => {
                const filled = validFiles.length > 0 ? i <= 2 : i === 0 ? true : i === 1 ? scopes.size > 0 : false;
                return (
                  <div key={label} className="flex-1 flex flex-col gap-1">
                    <div className={`h-1 rounded-full transition-all ${filled ? "bg-indigo-500" : "bg-gray-100"}`} />
                    <span className={`text-[9px] font-bold uppercase tracking-wider ${filled ? "text-indigo-500" : "text-gray-300"}`}>{label}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* ── Scanning state ──────────────────────────────────────────────────── */}
        {step === "scanning" && (
          <ScanningState files={validFiles.length > 0 ? validFiles : files} onDone={onScanAnimDone} />
        )}

        {/* ── Config body ─────────────────────────────────────────────────────── */}
        {step === "config" && (
          <div className="flex-1 overflow-y-auto">

            {/* PR Details */}
            <div className="px-6 py-5 space-y-4 border-b border-gray-50">
              <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest">PR Details</p>

              {/* Repo with dropdown */}
              <div className="relative">
                <label className="block text-xs font-semibold text-gray-600 mb-1.5">Repository</label>
                <div className="relative">
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-300">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M3 3h18v18H3z"/><path d="M9 3v18"/><path d="M3 9h6"/><path d="M3 15h6"/>
                    </svg>
                  </span>
                  <input
                    type="text"
                    value={repo}
                    onChange={e => { setRepo(e.target.value); setRepoOpen(true); }}
                    onFocus={() => setRepoOpen(true)}
                    onBlur={() => setTimeout(() => setRepoOpen(false), 150)}
                    placeholder="org/repo-name"
                    className="w-full text-sm border border-gray-200 rounded-xl pl-9 pr-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono bg-gray-50/50"
                  />
                </div>
                {repoOpen && (
                  <div className="absolute top-full left-0 right-0 mt-1 bg-white border border-gray-200 rounded-xl shadow-xl z-10 overflow-hidden">
                    {DEMO_REPOS.filter(r => r.toLowerCase().includes(repo.toLowerCase()) || repo === "")
                      .map(r => (
                        <button
                          key={r}
                          onMouseDown={() => { setRepo(r); setRepoOpen(false); }}
                          className="w-full text-left px-4 py-2.5 text-sm font-mono text-gray-700 hover:bg-indigo-50 hover:text-indigo-700 transition-colors flex items-center gap-2"
                        >
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-gray-400">
                            <path d="M3 3h18v18H3z"/><path d="M9 3v18"/>
                          </svg>
                          {r}
                        </button>
                      ))}
                  </div>
                )}
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-gray-600 mb-1.5">PR Number</label>
                  <input
                    type="number" value={prNumber} onChange={e => setPrNumber(e.target.value)} min={1} placeholder="42"
                    className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-gray-50/50"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-gray-600 mb-1.5">Branch</label>
                  <input
                    type="text" value={branch} onChange={e => setBranch(e.target.value)} placeholder="main"
                    className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono bg-gray-50/50"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-gray-600 mb-1.5">
                    Commit SHA
                    <span className="ml-1 text-gray-400 font-normal text-[10px]">(auto)</span>
                  </label>
                  <input
                    type="text" value={commitSha} onChange={e => setCommitSha(e.target.value)} placeholder="abc1234"
                    className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono bg-gray-50/50"
                  />
                </div>
              </div>
            </div>

            {/* Scan scope */}
            <div className="px-6 py-5 border-b border-gray-50 space-y-3">
              <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Scan Scope</p>
              <div className="grid grid-cols-2 gap-2">
                {SCAN_SCOPES.map(s => {
                  const on = scopes.has(s.id);
                  return (
                    <button
                      key={s.id}
                      onClick={() => toggleScope(s.id)}
                      className={`flex items-start gap-2.5 px-3.5 py-3 rounded-xl border text-left transition-all ${
                        on
                          ? "bg-indigo-50 border-indigo-300 ring-1 ring-indigo-200"
                          : "bg-gray-50 border-gray-200 hover:border-gray-300"
                      }`}
                    >
                      <span className="text-lg leading-none mt-0.5">{s.icon}</span>
                      <div className="min-w-0">
                        <p className={`text-xs font-bold leading-tight ${on ? "text-indigo-700" : "text-gray-700"}`}>{s.label}</p>
                        <p className="text-[10px] text-gray-400 mt-0.5 leading-tight">{s.desc}</p>
                      </div>
                      <div className={`ml-auto mt-0.5 w-4 h-4 rounded-full border-2 flex items-center justify-center shrink-0 transition-all ${on ? "bg-indigo-500 border-indigo-500" : "border-gray-300"}`}>
                        {on && (
                          <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="20 6 9 17 4 12"/>
                          </svg>
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

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
                    <button
                      key={name}
                      onClick={() => loadExample(name)}
                      className="flex items-start gap-2.5 px-3 py-3 rounded-xl border border-gray-200 text-left hover:border-indigo-200 hover:bg-indigo-50/50 transition-all group"
                    >
                      <span className="text-lg leading-none">{ex.icon}</span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <p className="text-xs font-bold text-gray-800 group-hover:text-indigo-700 transition-colors">{name}</p>
                          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-full"
                            style={{ background: rc.bg, color: rc.text, border: `1px solid ${rc.border}` }}>
                            {ex.risk}
                          </span>
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
                  {validFiles.length > 0 && (
                    <span className="ml-2 normal-case font-bold text-indigo-500">
                      {validFiles.length}/{files.length} ready
                    </span>
                  )}
                </p>
                <button
                  onClick={addFile}
                  className="flex items-center gap-1 text-xs font-bold text-indigo-600 hover:text-indigo-700 px-2.5 py-1 rounded-lg hover:bg-indigo-50 transition-colors"
                >
                  <PlusIcon /> Add file
                </button>
              </div>

              {/* Tab bar */}
              {files.length > 1 && (
                <div className="flex gap-1 overflow-x-auto pb-1 -mx-1 px-1">
                  {files.map((f, i) => (
                    <button
                      key={f.id}
                      onClick={() => setActiveFile(i)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono whitespace-nowrap shrink-0 transition-all ${
                        i === activeFile
                          ? "bg-indigo-600 text-white shadow-sm"
                          : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                      }`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${f.content.trim() ? (i === activeFile ? "bg-white" : "bg-green-500") : "bg-gray-300"}`} />
                      {f.path.split("/").pop() || `file ${i + 1}`}
                    </button>
                  ))}
                </div>
              )}

              {/* Active file editor */}
              {activeEntry && (
                <div className="border border-gray-200 rounded-xl overflow-hidden shadow-sm">
                  {/* Path bar */}
                  <div className="flex items-center gap-2 px-3 py-2.5 bg-gray-900 border-b border-gray-700">
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#6b7280" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
                    </svg>
                    <input
                      type="text"
                      value={activeEntry.path}
                      onChange={e => updateFile(activeFile, "path", e.target.value)}
                      placeholder="src/example.ts, pkg/handler.go, src/main.rs…"
                      className="flex-1 text-xs font-mono bg-transparent border-0 outline-none text-gray-300 placeholder-gray-600"
                    />
                    <div className="flex items-center gap-2 shrink-0">
                      {activeEntry.path && (
                        <span className="text-[9px] font-bold bg-gray-700 text-gray-400 px-1.5 py-0.5 rounded">
                          {lang(activeEntry.path)}
                        </span>
                      )}
                      {files.length > 1 && (
                        <button onClick={() => removeFile(activeFile)} className="text-gray-600 hover:text-rose-400 transition-colors">
                          <TrashIcon />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Code editor */}
                  <div className="relative bg-gray-950">
                    {/* Line numbers */}
                    <div className="absolute left-0 top-0 bottom-0 w-10 bg-gray-900 border-r border-gray-800 pointer-events-none flex flex-col pt-3">
                      {(activeEntry.content || "\n").split("\n").slice(0, 20).map((_, i) => (
                        <span key={i} className="text-[10px] text-gray-600 text-right pr-2 leading-5 font-mono">{i + 1}</span>
                      ))}
                    </div>
                    <textarea
                      value={activeEntry.content}
                      onChange={e => updateFile(activeFile, "content", e.target.value)}
                      placeholder={"Paste your code here...\n// TrustLedger scans any language for AI patterns & vulnerabilities"}
                      rows={12}
                      spellCheck={false}
                      className="w-full pl-12 pr-4 py-3 text-xs font-mono text-gray-200 bg-transparent resize-y focus:outline-none leading-5 placeholder-gray-700"
                      style={{ caretColor: "#818cf8" }}
                    />
                  </div>

                  {/* Status bar */}
                  <div className="px-3 py-2 bg-gray-900 border-t border-gray-800 flex items-center justify-between">
                    {activeEntry.content ? (
                      <>
                        <div className="flex items-center gap-3">
                          <span className="text-[10px] text-gray-500 font-mono">
                            {activeEntry.content.split("\n").length} lines
                          </span>
                          <span className="text-[10px] text-gray-500 font-mono">
                            {activeEntry.content.length} chars
                          </span>
                        </div>
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          activeEntry.content.trim() ? "text-emerald-400 bg-emerald-900/40" : "text-gray-600"
                        }`}>
                          {activeEntry.content.trim() ? "● Ready to scan" : "Empty"}
                        </span>
                      </>
                    ) : (
                      <span className="text-[10px] text-gray-600">Paste code to begin</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Footer ──────────────────────────────────────────────────────────── */}
        {step === "config" && (
          <div className="shrink-0 px-6 py-4 border-t border-gray-100 bg-gray-50/60 space-y-3">
            {error && (
              <div className="flex items-center gap-2 px-3 py-2.5 bg-rose-50 border border-rose-200 rounded-xl">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#be123c" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <p className="text-xs text-rose-600 font-medium">{error}</p>
              </div>
            )}
            <div className="flex items-center justify-between gap-3">
              <div>
                {validFiles.length === 0 ? (
                  <p className="text-xs text-gray-400">Paste code into a file to begin</p>
                ) : (
                  <p className="text-xs text-gray-500">
                    <span className="font-bold text-gray-700">{validFiles.length} file{validFiles.length !== 1 ? "s" : ""}</span>
                    {" · "}
                    {Array.from(scopes).map(s => SCAN_SCOPES.find(x => x.id === s)?.label).filter(Boolean).join(", ")}
                  </p>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button onClick={onClose} className="px-4 py-2 text-sm font-semibold text-gray-500 rounded-xl hover:bg-gray-100 transition-colors">
                  Cancel
                </button>
                <button
                  onClick={handleSubmit}
                  disabled={validFiles.length === 0 || scopes.size === 0}
                  className="flex items-center gap-2 px-5 py-2 text-sm font-bold bg-gradient-to-r from-indigo-600 to-violet-600 text-white rounded-xl hover:from-indigo-700 hover:to-violet-700 disabled:opacity-40 transition-all active:scale-[0.98] shadow-md shadow-indigo-200"
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/>
                    <path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>
                    <rect x="7" y="7" width="10" height="10" rx="1"/>
                  </svg>
                  Scan {validFiles.length > 0 ? `${validFiles.length} file${validFiles.length !== 1 ? "s" : ""}` : "PR"}
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
