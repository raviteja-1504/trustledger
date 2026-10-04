"use client";

/**
 * Settings → Repositories: connect the GitHub App, import the repositories it can see, and switch individual
 * repositories on or off. Only connected (switched-on) repositories are scanned, listed in Scan History and
 * the dashboard, and offered in New Scan. Switching off keeps a repo's history; nothing is deleted.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { authedFetch } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";

interface Repo { id: string; repo_full_name: string; default_branch: string | null; is_active: boolean; created_at: string }
interface GitHubStatus { installed: boolean; accounts: string[]; install_url: string | null }

function GitHubMark() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
    </svg>
  );
}

function Card({ title, subtitle, action, children }: { title: string; subtitle?: React.ReactNode; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="section-card animate-fade-up overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-50 flex items-start justify-between gap-4">
        <div className="min-w-0">
          <h2 className="text-sm font-bold text-gray-900">{title}</h2>
          {subtitle && <p className="text-xs text-gray-400 mt-0.5">{subtitle}</p>}
        </div>
        {action}
      </div>
      <div className="px-6 py-5 space-y-4">{children}</div>
    </section>
  );
}

export default function RepositoriesTab() {
  const { profile } = useAuth();
  const isAdmin = profile?.role === "admin";
  const [repos,   setRepos]   = useState<Repo[] | null>(null);
  const [github,  setGithub]  = useState<GitHubStatus | null>(null);
  const [loadErr, setLoadErr] = useState<string | null>(null);
  const [busy,    setBusy]    = useState<string | null>(null);   // "import" | repo id
  const [notice,  setNotice]  = useState<{ kind: "ok" | "error"; text: string } | null>(null);
  const [filter,  setFilter]  = useState("");

  const load = useCallback(async () => {
    setLoadErr(null);
    const [r, g] = await Promise.allSettled([
      authedFetch<{ repos: Repo[] }>("/api/repos"),
      authedFetch<GitHubStatus>("/api/repos/github"),
    ]);
    if (r.status === "fulfilled") setRepos(r.value.repos); else { setRepos([]); setLoadErr(r.reason instanceof Error ? r.reason.message : "Couldn't load repositories."); }
    setGithub(g.status === "fulfilled" ? g.value : { installed: false, accounts: [], install_url: null });
  }, []);
  useEffect(() => { load(); }, [load]);

  async function importFromGitHub() {
    setBusy("import"); setNotice(null);
    try {
      const res = await authedFetch<{ added: number; already_connected: number; total: number }>("/api/repos?import=github", { method: "POST" });
      setNotice({ kind: "ok", text: res.added > 0
        ? `Added ${res.added} repositor${res.added === 1 ? "y" : "ies"} from GitHub.${res.already_connected ? ` ${res.already_connected} were already here.` : ""}`
        : `No new repositories — all ${res.total} the GitHub App can see are already here.` });
      await load();
    } catch (e) {
      setNotice({ kind: "error", text: e instanceof Error ? e.message : "Import failed." });
    } finally { setBusy(null); }
  }

  async function toggle(repo: Repo) {
    setBusy(repo.id); setNotice(null);
    const next = !repo.is_active;
    setRepos(rs => rs?.map(r => r.id === repo.id ? { ...r, is_active: next } : r) ?? rs);
    try {
      await authedFetch("/api/repos", { method: "PATCH", body: JSON.stringify({ id: repo.id, is_active: next }) });
    } catch (e) {
      setRepos(rs => rs?.map(r => r.id === repo.id ? { ...r, is_active: !next } : r) ?? rs);
      setNotice({ kind: "error", text: e instanceof Error ? e.message : "Couldn't update that repository." });
    } finally { setBusy(null); }
  }

  const shown = useMemo(() => (repos ?? []).filter(r => r.repo_full_name.toLowerCase().includes(filter.trim().toLowerCase())), [repos, filter]);
  const activeCount = (repos ?? []).filter(r => r.is_active).length;

  return (
    <div className="space-y-5">
      {/* ── GitHub App ───────────────────────────────────────────────────── */}
      <Card title="GitHub App"
        subtitle="TrustLedger reads pull requests through its GitHub App. Install it on the GitHub accounts or organisations whose repositories you want scanned.">
        {github === null ? (
          <p className="text-xs text-gray-400">Checking…</p>
        ) : (
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-3 min-w-0">
              <span className={`w-9 h-9 rounded-xl flex items-center justify-center ${github.installed ? "bg-emerald-50 text-emerald-700" : "bg-gray-100 text-gray-500"}`}><GitHubMark /></span>
              <div className="min-w-0">
                <p className="text-sm font-semibold text-gray-900">{github.installed ? "Installed" : "Not installed"}</p>
                <p className="text-xs text-gray-500 truncate">
                  {github.installed
                    ? (github.accounts.length ? `On ${github.accounts.map(a => `@${a}`).join(", ")}` : "Connected to this organisation")
                    : "Install it, then come back here and import your repositories."}
                </p>
              </div>
            </div>
            {github.install_url && (
              <a href={github.install_url} target="_blank" rel="noopener noreferrer"
                className="shrink-0 inline-flex items-center gap-2 px-4 py-2 text-sm font-bold rounded-xl border border-gray-200 text-gray-800 hover:bg-gray-50">
                <GitHubMark /> {github.installed ? "Add another account or more repos" : "Install on GitHub"}
              </a>
            )}
          </div>
        )}
        {github && !github.install_url && (
          <p className="text-xs text-gray-400">Install the App from GitHub → Settings → Developer settings → GitHub Apps → TrustLedger → Install App.</p>
        )}
      </Card>

      {/* ── Repositories ─────────────────────────────────────────────────── */}
      <Card title="Repositories"
        subtitle={<>Switched-on repositories are scanned, appear in Scan History and the dashboard, and can be picked in New Scan. Switching one off keeps its history.</>}
        action={isAdmin ? (
          <button onClick={importFromGitHub} disabled={busy === "import" || github?.installed === false}
            title={github?.installed === false ? "Install the GitHub App first" : undefined}
            className="shrink-0 px-4 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50">
            {busy === "import" ? "Importing…" : "Import from GitHub"}
          </button>
        ) : undefined}>
        {notice && (
          <div role={notice.kind === "error" ? "alert" : "status"}
            className={`px-3.5 py-2.5 rounded-xl text-xs border ${notice.kind === "ok" ? "bg-emerald-50 border-emerald-200 text-emerald-800" : "bg-rose-50 border-rose-200 text-rose-700"}`}>
            {notice.text}
          </div>
        )}
        {loadErr && <p role="alert" className="text-xs text-rose-600">{loadErr}</p>}
        {!isAdmin && <p className="text-xs text-gray-400">Only admins can import or switch repositories.</p>}

        {repos === null ? (
          <p className="text-xs text-gray-400">Loading…</p>
        ) : repos.length === 0 ? (
          <div className="text-center py-8 space-y-1">
            <p className="text-sm font-semibold text-gray-700">No repositories yet</p>
            <p className="text-xs text-gray-400">{github?.installed ? "Click Import from GitHub to add the repositories the App can see." : "Install the GitHub App above, then import your repositories."}</p>
          </div>
        ) : (
          <>
            <div className="flex items-center justify-between gap-3">
              <p className="text-xs text-gray-500"><span className="font-bold text-gray-800">{activeCount}</span> of {repos.length} switched on</p>
              {repos.length > 6 && (
                <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter…" aria-label="Filter repositories"
                  className="text-xs border border-gray-200 rounded-lg px-3 py-1.5 w-44 focus:outline-none focus:ring-2 focus:ring-indigo-300" />
              )}
            </div>
            <ul className="divide-y divide-gray-100 border border-gray-100 rounded-xl overflow-hidden">
              {shown.map(r => (
                <li key={r.id} className={`flex items-center gap-3 px-4 py-3 ${r.is_active ? "" : "bg-gray-50/70"}`}>
                  <div className="min-w-0 flex-1">
                    <p className={`text-sm font-mono truncate ${r.is_active ? "text-gray-900 font-semibold" : "text-gray-400"}`}>{r.repo_full_name}</p>
                    <p className="text-[11px] text-gray-400">{r.is_active ? "On" : "Off"} · default branch {r.default_branch ?? "main"}</p>
                  </div>
                  <button role="switch" aria-checked={r.is_active} aria-label={`${r.repo_full_name} ${r.is_active ? "on" : "off"}`}
                    disabled={!isAdmin || busy === r.id} onClick={() => toggle(r)}
                    className={`relative w-10 h-6 rounded-full transition-colors shrink-0 disabled:opacity-50 ${r.is_active ? "bg-indigo-600" : "bg-gray-300"}`}>
                    <span className={`absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-all ${r.is_active ? "left-[18px]" : "left-0.5"}`} />
                  </button>
                </li>
              ))}
              {shown.length === 0 && <li className="px-4 py-4 text-xs text-gray-400">No repositories match “{filter}”.</li>}
            </ul>
          </>
        )}
      </Card>
    </div>
  );
}
