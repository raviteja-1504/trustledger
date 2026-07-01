"use client";

import { useEffect, useState } from "react";
import AuthGuard from "@/components/AuthGuard";
import { formatDateTime, formatDateOnly, relativeTime, useTimezone, getSavedTimezone } from "@/lib/timezone";
import { authedFetch } from "@/lib/useRealData";
import { useRole } from "@/lib/roles";
import { useAuth } from "@/lib/auth";
import { ROLE_LABELS, ROLE_COLORS, ROLE_DESCRIPTIONS, type UserRole } from "@/lib/roles";

interface Member {
  id:           string;
  user_id:      string | null;
  email:        string;
  name:         string | null;
  role:         UserRole;
  github_login: string | null;
  avatar_url:   string | null;
  created_at:   string;
}

function initials(m: Member) {
  if (m.name) return m.name.split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase();
  return m.email.slice(0, 2).toUpperCase();
}

function relDate(iso: string) {
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  if (d === 0) return "Today";
  if (d === 1) return "Yesterday";
  if (d < 30) return `${d}d ago`;
  return formatDateOnly(new Date(iso), getSavedTimezone());
}

const ROLE_ORDER: UserRole[] = ["admin", "security_reviewer", "developer"];

export default function TeamPage() {
    const tz = useTimezone();
  const { permissions } = useRole();
  const { profile } = useAuth();
  const isAdmin = permissions.canManageUsers;

  const [members,    setMembers]    = useState<Member[]>([]);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState<string | null>(null);

  // Invite form
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole,  setInviteRole]  = useState<UserRole>("developer");
  const [inviteName,  setInviteName]  = useState("");
  const [inviting,    setInviting]    = useState(false);
  const [inviteMsg,   setInviteMsg]   = useState<{ ok: boolean; text: string } | null>(null);

  // Per-member action state
  const [changingRole, setChangingRole] = useState<string | null>(null);
  const [removing,     setRemoving]     = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const data = await authedFetch<{ members: Member[] }>("/api/team");
      setMembers(data.members ?? []);
    } catch {
      setError("Failed to load team members.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function invite(e: React.FormEvent) {
    e.preventDefault();
    if (!inviteEmail.trim()) return;
    setInviting(true);
    setInviteMsg(null);
    try {
      await authedFetch("/api/team", {
        method: "POST",
        body: JSON.stringify({ email: inviteEmail.trim(), role: inviteRole, name: inviteName.trim() || undefined }),
      });
      setInviteMsg({ ok: true, text: `${inviteEmail} has been added as ${ROLE_LABELS[inviteRole]}.` });
      setInviteEmail(""); setInviteName(""); setInviteRole("developer");
      await load();
    } catch (err: unknown) {
      const raw = (err instanceof Error ? err.message : String(err)) ?? "Invite failed.";
      const text = raw === "already_member" ? `${inviteEmail} is already a member.`
        : raw.startsWith("invite_failed") ? `Insert error: ${raw}`
        : raw;
      setInviteMsg({ ok: false, text });
    } finally {
      setInviting(false);
    }
  }

  async function changeRole(userId: string, newRole: UserRole) {
    setChangingRole(userId);
    try {
      await authedFetch("/api/team", {
        method: "PATCH",
        body: JSON.stringify({ user_id: userId, role: newRole }),
      });
      setMembers(prev => prev.map(m => m.user_id === userId ? { ...m, role: newRole } : m));
    } catch { /* ignore */ }
    finally { setChangingRole(null); }
  }

  async function removeMember(m: Member) {
    if (!confirm(`Remove ${m.email} from the organisation?`)) return;
    const key = m.user_id ?? m.id;
    setRemoving(key);
    try {
      const qs = m.user_id ? `user_id=${m.user_id}` : `member_id=${m.id}`;
      await authedFetch(`/api/team?${qs}`, { method: "DELETE" });
      setMembers(prev => prev.filter(x => x.id !== m.id));
    } catch { /* ignore */ }
    finally { setRemoving(null); }
  }

  const byRole = ROLE_ORDER.map(role => ({
    role,
    members: members.filter(m => m.role === role),
  })).filter(g => g.members.length > 0);

  return (
    <AuthGuard>
      <div className="max-w-4xl mx-auto space-y-6 pb-12">

        {/* Header */}
        <div className="animate-fade-up">
          <h1 className="text-xl font-extrabold text-gray-900 tracking-tight">Team Management</h1>
          <p className="text-sm text-gray-500 mt-1">
            {members.length} member{members.length !== 1 ? "s" : ""} in{" "}
            <span className="font-semibold text-gray-700">{profile?.org_name || profile?.org_slug || "your organisation"}</span>
          </p>
        </div>

        {/* Invite form — admins only */}
        {isAdmin && (
          <form onSubmit={invite} className="animate-fade-up section-card p-5 space-y-4">
            <div>
              <p className="font-bold text-gray-900 text-sm">Invite a new member</p>
              <p className="text-xs text-gray-400 mt-0.5">They will be added immediately. Email notification coming soon.</p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <input
                type="email"
                placeholder="email@company.com"
                value={inviteEmail}
                onChange={e => setInviteEmail(e.target.value)}
                required
                className="col-span-1 sm:col-span-1 border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300"
              />
              <input
                type="text"
                placeholder="Full name (optional)"
                value={inviteName}
                onChange={e => setInviteName(e.target.value)}
                className="border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300"
              />
              <select
                value={inviteRole}
                onChange={e => setInviteRole(e.target.value as UserRole)}
                className="border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300"
              >
                {ROLE_ORDER.map(r => (
                  <option key={r} value={r}>{ROLE_LABELS[r]}</option>
                ))}
              </select>
            </div>
            {inviteRole && (
              <p className="text-xs text-gray-400">{ROLE_DESCRIPTIONS[inviteRole]}</p>
            )}
            <div className="flex items-center gap-3">
              <button
                type="submit"
                disabled={inviting || !inviteEmail.trim()}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition-colors"
              >
                {inviting ? "Adding…" : "Add member"}
              </button>
              {inviteMsg && (
                <p className={`text-xs font-medium ${inviteMsg.ok ? "text-emerald-600" : "text-rose-600"}`}>
                  {inviteMsg.text}
                </p>
              )}
            </div>
          </form>
        )}

        {/* Member list grouped by role */}
        {loading ? (
          <div className="section-card p-5 space-y-3">
            {[0,1,2].map(i => <div key={i} className="h-14 bg-gray-100 rounded-lg animate-pulse" />)}
          </div>
        ) : error ? (
          <div className="section-card p-5 text-sm text-rose-600">{error}</div>
        ) : (
          <div className="space-y-4">
            {byRole.map(({ role, members: group }) => {
              const colors = ROLE_COLORS[role];
              return (
                <div key={role} className="animate-fade-up section-card overflow-hidden">
                  {/* Group header */}
                  <div className="flex items-center gap-3 px-5 py-3 border-b border-gray-100 bg-gray-50/60">
                    <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${colors.bg} ${colors.text}`}>
                      {ROLE_LABELS[role]}
                    </span>
                    <span className="text-xs text-gray-400">{group.length} member{group.length !== 1 ? "s" : ""}</span>
                    <p className="ml-auto text-[11px] text-gray-400 hidden sm:block">{ROLE_DESCRIPTIONS[role]}</p>
                  </div>

                  {/* Members */}
                  <div className="divide-y divide-gray-50">
                    {group.map(m => {
                      const isSelf = m.user_id === profile?.org_id;  // compare to logged-in user
                      const isCurrentUser = m.email === profile?.email;
                      return (
                        <div key={m.id} className="flex items-center gap-4 px-5 py-3.5 hover:bg-gray-50/60 transition-colors">
                          {/* Avatar */}
                          <div className={`w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${colors.bg} ${colors.text}`}>
                            {m.avatar_url
                              ? <img src={m.avatar_url} alt="" className="w-9 h-9 rounded-full object-cover" />
                              : initials(m)
                            }
                          </div>

                          {/* Identity */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-semibold text-gray-900 truncate">
                                {m.name || m.email.split("@")[0]}
                              </p>
                              {isCurrentUser && (
                                <span className="text-[9px] font-bold text-indigo-600 bg-indigo-50 border border-indigo-200 px-1.5 py-0.5 rounded-full">YOU</span>
                              )}
                              {!m.user_id && (
                                <span className="text-[9px] font-bold text-amber-600 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded-full">PENDING</span>
                              )}
                            </div>
                            <p className="text-xs text-gray-400 truncate">
                              {m.email}
                              {m.github_login && <span className="ml-1.5 text-gray-300">· @{m.github_login}</span>}
                            </p>
                          </div>

                          {/* Joined */}
                          <p className="text-xs text-gray-400 shrink-0 hidden sm:block">{relDate(m.created_at)}</p>

                          {/* Role changer — admin only, not self */}
                          {isAdmin && !isCurrentUser && m.user_id && (
                            <select
                              value={m.role}
                              disabled={changingRole === m.user_id}
                              onChange={e => changeRole(m.user_id!, e.target.value as UserRole)}
                              className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-300 disabled:opacity-50 shrink-0"
                            >
                              {ROLE_ORDER.map(r => (
                                <option key={r} value={r}>{ROLE_LABELS[r]}</option>
                              ))}
                            </select>
                          )}

                          {/* Remove button — admin only, not self; works for pending (no user_id) too */}
                          {isAdmin && !isCurrentUser && (
                            <button
                              onClick={() => removeMember(m)}
                              disabled={removing === (m.user_id ?? m.id)}
                              className="shrink-0 text-xs font-semibold text-rose-500 hover:text-rose-700 disabled:opacity-40 transition-colors px-2 py-1 rounded-lg hover:bg-rose-50"
                            >
                              {removing === (m.user_id ?? m.id) ? "…" : "Remove"}
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Role reference */}
        <div className="animate-fade-up section-card p-5">
          <p className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3">Role permissions</p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {ROLE_ORDER.map(r => {
              const colors = ROLE_COLORS[r];
              const rows = [
                ["Attest files",       r !== "developer"],
                ["View all reports",   true],
                ["Export data",        r !== "developer"],
                ["Manage settings",    r === "admin"],
                ["Manage team",        r === "admin"],
                ["Billing & API keys", r === "admin"],
              ];
              return (
                <div key={r} className={`rounded-xl p-4 border ${colors.bg} border-opacity-50`} style={{ borderColor: "rgba(0,0,0,0.06)" }}>
                  <p className={`text-xs font-bold mb-2 ${colors.text}`}>{ROLE_LABELS[r]}</p>
                  <ul className="space-y-1">
                    {rows.map(([label, allowed]) => (
                      <li key={label as string} className="flex items-center gap-1.5 text-[11px] text-gray-600">
                        <span className={allowed ? "text-emerald-500" : "text-gray-300"}>
                          {allowed ? "✓" : "✗"}
                        </span>
                        {label as string}
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        </div>

      </div>
    </AuthGuard>
  );
}
