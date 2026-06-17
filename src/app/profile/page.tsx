"use client";

import { useState, useEffect } from "react";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { supabase } from "@/lib/supabase";
import { useToastHelpers } from "@/lib/toast";

interface Profile {
  display_name: string;
  bio:          string;
  avatar_url:   string;
  github_login: string;
  timezone:     string;
  theme:        string;
  notification_digest_day: string;
}

interface TwoFAStatus {
  enabled:       boolean;
  setup_pending: boolean;
}

const TIMEZONES = [
  "UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
  "America/Toronto", "Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Amsterdam",
  "Asia/Dubai", "Asia/Kolkata", "Asia/Singapore", "Asia/Tokyo", "Australia/Sydney",
];

function ClaimAdminCard() {
  const { profile } = useAuth();
  const [adminCount, setAdminCount] = useState<number | null>(null);
  const [claiming,   setClaiming]   = useState(false);
  const [done,       setDone]       = useState(false);

  useEffect(() => {
    if (!profile?.org_id) return;
    authedFetch<{ members: { role: string }[] }>("/api/team")
      .then(d => setAdminCount((d.members ?? []).filter(m => m.role === "admin").length))
      .catch(() => {});
  }, [profile?.org_id]);

  // Only show when there are no admins in the org
  if (adminCount === null || adminCount > 0) return null;

  if (done) {
    return (
      <div className="bg-emerald-50 border border-emerald-200 rounded-2xl p-5">
        <p className="text-sm font-bold text-emerald-800">✓ You are now the admin.</p>
        <p className="text-xs text-emerald-600 mt-1">Reload the page to see full access.</p>
        <button onClick={() => window.location.reload()}
          className="mt-3 px-4 py-2 text-xs font-bold rounded-xl bg-emerald-600 text-white hover:bg-emerald-700">
          Reload now
        </button>
      </div>
    );
  }

  return (
    <div className="bg-amber-50 border border-amber-200 rounded-2xl p-5">
      <p className="text-sm font-black text-amber-800 mb-1">⚠️ No admin in this organisation</p>
      <p className="text-xs text-amber-700 mb-4">
        Your organisation has no admin. Claim admin rights to access Settings, team management, and full org data.
      </p>
      <button
        onClick={async () => {
          setClaiming(true);
          try {
            await authedFetch("/api/claim-admin", { method: "POST" });
            setDone(true);
          } catch {
            alert("Could not claim admin. The org may already have an admin.");
          } finally {
            setClaiming(false);
          }
        }}
        disabled={claiming}
        className="px-4 py-2 text-sm font-bold rounded-xl bg-amber-600 text-white hover:bg-amber-700 disabled:opacity-50"
      >
        {claiming ? "Claiming…" : "Claim admin rights"}
      </button>
    </div>
  );
}

export default function ProfilePage() {
  const { profile: authProfile, user } = useAuth();
  const { success: toastSuccess, error: toastError } = useToastHelpers();
  const [prof,         setProf]        = useState<Profile>({ display_name:"", bio:"", avatar_url:"", github_login:"", timezone:"UTC", theme:"system", notification_digest_day:"monday" });
  const [twoFA,        setTwoFA]       = useState<TwoFAStatus>({ enabled:false, setup_pending:false });
  const [otpData,      setOtpData]     = useState<{ secret:string; otp_uri:string } | null>(null);
  const [backups,      setBackups]     = useState<string[] | null>(null);
  const [totpCode,     setTotpCode]    = useState("");
  const [saved,        setSaved]       = useState(false);
  const [loading,      setLoading]     = useState(true);
  const [tab,          setTab]         = useState<"profile"|"security"|"notifications">("profile");
  const [disableCode,  setDisableCode] = useState("");
  const [disabling,    setDisabling]   = useState(false);

  useEffect(() => {
    if (!user) { setLoading(false); return; }
    async function load() {
      // Load profile
      const { data: p } = await supabase.from("user_profiles").select("*").eq("user_id", user!.id).maybeSingle() as { data: Profile | null };
      if (p) setProf(p);
      else if (authProfile) {
        setProf(prev => ({
          ...prev,
          display_name: authProfile.name ?? "",
          avatar_url:   authProfile.avatar_url ?? "",
          github_login: authProfile.github_login ?? "",
        }));
      }
      // Load 2FA status
      if (!isSeedMode() || authProfile?.org_id) {
        try {
          const r = await authedFetch<TwoFAStatus>("/api/auth/2fa");
          setTwoFA(r);
        } catch {}
      }
      setLoading(false);
    }
    load();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.id]);

  async function saveProfile() {
    if (!user) return;
    await supabase.from("user_profiles").upsert({ user_id: user.id, ...prof, updated_at: new Date().toISOString() });
    setSaved(true); setTimeout(() => setSaved(false), 2500);
  }

  async function setup2FA() {
    const r = await authedFetch<{ secret:string; otp_uri:string; }>("/api/auth/2fa?action=setup", { method:"POST" });
    setOtpData(r);
  }

  async function verify2FA() {
    if (!totpCode) return;
    try {
      const r = await authedFetch<{ ok:boolean; backup_codes?:string[] }>("/api/auth/2fa?action=verify", {
        method:"POST", body: JSON.stringify({ code: totpCode }),
      });
      if (r.ok) { setTwoFA({ enabled:true, setup_pending:false }); setOtpData(null); setBackups(r.backup_codes ?? null); setTotpCode(""); }
    } catch (e) { toastError("Invalid code", e instanceof Error ? e.message : undefined); }
  }

  async function disable2FA() {
    if (!disableCode.trim()) return;
    setDisabling(true);
    try {
      await authedFetch("/api/auth/2fa?action=disable", { method:"POST", body: JSON.stringify({ code: disableCode }) });
      setTwoFA({ enabled:false, setup_pending:false });
      setDisableCode("");
      toastSuccess("2FA disabled", "Two-factor authentication has been turned off.");
    } catch (e) {
      toastError("Failed to disable 2FA", e instanceof Error ? e.message : undefined);
    } finally { setDisabling(false); }
  }

  if (loading) return <AuthGuard><PageSkeleton><div /></PageSkeleton></AuthGuard>;

  return (
    <AuthGuard>
      <div className="max-w-2xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="flex items-center gap-4 pt-1">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center text-2xl font-black text-white shrink-0"
            style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
            {(prof.display_name || authProfile?.email || "?").slice(0,1).toUpperCase()}
          </div>
          <div>
            <h1 className="text-xl font-black text-gray-900">{prof.display_name || authProfile?.name || authProfile?.email}</h1>
            <p className="text-sm text-gray-400">{authProfile?.email}{authProfile?.role && authProfile.role !== "undefined" ? ` · ${authProfile.role}` : ""}</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-1 bg-gray-100 p-0.5 rounded-xl w-fit">
          {(["profile","security","notifications"] as const).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm font-semibold rounded-lg capitalize transition-all ${tab===t?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
              {t}
            </button>
          ))}
        </div>

        {/* ── Profile tab ── */}
        {tab === "profile" && (
          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm space-y-5">
            <h3 className="text-sm font-black text-gray-900">Personal Information</h3>
            <div className="grid grid-cols-2 gap-4">
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Display name</span>
                <input value={prof.display_name} onChange={e => setProf(p => ({...p,display_name:e.target.value}))}
                  placeholder="Your full name" className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">GitHub username</span>
                <input value={prof.github_login} onChange={e => setProf(p => ({...p,github_login:e.target.value}))}
                  placeholder="your-github-handle" className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </label>
              <label className="block col-span-2">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Bio</span>
                <textarea value={prof.bio} onChange={e => setProf(p => ({...p,bio:e.target.value}))} rows={3}
                  placeholder="Brief bio or role description" className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 resize-none" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Timezone</span>
                <select value={prof.timezone} onChange={e => setProf(p => ({...p,timezone:e.target.value}))}
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white">
                  {TIMEZONES.map(tz => <option key={tz} value={tz}>{tz}</option>)}
                </select>
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Theme preference</span>
                <select value={prof.theme} onChange={e => setProf(p => ({...p,theme:e.target.value}))}
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white">
                  {["system","light","dark"].map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase()+t.slice(1)}</option>)}
                </select>
              </label>
            </div>
            <button onClick={saveProfile}
              className={`px-5 py-2 text-sm font-bold rounded-xl transition-all ${saved?"bg-emerald-500 text-white":"bg-indigo-600 text-white hover:bg-indigo-700"}`}>
              {saved ? "✓ Saved" : "Save changes"}
            </button>
          </div>
        )}

        {/* ── Security tab ── */}
        {tab === "security" && (
          <div className="space-y-4">
            {/* 2FA */}
            <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm">
              <div className="flex items-start justify-between gap-4 mb-4">
                <div>
                  <h3 className="text-sm font-black text-gray-900">Two-Factor Authentication</h3>
                  <p className="text-xs text-gray-500 mt-0.5">Add an extra layer of security using a TOTP authenticator app.</p>
                </div>
                <span className={`text-[11px] font-bold px-2.5 py-1 rounded-full ${twoFA.enabled ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200" : "bg-gray-100 text-gray-500"}`}>
                  {twoFA.enabled ? "Enabled" : "Disabled"}
                </span>
              </div>

              {!twoFA.enabled && !otpData && (
                <button onClick={setup2FA} disabled={isSeedMode() && !authProfile?.org_id}
                  className="px-5 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 transition-colors disabled:opacity-60">
                  Set up 2FA
                </button>
              )}

              {otpData && !twoFA.enabled && (
                <div className="space-y-4">
                  <div className="bg-gray-50 rounded-xl p-4 border border-gray-100">
                    <p className="text-xs font-semibold text-gray-600 mb-2">1. Scan this with your authenticator app</p>
                    {/* QR code display — use a QR library in production */}
                    <div className="bg-white border border-gray-200 rounded-lg p-4 flex items-center gap-3">
                      <div className="w-24 h-24 bg-gray-100 rounded-lg flex items-center justify-center text-xs text-gray-400 shrink-0">
                        [QR Code]<br/>(install qrcode lib)
                      </div>
                      <div>
                        <p className="text-[10px] text-gray-500 mb-1">Or enter manually:</p>
                        <code className="text-xs font-mono bg-gray-50 px-2 py-1 rounded border border-gray-200 select-all break-all">
                          {otpData.secret}
                        </code>
                      </div>
                    </div>
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-gray-600 mb-2">2. Enter the 6-digit code to verify</p>
                    <div className="flex gap-2">
                      <input value={totpCode} onChange={e => setTotpCode(e.target.value.replace(/\D/g,"").slice(0,6))}
                        placeholder="000000" maxLength={6}
                        className="w-32 text-center text-lg font-mono tracking-widest border border-gray-200 rounded-xl px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
                      <button onClick={verify2FA} disabled={totpCode.length !== 6}
                        className="px-5 py-2.5 text-sm font-bold rounded-xl bg-emerald-600 text-white hover:bg-emerald-700 disabled:opacity-60 transition-colors">
                        Verify & Enable
                      </button>
                      <button onClick={() => setOtpData(null)} className="px-4 py-2 text-sm text-gray-400 hover:text-gray-600">Cancel</button>
                    </div>
                  </div>
                </div>
              )}

              {backups && (
                <div className="mt-4 bg-amber-50 border border-amber-200 rounded-xl p-4">
                  <p className="text-xs font-black text-amber-800 mb-2">⚠️ Save your backup codes — shown only once</p>
                  <div className="grid grid-cols-2 gap-1.5">
                    {backups.map(code => (
                      <code key={code} className="text-xs font-mono bg-white px-2 py-1.5 rounded border border-amber-100 text-gray-700 text-center">
                        {code}
                      </code>
                    ))}
                  </div>
                  <button onClick={() => setBackups(null)} className="text-xs text-amber-700 font-semibold mt-3 hover:text-amber-900">
                    I've saved my backup codes ✓
                  </button>
                </div>
              )}

              {twoFA.enabled && (
                <div className="space-y-3">
                  <p className="text-xs text-emerald-700 bg-emerald-50 px-3 py-2 rounded-xl border border-emerald-200">
                    ✓ 2FA is enabled. Your account is protected with TOTP authentication.
                  </p>
                  <div className="space-y-2">
                    <p className="text-xs font-semibold text-gray-600">Enter your TOTP code or a backup code to disable 2FA:</p>
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        inputMode="numeric"
                        maxLength={12}
                        value={disableCode}
                        onChange={e => setDisableCode(e.target.value.replace(/\s/g, ""))}
                        placeholder="000000"
                        className="w-32 text-sm font-mono border border-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-rose-400"
                      />
                      <button
                        onClick={disable2FA}
                        disabled={!disableCode.trim() || disabling}
                        className="text-xs font-semibold text-rose-600 hover:text-rose-800 disabled:opacity-50 border border-rose-200 px-3 py-2 rounded-xl hover:bg-rose-50 transition-colors"
                      >
                        {disabling ? "Disabling…" : "Disable 2FA"}
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Claim Admin — shown only when the org has no admin */}
            <ClaimAdminCard />

            {/* Sessions */}
            <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm">
              <h3 className="text-sm font-black text-gray-900 mb-3">Active Session</h3>
              <div className="flex items-center justify-between gap-3 p-3 bg-gray-50 rounded-xl border border-gray-100">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-emerald-500" />
                  <div>
                    <p className="text-xs font-semibold text-gray-800">Current browser session</p>
                    <p suppressHydrationWarning className="text-[10px] text-gray-400">{typeof window !== "undefined" ? navigator.userAgent.split(" ").slice(-1)[0] : "Unknown"}</p>
                  </div>
                </div>
                <button onClick={() => supabase.auth.signOut()} className="text-xs font-semibold text-rose-500 hover:text-rose-700">
                  Sign out
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ── Notifications tab ── */}
        {tab === "notifications" && (
          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm space-y-5">
            <h3 className="text-sm font-black text-gray-900">Notification Preferences</h3>
            <label className="block">
              <span className="text-xs font-semibold text-gray-600 block mb-1">Weekly digest day</span>
              <select value={prof.notification_digest_day} onChange={e => setProf(p => ({...p, notification_digest_day:e.target.value}))}
                className="text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white">
                {["monday","tuesday","wednesday","thursday","friday","saturday","sunday","never"].map(d => (
                  <option key={d} value={d}>{d.charAt(0).toUpperCase()+d.slice(1)}</option>
                ))}
              </select>
            </label>
            <p className="text-xs text-gray-400">
              For granular notification controls (per-severity, per-channel), see{" "}
              <a href="/settings#notifications" className="text-indigo-600 hover:underline">Settings → Notifications</a>.
            </p>
            <button onClick={saveProfile}
              className={`px-5 py-2 text-sm font-bold rounded-xl transition-all ${saved?"bg-emerald-500 text-white":"bg-indigo-600 text-white hover:bg-indigo-700"}`}>
              {saved ? "✓ Saved" : "Save preferences"}
            </button>
          </div>
        )}

      </div>
    </AuthGuard>
  );
}
