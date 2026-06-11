"use client";
/**
 * Setup Guide — shown to new orgs with no scans yet.
 * Provides a checklist of steps to get started.
 */

import { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth";

interface SetupStep {
  key:         string;
  title:       string;
  description: string;
  href?:       string;
  action?:     string;
  check:       () => boolean;
  icon:        string;
}

function useSetupProgress() {
  const [progress, setProgress] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const checks: Record<string, boolean> = {
      github_connected: !!localStorage.getItem("tl_notif_snapshot") || localStorage.getItem("tl_force_seed") === "1",
      first_scan:       !!localStorage.getItem("tl_notif_snapshot"),
      invited_team:     (() => { try { return JSON.parse(localStorage.getItem("tl_team_members") ?? "[]").length > 1; } catch { return false; } })(),
      policy_set:       !!localStorage.getItem("tl_org_policy"),
      api_key:          (() => { try { return JSON.parse(localStorage.getItem("tl_api_keys") ?? "[]").length > 0; } catch { return false; } })(),
    };
    setProgress(checks);
  }, []);

  return progress;
}

const SETUP_STEPS: SetupStep[] = [
  {
    key:         "github_connected",
    icon:        "🔗",
    title:       "Connect GitHub",
    description: "Install the TrustLedger GitHub App to scan pull requests automatically.",
    href:        "/onboarding",
    action:      "Connect GitHub →",
    check:       () => false,
  },
  {
    key:         "first_scan",
    icon:        "🔍",
    title:       "Run your first scan",
    description: "Scan a pull request to see AI risk scores and security findings.",
    href:        "/onboarding#scan",
    action:      "Run a scan →",
    check:       () => false,
  },
  {
    key:         "invited_team",
    icon:        "👥",
    title:       "Invite your security reviewers",
    description: "Add team members who will attest AI-generated code.",
    href:        "/settings#team",
    action:      "Invite team →",
    check:       () => false,
  },
  {
    key:         "policy_set",
    icon:        "⚙️",
    title:       "Configure your policy",
    description: "Set which risk levels block merges and your attestation SLA.",
    href:        "/settings",
    action:      "Set policy →",
    check:       () => false,
  },
  {
    key:         "api_key",
    icon:        "🔑",
    title:       "Create an API key",
    description: "Generate an API key for CI/CD pipeline integration.",
    href:        "/settings#api",
    action:      "Create key →",
    check:       () => false,
  },
];

interface SetupGuideProps {
  compact?: boolean;
}

export default function SetupGuide({ compact = false }: SetupGuideProps) {
  const progress = useSetupProgress();
  const [dismissed, setDismissed] = useState(false);
  const { profile } = useAuth();

  useEffect(() => {
    setDismissed(localStorage.getItem("tl_setup_guide_dismissed") === "1");
  }, []);

  if (dismissed) return null;

  const completedCount = Object.values(progress).filter(Boolean).length;
  const totalCount     = SETUP_STEPS.length;
  const allDone        = completedCount === totalCount;

  if (allDone) {
    // Auto-dismiss when all done
    localStorage.setItem("tl_setup_guide_dismissed", "1");
    return null;
  }

  if (compact) {
    return (
      <div className="bg-indigo-50 rounded-2xl border border-indigo-100 p-4">
        <div className="flex items-center justify-between gap-3 mb-3">
          <p className="text-sm font-black text-indigo-900">Setup Guide</p>
          <span className="text-xs font-bold text-indigo-600">{completedCount}/{totalCount} done</span>
        </div>
        <div className="flex gap-1">
          {SETUP_STEPS.map(step => (
            <div key={step.key}
              className={`h-1.5 flex-1 rounded-full transition-all ${progress[step.key] ? "bg-indigo-600" : "bg-indigo-200"}`} />
          ))}
        </div>
        <Link href="/onboarding" className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 mt-2 block">
          Continue setup →
        </Link>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-2xl border border-indigo-100 shadow-sm overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between"
        style={{ background:"linear-gradient(135deg,#f8faff,#f0f4ff)" }}>
        <div>
          <p className="text-sm font-black text-indigo-900">
            👋 Welcome{profile?.name ? `, ${profile.name.split(" ")[0]}` : ""}!
          </p>
          <p className="text-xs text-indigo-600 mt-0.5">
            Complete your setup to start scanning AI-generated code
          </p>
        </div>
        <div className="text-right">
          <p className="text-2xl font-black text-indigo-600">{completedCount}/{totalCount}</p>
          <p className="text-[10px] text-indigo-400">steps done</p>
        </div>
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-indigo-50">
        <div
          className="h-full bg-indigo-600 transition-all duration-500"
          style={{ width: `${(completedCount / totalCount) * 100}%` }}
        />
      </div>

      {/* Steps */}
      <div className="divide-y divide-gray-50">
        {SETUP_STEPS.map(step => {
          const done = progress[step.key];
          return (
            <div key={step.key} className={`flex items-start gap-4 px-6 py-4 transition-colors ${done ? "opacity-50" : ""}`}>
              {/* Checkbox */}
              <div className={`mt-0.5 w-5 h-5 rounded-full border-2 flex items-center justify-center shrink-0 transition-all ${done ? "bg-emerald-500 border-emerald-500" : "border-gray-300"}`}>
                {done && (
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12"/>
                  </svg>
                )}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span>{step.icon}</span>
                  <p className={`text-sm font-bold ${done ? "line-through text-gray-400" : "text-gray-900"}`}>
                    {step.title}
                  </p>
                </div>
                {!done && <p className="text-xs text-gray-500 mt-0.5">{step.description}</p>}
              </div>

              {!done && step.href && (
                <Link href={step.href}
                  className="shrink-0 text-xs font-bold text-indigo-600 hover:text-indigo-800 whitespace-nowrap">
                  {step.action ?? "Start →"}
                </Link>
              )}
            </div>
          );
        })}
      </div>

      {/* Footer */}
      <div className="px-6 py-3 bg-gray-50 border-t border-gray-100 flex items-center justify-between">
        <p className="text-[10px] text-gray-400">Estimated time: 5 minutes</p>
        <button
          onClick={() => { localStorage.setItem("tl_setup_guide_dismissed","1"); setDismissed(true); }}
          className="text-[11px] text-gray-400 hover:text-gray-600 transition-colors">
          Dismiss
        </button>
      </div>
    </div>
  );
}
