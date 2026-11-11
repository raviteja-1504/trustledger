"use client";
/**
 * Setup wizard, "Connect GitHub": exactly what to fill in on GitHub's "Register new GitHub App" form (every field,
 * every permission, every event), the one-click shortcut that fills it all in, and what to do with the app's credentials.
 * The values come from lib/githubAppConfig.ts, the same source as the one-click manifest, so they cannot drift.
 */
import { useEffect, useState } from "react";
import {
  ACCESS_LABEL, EVENT_FORM, GITHUB_APP_EVENTS, GITHUB_APP_PERMISSIONS, PERMISSION_FORM, githubAppSettings,
} from "@/lib/githubAppConfig";

function newSecret(): string {
  try {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return Array.from({ length: 48 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
  }
}

function CopyField({ label, value, hint, id }: { label: string; value: string; hint?: string; id: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    navigator.clipboard?.writeText(value).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  }
  return (
    <div>
      <p className="text-xs font-semibold text-gray-600 mb-1">{label}</p>
      <div className="flex items-center gap-2 bg-white rounded-xl border border-gray-200 px-3 py-2">
        <code data-testid={id} className="text-xs font-mono text-gray-800 flex-1 break-all select-all">{value}</code>
        <button type="button" onClick={copy} className="shrink-0 text-xs font-bold px-2 py-1 rounded-lg"
          style={{ background: copied ? "#d1fae5" : "#f1f5f9", color: copied ? "#065f46" : "#374151" }}>
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
      {hint && <p className="text-[11px] text-gray-500 mt-1 leading-snug">{hint}</p>}
    </div>
  );
}

function Num({ n, tone = "indigo" }: { n: number; tone?: "indigo" | "gray" }) {
  return <span className={`w-6 h-6 rounded-full text-white text-xs font-black flex items-center justify-center shrink-0 ${tone === "indigo" ? "bg-indigo-600" : "bg-gray-600"}`}>{n}</span>;
}

export default function GithubAppGuide() {
  const [origin, setOrigin] = useState("");
  const [secret, setSecret] = useState("");
  useEffect(() => { setOrigin(window.location.origin); }, []);
  const s = githubAppSettings(origin || "https://your-site");

  return (
    <div className="space-y-4">
      {/* 1 — create the app */}
      <div className="bg-indigo-50 rounded-2xl p-4 border border-indigo-100 space-y-3">
        <div className="flex items-center gap-2">
          <Num n={1} />
          <p className="text-sm font-bold text-indigo-900">Create the GitHub App</p>
        </div>
        <p className="text-xs text-indigo-800 leading-relaxed">
          The quickest way: GitHub opens with <strong>every field below already filled in</strong>, and you only confirm it.
        </p>
        <a href="/setup/github-app" className="block text-center text-sm font-bold text-white rounded-xl py-2.5" style={{ background: "#24292f" }}>
          Create it for me in one click →
        </a>

        <details className="group">
          <summary className="cursor-pointer text-xs font-bold text-indigo-700 select-none">Or fill the form in yourself (field by field)</summary>
          <div className="mt-3 space-y-3">
            <p className="text-xs text-indigo-800">
              Open{" "}
              <a href="https://github.com/settings/apps/new" target="_blank" rel="noopener noreferrer" className="font-bold underline underline-offset-2">github.com/settings/apps/new</a>
              {" "}(or Settings → Developer settings → GitHub Apps → <strong>New GitHub App</strong>; for an organisation use its own Settings) and fill in:
            </p>

            <CopyField id="f-name" label="GitHub App name" value={s.name}
              hint="Must be unique across GitHub. If it is taken, add your company: for example TrustLedger-Acme." />
            <CopyField id="f-desc" label="Description (optional)" value={s.description} />
            <CopyField id="f-home" label="Homepage URL" value={s.homepageUrl} hint="This site's address." />

            <div className="rounded-xl bg-white border border-gray-200 p-3 space-y-2.5">
              <p className="text-xs font-bold text-gray-800">Identifying and authorizing users</p>
              <CopyField id="f-callback" label="Callback URL" value={s.callbackUrl} />
              <ul className="text-[11px] text-gray-600 leading-snug space-y-0.5 list-disc pl-4">
                <li>Tick <strong>Request user authorization (OAuth) during installation</strong>.</li>
                <li>Leave <strong>Expire user authorization tokens</strong> on (the default).</li>
              </ul>
            </div>

            <div className="rounded-xl bg-white border border-gray-200 p-3 space-y-2.5">
              <p className="text-xs font-bold text-gray-800">Post installation</p>
              <CopyField id="f-setup" label="Setup URL (optional)" value={s.setupUrl} />
              <ul className="text-[11px] text-gray-600 leading-snug list-disc pl-4">
                <li>Tick <strong>Redirect on update</strong>.</li>
              </ul>
            </div>

            <div className="rounded-xl bg-white border border-gray-200 p-3 space-y-2.5">
              <p className="text-xs font-bold text-gray-800">Webhook</p>
              <ul className="text-[11px] text-gray-600 leading-snug list-disc pl-4">
                <li>Tick <strong>Active</strong>, and keep <strong>SSL verification</strong> enabled.</li>
              </ul>
              <CopyField id="f-webhook" label="Webhook URL" value={s.webhookUrl} />
              {secret ? (
                <CopyField id="f-secret" label="Webhook secret" value={secret}
                  hint="Paste this into GitHub's Webhook secret field, AND set the same value as GITHUB_WEBHOOK_SECRET in step 2. If the two differ, every webhook is rejected." />
              ) : (
                <div>
                  <p className="text-xs font-semibold text-gray-600 mb-1">Webhook secret</p>
                  <button type="button" onClick={() => setSecret(newSecret())}
                    className="text-xs font-bold px-3 py-1.5 rounded-lg bg-gray-900 text-white">Generate a secret</button>
                  <p className="text-[11px] text-gray-500 mt-1 leading-snug">A long random value. You will use the same one in GitHub and in step 2.</p>
                </div>
              )}
            </div>

            <div className="rounded-xl bg-white border border-gray-200 p-3 space-y-2">
              <p className="text-xs font-bold text-gray-800">Repository permissions</p>
              <p className="text-[11px] text-gray-500">Open <strong>Repository permissions</strong> and set exactly these (leave every other permission at No access):</p>
              <table className="w-full text-[11px]">
                <thead><tr className="text-left text-gray-400"><th className="py-1 pr-2 font-semibold">Permission</th><th className="py-1 pr-2 font-semibold">Access</th><th className="py-1 font-semibold">Why</th></tr></thead>
                <tbody>
                  {(Object.keys(GITHUB_APP_PERMISSIONS) as Array<keyof typeof GITHUB_APP_PERMISSIONS>).map(k => (
                    <tr key={k} className="border-t border-gray-100 align-top">
                      <td className="py-1.5 pr-2 font-bold text-gray-800 whitespace-nowrap">{PERMISSION_FORM[k].label}</td>
                      <td className="py-1.5 pr-2 text-gray-800 whitespace-nowrap">{ACCESS_LABEL[GITHUB_APP_PERMISSIONS[k]]}</td>
                      <td className="py-1.5 text-gray-500">{PERMISSION_FORM[k].why}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="text-[11px] text-gray-500 leading-snug">Leave <strong>Organization permissions</strong> and <strong>Account permissions</strong> at <strong>No access</strong>. TrustLedger needs nothing there.</p>
            </div>

            <div className="rounded-xl bg-white border border-gray-200 p-3 space-y-1.5">
              <p className="text-xs font-bold text-gray-800">Subscribe to events</p>
              <p className="text-[11px] text-gray-500">These appear once the permissions above are set. Tick:</p>
              <div className="flex flex-wrap gap-1.5">
                {GITHUB_APP_EVENTS.map(e => <span key={e} className="text-[11px] font-bold px-2 py-0.5 rounded-md bg-indigo-50 text-indigo-800 border border-indigo-100">{EVENT_FORM[e]}</span>)}
              </div>
            </div>

            <div className="rounded-xl bg-white border border-gray-200 p-3 space-y-1">
              <p className="text-xs font-bold text-gray-800">Where can this GitHub App be installed?</p>
              <p className="text-[11px] text-gray-600 leading-snug">
                <strong>Only on this account</strong> if the repositories are yours. Choose <strong>Any account</strong> only if other organisations will install this app.
              </p>
            </div>

            <p className="text-[11px] text-indigo-800">Then click <strong>Create GitHub App</strong>.</p>
          </div>
        </details>
      </div>

      {/* 2 — credentials */}
      <div className="bg-gray-50 rounded-2xl p-4 border border-gray-100 space-y-2.5">
        <div className="flex items-center gap-2">
          <Num n={2} tone="gray" />
          <p className="text-sm font-bold text-gray-900">Give TrustLedger the app&apos;s credentials</p>
        </div>
        <p className="text-xs text-gray-600 leading-relaxed">
          On the new app&apos;s page, note the <strong>App ID</strong> and click <strong>Generate a private key</strong> (a <code>.pem</code> file downloads). The one-click flow shows all three values once.
          Then, in your hosting project (Vercel → Settings → Environment Variables), add these and redeploy:
        </p>
        <ul className="text-xs text-gray-700 space-y-1">
          <li><code className="font-mono font-bold">GITHUB_APP_ID</code> <span className="text-gray-500">— the App ID</span></li>
          <li><code className="font-mono font-bold">GITHUB_APP_PRIVATE_KEY</code> <span className="text-gray-500">— the full contents of the .pem file</span></li>
          <li><code className="font-mono font-bold">GITHUB_WEBHOOK_SECRET</code> <span className="text-gray-500">— the webhook secret from step 1</span></li>
        </ul>
        <p className="text-[11px] text-gray-500">Without these, GitHub&apos;s events are rejected and nothing is scanned.</p>
      </div>

      {/* 3 — install */}
      <div className="bg-gray-50 rounded-2xl p-4 border border-gray-100 space-y-2">
        <div className="flex items-center gap-2">
          <Num n={3} tone="gray" />
          <p className="text-sm font-bold text-gray-900">Install the app on your repositories</p>
        </div>
        <p className="text-xs text-gray-600 leading-relaxed">
          Open the app&apos;s page on GitHub and click <strong>Install App</strong>, choose your organisation, and select the repositories to scan
          (starting with one is fine). Then open or update a pull request: it is scanned automatically.
        </p>
      </div>
    </div>
  );
}
