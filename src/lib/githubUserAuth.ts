/**
 * Proof that the person finishing a GitHub App install really has access to that installation.
 *
 * The install callback receives `installation_id` in the URL, which anyone can edit (the ids are small sequential
 * numbers). With "Request user authorization during installation" on, GitHub also sends a one-time `code` for the person
 * who approved the install. We trade it for that person's token and ask GitHub which installations they can access: the
 * id from the URL counts only if it is in that list. Fails closed: any problem is "not verified".
 */

const GITHUB_API = "https://api.github.com";

export type InstallVerification =
  | { ok: true }
  | { ok: false; reason: "not_configured" | "no_code" | "exchange_failed" | "not_accessible" | "lookup_failed" };

const env = (k: string) => (process.env[k] ?? "").replace(/\r/g, "").trim();

export async function verifyInstallationAccess(code: string | null, installationId: number): Promise<InstallVerification> {
  const clientId = env("GITHUB_APP_CLIENT_ID");
  const clientSecret = env("GITHUB_APP_CLIENT_SECRET");
  if (!clientId || !clientSecret) return { ok: false, reason: "not_configured" };
  if (!code) return { ok: false, reason: "no_code" };
  if (!Number.isSafeInteger(installationId) || installationId <= 0) return { ok: false, reason: "not_accessible" };

  let token: string | undefined;
  try {
    const res = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code }),
    });
    if (!res.ok) return { ok: false, reason: "exchange_failed" };
    const data = await res.json() as { access_token?: string; error?: string };
    token = data.access_token;
  } catch {
    return { ok: false, reason: "exchange_failed" };
  }
  if (!token) return { ok: false, reason: "exchange_failed" };

  try {
    // the installations this user can access, for this app (5 pages of 100 is far more than anyone has)
    for (let page = 1; page <= 5; page++) {
      const res = await fetch(`${GITHUB_API}/user/installations?per_page=100&page=${page}`, {
        headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" },
      });
      if (!res.ok) return { ok: false, reason: "lookup_failed" };
      const data = await res.json() as { installations?: Array<{ id: number }> };
      const list = data.installations ?? [];
      if (list.some(i => i.id === installationId)) return { ok: true };
      if (list.length < 100) break;
    }
  } catch {
    return { ok: false, reason: "lookup_failed" };
  }
  return { ok: false, reason: "not_accessible" };
}
