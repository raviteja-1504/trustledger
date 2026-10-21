/**
 * Who the PR page shows as the reviewer in Review & Attest.
 *
 * Signed in, you attest as yourself: POST /api/attest records the signed-in account (and its GitHub login from the
 * membership) whatever the page sends. A reviewer remembered in this browser from an earlier sign-in must not be
 * shown instead. The remembered value is used only when there is no signed-in profile (demo mode).
 *
 * Client-safe: pure.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function resolveReviewer(
  profile: { email?: string | null; github_login?: string | null } | null | undefined,
  stored: { email: string; github: string },
): { email: string; github: string; signedIn: boolean } {
  const signedInEmail = profile?.email ?? "";
  if (signedInEmail) return { email: signedInEmail, github: profile?.github_login ?? "", signedIn: true };
  return { email: EMAIL_RE.test(stored.email) ? stored.email : "", github: stored.github, signedIn: false };
}
