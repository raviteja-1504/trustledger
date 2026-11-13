/**
 * The GitHub handle: the account that owns the repositories, i.e. the part right after github.com/ in a repository address
 * (`github.com/acme-corp/payments-api` -> `acme-corp`). A pull request is routed to a TrustLedger organisation by matching the
 * repository's owner against the handle saved on that organisation, so the saved value has to be exactly an owner name.
 *
 * People paste all sorts of things into that box: a repository URL, `@acme-corp`, `acme-corp/payments-api`, their email address,
 * their TrustLedger organisation's name. This turns what can be turned into an owner name and refuses the rest with a message
 * that says what to type. Shared by the setup wizard (to explain before saving) and the API (to save only a valid name).
 */

export type HandleProblem = "empty" | "email" | "invalid";

export type HandleResult =
  | { ok: true; handle: string; /** True when the input had to be cleaned up (a URL, an @, a repository path). */ changed: boolean }
  | { ok: false; problem: HandleProblem; message: string };

export const HANDLE_MESSAGE: Record<HandleProblem, string> = {
  empty: "Enter the GitHub account name that owns your repositories, for example acme-corp.",
  email: "That looks like an email address. Enter the GitHub account name instead: the part after github.com/ in your repository address.",
  invalid: "GitHub account names use only letters, numbers and hyphens, up to 39 characters. Enter just the name, for example acme-corp.",
};

// GitHub allows letters, digits and single hyphens (1-39 chars); Enterprise Managed Users add an underscore, so it is allowed too.
const HANDLE_RE = /^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,38})$/;

/** Clean up and check what was typed. The saved form is lower case: GitHub names are case-insensitive. */
export function normalizeGithubHandle(raw: string): HandleResult {
  let s = (raw ?? "").trim();
  if (!s) return { ok: false, problem: "empty", message: HANDLE_MESSAGE.empty };
  if (s.includes("@") && !s.startsWith("@")) return { ok: false, problem: "email", message: HANDLE_MESSAGE.email };

  const before = s;
  s = s.replace(/^https?:\/\//i, "").replace(/^(?:www\.)?github\.com\//i, "").replace(/^@/, "");
  // `acme-corp/payments-api`, `acme-corp/`, `acme-corp?tab=repos`: the owner is the first segment
  s = s.split(/[/?#]/)[0].trim();

  if (!HANDLE_RE.test(s)) return { ok: false, problem: "invalid", message: HANDLE_MESSAGE.invalid };
  return { ok: true, handle: s.toLowerCase(), changed: s !== before.trim() || s.toLowerCase() !== s };
}

/** Escape a value for an `ilike` pattern: the handle must match literally, `_` and `%` included. */
export function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, c => `\\${c}`);
}
