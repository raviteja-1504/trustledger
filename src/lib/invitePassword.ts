/**
 * An invited person is signed in by the emailed link with NO password, and nothing else tells them how to come back (there is
 * no "email me a sign-in link"). So every invited person MUST choose a password before using the app:
 *
 *  - required: invited by email (Supabase sets `invited_at`) and `password_set` is not yet true on the account
 *  - recorded: on the account itself (user_metadata), not in the browser, so it follows them to every device
 *  - there is no way to skip it. An earlier build offered "Not now" and stored `password_prompt_dismissed`; that flag no longer
 *    excuses anyone.
 *
 * Pure, client-safe.
 */
export interface InviteUserLike {
  invited_at?: string | null;
  user_metadata?: { password_set?: unknown } | null;
}

export function needsInvitePassword(user: InviteUserLike | null | undefined): boolean {
  if (!user?.invited_at) return false;
  return (user.user_metadata ?? {}).password_set !== true;
}

/** The query that sends a signed-in invitee to the password screen, and back to where they were going. */
export function invitePasswordUrl(next: string): string {
  return `/login?setup=password&next=${encodeURIComponent(next)}`;
}
