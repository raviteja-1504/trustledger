/**
 * Who is sent to the setup wizard. AuthGuard used to treat ANY organisation with a name as an existing one and mark
 * its onboarding complete on the first page load -- but /create-org always sets a name, so every self-signup was
 * completed the moment its creator left the wizard, and nothing ever brought them back.
 *
 *  - complete already              -> nothing
 *  - an admin who joined an organisation that already has other members -> mark complete, no setup
 *  - an organisation's creator who has not finished setup -> send them to the wizard once per browser session; after
 *    that the overview keeps offering it (components/setup/SetupBanner.tsx) until it is finished. The wizard always
 *    starts from the first step: leaving it part-way does not complete it.
 */
export interface OnboardingStatus {
  complete: boolean;
  org_name?: string;
  /** Members of the organisation, the caller included. */
  members?: number;
  /** Informational: whether anything has been scanned. Not used to decide (a creator who scanned but skipped steps still sees setup). */
  has_scans?: boolean;
}
export type OnboardingAction = "none" | "complete" | "setup";

export function onboardingAction(status: OnboardingStatus, alreadyPrompted: boolean): OnboardingAction {
  if (status.complete) return "none";
  if (!needsSetup(status)) return "complete";
  return alreadyPrompted ? "none" : "setup";
}

/** Setup is still owed: not complete, and the organisation has no other members (its creator is setting it up). */
export function needsSetup(status: OnboardingStatus): boolean {
  return !status.complete && (status.members ?? 1) <= 1;
}

/** Set once the wizard has been offered in this browser session (cleared with the rest of the account's state). */
export const ONBOARDING_PROMPTED_KEY = "tl_onboarding_prompted";
