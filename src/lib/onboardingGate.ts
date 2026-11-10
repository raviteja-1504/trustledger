/**
 * Who is sent to the setup wizard. AuthGuard used to treat ANY organisation with a name as an existing one and mark
 * its onboarding complete on the first page load -- but /create-org always sets a name, so every self-signup was
 * completed the moment its creator left the wizard, and nothing ever brought them back.
 *
 *  - complete already              -> nothing
 *  - an admin who joined an organisation that is already running (other members, or scans) -> mark complete, no setup
 *  - a brand-new organisation      -> send its creator to setup, once per browser session; after that they resume
 *                                      from the dashboard's setup guide, so leaving the wizard never traps them
 */
export interface OnboardingStatus {
  complete: boolean;
  org_name?: string;
  /** Members of the organisation, the caller included. */
  members?: number;
  has_scans?: boolean;
}
export type OnboardingAction = "none" | "complete" | "setup";

export function onboardingAction(status: OnboardingStatus, alreadyPrompted: boolean): OnboardingAction {
  if (status.complete) return "none";
  if ((status.members ?? 1) > 1 || status.has_scans) return "complete";
  return alreadyPrompted ? "none" : "setup";
}

/** Set once the wizard has been offered in this browser session (cleared with the rest of the account's state). */
export const ONBOARDING_PROMPTED_KEY = "tl_onboarding_prompted";
