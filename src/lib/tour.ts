/**
 * The guided tour for a new user: reading the scan list, opening a scan's pull request page, attesting files.
 * Two short tours, one per page, each shown once (remembered on the account, so it follows the person to any device)
 * and replayable from a "Take the tour" button. Pure and client-safe: the engine is components/tour/Tour.tsx.
 */

export interface TourStep {
  /** What to point at: the value of a `data-tour="..."` attribute on the page. The first match on the page is used. */
  target: string;
  title: string;
  body: string;
  /** Shown in the middle of the screen, with no pointer, when the target is not on the page (for example the Attest
   *  button when the person's role cannot attest). Without one, a step whose target is missing is skipped. */
  fallback?: string;
}

export interface TourDef {
  id: "scans" | "pr";
  steps: TourStep[];
  /** The last step's button. The default is "Done". */
  finishLabel?: string;
}

export const SCANS_TOUR: TourDef = {
  id: "scans",
  finishLabel: "Open a scan",
  steps: [
    {
      target: "scans-list",
      title: "Every scan, newest first",
      body: "Each time a pull request is opened or updated, TrustLedger scans it and the result appears here. The coloured badge is the worst risk found in that scan.",
    },
    {
      target: "scans-signoff",
      title: "Sign-off progress",
      body: "High-risk files must be reviewed and signed off by a person before the merge is allowed. This shows how many of them are done.",
    },
    {
      target: "scans-row",
      title: "Open a scan to review it",
      body: "Click any row to open its review page. That is where you read the findings and attest files. The next step opens the first scan for you.",
    },
  ],
};

export const PR_TOUR: TourDef = {
  id: "pr",
  steps: [
    {
      target: "pr-files",
      title: "The files in this pull request",
      body: "Every file that was scanned is listed with its risk and what was found. Click a row to expand it and read the findings, with the exact lines and a suggested fix.",
    },
    {
      target: "pr-filters",
      title: "Start with the riskiest",
      body: "\"Critical & High\" shows the files that need a person to review them. \"Needs Attest\" shows what is still waiting for your sign-off.",
    },
    {
      target: "pr-attest",
      title: "Attest a file",
      body: "Once you have read the findings and are satisfied (the code is fixed, or the finding is not a real risk), click Attest. It records your name and the time, and when every high-risk file is attested the merge is unblocked.",
      fallback: "To attest a file, a reviewer or admin opens a Critical or High file and clicks Attest. There is nothing for your role to attest on this scan, or everything is already signed off.",
    },
  ],
};

export const TOURS: Record<TourDef["id"], TourDef> = { scans: SCANS_TOUR, pr: PR_TOUR };

export const tourTarget = (name: string) => `[data-tour="${name}"]`;

/** The tours this person has finished or skipped, from the account's metadata. */
export function tourSeenOf(user: { user_metadata?: { tour_seen?: unknown } | null } | null | undefined): string[] {
  const raw = user?.user_metadata?.tour_seen;
  return Array.isArray(raw) ? raw.filter((x): x is string => typeof x === "string") : [];
}

/** The list to save after `id` is finished or skipped. */
export function withTourSeen(seen: readonly string[], id: string): string[] {
  return seen.includes(id) ? [...seen] : [...seen, id];
}
