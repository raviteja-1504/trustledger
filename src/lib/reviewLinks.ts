/**
 * Links to a high-risk file on its pull request. Someone whose role may sign the file off goes straight to its
 * sign-off (?attest=); anyone else goes to the file itself (?file=), so a developer is never handed the
 * attestation form. The PR page enforces the same rule for links built elsewhere (deepLinkAction).
 */
export function fileReviewHref(scanId: string, filePath: string, canAttest: boolean): string {
  return `/pr/${scanId}?${canAttest ? "attest" : "file"}=${encodeURIComponent(filePath)}`;
}

/**
 * What a deep link to a file does on the PR page:
 *   attest          → open the Review & Attest form (only for someone whose role may sign the file off)
 *   open            → open the file in place (?file=, or a file that's already signed off)
 *   open-read-only  → open the file in place and say why there's no sign-off: the link asked to attest it,
 *                     but this viewer's role can't
 */
export type DeepLinkAction = "attest" | "open" | "open-read-only";

export function deepLinkAction(kind: "attest" | "file", signedOff: boolean, canAttest: boolean): DeepLinkAction {
  if (kind === "file" || signedOff) return "open";
  return canAttest ? "attest" : "open-read-only";
}
