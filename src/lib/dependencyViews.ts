export type DependencyView = "packages" | "advisories";

/** `?view=advisories` opens the Vulnerabilities view; anything else the package list. */
export function viewFromLocation(search: string): DependencyView {
  const v = new URLSearchParams(search).get("view");
  return v === "advisories" || v === "vulnerabilities" ? "advisories" : "packages";
}

/** The path the old Threat intel page now lives at. */
export const ADVISORIES_PATH = "/dependencies?view=advisories";
