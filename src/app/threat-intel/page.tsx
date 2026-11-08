import { redirect } from "next/navigation";
import { ADVISORIES_PATH } from "@/lib/dependencyViews";

/** Threat intel is now the "Vulnerabilities & fixes" view of the Dependencies page (same data, one place). */
export default function ThreatIntelRedirect() {
  redirect(ADVISORIES_PATH);
}
