import { redirect } from "next/navigation";

// /vulnerabilities ("Policy Violations") was a separate, ~1000-line
// duplicate implementation of /violations -- same concept, its own copy of
// deriveViolations(), and its own localStorage-only status tracking that
// never synced with the server-backed violation_overrides system /violations
// and the Sidebar badge use. That's exactly why its counts could disagree
// with the rest of the app. Consolidated into one implementation rather than
// keeping two in sync forever.
export default function VulnerabilitiesRedirect() {
  redirect("/violations");
}
