import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Audit Trail — TrustLedger",
  description: "Immutable chronological log of all security events — scans, attestations, policy violations, and blocked merges.",
};

export default function AuditLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
