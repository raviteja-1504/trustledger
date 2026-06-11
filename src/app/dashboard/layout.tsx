import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Dashboard — TrustLedger",
  description: "Org-wide AI code health score, risk trends, attestation coverage, and blocked deploy tracking.",
};

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
