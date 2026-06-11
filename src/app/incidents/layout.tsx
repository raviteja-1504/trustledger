import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Incident Response — TrustLedger",
  description: "Security incident management with structured response playbooks, timeline tracking, and stakeholder notifications.",
};
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
