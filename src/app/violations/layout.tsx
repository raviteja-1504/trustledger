import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Policy Violations — TrustLedger",
  description: "Active policy violations across all repositories requiring immediate remediation.",
};
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
