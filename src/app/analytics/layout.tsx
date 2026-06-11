import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Analytics — TrustLedger",
  description: "Security trend analysis, scan velocity, AI content drift, and team performance metrics.",
};
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
