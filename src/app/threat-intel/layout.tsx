import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Threat Intelligence — TrustLedger",
  description: "Real-time AI code threat intelligence — emerging CVEs, zero-days, and vulnerability patterns targeting AI-generated codebases.",
};
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
