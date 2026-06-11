import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Security Posture — TrustLedger",
  description: "Real-time security posture score, domain breakdown, MTTR trends, and actionable recommendations for AI-generated codebases.",
};
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
