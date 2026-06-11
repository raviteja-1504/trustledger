import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Dependency Scanner — TrustLedger",
  description: "AI-introduced package risk assessment — vulnerable, unmaintained, and hallucinated dependency detection.",
};
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
