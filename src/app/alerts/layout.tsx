import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Security Alerts — TrustLedger",
  description: "Real-time security alert management — acknowledge, snooze, escalate, and resolve AI code security incidents.",
};
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
