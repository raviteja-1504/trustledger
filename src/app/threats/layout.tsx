import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Threats — TrustLedger",
  description: "Policy violations, security alerts and incidents in one place: what is out of policy, who has been told, and what was escalated.",
};
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
