import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Evidence Locker — TrustLedger",
  description: "Centralized compliance evidence organized by framework and control, ready for auditor review.",
};
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
