import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Risk Register — TrustLedger",
  description: "Formal security risk register with likelihood × impact scoring, owner assignment, and mitigation tracking.",
};
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
