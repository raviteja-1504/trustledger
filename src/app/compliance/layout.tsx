import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Compliance Center — TrustLedger",
  description: "Unified SOC 2, EU AI Act, and PCI-DSS compliance status, evidence tracking, and gap analysis.",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
