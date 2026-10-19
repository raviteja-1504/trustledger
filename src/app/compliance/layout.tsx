import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Compliance Evidence — TrustLedger",
  description: "Control evidence for SOC 2, ISO 27001, PCI DSS and AI code governance, measured from your scans, reviews and audit log, with an exception register.",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
