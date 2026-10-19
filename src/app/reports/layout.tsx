import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Audit Reports — TrustLedger",
  description: "Generate signed control-evidence reports for SOC 2, ISO 27001, PCI DSS and AI code governance, measured from real scans, reviews and audit records.",
};

export default function ReportsLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
