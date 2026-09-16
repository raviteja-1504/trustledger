import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Audit Reports — TrustLedger",
  description: "Generate signed AI code review evidence assessments for SOC 2, EU AI Act, PCI-DSS and ISO 27001, backed by real attestation records.",
};

export default function ReportsLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
