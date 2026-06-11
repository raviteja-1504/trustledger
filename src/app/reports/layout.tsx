import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Audit Reports — TrustLedger",
  description: "Generate cryptographically-signed compliance reports for SOC 2, EU AI Act, and PCI-DSS with full attestation evidence.",
};

export default function ReportsLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
