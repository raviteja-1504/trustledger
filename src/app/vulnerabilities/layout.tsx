import type { Metadata } from "next";
export const metadata: Metadata = {
  title: "Vulnerability Intelligence — TrustLedger",
  description: "AI-generated code vulnerability patterns mapped to CVEs, CVSS scores, and remediation guidance.",
};
export default function Layout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
