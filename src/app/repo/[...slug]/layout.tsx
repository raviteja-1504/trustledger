import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Repository — TrustLedger",
  description: "Scan history, AI content trends, and attestation status for this repository.",
};

export default function RepoLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
