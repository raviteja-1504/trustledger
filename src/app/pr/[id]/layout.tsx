import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "PR Review — TrustLedger",
  description: "Review AI-generated code, inspect risk signals, and record reviewer attestations for this pull request.",
};

export default function PRLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
