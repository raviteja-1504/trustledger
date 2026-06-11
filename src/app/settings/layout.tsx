import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Settings — TrustLedger",
  description: "Configure attestation policies, integrations, notifications, and team roles for your organisation.",
};

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
