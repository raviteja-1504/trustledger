import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Secret Scanner — TrustLedger",
  description: "Detect hardcoded API keys, passwords, tokens, and credentials in AI-generated code before they reach production.",
};

export default function SecretsLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
