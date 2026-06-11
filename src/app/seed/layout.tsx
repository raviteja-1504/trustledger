import type { Metadata } from "next";
export const metadata: Metadata = { title: "Seed — TrustLedger", robots: "noindex" };
export default function Layout({ children }: { children: React.ReactNode }) { return <>{children}</>; }
