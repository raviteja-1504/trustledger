import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

import AppShell from "@/components/AppShell";
import Providers from "@/components/Providers";

const inter = Inter({ subsets: ["latin"], display: "swap", variable: "--font-inter" });

const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "https://app.trustledger.dev";

export const metadata: Metadata = {
  metadataBase: new URL(APP_URL),
  title: {
    default:  "TrustLedger — AI Code Governance",
    template: "%s | TrustLedger",
  },
  description: "Scan every pull request for AI-generated code, enforce reviewer attestation, and generate signed SOC 2, EU AI Act, and PCI-DSS compliance reports.",
  keywords:    ["AI code governance","AI attestation","SOC2","PCI-DSS","EU AI Act","code provenance","GitHub security","AI code review"],
  authors:     [{ name:"TrustLedger", url:"https://trustledger.dev" }],
  creator:     "TrustLedger",
  publisher:   "TrustLedger",
  category:    "technology",
  robots: {
    index:              true,
    follow:             true,
    googleBot: {
      index:            true,
      follow:           true,
      "max-image-preview":   "large",
      "max-snippet":         -1,
      "max-video-preview":   -1,
    },
  },
  openGraph: {
    type:        "website",
    siteName:    "TrustLedger",
    title:       "TrustLedger — AI Code Governance Platform",
    description: "Know exactly how much AI wrote your code. Scan PRs, enforce policy, generate compliance reports.",
    url:         APP_URL,
    locale:      "en_US",
    images: [{
      url:    `${APP_URL}/og-image.png`,
      width:  1200,
      height: 630,
      alt:    "TrustLedger — AI Code Governance",
    }],
  },
  twitter: {
    card:        "summary_large_image",
    site:        "@trustledger",
    creator:     "@trustledger",
    title:       "TrustLedger — AI Code Governance Platform",
    description: "Know exactly how much AI wrote your code.",
    images:      [`${APP_URL}/og-image.png`],
  },
  manifest:    "/manifest.json",
  icons: {
    icon:        [
      { url:"/favicon-16x16.png", sizes:"16x16", type:"image/png" },
      { url:"/favicon-32x32.png", sizes:"32x32", type:"image/png" },
    ],
    apple:       "/apple-touch-icon.png",
    shortcut:    "/favicon.ico",
  },
  verification: {
    // Add your verification codes when connecting to search consoles
    // google:  "your-google-verification-code",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=5" />
        <meta name="theme-color" media="(prefers-color-scheme: light)" content="#6366f1" />
        <meta name="theme-color" media="(prefers-color-scheme: dark)"  content="#0f172a" />
      </head>
      <body className={`${inter.variable} ${inter.className} text-gray-900`}>
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
