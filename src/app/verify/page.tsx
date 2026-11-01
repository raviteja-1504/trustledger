import type { Metadata } from "next";
import { SitePage, EMERALD } from "@/components/marketing/Site";
import VerifyClient from "./VerifyClient";

export const metadata: Metadata = {
  title: "Verify a report — TrustLedger",
  description: "Check that a TrustLedger compliance report's evidence record is exactly what TrustLedger signed, in your browser, without uploading it.",
};

export default function VerifyPage() {
  return (
    <SitePage active="/verify" eyebrow="For auditors" eyebrowColor={EMERALD} title="Verify a report"
      lede="Every signed report comes with its evidence record (the JSON file saved next to the PDF). Choose it here to check it against TrustLedger's published signing key. The check runs in your browser: the file is not uploaded.">
      <VerifyClient />
    </SitePage>
  );
}
