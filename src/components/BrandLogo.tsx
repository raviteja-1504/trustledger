/**
 * TrustLedger brand marks (public/brand/*). The PNGs have transparent backgrounds with the black of the
 * source artwork turned into alpha, so they are drawn for dark surfaces only (every place the brand appears).
 *
 *   BrandMark     — the shield emblem alone (square)
 *   BrandWordmark — emblem + "TrustLedger"
 *   BrandLogo     — full lockup with the "Code security with proof" tagline
 */
/* eslint-disable @next/next/no-img-element */

const WORDMARK_RATIO = 900 / 228;
const LOGO_RATIO = 1200 / 306;

export function BrandMark({ size = 32, className = "" }: { size?: number; className?: string }) {
  return <img src="/brand/trustledger-mark.png" alt="TrustLedger" width={size} height={size} className={`shrink-0 ${className}`} />;
}

export function BrandWordmark({ height = 28, className = "" }: { height?: number; className?: string }) {
  return <img src="/brand/trustledger-wordmark.png" alt="TrustLedger" width={Math.round(height * WORDMARK_RATIO)} height={height} className={`shrink-0 ${className}`} />;
}

export function BrandLogo({ height = 64, className = "" }: { height?: number; className?: string }) {
  return <img src="/brand/trustledger-logo.png" alt="TrustLedger — code security with proof" width={Math.round(height * LOGO_RATIO)} height={height} className={`max-w-full h-auto ${className}`} />;
}
