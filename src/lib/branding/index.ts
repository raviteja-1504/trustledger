"use client";
/**
 * Custom branding / white-label support.
 * Enterprise customers can configure:
 *   - Company name + logo URL
 *   - Primary colour (hex)
 *   - Favicon URL
 *   - Support email
 *
 * Config stored in localStorage (tl_branding) and in org settings.
 * Applied via CSS custom properties on <html>.
 */

export interface BrandingConfig {
  org_name?:      string;
  logo_url?:      string;     // Full URL to a logo image
  primary_color?: string;     // Hex colour, e.g. "#6366f1"
  favicon_url?:   string;
  support_email?: string;
  tagline?:       string;
}

const BRANDING_KEY = "tl_branding";

export function loadBranding(): BrandingConfig {
  if (typeof window === "undefined") return {};
  try {
    return JSON.parse(localStorage.getItem(BRANDING_KEY) ?? "{}") as BrandingConfig;
  } catch { return {}; }
}

export function saveBranding(cfg: BrandingConfig): void {
  localStorage.setItem(BRANDING_KEY, JSON.stringify(cfg));
  applyBranding(cfg);
}

export function applyBranding(cfg: BrandingConfig): void {
  if (typeof window === "undefined") return;
  const root = document.documentElement;

  if (cfg.primary_color) {
    // Apply primary colour + derived shades
    root.style.setProperty("--color-primary",     cfg.primary_color);
    root.style.setProperty("--color-primary-hover",shadeColor(cfg.primary_color, -15));
    root.style.setProperty("--color-primary-light",shadeColor(cfg.primary_color, 50) + "20");
  }

  if (cfg.favicon_url) {
    const link = document.querySelector<HTMLLinkElement>("link[rel='icon']")
      ?? (() => { const l = document.createElement("link"); l.rel = "icon"; document.head.appendChild(l); return l; })();
    link.href = cfg.favicon_url;
  }

  if (cfg.org_name) {
    document.title = `${document.title.replace(/^.*—\s*/, "")} — ${cfg.org_name}`;
  }
}

function shadeColor(hex: string, percent: number): string {
  const num = parseInt(hex.replace("#",""), 16);
  const R = Math.min(255, Math.max(0, (num >> 16) + Math.round(255 * percent / 100)));
  const G = Math.min(255, Math.max(0, ((num >> 8) & 0x00ff) + Math.round(255 * percent / 100)));
  const B = Math.min(255, Math.max(0, (num & 0x0000ff) + Math.round(255 * percent / 100)));
  return `#${((1 << 24) + (R << 16) + (G << 8) + B).toString(16).slice(1)}`;
}

export function useBranding(): BrandingConfig {
  return loadBranding();
}
