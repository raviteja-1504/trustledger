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

/** What a branding form is allowed to hold. Pure, so it is testable without a browser. */
export interface BrandingCheck { ok: boolean; errors: Partial<Record<keyof BrandingConfig, string>>; cleaned: BrandingConfig }

const HEX_COLOR = /^#[0-9a-f]{6}$/i;
const EMAIL     = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function isWebUrl(v: string): boolean {
  try { const u = new URL(v); return u.protocol === "https:" || u.protocol === "http:"; } catch { return false; }
}

/**
 * Trim every field, drop the empty ones, and check what is left. Empty fields are not saved (they used to be stored as "" and the
 * page still said "Applied"). Saving needs at least one real value, and each value must look right: a hex colour, an http(s) URL for the
 * logo and favicon, a valid support email.
 */
export function validateBranding(input: BrandingConfig): BrandingCheck {
  const cleaned: BrandingConfig = {};
  const errors: BrandingCheck["errors"] = {};
  for (const key of Object.keys(input) as Array<keyof BrandingConfig>) {
    const v = (input[key] ?? "").trim();
    if (v) cleaned[key] = v;
  }
  if (cleaned.primary_color && !HEX_COLOR.test(cleaned.primary_color)) errors.primary_color = "Use a 6-digit hex colour such as #6366f1.";
  if (cleaned.logo_url && !isWebUrl(cleaned.logo_url))                 errors.logo_url = "Enter a full http(s) address, such as https://your-domain.com/logo.png.";
  if (cleaned.favicon_url && !isWebUrl(cleaned.favicon_url))           errors.favicon_url = "Enter a full http(s) address, such as https://your-domain.com/favicon.ico.";
  if (cleaned.support_email && !EMAIL.test(cleaned.support_email))     errors.support_email = "Enter a valid email address.";
  if (Object.keys(cleaned).length === 0) errors.org_name = "Enter at least one value before applying.";
  return { ok: Object.keys(errors).length === 0, errors, cleaned };
}
