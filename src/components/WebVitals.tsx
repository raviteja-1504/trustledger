"use client";
/**
 * Core Web Vitals reporting.
 * Sends LCP, FID, CLS, FCP, TTFB to PostHog and Sentry.
 * Only fires in production and when analytics consent is given.
 */

import { useEffect } from "react";
import { usePathname } from "next/navigation";

type MetricName = "CLS" | "FID" | "FCP" | "LCP" | "TTFB" | "INP";

interface WebVitalMetric {
  name:  MetricName;
  value: number;
  id:    string;
  delta: number;
  rating: "good" | "needs-improvement" | "poor";
}

// Thresholds per Google's Core Web Vitals guidelines
const THRESHOLDS: Record<MetricName, [number, number]> = {
  LCP:  [2500, 4000],  // ms
  FID:  [100,  300],   // ms
  CLS:  [0.1,  0.25],  // score
  FCP:  [1800, 3000],  // ms
  TTFB: [800,  1800],  // ms
  INP:  [200,  500],   // ms
};

function getRating(name: MetricName, value: number): "good" | "needs-improvement" | "poor" {
  const [good, poor] = THRESHOLDS[name] ?? [Infinity, Infinity];
  if (value <= good) return "good";
  if (value <= poor) return "needs-improvement";
  return "poor";
}

function reportMetric(metric: WebVitalMetric, pathname: string) {
  const payload = {
    metric_name:  metric.name,
    value:        Math.round(metric.value * (metric.name === "CLS" ? 1000 : 1)) / 1000,
    rating:       metric.rating,
    page:         pathname,
    metric_id:    metric.id,
  };

  if (process.env.NODE_ENV === "production") {
    // Report to PostHog in production
    import("@/lib/analytics").then(({ track }) => {
      track("web_vital", payload);
    }).catch(() => {});

    if (metric.rating === "poor") {
      import("@/lib/logger").then(({ logger }) => {
        logger.warn(`Poor ${metric.name}`, payload);
      }).catch(() => {});
    }
  } else {
    // Dev: surface vitals in the browser console so performance is visible locally
    const color = metric.rating === "good" ? "#16a34a" : metric.rating === "needs-improvement" ? "#d97706" : "#dc2626";
    // eslint-disable-next-line no-console
    console.log(`%c[WebVital] ${metric.name} ${payload.value} — ${metric.rating}`, `color:${color};font-weight:bold`, payload);
  }
}

export function WebVitals() {
  const pathname = usePathname() ?? "/";

  useEffect(() => {
    if (typeof window === "undefined") return;

    // In production, gate on cookie consent; in dev, always measure
    if (process.env.NODE_ENV === "production") {
      const consent = localStorage.getItem("tl_cookie_consent");
      if (consent !== "all") return;
    }

    // Dynamically import web-vitals library (v4+ removed onFID, added onINP)
    import("web-vitals").then((wv) => {
      const report = (name: MetricName) => (metric: { value: number; id: string; delta: number }) => {
        reportMetric({ ...metric, name, rating: getRating(name, metric.value) }, pathname);
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const v = wv as any;
      v.onCLS?.(report("CLS"));
      v.onFCP?.(report("FCP"));
      v.onLCP?.(report("LCP"));
      v.onTTFB?.(report("TTFB"));
      // onINP replaced onFID in web-vitals v4
      v.onINP?.(report("INP"));
      v.onFID?.(report("FID"));
    }).catch(() => {});
  }, [pathname]);

  return null;
}
