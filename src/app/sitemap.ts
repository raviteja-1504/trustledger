import { MetadataRoute } from "next";

const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date().toISOString();

  // Public pages — no auth required
  const publicPages: MetadataRoute.Sitemap = [
    {
      url:             APP_URL,
      lastModified:    now,
      changeFrequency: "weekly",
      priority:        1.0,
    },
    {
      url:             `${APP_URL}/login`,
      lastModified:    now,
      changeFrequency: "monthly",
      priority:        0.8,
    },
    {
      url:             `${APP_URL}/changelog`,
      lastModified:    now,
      changeFrequency: "weekly",
      priority:        0.7,
    },
    {
      url:             `${APP_URL}/docs`,
      lastModified:    now,
      changeFrequency: "weekly",
      priority:        0.9,
    },
    {
      url:             `${APP_URL}/status`,
      lastModified:    now,
      changeFrequency: "daily",
      priority:        0.5,
    },
    {
      url:             `${APP_URL}/onboarding`,
      lastModified:    now,
      changeFrequency: "monthly",
      priority:        0.6,
    },
  ];

  return publicPages;
}
