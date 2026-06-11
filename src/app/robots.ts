import { MetadataRoute } from "next";

const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent:  "*",
        allow:      ["/", "/login", "/changelog", "/docs", "/status"],
        disallow:   [
          "/dashboard",  // requires auth
          "/api/",       // API routes — never crawl
          "/seed",       // dev tool
          "/admin/",     // admin routes
          "/profile",    // personal data
          "/billing",    // billing info
          "/settings",   // settings
        ],
      },
      {
        // Block AI training bots
        userAgent:  ["GPTBot", "Google-Extended", "CCBot", "anthropic-ai"],
        disallow:   ["/"],
      },
    ],
    sitemap:   `${APP_URL}/sitemap.xml`,
    host:      APP_URL,
  };
}
