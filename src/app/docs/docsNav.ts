/** The documentation's pages, in reading order. Each slug has its content in ./content.tsx (api: ./api/page.tsx). */
export const DOCS_PAGES = [
  { slug: "getting-started", title: "Getting started", summary: "Create an account, connect GitHub, run your first scan and review the findings: five steps, about five minutes." },
  { slug: "architecture", title: "Engine architecture", summary: "Parsers, data-flow engines, line-level detectors and how results are merged." },
  { slug: "languages", title: "Language support", summary: "The ten language engines, the frameworks they model, and their known limitations." },
  { slug: "coverage", title: "Vulnerability coverage", summary: "Every rule, its CWE, and which language engines report it." },
  { slug: "taint-analysis", title: "Taint analysis", summary: "Sources, sinks, sanitizers, guards and cross-file traces." },
  { slug: "ai-attribution", title: "AI attribution", summary: "How the AI-generated estimate is computed, how it was validated, and its limits." },
  { slug: "pr-integration", title: "Pull-request integration", summary: "Check runs, annotations, merge gates and exceptions." },
  { slug: "attestation", title: "Attestation", summary: "What a reviewer sign-off records, what it covers, and how to verify it." },
  { slug: "api", title: "API reference", summary: "REST endpoints, authentication and schemas (interactive)." },
  { slug: "troubleshooting", title: "Troubleshooting", summary: "Scans that don't run, plan limits, the wrong account, numbers that look off, and known limitations." },
] as const;

export type DocsSlug = (typeof DOCS_PAGES)[number]["slug"];
