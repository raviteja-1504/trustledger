import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const isProd = process.env.NODE_ENV === "production";

// Safety warning at build time (not a hard error — enforced at runtime in validateEnv)
if (isProd && process.env.NEXT_PUBLIC_SKIP_AUTH === "true") {
  console.warn(
    "\n⚠️   WARNING: NEXT_PUBLIC_SKIP_AUTH=true — auth is disabled.\n" +
    "    This is fine for local builds but MUST be false in production deployments.\n" +
    "    The server will refuse to start if this is set in a live environment.\n"
  );
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",

  // ── Performance ─────────────────────────────────────────────────────────────
  compress:                    true,     // gzip/brotli responses
  poweredByHeader:             false,    // remove X-Powered-By header
  reactStrictMode:             true,     // catch subtle bugs
  swcMinify:                   true,     // faster minification

  // ── Image optimization: disabled ─────────────────────────────────────────────
  // next/image is not used anywhere in this app (avatars render via plain
  // <img>), so the optimizer -- and its remotePatterns/AVIF processing --
  // was pure attack surface with zero product benefit. It's also the
  // component behind several CVEs in the installed Next 13.5.11, including
  // a critical unauthenticated RCE when decoding AVIF files
  // (GHSA-2xp9-vwfh-vxw4). unoptimized:true turns off the /_next/image
  // route's transformation pipeline entirely, closing that surface without
  // needing the Next 13->16 major-version migration that would otherwise
  // be required to patch it in place.
  images: {
    unoptimized: true,
  },

  // ── Experimental ─────────────────────────────────────────────────────────────
  experimental: {
    instrumentationHook: true,
    optimizePackageImports: [
      "recharts",
      "@supabase/supabase-js",
      "@supabase/auth-helpers-nextjs",
    ],
    // @react-pdf/renderer needs the full "react" package (React.Component,
    // full reconciler) for its own custom renderer. Left in the normal
    // webpack bundle, the App Router's build graph resolves react through
    // the restricted "react-server" condition for anything under app/**
    // (route handlers included), which is missing what react-pdf needs --
    // it crashed in production with "X.Component is not a constructor".
    // Marking it external makes Next require() it directly from
    // node_modules at runtime instead, getting the full React build.
    // web-tree-sitter (Phase 2 Python AST taint engine, astTaintPython.ts)
    // is external for a related but distinct reason: it does its own
    // runtime environment sniffing (typeof window, module-relative WASM
    // asset resolution) to decide how to instantiate its .wasm module --
    // webpack rewriting its require()/fs calls at bundle time risks making
    // that sniffing lie about the runtime environment, the same failure
    // class as the react-pdf crash above. tree-sitter-wasms (the separate
    // package holding the actual prebuilt tree-sitter-python.wasm binary)
    // must be external too, for a harder reason: without this, webpack
    // statically resolves astTaintPython.ts's
    // require.resolve("tree-sitter-wasms/out/tree-sitter-python.wasm") and
    // tries to bundle the .wasm file as a JS module, which fails the build
    // outright ("Module parse failed... WebAssembly is not enabled by
    // default") since this project has no webpack WASM experiment enabled
    // (and doesn't need one -- the file is only ever read as raw bytes via
    // fs.readFileSync, never executed as a webpack module).
    serverComponentsExternalPackages: ["@react-pdf/renderer", "web-tree-sitter", "tree-sitter-wasms"],
    // web-tree-sitter needs its own runtime binary plus one grammar binary
    // PER LANGUAGE at runtime, all of which Next's @vercel/nft build tracer
    // (active because output:"standalone" is set above) needs an explicit
    // hint to copy into each deployed serverless function's bundle, since
    // none of these are a plain JS import the tracer's static analysis is
    // guaranteed to follow:
    //   1. web-tree-sitter's OWN internal runtime binary (tree-sitter.wasm,
    //      shipped inside the web-tree-sitter package itself) -- required by
    //      Parser.init() before any language grammar is even loaded, and
    //      shared across every language (not per-grammar).
    //   2. tree-sitter-wasms' prebuilt tree-sitter-python.wasm grammar (Phase 2).
    //   3. tree-sitter-wasms' prebuilt tree-sitter-go.wasm grammar (Phase 4).
    // Confirmed via a real production deployment that #1 was originally
    // missed (it was assumed the language grammar file was the only binary
    // involved) -- Parser.init() failed with ENOENT for tree-sitter.wasm on
    // EVERY route that cold-started a Node.js lambda (/healthz, /api/me,
    // /api/dashboard, not just the scan-related routes), because
    // instrumentation.ts's register() -- which calls warmPythonTaintEngine()
    // (and now warmGoTaintEngine()) -- runs on any Node.js serverless
    // function's cold start, not only scan-specific ones. So this is scoped
    // to every route ("/**"), not just the handful that call
    // runScan()/analyzeFile() directly -- and a new language's grammar
    // binary must always be added here too, or it silently reproduces the
    // exact same ENOENT failure for every route, not just that language's
    // own scans.
    outputFileTracingIncludes: {
      "/**": [
        "./node_modules/web-tree-sitter/tree-sitter.wasm",
        "./node_modules/tree-sitter-wasms/out/tree-sitter-python.wasm",
        "./node_modules/tree-sitter-wasms/out/tree-sitter-go.wasm",
      ],
    },
  },

  // ── Security headers (supplements middleware.ts) ─────────────────────────────
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key:"X-DNS-Prefetch-Control", value:"on" },
          { key:"X-Content-Type-Options", value:"nosniff" },
        ],
      },
      {
        // API routes — no caching by default
        source: "/api/(.*)",
        headers: [
          { key:"Cache-Control", value:"no-store, no-cache, must-revalidate" },
          { key:"Pragma",        value:"no-cache" },
        ],
      },
    ];
  },

  webpack: (config, { isServer }) => {
    // ── Server-side: stub Node.js modules that break in edge/browser ──────────
    if (isServer) {
      config.resolve.alias = {
        ...config.resolve.alias,
        undici: path.resolve(__dirname, "src/mocks/empty.js"),
      };
    }

    // ── Client-side: prevent server-only packages from being bundled ──────────
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs:     false,
        net:    false,
        tls:    false,
        crypto: false,
      };
    }

    // ── Production: disable source maps to reduce bundle size ─────────────────
    if (isProd) {
      config.devtool = false;
    }

    // ── Suppress Node.js-only OpenTelemetry "Critical dependency" warning.
    //    require-in-the-middle uses dynamic require() for monkey-patching Node
    //    modules — valid at runtime on the server, but webpack can't statically
    //    extract the dependencies and emits a noisy warning for client bundles.
    config.ignoreWarnings = [
      ...(config.ignoreWarnings ?? []),
      { module: /require-in-the-middle/ },
    ];

    // ── Suppress "Serializing big strings" infrastructure warnings.
    //    These come from large page modules (settings ~114KB, dashboard ~103KB)
    //    and are cosmetic only — they do not affect the build output.
    config.infrastructureLogging = {
      ...config.infrastructureLogging,
      level: "error",
    };

    return config;
  },
};
export default nextConfig;
