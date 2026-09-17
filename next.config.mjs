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
    // web-tree-sitter's Language.load(wasmPath) reads tree-sitter-python.wasm
    // from disk at runtime via a require.resolve()'d path -- Next's @vercel/nft
    // build tracer (active because output:"standalone" is set above) needs an
    // explicit hint to guarantee that binary asset is copied into each
    // deployed serverless function's bundle, since it's not a plain JS import
    // the tracer's static analysis is guaranteed to follow. Scoped to only the
    // routes that actually call runScan()/analyzeFile() on Python files.
    // IMPORTANT: this can only be verified against a real Vercel deployment,
    // never locally (next dev/start read node_modules directly) -- see the
    // Phase 2 plan's verification section.
    outputFileTracingIncludes: {
      "/api/scan-worker/**":          ["./node_modules/tree-sitter-wasms/out/tree-sitter-python.wasm"],
      "/api/scans/**":                ["./node_modules/tree-sitter-wasms/out/tree-sitter-python.wasm"],
      "/api/cron/scheduled-scans/**": ["./node_modules/tree-sitter-wasms/out/tree-sitter-python.wasm"],
      "/api/webhook/bitbucket/**":    ["./node_modules/tree-sitter-wasms/out/tree-sitter-python.wasm"],
      "/api/webhook/gitlab/**":       ["./node_modules/tree-sitter-wasms/out/tree-sitter-python.wasm"],
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
