"use client";

import { useEffect } from "react";
import Script from "next/script";
import Link from "next/link";

/** The interactive API reference: Swagger UI over the OpenAPI spec served at /api/docs. */
export default function ApiDocsPage() {
  // Load Swagger CSS on mount — ID guard survives Strict Mode double-invocation
  useEffect(() => {
    if (document.getElementById("swagger-ui-css")) return;
    const link = document.createElement("link");
    link.id   = "swagger-ui-css";
    link.rel  = "stylesheet";
    link.href = "https://unpkg.com/swagger-ui-dist@5/swagger-ui.css";
    document.head.appendChild(link);
  }, []);

  return (
    <div style={{ minHeight:"100vh", background:"#fff" }}>
      {/* Swagger overrides */}
      <style dangerouslySetInnerHTML={{ __html:`
        .swagger-ui .topbar { display:none !important; }
        #swagger-ui .swagger-ui { font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
        #swagger-ui { max-width:1200px; margin:0 auto; padding:24px; }
        .swagger-ui .info { margin:0 !important; }
      `}} />

      {/* Header */}
      <div style={{ background:"#050810", padding:"20px 24px", display:"flex", alignItems:"center", gap:"12px", borderBottom:"1px solid rgba(255,255,255,0.06)" }}>
        <div>
          <p style={{ color:"#fff", fontSize:18, fontWeight:900, letterSpacing:"-0.5px", margin:0 }}>TrustLedger API reference</p>
          <p style={{ color:"rgba(255,255,255,0.5)", fontSize:12, margin:0 }}>Authenticate with an API key in the <code>X-TrustLedger-Key</code> header, or a session JWT as <code>Authorization: Bearer</code>.</p>
        </div>
        <Link href="/docs" style={{ marginLeft:"auto", color:"#a5f3fc", fontSize:13, fontWeight:700 }}>← Documentation</Link>
      </div>

      {/* Swagger UI mount point */}
      <div id="swagger-ui" />

      {/* next/script handles deduplication + proper load ordering */}
      <Script
        src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"
        strategy="afterInteractive"
        onLoad={() => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const SW = (window as any).SwaggerUIBundle;
          if (!SW || !document.getElementById("swagger-ui")) return;
          SW({
            url:                      "/api/docs",
            dom_id:                   "#swagger-ui",
            deepLinking:              true,
            presets:                  [SW.presets.apis],
            layout:                   "BaseLayout",
            defaultModelsExpandDepth: 1,
            defaultModelExpandDepth:  2,
            tryItOutEnabled:          true,
            onComplete: () => {
              document.querySelector(".swagger-ui .topbar")?.remove();
            },
          });
        }}
      />
    </div>
  );
}
