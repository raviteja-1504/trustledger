"use client";

import { useEffect } from "react";
import Script from "next/script";

export default function DocsPage() {
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
      <div style={{ background:"linear-gradient(135deg,#0f172a,#1e1b4b)", padding:"20px 24px", display:"flex", alignItems:"center", gap:"12px", borderBottom:"1px solid rgba(255,255,255,0.06)" }}>
        <div style={{ width:36, height:36, background:"linear-gradient(135deg,#6366f1,#7c3aed)", borderRadius:10, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <polyline points="9 12 11 14 15 10"/>
          </svg>
        </div>
        <div>
          <p style={{ color:"#fff", fontSize:18, fontWeight:900, letterSpacing:"-0.5px", margin:0 }}>TrustLedger API</p>
          <p style={{ color:"rgba(255,255,255,0.4)", fontSize:12, marginTop:2, margin:0 }}>AI code provenance, attestation, and compliance</p>
        </div>
        <span style={{ marginLeft:"auto", background:"rgba(99,102,241,0.2)", color:"#a5b4fc", border:"1px solid rgba(99,102,241,0.3)", borderRadius:20, padding:"4px 12px", fontSize:11, fontWeight:700 }}>v1.0.0</span>
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
