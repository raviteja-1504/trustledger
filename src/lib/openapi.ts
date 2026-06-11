/**
 * TrustLedger OpenAPI 3.1 specification.
 * Served at /api/docs as JSON and rendered via Swagger UI.
 */

const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

export const OPENAPI_SPEC = {
  openapi: "3.1.0",
  info: {
    title:       "TrustLedger API",
    version:     "1.0.0",
    description: "AI code provenance, attestation, and compliance API. Authenticate with a TrustLedger API key (`tl_live_...`) in the `X-TrustLedger-Key` header, or with a Supabase JWT in the `Authorization: Bearer` header.",
    contact: {
      name:  "TrustLedger Support",
      email: "support@trustledger.dev",
      url:   "https://docs.trustledger.dev",
    },
    license: { name:"Proprietary" },
  },
  servers: [
    { url: APP_URL,                         description: "Production" },
    { url: "http://localhost:3000",          description: "Local development" },
  ],
  security: [
    { ApiKeyAuth: [] },
    { BearerAuth: [] },
  ],
  components: {
    securitySchemes: {
      ApiKeyAuth: {
        type: "apiKey",
        in:   "header",
        name: "X-TrustLedger-Key",
        description: "TrustLedger API key. Generate in Settings → API Access.",
      },
      BearerAuth: {
        type:   "http",
        scheme: "bearer",
        bearerFormat: "JWT",
        description: "Supabase session JWT (browser clients).",
      },
    },
    schemas: {
      Error: {
        type: "object",
        properties: {
          error:  { type:"string", description:"Error code" },
          detail: { type:"string", description:"Human-readable detail" },
        },
        required: ["error"],
      },
      RiskLevel: {
        type: "string",
        enum: ["LOW","MEDIUM","HIGH","CRITICAL","UNKNOWN"],
      },
      FileResult: {
        type: "object",
        properties: {
          file_path:       { type:"string", example:"src/processors/card_validator.py" },
          language:        { type:"string", example:"python" },
          ai_percentage:   { type:"number", minimum:0, maximum:1, example:0.91, description:"Fraction of code estimated as AI-generated" },
          risk_score:      { $ref:"#/components/schemas/RiskLevel" },
          risk_indicators: { type:"array", items:{ type:"string" }, example:["sql-injection","hardcoded-secret"] },
          attested:        { type:"boolean" },
          content:         { type:"string", description:"File source (optional, sent in scan request)" },
        },
        required: ["file_path","language","ai_percentage","risk_score","risk_indicators","attested"],
      },
      ScanResult: {
        type: "object",
        properties: {
          scan_id:             { type:"string", format:"uuid" },
          repo:                { type:"string", example:"acme/payments-api" },
          pr_number:           { type:"integer", example:482 },
          commit_sha:          { type:"string", example:"a3f9c21d" },
          overall_risk:        { $ref:"#/components/schemas/RiskLevel" },
          total_ai_percentage: { type:"number", minimum:0, maximum:1, example:0.71 },
          file_count:          { type:"integer", example:8 },
          duration_ms:         { type:"integer", example:142 },
          files:               { type:"array", items:{ $ref:"#/components/schemas/FileResult" } },
        },
        required: ["scan_id","repo","pr_number","commit_sha","overall_risk","total_ai_percentage","files"],
      },
      AttestationResult: {
        type: "object",
        properties: {
          attestation_id: { type:"string", format:"uuid" },
          payload_hash:   { type:"string", description:"SHA-256 of scan_id||file_path||reviewer_email||timestamp" },
          attested_at:    { type:"string", format:"date-time" },
          file_path:      { type:"string" },
          reviewer_email: { type:"string", format:"email" },
        },
        required: ["attestation_id","payload_hash","attested_at"],
      },
      Violation: {
        type: "object",
        properties: {
          id:             { type:"string", format:"uuid" },
          scan_id:        { type:"string", format:"uuid" },
          file_path:      { type:"string" },
          risk_score:     { $ref:"#/components/schemas/RiskLevel" },
          status:         { type:"string", enum:["open","in_review","resolved","accepted"] },
          sla_deadline:   { type:"string", format:"date-time", nullable:true },
          assigned_email: { type:"string", format:"email", nullable:true },
          created_at:     { type:"string", format:"date-time" },
        },
      },
      DashboardData: {
        type: "object",
        properties: {
          repos:                   { type:"array", items:{ type:"object" } },
          overall_ai_pct:          { type:"number" },
          attestation_rate:        { type:"number" },
          unattested_deploy_count: { type:"integer" },
          scan_count:              { type:"integer" },
          file_count:              { type:"integer" },
          risk_trend:              { type:"array", items:{ type:"object" } },
          top_risk_files:          { type:"array", items:{ type:"object" } },
        },
      },
    },
  },
  paths: {
    "/api/scans": {
      post: {
        summary:     "Submit a scan",
        description: "Analyse files from a pull request for AI-generated code and security vulnerabilities. Returns risk scores, indicators, and detected secrets.",
        operationId: "submitScan",
        tags:        ["Scanning"],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["repo","pr_number","commit_sha","files"],
                properties: {
                  repo:       { type:"string", example:"acme/payments-api", description:"Full repo name (owner/repo)" },
                  pr_number:  { type:"integer", example:482 },
                  commit_sha: { type:"string", example:"a3f9c21d" },
                  branch:     { type:"string", example:"feature/ai-refactor" },
                  files: {
                    type: "array",
                    description: "Files to scan. Max 50 files per request.",
                    maxItems: 50,
                    items: {
                      type: "object",
                      required: ["path","content"],
                      properties: {
                        path:    { type:"string", example:"src/processors/card_validator.py" },
                        content: { type:"string", description:"Full file content (UTF-8)" },
                      },
                    },
                  },
                },
              },
            },
          },
        },
        responses: {
          "200": {
            description: "Scan completed successfully",
            content: { "application/json": { schema: { $ref:"#/components/schemas/ScanResult" } } },
          },
          "400": { description:"Missing required fields", content:{ "application/json":{ schema:{ $ref:"#/components/schemas/Error" } } } },
          "401": { description:"Authentication required",  content:{ "application/json":{ schema:{ $ref:"#/components/schemas/Error" } } } },
          "429": { description:"Rate limit exceeded (60 scans/minute)", content:{ "application/json":{ schema:{ $ref:"#/components/schemas/Error" } } } },
        },
      },
    },
    "/api/scans/{id}": {
      get: {
        summary:     "Get scan by ID",
        operationId: "getScan",
        tags:        ["Scanning"],
        parameters:  [{ name:"id", in:"path", required:true, schema:{ type:"string", format:"uuid" } }],
        responses: {
          "200": { description:"Scan found",     content:{ "application/json":{ schema:{ $ref:"#/components/schemas/ScanResult" } } } },
          "404": { description:"Scan not found", content:{ "application/json":{ schema:{ $ref:"#/components/schemas/Error"  } } } },
        },
      },
    },
    "/api/attest": {
      post: {
        summary:     "Attest a file",
        description: "Record a reviewer's attestation for a specific file. Creates an immutable, cryptographically-signed record. Resolves the associated violation.",
        operationId: "attestFile",
        tags:        ["Attestation"],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["scan_id","file_path","reviewer_email"],
                properties: {
                  scan_id:         { type:"string", format:"uuid" },
                  file_path:       { type:"string", example:"src/processors/card_validator.py" },
                  reviewer_email:  { type:"string", format:"email", example:"alice@acme.io" },
                  reviewer_github: { type:"string", example:"alice-acme" },
                },
              },
            },
          },
        },
        responses: {
          "200": { description:"Attestation created", content:{ "application/json":{ schema:{ $ref:"#/components/schemas/AttestationResult" } } } },
          "401": { description:"Authentication required" },
          "404": { description:"Scan not found" },
        },
      },
    },
    "/api/violations": {
      get: {
        summary:     "List violations",
        operationId: "listViolations",
        tags:        ["Violations"],
        parameters: [
          { name:"status", in:"query", schema:{ type:"string", enum:["open","in_review","resolved","accepted"] } },
          { name:"repo",   in:"query", schema:{ type:"string" } },
          { name:"limit",  in:"query", schema:{ type:"integer", default:100, maximum:500 } },
        ],
        responses: {
          "200": {
            description: "Violations list",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: { violations:{ type:"array", items:{ $ref:"#/components/schemas/Violation" } } },
                },
              },
            },
          },
        },
      },
      patch: {
        summary:     "Update violation status",
        operationId: "updateViolation",
        tags:        ["Violations"],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["id","status"],
                properties: {
                  id:             { type:"string", format:"uuid" },
                  status:         { type:"string", enum:["open","in_review","resolved","accepted"] },
                  assigned_email: { type:"string", format:"email" },
                  note:           { type:"string" },
                },
              },
            },
          },
        },
        responses: {
          "200": { description:"Updated" },
          "401": { description:"Authentication required" },
        },
      },
    },
    "/api/dashboard": {
      get: {
        summary:     "Get dashboard metrics",
        operationId: "getDashboard",
        tags:        ["Dashboard"],
        parameters: [
          { name:"org",        in:"query", required:true, schema:{ type:"string" } },
          { name:"days",       in:"query", schema:{ type:"integer", default:90 } },
          { name:"start_date", in:"query", schema:{ type:"string", format:"date" } },
          { name:"end_date",   in:"query", schema:{ type:"string", format:"date" } },
        ],
        responses: {
          "200": { description:"Dashboard data", content:{ "application/json":{ schema:{ $ref:"#/components/schemas/DashboardData" } } } },
        },
      },
    },
    "/api/audit": {
      get: {
        summary:     "Get audit log",
        operationId: "getAuditLog",
        tags:        ["Audit"],
        parameters: [
          { name:"page",  in:"query", schema:{ type:"integer", default:0 } },
          { name:"limit", in:"query", schema:{ type:"integer", default:100, maximum:500 } },
        ],
        responses: {
          "200": {
            description: "Audit events",
            content: { "application/json": { schema: {
              type: "object",
              properties: { events:{ type:"array" }, total:{ type:"integer" } },
            }}},
          },
        },
      },
      post: {
        summary:     "Verify audit log integrity",
        description: "Verifies the SHA-256 hash chain of the audit log. Returns whether any records have been tampered with.",
        operationId: "verifyAuditChain",
        tags:        ["Audit"],
        responses: {
          "200": {
            description: "Chain integrity result",
            content: { "application/json": { schema: {
              type:"object",
              properties: {
                valid:     { type:"boolean" },
                total:     { type:"integer" },
                broken_at: { type:"integer", nullable:true, description:"Row ID of first tampered entry" },
              },
            }}},
          },
        },
      },
    },
    "/api/keys": {
      get: {
        summary:     "List API keys",
        operationId: "listApiKeys",
        tags:        ["API Keys"],
        responses: {
          "200": { description:"API keys (raw key never returned after creation)" },
        },
      },
      post: {
        summary:     "Create API key",
        description: "The raw key is returned **once** — store it immediately. Future calls only return the key prefix.",
        operationId: "createApiKey",
        tags:        ["API Keys"],
        requestBody: {
          required: true,
          content: { "application/json": { schema: {
            type:"object", required:["name"],
            properties: {
              name:        { type:"string", example:"CI/CD pipeline" },
              expires_days:{ type:"integer", example:365, description:"Optional expiry in days" },
            },
          }}},
        },
        responses: {
          "200": {
            description:"Key created",
            content: { "application/json": { schema: {
              type:"object",
              properties: {
                id:        { type:"string", format:"uuid" },
                raw_key:   { type:"string", example:"tl_live_abc123...", description:"Shown only once" },
                key_prefix:{ type:"string", example:"tl_live_ab12..." },
                created_at:{ type:"string", format:"date-time" },
              },
            }}},
          },
        },
      },
      delete: {
        summary:     "Revoke API key",
        operationId: "revokeApiKey",
        tags:        ["API Keys"],
        requestBody: {
          required: true,
          content: { "application/json": { schema: { type:"object", properties: { id:{ type:"string", format:"uuid" } }, required:["id"] } } },
        },
        responses: { "200": { description:"Revoked" } },
      },
    },
    "/api/webhook/github": {
      post: {
        summary:     "GitHub webhook receiver",
        description: "Receives GitHub App webhook events. Verify with `X-Hub-Signature-256` header. Handles: `pull_request` (opened/synchronize/reopened).",
        operationId: "githubWebhook",
        tags:        ["Webhooks"],
        parameters: [
          { name:"X-Hub-Signature-256", in:"header", required:true, schema:{ type:"string" }, description:"HMAC-SHA256 signature of the payload" },
          { name:"X-GitHub-Event",      in:"header", required:true, schema:{ type:"string" } },
        ],
        responses: {
          "200": { description:"Event processed" },
          "401": { description:"Invalid signature" },
          "429": { description:"Rate limit exceeded" },
        },
      },
    },
    "/healthz": {
      get: {
        summary:     "Health check",
        operationId: "healthCheck",
        tags:        ["System"],
        security:    [],
        responses: {
          "200": {
            description: "Service healthy",
            content: { "application/json": { schema: {
              type:"object",
              properties: {
                status:     { type:"string", enum:["ok","degraded"] },
                db:         { type:"string", enum:["connected","unavailable"] },
                version:    { type:"string" },
                latency_ms: { type:"integer" },
              },
            }}},
          },
          "503": { description:"Service degraded" },
        },
      },
    },
  },
  tags: [
    { name:"Scanning",    description:"Submit code for AI analysis and security scanning" },
    { name:"Attestation", description:"Record reviewer sign-offs on AI-generated files" },
    { name:"Violations",  description:"Manage open security violations" },
    { name:"Dashboard",   description:"Aggregate metrics across all repositories" },
    { name:"Audit",       description:"Tamper-evident event log with hash chain" },
    { name:"API Keys",    description:"Manage API keys for CI/CD integration" },
    { name:"Webhooks",    description:"Inbound webhook receivers" },
    { name:"System",      description:"Health and status endpoints" },
  ],
};
