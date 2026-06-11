/**
 * Dependency Risk Graph API
 * Analyses package.json / requirements.txt / go.mod etc. to build
 * a dependency risk graph with AI vulnerability correlation.
 *
 * GET /api/dependencies/graph?scan_id=...  → graph for a specific scan
 * POST /api/dependencies/graph             → analyse manifest content directly
 *
 * Returns nodes (packages) + edges (depends-on) with risk metadata.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";

// ── Known vulnerable packages (simplified NVD-like data) ─────────────────────
const VULN_DB: Record<string, { cve: string; severity: string; desc: string; fixed_version?: string }[]> = {
  "requests":          [{ cve:"CVE-2023-32681", severity:"HIGH",     desc:"SSRF via Proxy-Authorization",              fixed_version:"2.31.0" }],
  "django":            [{ cve:"CVE-2023-36053", severity:"HIGH",     desc:"Potential ReDoS in EmailValidator",          fixed_version:"4.2.3"  }],
  "pillow":            [{ cve:"CVE-2023-44271", severity:"HIGH",     desc:"Denial of service via crafted image",        fixed_version:"10.0.1" }],
  "cryptography":      [{ cve:"CVE-2023-49083", severity:"MEDIUM",   desc:"NULL pointer dereference",                   fixed_version:"41.0.6" }],
  "paramiko":          [{ cve:"CVE-2023-48795", severity:"MEDIUM",   desc:"Terrapin prefix truncation attack",          fixed_version:"3.4.0"  }],
  "lodash":            [{ cve:"CVE-2021-23337", severity:"HIGH",     desc:"Command injection via template",             fixed_version:"4.17.21"}],
  "axios":             [{ cve:"CVE-2023-45857", severity:"MEDIUM",   desc:"CSRF token leakage",                         fixed_version:"1.6.0"  }],
  "moment":            [{ cve:"CVE-2022-24785", severity:"HIGH",     desc:"Path traversal in locale loading",           fixed_version:"2.29.4" }],
  "jsonwebtoken":      [{ cve:"CVE-2022-23529", severity:"HIGH",     desc:"Secret disclosure via insecure defaults",    fixed_version:"9.0.0"  }],
  "log4j":             [{ cve:"CVE-2021-44228", severity:"CRITICAL", desc:"Remote code execution via JNDI",            fixed_version:"2.17.1" }],
  "spring-core":       [{ cve:"CVE-2022-22965", severity:"CRITICAL", desc:"Spring4Shell RCE via DataBinder",           fixed_version:"5.3.18" }],
};

const HALLUCINATED_PACKAGES = new Set([
  "ml-utils-fast", "stripe-client", "tensorflow-utils", "pytorch-helper",
  "openai-connector", "llm-bridge", "ai-sdk-helper", "gpt-wrapper",
]);

interface DepNode {
  id:          string;
  name:        string;
  version?:    string;
  ecosystem:   string;
  risk_score:  "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  is_direct:   boolean;
  hallucinated:boolean;
  vulns:       Array<{ cve:string; severity:string; desc:string; fixed_version?:string }>;
  ai_introduced:boolean;  // detected in AI-generated files
}

interface DepEdge {
  from: string;
  to:   string;
  type: "depends_on";
}

interface DepGraph {
  nodes: DepNode[];
  edges: DepEdge[];
  stats: {
    total:       number;
    vulnerable:  number;
    hallucinated:number;
    critical:    number;
    high:        number;
  };
}

function parseRequirements(content: string): Array<{ name: string; version?: string }> {
  return content.split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#") && !l.startsWith("-"))
    .map(l => {
      const match = l.match(/^([a-zA-Z0-9_-]+)([>=<!~^].*)?$/);
      if (!match) return null;
      const ver = match[2]?.replace(/[>=<!~^]/g,"").split(",")[0].trim();
      return { name: match[1].toLowerCase(), version: ver };
    })
    .filter(Boolean) as Array<{ name: string; version?: string }>;
}

function parsePackageJson(content: string): Array<{ name: string; version?: string }> {
  try {
    const pkg = JSON.parse(content) as { dependencies?: Record<string,string>; devDependencies?: Record<string,string> };
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    return Object.entries(deps).map(([name, ver]) => ({
      name,
      version: ver.replace(/[\^~>=]/g,"").split(" ")[0],
    }));
  } catch { return []; }
}

function parseGoMod(content: string): Array<{ name: string; version?: string }> {
  return content.split("\n")
    .filter(l => l.trim().startsWith("require") || l.includes("github.com") || l.includes("golang.org"))
    .map(l => {
      const match = l.trim().match(/([a-zA-Z0-9./\-_]+)\s+v([0-9.]+)/);
      if (!match) return null;
      return { name: match[1].split("/").pop() ?? match[1], version: match[2] };
    })
    .filter(Boolean) as Array<{ name: string; version?: string }>;
}

function buildGraph(
  deps: Array<{ name: string; version?: string }>,
  ecosystem: string,
  aiIntroducedNames: Set<string>,
): DepGraph {
  const nodes: DepNode[] = deps.map(dep => {
    const vulns       = VULN_DB[dep.name.toLowerCase()] ?? [];
    const hallucinated= HALLUCINATED_PACKAGES.has(dep.name.toLowerCase());
    const maxSev      = vulns.reduce((m, v) => {
      const order: Record<string,number> = { CRITICAL:3,HIGH:2,MEDIUM:1,LOW:0 };
      return (order[v.severity]??0) > (order[m]??0) ? v.severity : m;
    }, "LOW");
    const risk = hallucinated ? "CRITICAL" :
                 maxSev === "CRITICAL" ? "CRITICAL" :
                 maxSev === "HIGH"     ? "HIGH"     :
                 maxSev === "MEDIUM"   ? "MEDIUM"   : "LOW";
    return {
      id:           dep.name,
      name:         dep.name,
      version:      dep.version,
      ecosystem,
      risk_score:   risk as DepNode["risk_score"],
      is_direct:    true,
      hallucinated,
      vulns,
      ai_introduced:aiIntroducedNames.has(dep.name.toLowerCase()),
    };
  });

  // Simple edges: each package depends on "runtime" root
  const edges: DepEdge[] = nodes.map(n => ({ from:"__root__", to:n.id, type:"depends_on" as const }));

  const stats = {
    total:       nodes.length,
    vulnerable:  nodes.filter(n => n.vulns.length > 0).length,
    hallucinated:nodes.filter(n => n.hallucinated).length,
    critical:    nodes.filter(n => n.risk_score === "CRITICAL").length,
    high:        nodes.filter(n => n.risk_score === "HIGH").length,
  };

  return { nodes, edges, stats };
}

export async function POST(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as {
    filename: string;        // "requirements.txt" | "package.json" | "go.mod"
    content:  string;
    ai_files?: string[];     // file paths that were AI-generated
  };

  if (!body.filename || !body.content) {
    return NextResponse.json({ error:"missing_fields" }, { status:400 });
  }

  const aiIntroduced = new Set((body.ai_files ?? []).map(f => f.toLowerCase()));
  let deps: Array<{ name:string; version?:string }> = [];
  let ecosystem = "unknown";

  if (body.filename.endsWith("requirements.txt") || body.filename.endsWith("Pipfile")) {
    deps = parseRequirements(body.content);
    ecosystem = "python";
  } else if (body.filename === "package.json") {
    deps = parsePackageJson(body.content);
    ecosystem = "npm";
  } else if (body.filename === "go.mod") {
    deps = parseGoMod(body.content);
    ecosystem = "go";
  } else {
    return NextResponse.json({ error:"unsupported_manifest" }, { status:400 });
  }

  const graph = buildGraph(deps, ecosystem, aiIntroduced);
  return NextResponse.json(graph);
}

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url    = new URL(req.url);
  const scanId = url.searchParams.get("scan_id");
  if (!scanId) return NextResponse.json({ error:"scan_id required" }, { status:400 });

  const db = createServiceClient();

  // Find manifest files in scan_files
  const { data: manifests } = await db
    .from("scan_files")
    .select("file_path, content_hash, risk_indicators")
    .eq("scan_id", scanId)
    .or("file_path.ilike.%requirements.txt,file_path.ilike.%package.json,file_path.ilike.%go.mod") as {
      data: Array<{ file_path:string; content_hash:string; risk_indicators:string[] }> | null
    };

  if (!manifests || manifests.length === 0) {
    return NextResponse.json({ message:"No dependency manifests found in this scan", nodes:[], edges:[], stats:{total:0,vulnerable:0,hallucinated:0,critical:0,high:0} });
  }

  // Use existing vulnerability findings as proxy for the graph
  const { data: secrets } = await db
    .from("secret_findings")
    .select("file_path, label")
    .eq("scan_id", scanId) as { data: Array<{ file_path:string; label:string }> | null };

  const aiIntroduced = new Set((manifests ?? []).filter(m => m.risk_indicators.length > 0).map(m => m.file_path.toLowerCase()));

  // Return a summary without actual content (content not stored in DB)
  return NextResponse.json({
    message: `Found ${manifests.length} manifest file(s). Use POST with file content for full graph analysis.`,
    manifest_files: manifests.map(m => m.file_path),
    secret_findings: (secrets ?? []).length,
    ai_touched_manifests: Array.from(aiIntroduced),
  });
}
