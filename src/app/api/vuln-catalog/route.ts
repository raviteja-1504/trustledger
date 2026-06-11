import { NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { VULN_CATALOG } from "@/lib/vulnCatalog";
import type { CatalogEntry } from "@/lib/vulnCatalog";

export async function GET() {
  try {
    const db = createServiceClient();
    const { data, error } = await db.from("vuln_catalog").select("*");
    if (error || !data || data.length === 0) throw new Error("no data");

    const catalog: Record<string, CatalogEntry> = {};
    for (const row of data) {
      catalog[row.id] = {
        cve:           row.cve,
        cvss:          Number(row.cvss),
        cvss_vector:   row.cvss_vector  ?? undefined,
        epss_score:    row.epss_score   != null ? Number(row.epss_score) : undefined,
        severity:      row.severity,
        category:      row.category,
        cweId:         row.cwe_id,
        cweLabel:      row.cwe_label,
        title:         row.title,
        description:   row.description,
        patternDesc:   row.pattern_desc ?? "",
        remediation:   row.remediation,
        references:    row.refs         ?? [],
        secureRewrite: row.secure_rewrite ?? undefined,
      };
    }
    return NextResponse.json({ catalog });
  } catch {
    return NextResponse.json({ catalog: VULN_CATALOG });
  }
}
