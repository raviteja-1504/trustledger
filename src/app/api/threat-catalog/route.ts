import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { DEFAULT_THREATS } from "@/lib/threatCatalog";
import type { ThreatEntry } from "@/lib/threatCatalog";

export async function GET(_req: NextRequest) {
  try {
    const db = createServiceClient();
    const { data, error } = await db.from("threat_catalog").select("*").order("id");
    if (error || !data || data.length === 0) throw new Error("no data");

    const threats: ThreatEntry[] = data.map(row => ({
      id:                 row.id,
      cve:                row.cve          ?? undefined,
      title:              row.title,
      description:        row.description,
      severity:           row.severity,
      category:           row.category,
      status:             row.status,
      cvss:               row.cvss         != null ? Number(row.cvss)       : undefined,
      epss_score:         row.epss_score   != null ? Number(row.epss_score) : undefined,
      mitre_tactic:       row.mitre_tactic     ?? undefined,
      mitre_technique:    row.mitre_technique  ?? undefined,
      sla_hours:          row.sla_hours        ?? undefined,
      published:          String(row.published),
      last_updated:       String(row.last_updated),
      affected_pattern:   row.affected_pattern,
      affected_languages: row.affected_languages ?? [],
      in_your_codebase:   row.in_your_codebase,
      exploit_available:  row.exploit_available,
      exploit_in_wild:    row.exploit_in_wild,
      references:         row.refs        ?? [],
      mitigation:         row.mitigation,
      ai_specific:        row.ai_specific,
      relevance_score:    row.relevance_score,
    }));
    return NextResponse.json({ threats });
  } catch {
    return NextResponse.json({ threats: DEFAULT_THREATS });
  }
}
