import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { EVENT_CONFIG, EVENT_SOC2 } from "@/lib/auditConfig";
import type { AuditEventType, AuditEventConfig } from "@/lib/auditConfig";

export async function GET(req: NextRequest) {
  try {
    const db = createServiceClient();
    const { data, error } = await db.from("audit_event_config").select("*");
    if (error || !data || data.length === 0) throw new Error("no data");

    const eventConfig = {} as Record<AuditEventType, AuditEventConfig>;
    const eventSoc2: Partial<Record<AuditEventType, string[]>> = {};

    for (const row of data) {
      const type = row.event_type as AuditEventType;
      eventConfig[type] = {
        label:  row.label,
        icon:   row.icon,
        bg:     row.bg,
        text:   row.text_color,
        border: row.border_color,
        dot:    row.dot_color,
      };
      if (row.soc2_controls?.length > 0) {
        eventSoc2[type] = row.soc2_controls as string[];
      }
    }

    return NextResponse.json({ eventConfig, eventSoc2 });
  } catch {
    return NextResponse.json({
      eventConfig: EVENT_CONFIG,
      eventSoc2:   EVENT_SOC2,
    });
  }
}
