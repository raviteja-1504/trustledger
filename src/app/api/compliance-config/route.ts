import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { makeFrameworks, CROSS_FRAMEWORK_THEMES } from "@/lib/complianceConfig";
import type { FrameworkDef, CrossFrameworkTheme } from "@/lib/complianceConfig";

export async function GET(req: NextRequest) {
  const org = new URL(req.url).searchParams.get("org") ?? "novapay";
  try {
    const db = createServiceClient();
    const [framesRes, themesRes] = await Promise.all([
      db.from("compliance_frameworks").select("*").order("sort_order"),
      db.from("compliance_cross_themes").select("*").order("sort_order"),
    ]);
    if (framesRes.error || !framesRes.data?.length) throw new Error("no data");

    // Substitute {{ORG}} placeholder stored in controls JSONB
    const rawFrames = JSON.parse(
      JSON.stringify(framesRes.data).replace(/\{\{ORG\}\}/g, org),
    ) as Array<Record<string, unknown>>;

    const frameworks: FrameworkDef[] = rawFrames.map(r => ({
      id:        r.id        as string,
      shortName: r.short_name as string,
      fullName:  r.full_name  as string,
      standard:  r.standard   as string,
      color:     r.color      as string,
      gradient:  r.gradient   as string,
      headerBg:  r.header_bg  as string,
      certBody:  r.cert_body  as string,
      nextAudit: r.next_audit as string,
      ...(r.cert_expiry ? { certExpiry: r.cert_expiry as string } : {}),
      controls:  r.controls   as FrameworkDef["controls"],
    }));

    const crossFrameworkThemes: CrossFrameworkTheme[] = (themesRes.data ?? []).map(r => ({
      theme:       r.theme       as string,
      description: r.description as string,
      controls:    r.controls    as CrossFrameworkTheme["controls"],
    }));

    return NextResponse.json({ frameworks, crossFrameworkThemes });
  } catch {
    return NextResponse.json({
      frameworks:           makeFrameworks(org),
      crossFrameworkThemes: CROSS_FRAMEWORK_THEMES,
    });
  }
}
