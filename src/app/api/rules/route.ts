/**
 * Rule catalog API
 *
 * GET /api/rules → every rule the scanner can report (lib/ruleCatalog.ts). Static per deploy, so it is built
 * once per server instance.
 */
import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "../_middleware";
import { buildRuleCatalog, type CatalogRule } from "@/lib/ruleCatalog";

let cachedRules: CatalogRule[] | null = null;

export async function GET(req: NextRequest) {
  const { error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });
  cachedRules ??= buildRuleCatalog();
  return NextResponse.json({ rules: cachedRules });
}
