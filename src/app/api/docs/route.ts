import { NextResponse } from "next/server";
import { OPENAPI_SPEC } from "@/lib/openapi";

export async function GET() {
  return NextResponse.json(OPENAPI_SPEC, {
    headers: { "Access-Control-Allow-Origin": "*" },
  });
}
