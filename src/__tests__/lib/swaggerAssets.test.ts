/**
 * @jest-environment node
 *
 * /docs/api loads Swagger UI from a public CDN. It must stay pinned to an exact version with Subresource Integrity,
 * so a tampered package is refused by the browser instead of running on our origin.
 */
import * as fs from "fs";
import * as path from "path";
import { SWAGGER_VERSION, SWAGGER_CSS_URL, SWAGGER_JS_URL, SWAGGER_CSS_SRI, SWAGGER_JS_SRI } from "@/lib/swaggerAssets";

const PAGE = fs.readFileSync(path.join(__dirname, "../../app/docs/api/page.tsx"), "utf8");

describe("Swagger UI CDN assets are pinned and integrity-checked", () => {
  it("uses an exact x.y.z version, not a floating range", () => {
    expect(SWAGGER_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(SWAGGER_CSS_URL).toBe(`https://unpkg.com/swagger-ui-dist@${SWAGGER_VERSION}/swagger-ui.css`);
    expect(SWAGGER_JS_URL).toBe(`https://unpkg.com/swagger-ui-dist@${SWAGGER_VERSION}/swagger-ui-bundle.js`);
  });
  it("has a well-formed sha384 hash for each file (48 bytes, base64)", () => {
    for (const sri of [SWAGGER_CSS_SRI, SWAGGER_JS_SRI]) {
      expect(sri).toMatch(/^sha384-[A-Za-z0-9+/]{64}$/);
    }
    expect(SWAGGER_CSS_SRI).not.toBe(SWAGGER_JS_SRI);
  });
  it("the page loads both files through the pinned constants with integrity + crossOrigin, and has no raw unpkg URL", () => {
    expect(PAGE).not.toMatch(/unpkg\.com/);
    expect(PAGE).toMatch(/link\.href\s*=\s*SWAGGER_CSS_URL/);
    expect(PAGE).toMatch(/link\.integrity\s*=\s*SWAGGER_CSS_SRI/);
    expect(PAGE).toMatch(/link\.crossOrigin\s*=\s*"anonymous"/);
    expect(PAGE).toMatch(/src=\{SWAGGER_JS_URL\}/);
    expect(PAGE).toMatch(/integrity=\{SWAGGER_JS_SRI\}/);
    expect(PAGE).toMatch(/crossOrigin="anonymous"/);
  });
});
