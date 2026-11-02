/**
 * @jest-environment node
 *
 * Secret finding labels: patterns already named "Hardcoded …" are not prefixed twice ("Hardcoded Hardcoded
 * password"), and labels stored before the fix are tidied when shown.
 */
import { analyzeFile } from "@/lib/scanner";
import { tidySecretLabel } from "@/lib/findingCatalog";

describe("secret labels", () => {
  it("a password pattern reads 'Hardcoded password', and a private key still gets its prefix", () => {
    const labels = analyzeFile("src/db.ts", 'const db = connect({ password: "Zr8#qLm2Vw7!pTx4" });\n').indicators
      .filter(i => i.id === "hardcoded-secret").map(i => i.label);
    expect(labels).toContain("Hardcoded password");
    expect(labels.some(l => /Hardcoded\s+Hardcoded/i.test(l))).toBe(false);
  });

  it("stored labels are tidied for display; correct ones are left alone", () => {
    expect(tidySecretLabel("Hardcoded Hardcoded secret")).toBe("Hardcoded secret");
    expect(tidySecretLabel("Hardcoded hardcoded password")).toBe("hardcoded password");
    expect(tidySecretLabel("Hardcoded Private key")).toBe("Hardcoded Private key");
    expect(tidySecretLabel("Hardcoded credential in .properties file")).toBe("Hardcoded credential in .properties file");
  });
});
