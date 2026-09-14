/**
 * Benchmark against REAL WebGoat source (not synthetic snippets) — the
 * files here are unmodified copies (GPL-2.0-or-later, OWASP WebGoat) pulled
 * directly from github.com/WebGoat/WebGoat, used as a public security
 * training app's own regression corpus. Ground truth below was established
 * by hand-reading each file, not by trusting the filename/lesson name —
 * several WebGoat files whose names suggest a vulnerability (IDOR.java,
 * PathTraversal.java, SSRF.java, etc.) turn out to be pure lesson-metadata
 * stubs with no actual sink, while the real vulnerable code lives in a
 * differently-named sibling class. That mismatch is itself a documented
 * finding, not an oversight — see the Phase 3 report.
 *
 * Measured result at the time this suite was written: 4 of 6 files with a
 * directly-visible (non-interprocedural) vulnerability were caught, 0 false
 * positives across all 8 files. The 2 misses are real, known limitations
 * (cross-method taint, an object-construction IDOR shape) that need actual
 * interprocedural/AST analysis to fix safely — not something to patch with
 * a broader regex, which would trade false negatives for false positives.
 */
import fs from "fs";
import path from "path";
import { analyzeFile } from "@/lib/scanner";

const FIXTURE_DIR = path.join(__dirname, "..", "fixtures", "webgoat-real");
function load(name: string): string {
  return fs.readFileSync(path.join(FIXTURE_DIR, name), "utf8");
}

describe("scanner benchmark — real WebGoat source (ground truth hand-verified)", () => {
  it("SqlInjectionLesson6a.java: string-concatenated SELECT built from @RequestParam", () => {
    const result = analyzeFile("SqlInjectionLesson6a.java", load("SqlInjectionLesson6a.java"));
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(true);
  });

  it("SqlInjectionChallenge.java: unsafe Statement.executeQuery next to a SAFE PreparedStatement in the same file (precision check)", () => {
    const result = analyzeFile("SqlInjectionChallenge.java", load("SqlInjectionChallenge.java"));
    const sqli = result.indicators.filter(i => i.id === "sql-injection");
    expect(sqli.length).toBeGreaterThan(0);
    // The PreparedStatement.setString(...) call a few lines below the real
    // injection must NOT also be flagged -- that's the parameterised-query
    // path this exact lesson is contrasting against.
    expect(sqli.every(i => (i.line ?? 0) < 65)).toBe(true);
  });

  it("JWTRefreshEndpoint.java: two hardcoded JWT signing secrets", () => {
    const result = analyzeFile("JWTRefreshEndpoint.java", load("JWTRefreshEndpoint.java"));
    const secrets = result.indicators.filter(i => i.id === "hardcoded-secret");
    expect(secrets.length).toBeGreaterThanOrEqual(2);
    // The defensive `"none".equals(jwt.getHeader().get("alg"))` check later
    // in this same file (the student verifying the alg==none bypass) must
    // NOT itself be flagged as a jwt-none-alg vulnerability -- it's the
    // opposite: code checking for the attack, not code enabling it.
    expect(result.indicators.some(i => i.id === "jwt-none-alg")).toBe(false);
  });

  it("CommentsCache.java: XMLInputFactory (StAX) XXE, conditionally-disabled protection", () => {
    const result = analyzeFile("CommentsCache.java", load("CommentsCache.java"));
    expect(result.indicators.some(i => i.id === "xxe")).toBe(true);
  });

  it("SSRFTask1.java: no real outbound-fetch sink in the visible code -- must NOT false-positive", () => {
    const result = analyzeFile("SSRFTask1.java", load("SSRFTask1.java"));
    expect(result.indicators.some(i => i.id === "ssrf")).toBe(false);
  });

  it("BlindSendFileAssignment.java: delegates XML parsing to CommentsCache -- no direct sink here, must NOT false-positive", () => {
    const result = analyzeFile("BlindSendFileAssignment.java", load("BlindSendFileAssignment.java"));
    expect(result.indicators.some(i => i.id === "xxe")).toBe(false);
  });

  // ── Known, documented misses (not fixed here) ──────────────────────────
  // These assertions describe the CURRENT (imperfect) behavior, not the
  // desired one -- they exist so a future fix is a deliberate, visible
  // change to this test, not a silent behavior shift discovered by accident.

  it("KNOWN MISS — ProfileUploadBase.java: path traversal where the tainted param crosses a method boundary from a sibling class", () => {
    const result = analyzeFile("ProfileUploadBase.java", load("ProfileUploadBase.java"));
    // `new File(uploadDirectory, fullName)` at line 51 -- `fullName` is a
    // plain method parameter here, populated by @RequestParam in
    // ProfileUpload.java (a different file). No regex/same-file taint
    // pattern can see across that boundary; this needs real interprocedural
    // analysis. Documenting the miss rather than reaching for a
    // false-positive-prone "any new File(dir, anyParam)" pattern.
    expect(result.indicators.some(i => i.id === "path-traversal")).toBe(false);
  });

  it("KNOWN MISS — IDORViewOtherProfile.java: IDOR via direct object construction, not a repository lookup", () => {
    const result = analyzeFile("IDORViewOtherProfile.java", load("IDORViewOtherProfile.java"));
    // `new UserProfile(userId)` where userId is @PathVariable-bound, behind
    // a bypassable session check -- findIDORJava only recognizes
    // .findById()/.getOne()/.getById() repository-shaped sinks (a Spring
    // Data pattern), not arbitrary constructor calls. Broadening to "any
    // constructor fed by a path variable" would be extremely noisy (most
    // such calls are legitimate) without real ownership-check analysis.
    expect(result.indicators.some(i => i.id === "idor")).toBe(false);
  });
});
