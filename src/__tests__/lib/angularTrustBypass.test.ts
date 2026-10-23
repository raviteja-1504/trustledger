/**
 * Angular DomSanitizer trust bypasses (found testing OWASP Juice Shop): Html, Script, ResourceUrl and Url hand a
 * value to the browser without Angular's sanitizing; only a constant argument is the safe, common use.
 */
import { analyzeFile } from "@/lib/scanner";

const xssLines = (body: string) => {
  const src = `import { DomSanitizer } from '@angular/platform-browser'\nexport class SearchResultComponent {\n  constructor (private readonly sanitizer: DomSanitizer, private readonly route: ActivatedRoute) {}\n  filterTable () {\n    const queryParam: string = this.route.snapshot.queryParams.q\n    ${body}\n  }\n}\n`;
  return analyzeFile("frontend/src/app/search-result/search-result.component.ts", src).indicators.filter(i => i.id === "xss").map(i => i.line);
};

describe("Angular trust bypasses", () => {
  it.each(["Html", "Script", "ResourceUrl", "Url"])("bypassSecurityTrust%s on a variable is XSS", kind => {
    expect(xssLines(`this.searchValue = this.sanitizer.bypassSecurityTrust${kind}(queryParam)`)).toEqual([6]);
  });

  it("a constant URL (embedding a fixed video) is not reported", () => {
    expect(xssLines(`this.video = this.sanitizer.bypassSecurityTrustResourceUrl('https://www.youtube.com/embed/abc123')`)).toEqual([]);
    expect(xssLines(`this.link = this.sanitizer.bypassSecurityTrustUrl("/help")`)).toEqual([]);
  });

  it("Style (CSS injection, not script) and made-up names (Juice Shop's distractors) are not XSS", () => {
    expect(xssLines(`this.searchValue = this.sanitizer.bypassSecurityTrustStyle(queryParam)`)).toEqual([]);
    expect(xssLines(`this.searchValue = this.sanitizer.bypassSecurityTrustSoundCloud(queryParam)`)).toEqual([]);
    expect(xssLines(`this.searchValue = this.sanitizer.bypassSecurityTrustIframe(queryParam)`)).toEqual([]);
  });
});
