/**
 * The literal TEXT of every string, template and JSX text in a parsed JS/TS file, as [start, end) inside the quotes
 * -- a template's `${…}` substitutions are code and are kept. scanner.ts blanks these for detectors that look for
 * calls: a call written inside a string ("eval() runs arbitrary code", a sample shown in the UI, a title template)
 * is text, not a call.
 */
import ts from "typescript";

export function stringTextSpans(sf: ts.SourceFile): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  const inner = (n: ts.Node, open: number, close: number) => {
    const s = n.getStart(sf) + open, e = n.end - close;
    if (e > s) spans.push([s, e]);
  };
  const visit = (n: ts.Node): void => {
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) return inner(n, 1, 1);
    if (n.kind === ts.SyntaxKind.TemplateHead) return inner(n, 1, 2);          // `text${
    if (n.kind === ts.SyntaxKind.TemplateMiddle) return inner(n, 1, 2);        // }text${
    if (n.kind === ts.SyntaxKind.TemplateTail) return inner(n, 1, 1);          // }text`
    if (ts.isJsxText(n)) return inner(n, 0, 0);
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return spans;
}
