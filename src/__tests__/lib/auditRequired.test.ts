/**
 * @jest-environment node
 *
 * P0.4: a route that records a REQUIRED audit event (role changes, API keys, policy/config changes, attestations, exports,
 * destructive actions) must use requireAudit() -- the action fails, or is undone, when its audit entry cannot be written.
 * This scans the source: a new route writing one of these events through the best-effort writeAuditLog() fails here.
 */
import fs from "fs";
import path from "path";
import ts from "typescript";
import { REQUIRED_AUDIT_EVENTS } from "@/lib/audit";

const ROOT = path.join(__dirname, "../..");

function walk(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]);
}
const files = [...walk(path.join(ROOT, "app/api")), ...walk(path.join(ROOT, "lib"))]
  .filter(f => /\.(ts|tsx)$/.test(f) && !f.endsWith(`${path.sep}audit.ts`) && !f.endsWith(`${path.sep}auditRequired.ts`));

interface Site { file: string; line: number; events: string[]; call: "writeAuditLog" | "requireAudit"; bestEffort: boolean; strict: boolean }

function sites(): Site[] {
  const out: Site[] = [];
  for (const file of files) {
    const src = fs.readFileSync(file, "utf8");
    if (!/writeAuditLog|requireAudit/.test(src)) continue;
    const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true);
    const visit = (node: ts.Node) => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && (node.expression.text === "writeAuditLog" || node.expression.text === "requireAudit")) {
        const arg = node.arguments[1];
        const events: string[] = [];
        if (arg && ts.isObjectLiteralExpression(arg)) {
          for (const p of arg.properties) {
            if (ts.isPropertyAssignment(p) && p.name.getText(sf) === "event_type") {
              const collect = (n: ts.Node) => { if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) events.push(n.text); ts.forEachChild(n, collect); };
              collect(p.initializer);
            }
          }
        }
        // the call's own statement, including the comments just above it
        let stmt: ts.Node = node;
        while (stmt.parent && !ts.isExpressionStatement(stmt) && !ts.isVariableStatement(stmt) && !ts.isReturnStatement(stmt) && !ts.isBlock(stmt.parent)) stmt = stmt.parent;
        out.push({
          file: path.relative(ROOT, file).split(path.sep).join("/"), line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1, events,
          call: node.expression.text as Site["call"],
          // best effort on purpose (marked), or an explicit strict write ({ strict: true }) that throws when it fails
          bestEffort: /audit: best-effort/.test(stmt.getFullText(sf)),
          strict: !!node.arguments[2] && /strict:\s*true/.test(node.arguments[2].getText(sf)),
        });
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return out;
}

describe("required audit events", () => {
  const all = sites();

  it("finds the call sites (the scan itself works)", () => {
    expect(all.length).toBeGreaterThan(40);
    expect(all.some(s => s.call === "requireAudit" && s.events.includes("api_key_created"))).toBe(true);
  });

  it("no route writes a required event through the best-effort writeAuditLog (unless marked 'audit: best-effort' on purpose)", () => {
    const bad = all
      .filter(s => s.call === "writeAuditLog" && !s.bestEffort && !s.strict && s.events.some(e => REQUIRED_AUDIT_EVENTS.has(e as never)))
      .map(s => `${s.file}:${s.line}  ${s.events.join("|")}`);
    expect(bad).toEqual([]);
  });

  it("requireAudit is only used for events in the required set", () => {
    const stray = all.filter(s => s.call === "requireAudit" && !s.events.some(e => REQUIRED_AUDIT_EVENTS.has(e as never))).map(s => `${s.file}:${s.line}  ${s.events.join("|")}`);
    expect(stray).toEqual([]);
  });

  it("a best-effort marker is used only on a required event it really applies to", () => {
    const useless = all.filter(s => s.bestEffort && !s.events.some(e => REQUIRED_AUDIT_EVENTS.has(e as never))).map(s => `${s.file}:${s.line}`);
    expect(useless).toEqual([]);
  });
});
