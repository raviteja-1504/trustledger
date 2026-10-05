/**
 * Write-route authorization audit: every POST/PATCH/PUT/DELETE handler under src/app/api must check what
 * the caller may do -- requirePermission / requireRole / permissionsFor / a custom gate() -- or be on the
 * reviewed list in routeAuthorization.test.ts (webhooks verified by signature, cron jobs, own-account routes).
 *
 *   node scripts/routeAuthAudit.cjs     → handlers with no check
 */
const fs = require("fs");
const path = require("path");
const ts = require("typescript");

const API = path.join(__dirname, "..", "src", "app", "api");
const WRITE = new Set(["POST", "PATCH", "PUT", "DELETE"]);
/** Calls that count as an authorization check inside a handler (or a helper it calls). */
const CHECKS = /\b(requirePermission|requireRole|requirePlatformAdmin|permissionsFor|gate)\s*\(/;

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]);
}

function audit() {
  const out = [];
  for (const file of walk(API).filter(f => /route\.ts$/.test(f))) {
    const src = fs.readFileSync(file, "utf8");
    const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true);
    // Same-file helpers a handler delegates to (e.g. POST → runWithTrace(() => handle(req))) count as its body.
    const local = new Map();
    for (const st of sf.statements) if (ts.isFunctionDeclaration(st) && st.name && st.body) local.set(st.name.text, st.body.getText(sf));
    const withHelpers = (text, seen) => {
      let all = text;
      for (const [name, body] of local) {
        if (seen.has(name) || !new RegExp(String.raw`\b${name}\s*\(`).test(text)) continue;
        seen.add(name);
        all += "\n" + withHelpers(body, seen);
      }
      return all;
    };
    for (const st of sf.statements) {
      if (!ts.isFunctionDeclaration(st) || !st.name || !WRITE.has(st.name.text)) continue;
      if (!st.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) continue;
      const body = st.body ? withHelpers(st.body.getText(sf), new Set([st.name.text])) : "";
      out.push({ route: path.relative(API, path.dirname(file)).replace(/\\/g, "/"), method: st.name.text, checked: CHECKS.test(body) });
    }
  }
  return out;
}

module.exports = { audit };

if (require.main === module) {
  const all = audit();
  const open = all.filter(h => !h.checked);
  console.log(`write handlers: ${all.length}  checked: ${all.length - open.length}  unchecked: ${open.length}`);
  for (const h of open) console.log(`${h.method.padEnd(6)} ${h.route}`);
}
