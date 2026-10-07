/**
 * The regex LDAP rule for template literals (`filter = \`(uid=${x})\``) needs an LDAP clause before the
 * interpolation: a CSS `filter: \`drop-shadow(0 0 6px ${color}88)\`` style is not an LDAP filter.
 */
import { runScan, LDAP_INJECT_RE } from "@/lib/scanner";

const ldapLines = (path: string, content: string) =>
  (runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] }).files[0]?.indicators ?? [])
    .filter(i => i.id === "ldap-injection").map(i => i.line);
const ruleMatches = (line: string) => LDAP_INJECT_RE.some(re => re.test(line));

describe("ldap-injection: template-literal filters", () => {
  it("the rule matches interpolated LDAP filters, any comparison operator", () => {
    for (const line of [
      "const filter = `(uid=${req.query.u})`;",
      "const opts = { filter: `(&(objectClass=user)(cn=${name}))` };",
      "const searchFilter = `(displayName~=${q})`;",
      "const ldapFilter = `(createTimestamp>=${since})`;",
      "const filter = `( sAMAccountName = ${user} )`;",
    ]) expect([line, ruleMatches(line)]).toEqual([line, true]);
  });

  it("the rule does not match CSS filter styles or a filter with no LDAP clause", () => {
    for (const line of [
      "const s = { filter: `drop-shadow(0 0 6px ${color}88)` };",
      "el.style.filter = `blur(${px}px) hue-rotate(${deg}deg)`;",
      "const filter = `${field} = ${value}`;",
      "const filter = `type=${t}&page=${p}`;",
      "channel.on(\"postgres_changes\", { event: \"*\", schema: \"public\", table: \"scans\", filter: `org_id=eq.${orgId}` }, cb);",
    ]) expect([line, ruleMatches(line)]).toEqual([line, false]);
  });

  it("end to end: reported for an LDAP filter, not for the landing page's CSS filter", () => {
    expect(ldapLines("src/ldap.js", "const filter = `(uid=${req.query.u})`;\nclient.search('dc=x', { filter });\n")).toContain(1);
    expect(ldapLines("src/ldap.js", "const opts = { filter: `(&(objectClass=user)(cn=${name}))` };\n")).toContain(1);
    expect(ldapLines("src/Gauge.tsx", "const s = { filter: `drop-shadow(0 0 6px ${color}88)` };\n")).toEqual([]);
    expect(ldapLines("src/Card.tsx", "el.style.filter = `blur(${px}px) hue-rotate(${deg}deg)`;\n")).toEqual([]);
  });
});
