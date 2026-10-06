/**
 * Per-language sanitizer tables, keyed by the sink classes each one actually
 * neutralizes. Replaces six flat name sets that cleared taint for EVERY sink
 * class -- html.escape/Encode.forHtml/htmlspecialchars silently cleared SQL,
 * command and path taint too (a false negative), and filter_var cleared
 * regardless of its filter constant.
 *
 * Contract (unchanged from before): an OPAQUE call -- one not in these
 * tables and not a known propagating function -- still returns untainted.
 * Flipping that default is a separate, large false-positive decision. What
 * changed is what a KNOWN sanitizer does: it now returns
 * `argMask & ~clears` instead of a hard clear, so the classes it does not
 * neutralize stay tainted.
 */

import { ALL, SinkClass as C, URL_SAFE } from "./taintCore";

export type SanitizerLang = "js" | "py" | "go" | "java" | "cs" | "php" | "rb" | "kt";

/** A fixed mask, or a function of the callee text and argument source texts
 * (for entries whose effect depends on a receiver or a flag argument). */
type Clears = number | ((callee: string, args: readonly string[]) => number);

interface Table { exact: Record<string, Clears>; tail: Record<string, Clears> }

const XSS = C.XSS;
const NUMERIC = ALL & ~C.CONTROL; // coercion to a number/bool/uuid neutralizes every INJECTION class (not "attacker-controlled")
/** Exported for engines that model numeric CASTS (C# `(int)x`, PHP `(int)$x`) rather than calls. */
export const NUMERIC_CLEARS = NUMERIC;

const TABLES: Record<SanitizerLang, Table> = {
  js: {
    exact: {
      "DOMPurify.sanitize": XSS, "sanitizeHtml": XSS, "he.encode": XSS, "he.escape": XSS,
      "escapeHtml": XSS, "xss": XSS, "validator.escape": XSS, "_.escape": XSS, "lodash.escape": XSS,
      "encodeURIComponent": URL_SAFE, "encodeURI": C.REDIRECT | C.HEADER,
      "path.basename": C.PATH,
      "parseInt": NUMERIC, "parseFloat": NUMERIC, "Number": NUMERIC, "Boolean": NUMERIC, "BigInt": NUMERIC,
      // String(x) keeps every string-injection class but defeats operator-object (NoSQL) injection
      "String": C.NOSQL,
      // mysql/mysql2/node-mysql `Connection.escape(value)` (also exposed as the standalone `mysql.escape`),
      // and the `sqlstring` package's own `SqlString.escape` -- quote-escapers, valid only inside a quoted
      // string literal (see taint/sinkShape.ts's assessSqlInjection for the position check that consumes this).
      "mysql.escape": C.SQL, "connection.escape": C.SQL, "pool.escape": C.SQL, "SqlString.escape": C.SQL,
      "sqlstring.escape": C.SQL,
    },
    tail: {},
  },
  py: {
    exact: {
      "markupsafe.escape": XSS, "Markup.escape": XSS, "bleach.clean": XSS, "html.escape": XSS,
      "django.utils.html.escape": XSS, "flask.escape": XSS, "escape": XSS, "escape_html": XSS, "html_escape": XSS,
      "sanitize_html": XSS, "escape_for_html": XSS,
      // str(x) keeps every string-injection class but defeats operator-object (NoSQL) injection
      "str": C.NOSQL,
      // pymysql/MySQLdb quote-escapers -- valid only inside a quoted string literal (see
      // taint/sinkShape.ts's assessSqlInjection for the position check that consumes this).
      "pymysql.escape_string": C.SQL, "MySQLdb.escape_string": C.SQL, "escape_string": C.SQL,
      "shlex.quote": C.CMD,
      "os.path.basename": C.PATH, "werkzeug.utils.secure_filename": C.PATH, "secure_filename": C.PATH,
      "urllib.parse.quote": URL_SAFE, "urllib.parse.quote_plus": URL_SAFE,
      "int": NUMERIC, "float": NUMERIC, "bool": NUMERIC, "uuid.UUID": NUMERIC,
    },
    tail: {},
  },
  go: {
    exact: {
      "html.EscapeString": XSS, "template.HTMLEscapeString": XSS, "template.JSEscapeString": XSS,
      "url.QueryEscape": URL_SAFE, "url.PathEscape": URL_SAFE,
      "filepath.Base": C.PATH, "path.Base": C.PATH,
      "strconv.Atoi": NUMERIC, "strconv.ParseInt": NUMERIC, "strconv.ParseUint": NUMERIC,
      "strconv.ParseFloat": NUMERIC, "strconv.ParseBool": NUMERIC,
    },
    tail: {},
  },
  java: {
    exact: {},
    tail: {
      forHtml: XSS, forHtmlAttribute: XSS, forHtmlContent: XSS, forJavaScript: XSS,
      forUriComponent: URL_SAFE, encodeForHTML: XSS, encodeForJavaScript: XSS,
      escapeHtml4: XSS, escapeHtml3: XSS, htmlEscape: XSS, escapeXml10: XSS, escapeXml11: XSS,
      encodeForSQL: C.SQL, encodeForOS: C.CMD, encodeForLDAP: C.LDAP, encodeForXPath: C.XPATH,
      parseInt: NUMERIC, parseLong: NUMERIC, parseDouble: NUMERIC, parseBoolean: NUMERIC,
    },
  },
  cs: {
    exact: {},
    tail: {
      HtmlEncode: XSS, JavaScriptStringEncode: XSS, UrlEncode: URL_SAFE, EscapeDataString: URL_SAFE,
      GetFileName: C.PATH,
      // Receiver-aware: `Encode` alone is also Base64/other encoders that
      // neutralize nothing -- only the web encoders do.
      Encode: (callee) =>
        /HtmlEncoder/.test(callee) ? XSS
          : /JavaScriptEncoder/.test(callee) ? XSS
            : /UrlEncoder/.test(callee) ? URL_SAFE : 0,
      // Only numeric/bool/Guid parsers -- JObject.Parse/Uri.Parse etc. return
      // attacker-shaped data and must stay tainted.
      Parse: (callee) =>
        /^(?:int|long|short|byte|double|float|decimal|bool|Guid|Int32|Int64|Int16|Double|Single|Decimal|Boolean)\.Parse$/.test(callee) ? NUMERIC : 0,
      ToInt32: NUMERIC, ToInt64: NUMERIC, ToDouble: NUMERIC, ToBoolean: NUMERIC, ToDecimal: NUMERIC,
    },
  },
  php: {
    exact: {
      htmlspecialchars: XSS, htmlentities: XSS, strip_tags: XSS,
      escapeshellarg: C.CMD, escapeshellcmd: C.CMD,
      mysqli_real_escape_string: C.SQL,
      basename: C.PATH,
      urlencode: URL_SAFE, rawurlencode: URL_SAFE,
      intval: NUMERIC, floatval: NUMERIC, boolval: NUMERIC, abs: NUMERIC,
      // filter_var neutralizes nothing by itself: what it does depends
      // entirely on the filter constant (2nd arg). FILTER_DEFAULT /
      // FILTER_UNSAFE_RAW / an omitted filter clear nothing.
      filter_var: (_callee, args) => {
        const f = args[1] ?? "";
        if (/FILTER_VALIDATE_(?:INT|FLOAT|BOOLEAN|BOOL|IP|EMAIL|MAC)\b/.test(f)) return NUMERIC;
        if (/FILTER_SANITIZE_NUMBER_(?:INT|FLOAT)\b/.test(f)) return NUMERIC;
        if (/FILTER_SANITIZE_(?:SPECIAL_CHARS|FULL_SPECIAL_CHARS|ENCODED)\b/.test(f)) return XSS;
        return 0;
      },
    },
    // Receiver-style sanitizers: mysqli->real_escape_string, PDO->quote.
    tail: { real_escape_string: C.SQL, quote: C.SQL },
  },
  // Ruby: function-style calls only. Method-on-receiver conversions (x.to_i, x.shellescape) are modelled in
  // astTaintRuby.ts, where the receiver -- not an argument -- is the value being cleared.
  rb: {
    exact: {
      "ERB::Util.html_escape": XSS, "ERB::Util.h": XSS, "CGI.escapeHTML": XSS, "Rack::Utils.escape_html": XSS,
      "h": XSS, "html_escape": XSS, "sanitize": XSS, "strip_tags": XSS, "escape_javascript": XSS, "j": XSS,
      "Loofah.fragment": XSS, "Rails::Html::FullSanitizer.new.sanitize": XSS,
      "Shellwords.escape": C.CMD, "Shellwords.shellescape": C.CMD, "Shellwords.join": C.CMD,
      "File.basename": C.PATH,
      "CGI.escape": URL_SAFE, "ERB::Util.url_encode": URL_SAFE, "ERB::Util.u": URL_SAFE, "URI.encode_www_form_component": URL_SAFE,
      "Rack::Utils.escape": URL_SAFE, "Rack::Utils.escape_path": URL_SAFE,
      "Integer": NUMERIC, "Float": NUMERIC, "Rational": NUMERIC, "Complex": NUMERIC, "BigDecimal": NUMERIC,
      // These return a complete, safely quoted SQL fragment (a literal, not an escaped substring).
      "ActiveRecord::Base.sanitize_sql": C.SQL, "ActiveRecord::Base.sanitize_sql_array": C.SQL,
      "sanitize_sql": C.SQL, "sanitize_sql_array": C.SQL, "sanitize_sql_for_conditions": C.SQL,
    },
    // connection.quote / ActiveRecord::Base.connection.quote / conn.quote_string
    tail: { quote: C.SQL, quote_string: C.SQL, quote_column_name: C.SQL, quote_table_name: C.SQL },
  },
  // Kotlin runs on the JVM and calls the same libraries: Java's tail table, plus JVM/Kotlin calls whose tail alone
  // is too generic to trust (`encode`, `fromString`, `getName`, `clean`). Receiver conversions (x.toInt()) are
  // modelled in astTaintKotlin.ts.
  kt: {
    exact: {
      "URLEncoder.encode": URL_SAFE, "UriUtils.encode": URL_SAFE, "UriUtils.encodePathSegment": URL_SAFE,
      "UriUtils.encodeQueryParam": URL_SAFE,
      "UUID.fromString": NUMERIC, "Integer.valueOf": NUMERIC, "Long.valueOf": NUMERIC, "BigDecimal": NUMERIC,
      "FilenameUtils.getName": C.PATH, "StringUtils.cleanPath": 0,
      "Jsoup.clean": XSS, "HtmlUtils.htmlEscape": XSS, "StringEscapeUtils.escapeHtml4": XSS, "Encode.forHtml": XSS,
      "Regex.escape": 0, "Pattern.quote": 0,
    },
    tail: {
      forHtml: XSS, forHtmlAttribute: XSS, forHtmlContent: XSS, forJavaScript: XSS,
      forUriComponent: URL_SAFE, encodeForHTML: XSS, encodeForJavaScript: XSS,
      escapeHtml4: XSS, escapeHtml3: XSS, htmlEscape: XSS, escapeXml10: XSS, escapeXml11: XSS,
      encodeForSQL: C.SQL, encodeForOS: C.CMD, encodeForLDAP: C.LDAP, encodeForXPath: C.XPATH,
      parseInt: NUMERIC, parseLong: NUMERIC, parseDouble: NUMERIC, parseBoolean: NUMERIC,
    },
  },
};

/**
 * Classes neutralized by calling `calleeText` (with the given argument source
 * texts), or `null` if it is not a known sanitizer at all. `0` means "known
 * name, but this particular use neutralizes nothing" (e.g. filter_var with
 * FILTER_DEFAULT) -- distinct from null only in that the value still passes
 * THROUGH the call instead of being treated as opaque.
 */
export function sanitizerClears(
  lang: SanitizerLang, calleeText: string, args: readonly string[] = [],
): number | null {
  const table = TABLES[lang];
  const tailName = calleeText.split(".").pop() ?? calleeText;
  // Own-property lookups only: these are plain objects, so a bare
  // `table.exact["toString"]`/["constructor"] would otherwise hit
  // Object.prototype and read a real (non-sanitizer) function as a match.
  const has = (o: Record<string, Clears>, k: string) => Object.prototype.hasOwnProperty.call(o, k);
  const entry = has(table.exact, calleeText) ? table.exact[calleeText]
    : has(table.tail, tailName) ? table.tail[tailName]
      : undefined;
  if (entry === undefined) return null;
  return typeof entry === "function" ? entry(calleeText, args) : entry;
}
