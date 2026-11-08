/**
 * Propagator models: library calls that carry taint without validating or neutralising it (Universal Taint Model,
 * docs/taint/utm-gap-report.md §6.2, step 5). Each engine reads its sets from here (propagatorNames) instead of
 * keeping its own; `engineSet` names the constant it replaced. Names are as the engine matches them -- a full
 * callee (`path.join`, `strings.TrimSpace`), a method name (`replace`), or, for Java, a call's last segment.
 *
 * Moved verbatim (comments included) from the engines, so detection is unchanged. Opaque calls outside these
 * lists stay untainted -- that default is step 7's decision, not these lists'.
 */
import type { ModelLang } from "./types";

/** `call-args`: a function / constructor whose result carries its arguments (`path.join(a, b)`, `String(x)`);
 * `constructor-args`: the same for a `new` expression (JS); `method-args`: a method whose result carries its
 * arguments as well as its receiver (`s.replace(a, b)`); `mutator`: a method that writes its arguments into the
 * receiver (`sb.append(x)`, `list.push(x)`); `decoder`: undoes an encoding, so the classes an encoder cleared are
 * tainted again (`decodeURIComponent`). */
export type PropagatorKind = "call-args" | "constructor-args" | "method-args" | "mutator" | "decoder";

export interface PropagatorModel {
  id: string;
  lang: ModelLang;
  kind: PropagatorKind;
  /** The engine constant these names replaced. */
  engineSet: string;
  names: string[];
}

export const PROPAGATOR_MODELS: readonly PropagatorModel[] = [
  { id: "js:call-args", lang: "js", kind: "call-args", engineSet: "astTaint.PASSTHROUGH_CALLS",
    names: [
    "String", "JSON.parse", "JSON.stringify", "Buffer.from", "Buffer.concat", "path.join", "path.resolve",
    "path.normalize", "path.format", "path.relative", "path.dirname", "Object.assign", "Object.values",
    "Object.entries", "Object.keys", "Object.fromEntries", "Array.from", "Array.of", "Promise.resolve",
    "Promise.all", "Promise.race", "Promise.allSettled", "String.raw", "structuredClone", "url.format",
    "querystring.stringify", "querystring.parse", "decodeURIComponent", "decodeURI", "unescape", "atob", "btoa",
    ] },
  { id: "js:decoder", lang: "js", kind: "decoder", engineSet: "astTaint.DECODERS",
    names: ["decodeURIComponent", "decodeURI", "unescape", "atob", "JSON.parse"] },
  { id: "js:constructor-args", lang: "js", kind: "constructor-args", engineSet: "astTaint.PASSTHROUGH_NEW",
    names: ["URL", "URLSearchParams", "Buffer", "String", "Array", "Set", "Map", "Error"] },
  { id: "js:method-args", lang: "js", kind: "method-args", engineSet: "astTaint.ARG_CARRYING_METHODS",
    names: ["replace", "replaceAll", "concat", "padStart", "padEnd"] },
  { id: "py:call-args", lang: "py", kind: "call-args", engineSet: "astTaintPython.PY_PASSTHROUGH",
    names: [
    "str", "bytes", "bytearray", "repr", "ascii", "list", "tuple", "set", "frozenset", "dict", "sorted", "reversed",
    "enumerate", "zip", "map", "filter", "iter", "next", "getattr", "copy.copy", "copy.deepcopy",
    "json.loads", "json.dumps", "json.load",
    // Regex substitution reshapes a string without validating it. (re.escape is deliberately absent: its result
    // stays untainted so a pattern built from it isn't reported as regex injection -- there is no dedicated ReDoS
    // class to clear on its own.)
    "re.sub", "re.subn",
    "base64.b64decode", "base64.b64encode", "base64.urlsafe_b64decode", "base64.urlsafe_b64encode",
    "b64decode", "b64encode", "urlsafe_b64decode", "urlsafe_b64encode",
    "urllib.parse.unquote", "urllib.parse.unquote_plus", "urllib.parse.unquote_to_bytes", "urllib.parse.urljoin",
    "urllib.parse.urlparse", "urllib.parse.urlunparse", "urllib.parse.urlsplit", "urllib.parse.urlunsplit",
    "urllib.parse.parse_qs", "urllib.parse.parse_qsl", "urllib.parse.urlencode",
    "unquote", "unquote_plus", "urljoin", "urlparse", "urlunparse", "urlsplit", "urlunsplit", "parse_qs", "parse_qsl",
    "os.path.join", "os.path.abspath", "os.path.normpath", "os.path.realpath", "os.path.expanduser", "os.path.dirname",
    "os.fspath", "pathlib.Path", "Path", "PurePath", "html.unescape", "textwrap.dedent", "shlex.split",
    ] },
  { id: "py:decoder", lang: "py", kind: "decoder", engineSet: "astTaintPython.PY_DECODERS",
    names: [
    "urllib.parse.unquote", "urllib.parse.unquote_plus", "urllib.parse.unquote_to_bytes", "unquote", "unquote_plus",
    "base64.b64decode", "base64.urlsafe_b64decode", "b64decode", "urlsafe_b64decode", "html.unescape",
    ] },
  { id: "py:method-args", lang: "py", kind: "method-args", engineSet: "astTaintPython.PY_ARG_CARRYING_METHODS",
    // load / loads: a marshmallow / pydantic-style schema parses the payload into a validated dict that still holds
    // what the client sent (`data = self.schema.load(request.get_json())`)
    names: ["join", "replace", "format", "ljust", "rjust", "center", "removeprefix", "removesuffix", "load", "loads"] },
  { id: "go:call-args", lang: "go", kind: "call-args", engineSet: "astTaintGo.GO_PASSTHROUGH",
    names: [
    "strings.TrimSpace", "strings.Trim", "strings.TrimLeft", "strings.TrimRight", "strings.TrimPrefix", "strings.TrimSuffix",
    "strings.TrimFunc", "strings.ToLower", "strings.ToUpper", "strings.ToTitle", "strings.Title", "strings.Replace",
    "strings.ReplaceAll", "strings.Join", "strings.Split", "strings.SplitN", "strings.SplitAfter", "strings.Fields",
    "strings.Repeat", "strings.Map", "strings.NewReader", "strings.Clone",
    "bytes.TrimSpace", "bytes.Trim", "bytes.ToLower", "bytes.ToUpper", "bytes.ReplaceAll", "bytes.NewBuffer",
    "bytes.NewBufferString", "bytes.NewReader", "bytes.Join", "bytes.Split",
    "fmt.Errorf", "url.QueryUnescape", "url.PathUnescape", "url.Parse", "url.ParseRequestURI", "url.JoinPath",
    "filepath.Join", "filepath.Clean", "filepath.Abs", "filepath.Dir", "filepath.ToSlash", "filepath.FromSlash", "filepath.Rel",
    "path.Join", "path.Clean", "path.Dir", "json.Marshal", "json.MarshalIndent", "json.NewDecoder", "xml.NewDecoder",
    "gob.NewDecoder", "yaml.NewDecoder", "io.ReadAll", "ioutil.ReadAll", "bufio.NewReader", "bufio.NewScanner",
    "html.UnescapeString", "hex.DecodeString", "hex.EncodeToString", "strconv.Quote", "template.HTML", "template.JS",
    "template.JSStr", "template.URL", "template.CSS", "template.HTMLAttr", "textwrap.Dedent", "strconv.Itoa", "strconv.FormatInt",
    "strconv.FormatUint",
    ] },
  { id: "go:decoder", lang: "go", kind: "decoder", engineSet: "astTaintGo.GO_DECODERS",
    names: ["url.QueryUnescape", "url.PathUnescape", "html.UnescapeString", "hex.DecodeString"] },
  { id: "go:method-args", lang: "go", kind: "method-args", engineSet: "astTaintGo.GO_ARG_CARRYING_METHODS",
    names: ["Replace", "ReplaceAll", "Join", "Sprintf", "Format"] },
  { id: "go:mutator", lang: "go", kind: "mutator", engineSet: "astTaintGo.GO_MUTATORS",
    names: ["WriteString", "Write", "WriteByte", "WriteRune", "Add", "Set", "Push", "Store", "Put", "Insert", "Append", "Enqueue"] },
  { id: "cs:call-args", lang: "cs", kind: "call-args", engineSet: "astTaintCSharp.CS_PASSTHROUGH",
    names: [
    "string.Join", "String.Join", "string.Concat", "String.Concat", "string.Format", "String.Format", "string.Copy", "String.Copy",
    "Path.Combine", "Path.GetFullPath", "Path.GetDirectoryName", "Path.ChangeExtension", "Path.GetRelativePath",
    "WebUtility.UrlDecode", "HttpUtility.UrlDecode", "Uri.UnescapeDataString", "WebUtility.HtmlDecode", "HttpUtility.HtmlDecode",
    "Convert.FromBase64String", "Convert.ToBase64String", "Convert.ToString",
    "JsonConvert.SerializeObject", "JsonConvert.DeserializeObject", "JsonSerializer.Serialize", "JsonSerializer.Deserialize",
    "Enumerable.Concat", "Enumerable.Repeat", "Task.FromResult", "Uri.EscapeUriString", "Environment.ExpandEnvironmentVariables",
    ] },
  { id: "cs:decoder", lang: "cs", kind: "decoder", engineSet: "astTaintCSharp.CS_DECODERS",
    names: ["WebUtility.UrlDecode", "HttpUtility.UrlDecode", "Uri.UnescapeDataString", "WebUtility.HtmlDecode", "HttpUtility.HtmlDecode", "Convert.FromBase64String"] },
  { id: "cs:method-args", lang: "cs", kind: "method-args", engineSet: "astTaintCSharp.CS_ARG_CARRYING_METHODS",
    names: ["Replace", "Concat", "Insert", "PadLeft", "PadRight", "Format", "Join", "AppendFormat"] },
  { id: "cs:mutator", lang: "cs", kind: "mutator", engineSet: "astTaintCSharp.CS_MUTATORS",
    names: ["Add", "AddRange", "Append", "AppendLine", "AppendFormat", "Insert", "Push", "Enqueue", "TryAdd", "Set", "Put", "AddFirst", "AddLast"] },
  { id: "php:call-args", lang: "php", kind: "call-args", engineSet: "astTaintPHP.PHP_PASSTHROUGH",
    names: [
    "trim", "ltrim", "rtrim", "strtolower", "strtoupper", "mb_strtolower", "mb_strtoupper", "ucfirst", "lcfirst",
    "ucwords", "nl2br", "addslashes", "stripslashes", "wordwrap", "str_pad", "str_repeat", "number_format",
    "substr", "mb_substr", "sprintf", "vsprintf", "str_replace", "str_ireplace", "preg_replace", "preg_replace_callback",
    "implode", "join", "explode", "array_merge", "array_merge_recursive", "array_combine", "array_values", "array_keys",
    "array_map", "array_filter", "array_slice", "array_unique", "array_reverse", "array_pad",
    "json_encode", "json_decode", "serialize", "realpath", "dirname", "pathinfo",
    "base64_encode", "base64_decode", "bin2hex", "hex2bin", "htmlspecialchars_decode", "html_entity_decode",
    "urldecode", "rawurldecode",
    ] },
  { id: "php:decoder", lang: "php", kind: "decoder", engineSet: "astTaintPHP.PHP_DECODERS",
    names: ["urldecode", "rawurldecode", "base64_decode", "html_entity_decode", "htmlspecialchars_decode"] },
  { id: "rb:method-args", lang: "rb", kind: "method-args", engineSet: "astTaintRuby.ARG_FLOW_METHODS",
    names: [
    "concat", "prepend", "insert", "sub", "gsub", "sub!", "gsub!", "replace", "merge", "merge!", "update", "reverse_merge",
    "deep_merge", "push", "append", "unshift", "<<", "+", "join", "format", "%", "center", "ljust", "rjust", "zip", "product",
    ] },
  { id: "rb:mutator", lang: "rb", kind: "mutator", engineSet: "astTaintRuby.MUTATOR_METHODS",
    names: ["<<", "concat", "prepend", "insert", "push", "append", "unshift", "merge!", "update", "replace", "store", "[]="] },
  { id: "rb:call-args", lang: "rb", kind: "call-args", engineSet: "astTaintRuby.PASSTHROUGH_CALLS",
    names: [
    "format", "sprintf", "String", "Array", "Hash", "URI", "URI.parse", "URI.join", "URI::HTTP.build", "URI::HTTPS.build",
    "File.join", "File.expand_path", "File.absolute_path", "File.realpath", "Pathname.new", "Pathname", "Rails.root.join",
    "Base64.decode64", "Base64.strict_decode64", "Base64.urlsafe_decode64", "Base64.encode64", "Base64.strict_encode64",
    "CGI.unescape", "URI.decode_www_form_component", "Rack::Utils.unescape", "JSON.parse", "JSON.generate", "Oj.dump",
    "ActiveSupport::JSON.decode", "declared", "OpenStruct.new", "Struct.new", "Kernel.format", "Kernel.sprintf",
    ] },
  { id: "rb:decoder", lang: "rb", kind: "decoder", engineSet: "astTaintRuby.DECODER_CALLS",
    names: ["Base64.decode64", "Base64.strict_decode64", "Base64.urlsafe_decode64", "CGI.unescape", "URI.decode_www_form_component", "Rack::Utils.unescape"] },
  { id: "kt:method-args", lang: "kt", kind: "method-args", engineSet: "astTaintKotlin.ARG_FLOW_METHODS",
    names: [
    "plus", "format", "replace", "replaceFirst", "replaceRange", "append", "appendLine", "insert", "concat", "copy", "resolve",
    "resolveSibling", "queryParam", "path", "pathSegment", "host", "scheme", "uri", "fromUriString", "fromHttpUrl", "port",
    "plusElement", "zip", "padStart", "padEnd", "replaceAll", "with", "withPath", "setPath", "addPathSegment", "addQueryParameter",
    "build", "buildAndExpand", "expand", "header", "body", "put", "putIfAbsent", "getOrDefault", "getOrElse", "orElse", "or",
    ] },
  { id: "kt:mutator", lang: "kt", kind: "mutator", engineSet: "astTaintKotlin.MUTATOR_METHODS",
    names: ["append", "appendLine", "add", "addAll", "put", "putAll", "set", "insert", "push", "offer", "addFirst", "addLast", "plusAssign", "putIfAbsent", "setProperty"] },
  { id: "kt:call-args", lang: "kt", kind: "call-args", engineSet: "astTaintKotlin.PASSTHROUGH_CALLS",
    names: [
    "String.format", "listOf", "mutableListOf", "arrayListOf", "arrayOf", "setOf", "mutableSetOf", "hashSetOf", "mapOf",
    "mutableMapOf", "hashMapOf", "linkedMapOf", "requireNotNull", "checkNotNull", "URI.create", "Paths.get", "Path.of",
    "URLDecoder.decode", "String.valueOf", "Objects.toString", "Objects.requireNonNull", "UriComponentsBuilder.fromHttpUrl",
    "UriComponentsBuilder.fromUriString", "MessageFormat.format", "StringBuilder", "buildString", "sequenceOf", "Optional.of",
    "Optional.ofNullable", "Base64.getDecoder.decode", "Base64.getUrlDecoder.decode", "Base64.getMimeDecoder.decode",
    ] },
  { id: "rs:method-args", lang: "rs", kind: "method-args", engineSet: "astTaintRust.ARG_FLOW_METHODS",
    names: [
    "push_str", "push", "extend", "insert", "replace", "replacen", "unwrap_or", "or", "chain", "join", "with_file_name",
    "with_extension", "concat", "append", "add", "set_path", "set_query", "set_host", "query", "header", "body", "uri", "url",
    "path", "or_else", "unwrap_or_else", "map_or", "extend_from_slice", "zip", "and",
    ] },
  { id: "rs:mutator", lang: "rs", kind: "mutator", engineSet: "astTaintRust.MUTATOR_METHODS",
    names: ["push_str", "push", "extend", "insert", "append", "extend_from_slice", "write_str", "write_all", "push_front", "push_back", "set_path", "set_query", "set_host"] },
  { id: "rs:call-args", lang: "rs", kind: "call-args", engineSet: "astTaintRust.PASSTHROUGH_PATHS",
    names: [
    "String::from", "PathBuf::from", "Path::new", "OsString::from", "OsStr::new", "Url::parse", "Url::join", "Uri::from_str",
    "Uri::try_from", "Cow::from", "Box::new", "Arc::new", "Rc::new", "urlencoding::decode", "percent_decode_str",
    "percent_encoding::percent_decode_str", "base64::decode", "serde_json::from_str", "serde_json::from_slice",
    "serde_json::from_value", "serde_urlencoded::from_str", "serde_qs::from_str", "toml::from_str", "serde_yaml::from_str",
    "String::from_utf8", "String::from_utf8_lossy", "str::from_utf8", "std::str::from_utf8", "Vec::from", "Document::from",
    "bson::to_document", "Value::from", "STANDARD.decode", "general_purpose::STANDARD.decode",
    ] },
  { id: "cpp:call-args", lang: "cpp", kind: "call-args", engineSet: "astTaintCpp.RETURN_PASSTHROUGH",
    names: ["strdup", "strndup", "wcsdup", "_strdup", "_wcsdup", "strchr", "strrchr", "strstr", "strtok", "basename", "dirname", "string", "wstring", "c_str", "data", "substr", "str", "to_string",
      // the value an object or argument already holds: std::move / std::forward, element and optional accessors
      "move", "forward", "at", "front", "back", "value", "value_or", "top"] },
  { id: "java:call-args", lang: "java", kind: "call-args", engineSet: "astTaintJava.ARG_CARRYING_TAILS",
    names: [
    "replace", "replaceAll", "replaceFirst", "concat", "join", "valueOf", "copyValueOf", "of", "ofNullable", "asList",
    "resolve", "resolveSibling", "decode", "encode", "encodeToString", "decodeToString", "requireNonNull",
    // Commons Codec's Base64: the encoded form keeps "/" (not path-safe), and decoding gives the input back
    "encodeBase64", "encodeBase64String", "encodeBase64URLSafe", "encodeBase64URLSafeString", "decodeBase64",
    "requireNonNullElse", "copyOf", "singletonList", "unmodifiableList", "unmodifiableSet", "unmodifiableMap",
    "orElse", "getOrDefault", "create", "toURI", "normalize", "strip", "trim",
    ] },
];

/** The names one engine uses for one kind of propagation. */
export function propagatorNames(lang: ModelLang, kind: PropagatorKind): Set<string> {
  return new Set(PROPAGATOR_MODELS.filter(p => p.lang === lang && p.kind === kind).flatMap(p => p.names));
}
