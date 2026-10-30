/**
 * What the public site says about coverage, derived from the engines' own registries so the numbers can't drift
 * from the code: DATA_FLOW_LANGUAGES (ruleLanguages.ts, compile-time checked against every engine's id type) says
 * which language engine reports which rule; FINDING_CATALOG / INDICATOR_CWE_MAP give each rule's title, description
 * and CWE. The landing page's counts, the docs coverage matrix and the benchmark report all read from here.
 */
import { DATA_FLOW_LANGUAGES } from "@/lib/ruleLanguages";
import { FINDING_CATALOG } from "@/lib/findingCatalog";
import { cweFor } from "@/lib/cweMap";

export interface CoverageRule {
  id: string;
  title: string;
  description: string;
  cwe: string | null;
  /** Language engines whose data-flow analysis reports this rule. */
  languages: string[];
}

export const COVERAGE_LANGUAGES: string[] = DATA_FLOW_LANGUAGES.map(l => l.language);

/** Every rule at least one data-flow engine reports, most widely supported first. */
export function dataFlowRules(): CoverageRule[] {
  const ids = [...new Set(DATA_FLOW_LANGUAGES.flatMap(l => [...l.ids]))];
  return ids
    .map(id => {
      const meta = FINDING_CATALOG[id];
      return {
        id,
        title: meta?.title ?? id,
        description: meta?.description ?? "",
        cwe: meta?.cwe ?? cweFor(id)?.id ?? null,
        languages: DATA_FLOW_LANGUAGES.filter(l => l.ids.includes(id)).map(l => l.language),
      };
    })
    .sort((a, b) => b.languages.length - a.languages.length || a.title.localeCompare(b.title));
}

/** Rules each language engine reports. */
export function rulesByLanguage(): { language: string; ruleCount: number }[] {
  return DATA_FLOW_LANGUAGES.map(l => ({ language: l.language, ruleCount: new Set(l.ids).size }));
}

/**
 * The ten language engines as the site describes them. `engine` is the DATA_FLOW_LANGUAGES name the coverage
 * matrix uses; `limitations` lists gaps we know about from the benchmark runs (see /benchmarks).
 */
export interface LanguageEngine {
  engine: string; lang: string; short: string; mono: string; color: string; ext: string; note: string; extra: string;
  frameworks: string[]; limitations: string[];
}
export const LANGUAGE_ENGINES: LanguageEngine[] = [
  { engine: "JavaScript/TypeScript", lang: "TypeScript / JavaScript", short: "TypeScript", mono: "TS", color: "#3b82f6", ext: ".ts .tsx .js", note: "Cross-file flows through functions, classes & services", extra: "Named, default, namespace & CommonJS imports; NestJS injection", frameworks: ["Express", "NestJS", "Next.js", "browser DOM"], limitations: ["Dynamic property access with computed keys is followed only for literal keys.", "Framework middleware defined in another package is not inspected."] },
  { engine: "Python", lang: "Python", short: "Python", mono: "Py", color: "#facc15", ext: ".py", note: "Cross-module flows through functions & service classes", extra: "Relative & absolute imports, injected services", frameworks: ["Flask", "FastAPI", "Django"], limitations: ["Values that pass through dynamically imported modules (importlib) are not followed."] },
  { engine: "Java", lang: "Java", short: "Java", mono: "Jv", color: "#f97316", ext: ".java", note: "Spring services across files, entry-point aware", extra: "@Autowired & constructor injection, request wrappers in other files", frameworks: ["Servlet", "Spring", "JAX-RS"], limitations: ["An algorithm or setting read from a .properties file is not resolved (BenchmarkJava hash cases).", "Values built by a factory in another file are followed only through its return value, not its internal state."] },
  { engine: "Kotlin", lang: "Kotlin", short: "Kotlin", mono: "Kt", color: "#a78bfa", ext: ".kt .kts", note: "Spring, Ktor, Servlet & Android; shares cross-file evidence with Java", extra: "Coroutine builders, trailing-lambda calls, Android intents and WebViews", frameworks: ["Spring", "Ktor", "Android"], limitations: ["There is no public labelled Kotlin corpus, so Kotlin results are not in the benchmark report; the engine is tested with unit tests and the AndroGoat / Goatlin apps."] },
  { engine: "Go", lang: "Go", short: "Go", mono: "Go", color: "#22d3ee", ext: ".go", note: "Cross-package calls, path-sensitive, BOLA dominance", extra: "Struct-field and typed-parameter method resolution", frameworks: ["net/http", "Gin", "Echo", "Fiber"], limitations: ["Code-injection and authentication-failure categories score low on the sast-benchmark corpus."] },
  { engine: "C#", lang: "C#", short: "C#", mono: "C#", color: "#c084fc", ext: ".cs", note: "Services across files, path-sensitive, BOLA dominance", extra: "Constructor & primary-constructor injection; proofs from the batch's own call sites", frameworks: ["ASP.NET Core", "System.Web (HttpRequest)"], limitations: ["A value returned by a method in another file is not yet used to prove a sink safe (Juliet flow variant 61), which leaves some SQL false positives."] },
  { engine: "PHP", lang: "PHP", short: "PHP", mono: "PHP", color: "#818cf8", ext: ".php", note: "Functions & classes across includes, path-sensitive", extra: "__DIR__, relative & transitive includes; static calls", frameworks: ["Laravel", "plain PHP", "WordPress nonces"], limitations: ["XXE detection follows libxml's real defaults, so many corpus cases labelled vulnerable are not flagged.", "CSRF is reported only for session- or cookie-authenticated handlers."] },
  { engine: "Ruby", lang: "Ruby", short: "Ruby", mono: "Rb", color: "#f43f5e", ext: ".rb", note: "Rails & Sinatra controllers to services and models", extra: "Strong params, before_action state, service objects, scopes", frameworks: ["Rails", "Sinatra"], limitations: ["XXE: we follow Nokogiri's real defaults (external entities off), which disagrees with the corpus labels.", "Authorization-failure and CSRF categories are not detected yet."] },
  { engine: "Rust", lang: "Rust", short: "Rust", mono: "Rs", color: "#fb923c", ext: ".rs", note: "Axum, Actix & Rocket handlers, format! traced per argument", extra: "Integer overflow, unsafe raw memory access, allocation sizes", frameworks: ["Axum", "Actix", "Rocket", "Warp"], limitations: ["Calls to a project's own stub HTTP clients or deserializers are not treated as sinks; only real library calls are."] },
  { engine: "C/C++", lang: "C / C++", short: "C/C++", mono: "C++", color: "#60a5fa", ext: ".c .cpp .cc .h .hpp", note: "argv, stdin, sockets & getenv into exec, printf formats, SQL and files", extra: "Use-after-free, double free, unchecked malloc, buffer bounds, new T[n] sizes", frameworks: ["POSIX", "Win32", "C++ STL streams"], limitations: ["Macros defined in headers that are not in the scan are not expanded.", "rand() is not treated as attacker input, so Juliet's rand-sourced cases are not flagged."] },
];

/** Distinct CWE identifiers across the data-flow rules. */
export function dataFlowCwes(): string[] {
  return [...new Set(dataFlowRules().map(r => r.cwe).filter((c): c is string => !!c))].sort();
}
